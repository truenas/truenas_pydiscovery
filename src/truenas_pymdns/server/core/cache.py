"""Per-interface mDNS record cache with TTL management."""
from __future__ import annotations

import logging
from collections import defaultdict
from enum import Enum

from truenas_pymdns.protocol.constants import (
    DEFAULT_CACHE_MAX_ENTRIES,
    GOODBYE_DELAY_TTL,
    POOF_THRESHOLD,
    QType,
)
from truenas_pymdns.protocol.records import MDNSRecord, MDNSRecordKey

logger = logging.getLogger(__name__)


class CacheEvent(Enum):
    """Outcome of adding a record to the cache."""
    NEW = "new"
    UPDATE = "update"
    REMOVE = "remove"
    NOOP = "noop"


class RecordCache:
    """Cache of received mDNS records with TTL-based expiry."""

    def __init__(self, max_entries: int = DEFAULT_CACHE_MAX_ENTRIES):
        self._max_entries = max_entries
        # Each bucket is keyed on the record itself (hashable per the
        # RFC 6762 / Apple ``IdenticalResourceRecord`` identity tuple)
        # with the same record as value — so bucket operations
        # (membership, add, replace, remove) are O(1) instead of the
        # O(n) ``list.index`` walk the previous list-based structure
        # required.  CPython dict iteration is insertion-ordered
        # (PEP 468; Python ≥ 3.7), matching the earlier list
        # semantics any caller might depend on.
        self._records: dict[
            MDNSRecordKey, dict[MDNSRecord, MDNSRecord]
        ] = {}
        self._poof_counts: dict[MDNSRecordKey, int] = defaultdict(int)

    def add(self, record: MDNSRecord, now: float) -> CacheEvent:
        """Add or update a record.  Handles cache-flush bit (RFC 6762 s10.2)."""
        record.created_at = now

        # RFC 6762 s10.1: TTL == 0 means goodbye.  SHOULD NOT delete
        # immediately — set TTL to 1 second so cooperating responders
        # have a window to "rescue" the record.
        if record.ttl == 0:
            return self._handle_goodbye(record, now)

        key = record.key
        existing = self._records.get(key)

        if record.cache_flush and existing:
            # Mark other records with same name+class for fast expiry
            # (1 second).  ``rec != record`` uses identity equality
            # (RFC 6762 §10.2), so any bucket entry whose rdata
            # differs from the incoming one is demoted.
            for rec in existing.values():
                if rec != record:
                    rec.created_at = now
                    rec.ttl = 1

        if existing is None:
            self._records[key] = {record: record}
            self._poof_counts.pop(key, None)
            self._enforce_max_entries()
            return CacheEvent.NEW

        # RFC 6762 §10.2: "identical record" = same name+class+type+rdata.
        # ``MDNSRecord.__eq__`` is that predicate, so dict key
        # membership replaces the prior list scan.
        is_update = record in existing
        existing[record] = record
        self._poof_counts.pop(key, None)
        if is_update:
            return CacheEvent.UPDATE
        self._enforce_max_entries()
        return CacheEvent.NEW

    def _handle_goodbye(self, record: MDNSRecord, now: float) -> CacheEvent:
        """RFC 6762 s10.1: set TTL=1 on matching records, expire 1s later."""
        existing = self._records.get(record.key)
        if not existing:
            return CacheEvent.NOOP
        target = existing.get(record)
        if target is None:
            return CacheEvent.NOOP
        target.ttl = GOODBYE_DELAY_TTL
        target.created_at = now
        return CacheEvent.REMOVE

    def remove(self, key: MDNSRecordKey) -> list[MDNSRecord]:
        """Remove all records for a key and drop any POOF state."""
        self._poof_counts.pop(key, None)
        bucket = self._records.pop(key, None)
        return list(bucket.values()) if bucket else []

    def _remove_matching(self, record: MDNSRecord) -> bool:
        """Remove a specific record by key + rdata match."""
        existing = self._records.get(record.key)
        if not existing or record not in existing:
            return False
        del existing[record]
        if not existing:
            del self._records[record.key]
        return True

    def lookup(self, key: MDNSRecordKey, now: float) -> list[MDNSRecord]:
        """Return all non-expired records matching key."""
        bucket = self._records.get(key)
        if bucket is None:
            return []
        return [r for r in bucket.values() if not r.is_expired(now)]

    def lookup_name(self, name: str, now: float) -> list[MDNSRecord]:
        """Return all non-expired records for a given name (any type)."""
        name_lower = name.lower()
        results: list[MDNSRecord] = []
        for key, bucket in self._records.items():
            if key.name == name_lower:
                results.extend(
                    r for r in bucket.values() if not r.is_expired(now)
                )
        return results

    def known_answers_for(self, name: str, qtype: int, now: float) -> list[MDNSRecord]:
        """Return records suitable for known-answer suppression."""
        results: list[MDNSRecord] = []
        name_lower = name.lower()
        for key, bucket in self._records.items():
            if key.name != name_lower:
                continue
            if qtype != QType.ANY and key.rtype.value != qtype:
                continue
            for r in bucket.values():
                if not r.is_expired(now) and r.remaining_ttl(now) > r.ttl // 2:
                    results.append(r)
        return results

    def expire(self, now: float) -> list[MDNSRecord]:
        """Remove and return all expired records."""
        expired: list[MDNSRecord] = []
        keys_to_remove: list[MDNSRecordKey] = []
        for key, bucket in self._records.items():
            # Collect before deleting so we don't mutate ``bucket``
            # during ``values()`` iteration.
            to_expire = [r for r in bucket.values() if r.is_expired(now)]
            for r in to_expire:
                expired.append(r)
                del bucket[r]
            if not bucket:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del self._records[key]
            self._poof_counts.pop(key, None)
        return expired

    def get_refresh_candidates(self, now: float) -> list[MDNSRecord]:
        """Return records that need TTL-refresh queries."""
        candidates = []
        for bucket in self._records.values():
            for r in bucket.values():
                nrt = r.next_refresh_time()
                if nrt is not None and now >= nrt:
                    candidates.append(r)
        return candidates

    def keys_matching_name(self, name: str) -> list[MDNSRecordKey]:
        """Return every cached key whose name matches *name* (case
        insensitive).  Used by the RFC 6762 §10.5 POOF path to bump
        failure counters for every cached record a peer queried."""
        name_lower = name.lower()
        return [k for k in self._records if k.name == name_lower]

    def record_poof(self, key: MDNSRecordKey) -> None:
        """Record a Passive Observation Of Failure."""
        if key in self._records:
            self._poof_counts[key] += 1

    def clear_poof(self, key: MDNSRecordKey) -> None:
        """Clear the POOF counter for a key (record was refreshed)."""
        self._poof_counts.pop(key, None)

    def get_poof_candidates(self) -> list[MDNSRecordKey]:
        """Return keys with POOF count >= threshold."""
        return [k for k, v in self._poof_counts.items() if v >= POOF_THRESHOLD]

    def next_event_at(self) -> float | None:
        """Return the monotonic time of the nearest future cache event.

        The minimum across all cached records of the next TTL-refresh
        time (RFC 6762 s5.2: 80/85/90/95% of the original TTL) and the
        hard expiry time (``created_at + ttl``).  ``None`` if empty.
        """
        soonest: float | None = None
        for bucket in self._records.values():
            for r in bucket.values():
                expiry = r.created_at + r.ttl
                candidates = [expiry]
                nrt = r.next_refresh_time()
                if nrt is not None:
                    candidates.append(nrt)
                for t in candidates:
                    if soonest is None or t < soonest:
                        soonest = t
        return soonest

    def stats(self) -> dict:
        """Summary of what's in the cache, for SIGUSR1 status dumps.

        ``by_type`` counts records per record-type name (``"A"``,
        ``"PTR"``, …).  ``service_types`` groups PTR entries by their
        holder name (e.g. ``"_smb._tcp.local"``) so operators can see
        which DNS-SD service types are populating the cache.
        """
        by_type: dict[str, int] = {}
        service_types: dict[str, int] = {}
        for key, bucket in self._records.items():
            type_name = (
                key.rtype.name if hasattr(key.rtype, "name")
                else str(key.rtype)
            )
            by_type[type_name] = by_type.get(type_name, 0) + len(bucket)
            if key.rtype == QType.PTR:
                service_types[key.name] = (
                    service_types.get(key.name, 0) + len(bucket)
                )
        return {
            "total_entries": len(self),
            "by_type": by_type,
            "service_types": service_types,
            "poof_tracked": len(self._poof_counts),
            "poof_candidates": len(self.get_poof_candidates()),
        }

    def __len__(self) -> int:
        return sum(len(v) for v in self._records.values())

    def _enforce_max_entries(self) -> None:
        """Evict oldest records when cache exceeds max size."""
        total = len(self)
        if total <= self._max_entries:
            return
        # Collect all records with timestamps, sort by created_at
        all_records: list[tuple[MDNSRecordKey, MDNSRecord]] = []
        for key, bucket in self._records.items():
            for r in bucket.values():
                all_records.append((key, r))
        all_records.sort(key=lambda x: x[1].created_at)
        to_remove = total - self._max_entries
        for i in range(min(to_remove, len(all_records))):
            key, rec = all_records[i]
            b = self._records.get(key)
            if b is not None and rec in b:
                del b[rec]
                if not b:
                    del self._records[key]
