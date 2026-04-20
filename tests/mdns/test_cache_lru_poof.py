"""RecordCache edge behaviour: RFC 6762 s10.2 cache-flush demotion,
LRU eviction at ``max_entries``, POOF (passive observation of failure)
tracking, the new ``next_event_at`` accessor used by the L1
adaptive-maintenance hook, and goodbye TTL demotion.
"""
from __future__ import annotations

import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    GOODBYE_DELAY_TTL,
    POOF_THRESHOLD,
    QType,
)
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.cache import CacheEvent, RecordCache


def _a(name: str, addr: str, ttl: int = 120,
       cache_flush: bool = False) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=cache_flush,
    )


class TestLRUEviction:
    def test_lru_evicts_oldest_when_over_max_entries(self):
        """Adding records past ``max_entries`` evicts the oldest by
        ``created_at`` until the cache is back at the limit."""
        cache = RecordCache(max_entries=3)
        now = time.monotonic()
        # Insert 5 records with strictly-increasing timestamps.
        for i in range(5):
            cache.add(_a(f"h{i}.local", f"10.0.0.{i + 1}"), now=now + i)

        assert len(cache) == 3
        # Oldest two (h0, h1) must be gone; h2, h3, h4 remain.
        assert cache.lookup(MDNSRecordKey("h0.local", QType.A), now + 5) == []
        assert cache.lookup(MDNSRecordKey("h1.local", QType.A), now + 5) == []
        assert cache.lookup(MDNSRecordKey("h4.local", QType.A), now + 5)


class TestCacheFlushDemotion:
    def test_cache_flush_bit_demotes_prior_rdata_ttl_to_one(self):
        """RFC 6762 s10.2: when a cache-flush record arrives, records
        with the same name + class but different rdata are demoted
        to TTL=1 so they expire 1 second later."""
        cache = RecordCache()
        now = time.monotonic()
        cache.add(_a("flush.local", "10.0.0.1", ttl=120), now=now)
        cache.add(_a("flush.local", "10.0.0.2", ttl=120), now=now)

        # New cache-flush record for same name; different rdata.
        cache.add(
            _a("flush.local", "10.0.0.3", ttl=120, cache_flush=True),
            now=now + 0.5,
        )

        # The two original records were demoted to ttl=1.
        existing = cache._records[MDNSRecordKey("flush.local", QType.A)]
        new_record = [r for r in existing if
                      r.data.address == IPv4Address("10.0.0.3")][0]
        old_records = [r for r in existing if r is not new_record]
        assert len(old_records) == 2
        for old in old_records:
            assert old.ttl == 1


class TestPOOF:
    def test_poof_candidates_surface_past_threshold(self):
        cache = RecordCache()
        now = time.monotonic()
        key = MDNSRecordKey("poof.local", QType.A)
        cache.add(_a("poof.local", "10.0.0.1"), now=now)
        # POOF_THRESHOLD consecutive failures to refresh.
        for _ in range(POOF_THRESHOLD):
            cache.record_poof(key)
        assert key in cache.get_poof_candidates()

    def test_poof_cleared_on_record_refresh(self):
        cache = RecordCache()
        now = time.monotonic()
        key = MDNSRecordKey("clr.local", QType.A)
        cache.add(_a("clr.local", "10.0.0.1"), now=now)
        cache.record_poof(key)
        cache.record_poof(key)
        # Adding the same record again (refresh) clears the POOF count.
        cache.add(_a("clr.local", "10.0.0.1"), now=now + 30)
        assert key not in cache.get_poof_candidates()


class TestGoodbyeDemotion:
    def test_goodbye_record_demotes_existing_ttl_to_goodbye_delay(self):
        """RFC 6762 s10.1: a TTL=0 add is a goodbye; existing matching
        records have their TTL set to ``GOODBYE_DELAY_TTL`` (1)."""
        cache = RecordCache()
        now = time.monotonic()
        cache.add(_a("bye.local", "10.0.0.1", ttl=120), now=now)

        event = cache.add(_a("bye.local", "10.0.0.1", ttl=0), now=now + 5)
        assert event == CacheEvent.REMOVE

        bucket = cache._records[MDNSRecordKey("bye.local", QType.A)]
        remaining = next(iter(bucket.values()))
        assert remaining.ttl == GOODBYE_DELAY_TTL

    def test_goodbye_for_unknown_record_is_noop(self):
        cache = RecordCache()
        event = cache.add(
            _a("ghost.local", "10.0.0.1", ttl=0), now=time.monotonic(),
        )
        assert event == CacheEvent.NOOP


class TestNextEventAt:
    def test_empty_cache_returns_none(self):
        assert RecordCache().next_event_at() is None

    def test_returns_earliest_of_refresh_and_expiry(self):
        """``next_event_at`` is used by the L1 adaptive-maintenance
        hook to wake exactly when something is due — neither later
        (wasted idleness) nor sooner (wasted wakeups)."""
        cache = RecordCache()
        now = time.monotonic()

        # Record A: ttl=100, will refresh at 80s, expire at 100s.
        cache.add(_a("short.local", "10.0.0.1", ttl=100), now=now)
        # Record B: ttl=1000, will refresh at 800s, expire at 1000s.
        cache.add(_a("long.local", "10.0.0.2", ttl=1000), now=now)

        nxt = cache.next_event_at()
        assert nxt is not None
        # Earliest event is short's 80% refresh ≈ now + 80.
        assert abs(nxt - (now + 80)) < 1.0

    def test_ignores_records_whose_refresh_quartiles_are_exhausted(self):
        """Once all four refresh quartiles have been consumed, the
        only remaining event for that record is its hard expiry."""
        cache = RecordCache()
        now = time.monotonic()
        cache.add(_a("done.local", "10.0.0.1", ttl=120), now=now)

        bucket = cache._records[MDNSRecordKey("done.local", QType.A)]
        rec = next(iter(bucket.values()))
        rec.refresh_sent = 4  # past the 80/85/90/95% table

        # next_event_at falls back to expiry time (now + 120).
        nxt = cache.next_event_at()
        assert nxt is not None
        assert abs(nxt - (now + 120)) < 1.0
