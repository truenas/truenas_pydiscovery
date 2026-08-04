"""Response scheduling with jitter, rate limiting, and suppression.

RFC 6762 s6: response timing rules, QU vs QM, legacy unicast.
RFC 6762 s6.7: legacy unicast responses (source port != 5353).
RFC 6762 s7.4: duplicate answer suppression.
RFC 6763 s12: additional record generation.

Avahi equivalent: avahi-core/response-sched.c
  - Three queues: jobs (scheduled), history (recently sent/seen), suppressed
  - 500ms history window for distributed duplicate answer suppression

mDNSResponder equivalent: mDNSCore/mDNS.c
  - LastMCTime / LastMCInterface fields ride on each AuthRecord
  - ShouldSuppressKnownAnswer compares via IdenticalResourceRecord
  - We adopt that pattern: state lives on OwnedRecord in the registry
    so it tracks the record's lifecycle, with no side dict to prune.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Callable

from truenas_pymdns.protocol.constants import (
    MDNS_PORT,
    MULTICAST_RATE_LIMIT,
    QType,
    RESPONSE_DEFER_MAX,
    RESPONSE_DEFER_MIN,
    TC_DEFER_MAX,
    TC_DEFER_MIN,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import MDNSRecord, PTRRecordData, SRVRecordData
from ..core.entry_group import OwnedRecord
from ..service.registry import ServiceRegistry

logger = logging.getLogger(__name__)

# Avahi uses RESPONSE_SUPPRESS_MSEC=700 and RESPONSE_HISTORY_MSEC=500.
# We use 500ms for the history window (how long a network-seen answer
# suppresses our own) matching avahi's history queue.
_ANSWER_HISTORY_WINDOW = 0.500


class Responder:
    """Schedules and sends mDNS responses per RFC 6762.

    - QU queries: immediate unicast response (RFC 6762 s5.4)
    - QM queries: deferred 20-120ms multicast (RFC 6762 s6)
    - Legacy queries (port != 5353): unicast with echoed ID (s6.7)
    - 1-second per-record multicast rate limit (RFC 6762 s6)
    - Distributed duplicate answer suppression (RFC 6762 s7.4)
    - Additional record generation (RFC 6763 s12)
    """

    def __init__(
        self,
        send_fn: Callable[[MDNSMessage], None],
        unicast_send_fn: Callable[[MDNSMessage, tuple], None],
        registry: ServiceRegistry,
    ) -> None:
        self._send = send_fn
        self._unicast_send = unicast_send_fn
        self._registry = registry
        # pkey -> (owned records, additionals, timer_handle, interface_index)
        self._pending: dict[str, tuple[
            list[OwnedRecord], list[MDNSRecord] | None, asyncio.TimerHandle,
            int,
        ]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Bind to the event loop for deferred response scheduling."""
        self._loop = loop

    def handle_query(
        self,
        message: MDNSMessage,
        source: tuple,
        interface_index: int,
    ) -> None:
        """Process incoming query and schedule responses (RFC 6762 s6)."""
        source_port = source[1] if len(source) >= 2 else MDNS_PORT
        is_legacy = source_port != MDNS_PORT

        for question in message.questions:
            matching = self._registry.lookup(
                question.name, question.qtype, interface_index
            )
            if not matching:
                continue

            # RFC 6762 §7.1: suppress our answer only when the
            # querier's known answer carries an RR TTL at least half
            # the true value.  If its cached copy has decayed below
            # half we MUST still answer, to refresh the querier before
            # the record expires.  Map each known rdata to the largest
            # TTL the querier listed for it.
            known_ttl: dict[bytes, int] = {}
            for ka in message.answers:
                if ka.key.name.lower() == question.name.lower():
                    w = ka.rdata_wire()
                    if ka.ttl > known_ttl.get(w, -1):
                        known_ttl[w] = ka.ttl

            eligible = [
                ow for ow in matching
                if known_ttl.get(ow.record.rdata_wire(), -1)
                < ow.record.ttl // 2
            ]
            if not eligible:
                continue

            answer_records = [ow.record for ow in eligible]
            # RFC 6763 s12: attach additional records
            additionals = self._collect_additionals(
                answer_records, interface_index
            )

            if is_legacy:
                # RFC 6762 s6.7: legacy unicast response
                resp = MDNSMessage.build_legacy_response(
                    message, answer_records
                )
                if additionals:
                    resp.additionals = additionals
                self._unicast_send(resp, source)
            elif question.unicast_response:
                # RFC 6762 s5.4: QU — send unicast response
                msg = MDNSMessage.build_response(answer_records, additionals)
                self._unicast_send(msg, source)
            else:
                # QM — deferred multicast with jitter.  If the query
                # carried the TC bit, RFC 6762 §7.2 says follow-up
                # known-answer packets will arrive soon; defer 400-500
                # ms to give them time to land before we respond.
                self._schedule_response(
                    eligible, interface_index, additionals,
                    truncated_query=message.is_truncated,
                )

    def handle_probe_query(
        self,
        message: MDNSMessage,
        source: tuple,
        interface_index: int,
    ) -> None:
        """RFC 6762 s8.1: defend our names against probes without delay."""
        for rr in message.authorities:
            our_records = self._registry.lookup(
                rr.key.name, rr.key.rtype, interface_index
            )
            if our_records:
                msg = MDNSMessage.build_response(
                    [ow.record for ow in our_records]
                )
                self._send(msg)

    def suppress_if_answered(
        self, message: MDNSMessage, interface_index: int,
    ) -> None:
        """RFC 6762 s7.4: distributed duplicate answer suppression.

        For each peer answer seen on *interface_index*, find owned
        records matching name, type AND rdata (per-record, like
        mDNSResponder's IdenticalResourceRecord and avahi's
        avahi_record_equal_no_ttl), stamp their per-interface
        last_peer_answer timestamps, and remove them from any pending
        batched response.  The lookup is scoped to *interface_index*
        so a peer answer on one link cannot suppress our response on
        another (§7.4 is per-interface — the answer is only "seen" on
        the link it arrived on).
        """
        now = time.monotonic()
        for rr in message.answers:
            # RFC 6762 §16: compare rdata case-insensitively for
            # name-bearing record types.  ``RecordData.__eq__`` uses
            # ``_identity`` (case-folded for PTR/SRV targets,
            # byte-exact for A/AAAA/TXT per their respective specs).
            matches = [
                ow for ow in self._registry.lookup(
                    rr.key.name, rr.key.rtype, interface_index,
                )
                if ow.record.data == rr.data
            ]
            if not matches:
                continue

            for ow in matches:
                ow.last_peer_answer[interface_index] = now

            # Drop any matching records from pending batches; if a
            # batch becomes empty, cancel its timer.
            self._drop_from_pending(
                set(matches), f"peer answered {rr.key.name}",
            )

    def drop_pending(self, owned_records: list[OwnedRecord]) -> None:
        """Remove *owned_records* from any pending batched response.

        Used by conflict withdrawal (RFC 6762 §9): once a record is
        discarded, a deferred answer scheduled moments earlier must
        not re-assert it.
        """
        self._drop_from_pending(
            set(owned_records), "record withdrawn",
        )

    def _drop_from_pending(
        self, matched: set[OwnedRecord], context: str,
    ) -> None:
        """Drop *matched* records from every pending batch, cancelling
        a batch's timer when it empties."""
        empty_pkeys: list[str] = []
        for pkey, (records, add, handle, iface) in self._pending.items():
            remaining = [
                ow for ow in records if ow not in matched
            ]
            if len(remaining) == len(records):
                continue
            if remaining:
                self._pending[pkey] = (remaining, add, handle, iface)
            else:
                handle.cancel()
                empty_pkeys.append(pkey)
                logger.debug(
                    "Suppressed pending response (%s)", context,
                )
        for pkey in empty_pkeys:
            del self._pending[pkey]

    def cancel_all(self) -> None:
        """Cancel all pending deferred responses."""
        for _, _, handle, _iface in self._pending.values():
            handle.cancel()
        self._pending.clear()

    def _schedule_response(
        self, owned: list[OwnedRecord],
        interface_index: int,
        additionals: list[MDNSRecord] | None = None,
        truncated_query: bool = False,
    ) -> None:
        if not self._loop:
            return

        now = time.monotonic()

        # Filter out records that fail rate limit or were recently
        # answered by a peer (distributed duplicate suppression).  Both
        # gates read this interface's timestamps only (RFC 6762 §6/§7.4
        # are per-interface).
        eligible: list[OwnedRecord] = []
        for ow in owned:
            # RFC 6762 §6: 1-second per-record, per-interface rate limit
            if now - ow.last_multicast.get(interface_index, 0.0) \
                    < MULTICAST_RATE_LIMIT:
                continue
            # RFC 6762 §7.4: suppress if a peer answered on this iface
            if now - ow.last_peer_answer.get(interface_index, 0.0) \
                    < _ANSWER_HISTORY_WINDOW:
                continue
            eligible.append(ow)

        if not eligible:
            return

        pkey = self._pending_key(eligible)

        if pkey in self._pending:
            existing_records, _, _, _ = self._pending[pkey]
            # A record appears at most once per response (RFC 6762 §7.4;
            # avahi avahi_record_list_push guards the same way): dedup by
            # identity so a repeat query for the same records within the
            # defer window doesn't emit each answer twice.
            existing = set(existing_records)
            existing_records.extend(
                ow for ow in eligible if ow not in existing
            )
            return

        # RFC 6762 §7.2: when the inbound query has TC=1, wait
        # 400-500 ms instead of the usual 20-120 ms so follow-up
        # known-answer packets can arrive and further suppress us.
        if truncated_query:
            delay = random.uniform(TC_DEFER_MIN, TC_DEFER_MAX)
        else:
            delay = random.uniform(RESPONSE_DEFER_MIN, RESPONSE_DEFER_MAX)
        handle = self._loop.call_later(delay, self._send_pending, pkey)
        self._pending[pkey] = (eligible, additionals, handle, interface_index)

    def _send_pending(self, pkey: str) -> None:
        item = self._pending.pop(pkey, None)
        if item is None:
            return
        owned, additionals, _, interface_index = item

        # Final suppression check — a peer may have answered while we
        # were waiting the 20-120ms jitter.
        now = time.monotonic()
        still_needed = [
            ow for ow in owned
            if now - ow.last_peer_answer.get(interface_index, 0.0)
            >= _ANSWER_HISTORY_WINDOW
        ]

        if not still_needed:
            return

        msg = MDNSMessage.build_response(
            [ow.record for ow in still_needed], additionals,
        )
        self._send(msg)

        for ow in still_needed:
            ow.last_multicast[interface_index] = now

    def _collect_additionals(
        self, answers: list[MDNSRecord], interface_index: int,
    ) -> list[MDNSRecord]:
        """RFC 6763 s12: when returning PTR, include SRV+TXT+A/AAAA."""
        additionals: list[MDNSRecord] = []
        seen_keys: set[tuple] = set()

        for ans in answers:
            if (ans.key.rtype == QType.PTR
                    and isinstance(ans.data, PTRRecordData)):
                target = ans.data.target
                for rtype in (QType.SRV, QType.TXT):
                    for ow in self._registry.lookup(
                        target, rtype, interface_index
                    ):
                        rk = self._record_key(ow.record)
                        if rk not in seen_keys:
                            seen_keys.add(rk)
                            additionals.append(ow.record)
                            if isinstance(ow.record.data, SRVRecordData):
                                additionals.extend(
                                    self._address_records_for(
                                        ow.record.data.target,
                                        interface_index,
                                        seen_keys,
                                    )
                                )

            elif (ans.key.rtype == QType.SRV
                    and isinstance(ans.data, SRVRecordData)):
                additionals.extend(
                    self._address_records_for(
                        ans.data.target, interface_index,
                        seen_keys,
                    )
                )

        return additionals

    def _address_records_for(
        self, hostname: str, interface_index: int,
        seen_keys: set[tuple],
    ) -> list[MDNSRecord]:
        result: list[MDNSRecord] = []
        for rtype in (QType.A, QType.AAAA):
            for ow in self._registry.lookup(
                hostname, rtype, interface_index
            ):
                rk = self._record_key(ow.record)
                if rk not in seen_keys:
                    seen_keys.add(rk)
                    result.append(ow.record)
        return result

    @staticmethod
    def _pending_key(eligible: list[OwnedRecord]) -> str:
        """Coalescing key for a batch of deferred multicast answers.

        Identifies the batch by the RRSets it answers, so a repeat
        query arriving inside the defer window merges into the pending
        response instead of scheduling a second one.  Individual RRSet
        members are then merged by object identity, which is why this
        key stops at name and type.
        """
        return "|".join(sorted(
            f"{ow.record.key.name.lower()}|{ow.record.key.rtype.value}"
            for ow in eligible
        ))

    @staticmethod
    def _record_key(rr: MDNSRecord) -> tuple:
        """Identity used to keep an additional from being attached twice.

        Keyed on (name, type, rdata): name and type alone identify an
        RRSet, not a record, and a host with two addresses on one
        interface owns a multi-member RRSet.  RFC 6762 §6.2 requires a
        response to carry *all* the addresses valid on the interface
        it is sent on, so every member has to survive the
        de-duplication.

        ``RecordData`` equality and hashing go through its case-folded
        identity, which gives the §16 case-insensitive comparison for
        name-bearing rdata (PTR and SRV targets) for free.
        """
        return (rr.key.name.lower(), rr.key.rtype.value, rr.data)
