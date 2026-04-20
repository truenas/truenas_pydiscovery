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
        # pkey -> (owned records, additionals, timer_handle)
        self._pending: dict[str, tuple[
            list[OwnedRecord], list[MDNSRecord] | None, asyncio.TimerHandle,
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

            # RFC 6762 s7.1: known-answer suppression
            known_rdata = set()
            for ka in message.answers:
                if ka.key.name.lower() == question.name.lower():
                    known_rdata.add(ka.rdata_wire())

            eligible = [
                ow for ow in matching
                if ow.record.rdata_wire() not in known_rdata
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
                    eligible, additionals,
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
            if self._registry.has_name(rr.key.name):
                our_records = self._registry.lookup(
                    rr.key.name, rr.key.rtype, interface_index
                )
                if our_records:
                    msg = MDNSMessage.build_response(
                        [ow.record for ow in our_records]
                    )
                    self._send(msg)

    def suppress_if_answered(self, message: MDNSMessage) -> None:
        """RFC 6762 s7.4: distributed duplicate answer suppression.

        For each peer answer, find owned records matching name, type
        AND rdata (per-record, like mDNSResponder's
        IdenticalResourceRecord and avahi's avahi_record_equal_no_ttl),
        stamp their last_peer_answer timestamps, and remove them from
        any pending batched response.
        """
        now = time.monotonic()
        for rr in message.answers:
            peer_rdata = rr.rdata_wire()
            matches = [
                ow for ow in self._registry.lookup(rr.key.name, rr.key.rtype)
                if ow.record.rdata_wire() == peer_rdata
            ]
            if not matches:
                continue

            for ow in matches:
                ow.last_peer_answer = now

            # Drop any matching records from pending batches; if a
            # batch becomes empty, cancel its timer.
            matched_ids = {id(ow) for ow in matches}
            empty_pkeys: list[str] = []
            for pkey, (records, _additionals, handle) in self._pending.items():
                remaining = [
                    ow for ow in records if id(ow) not in matched_ids
                ]
                if len(remaining) == len(records):
                    continue
                if remaining:
                    self._pending[pkey] = (
                        remaining,
                        self._pending[pkey][1],
                        handle,
                    )
                else:
                    handle.cancel()
                    empty_pkeys.append(pkey)
                    logger.debug(
                        "Suppressed response for %s (peer answered)",
                        rr.key.name,
                    )
            for pkey in empty_pkeys:
                del self._pending[pkey]

    def cancel_all(self) -> None:
        """Cancel all pending deferred responses."""
        for _, _, handle in self._pending.values():
            handle.cancel()
        self._pending.clear()

    def _schedule_response(
        self, owned: list[OwnedRecord],
        additionals: list[MDNSRecord] | None = None,
        truncated_query: bool = False,
    ) -> None:
        if not self._loop:
            return

        now = time.monotonic()

        # Filter out records that fail rate limit or were recently
        # answered by a peer (distributed duplicate suppression).
        eligible: list[OwnedRecord] = []
        for ow in owned:
            # RFC 6762 s6: 1-second per-record multicast rate limit
            if now - ow.last_multicast < MULTICAST_RATE_LIMIT:
                continue
            # RFC 6762 s7.4: suppress if peer recently answered
            if now - ow.last_peer_answer < _ANSWER_HISTORY_WINDOW:
                continue
            eligible.append(ow)

        if not eligible:
            return

        pkey = "|".join(sorted(self._record_key(ow.record) for ow in eligible))

        if pkey in self._pending:
            existing_records, _, _ = self._pending[pkey]
            existing_records.extend(eligible)
            return

        # RFC 6762 §7.2: when the inbound query has TC=1, wait
        # 400-500 ms instead of the usual 20-120 ms so follow-up
        # known-answer packets can arrive and further suppress us.
        if truncated_query:
            delay = random.uniform(TC_DEFER_MIN, TC_DEFER_MAX)
        else:
            delay = random.uniform(RESPONSE_DEFER_MIN, RESPONSE_DEFER_MAX)
        handle = self._loop.call_later(delay, self._send_pending, pkey)
        self._pending[pkey] = (eligible, additionals, handle)

    def _send_pending(self, pkey: str) -> None:
        item = self._pending.pop(pkey, None)
        if item is None:
            return
        owned, additionals, _ = item

        # Final suppression check — a peer may have answered while we
        # were waiting the 20-120ms jitter.
        now = time.monotonic()
        still_needed = [
            ow for ow in owned
            if now - ow.last_peer_answer >= _ANSWER_HISTORY_WINDOW
        ]

        if not still_needed:
            return

        msg = MDNSMessage.build_response(
            [ow.record for ow in still_needed], additionals,
        )
        self._send(msg)

        for ow in still_needed:
            ow.last_multicast = now

    def _collect_additionals(
        self, answers: list[MDNSRecord], interface_index: int,
    ) -> list[MDNSRecord]:
        """RFC 6763 s12: when returning PTR, include SRV+TXT+A/AAAA."""
        additionals: list[MDNSRecord] = []
        seen_keys: set[str] = set()

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
        seen_keys: set[str],
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
    def _record_key(rr: MDNSRecord) -> str:
        return f"{rr.key.name.lower()}|{rr.key.rtype.value}"
