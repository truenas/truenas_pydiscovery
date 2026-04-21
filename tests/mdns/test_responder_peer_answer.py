"""RFC 6762 s7.4 distributed duplicate answer suppression: pending-batch
cancellation and peer-answer window behaviour on ``Responder``.

Complements ``test_owned_record.py`` (which covers the per-rdata
stamping on ``OwnedRecord``) by exercising the interaction between
``suppress_if_answered`` and in-flight deferred responses in
``Responder._pending``.  These invariants used to live in an
``_answer_history`` dict that required periodic pruning — the L3
memory-leak fix migrated the state onto ``OwnedRecord`` and relies
on this cancellation path instead.
"""
from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    MULTICAST_RATE_LIMIT,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.query.responder import Responder
from truenas_pymdns.server.service.registry import ServiceRegistry

_ANSWER_HISTORY_WINDOW = 0.500  # mirrors responder._ANSWER_HISTORY_WINDOW


def _a(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


def _registry_with(*records: MDNSRecord) -> ServiceRegistry:
    group = EntryGroup()
    for r in records:
        group.add_record(r)
    reg = ServiceRegistry()
    reg.add_group(group)
    return reg


def _responder_on_loop(
    registry: ServiceRegistry, sent: list[MDNSMessage],
) -> tuple[Responder, asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    resp = Responder(sent.append, lambda msg, addr: None, registry)
    resp.start(loop)
    return resp, loop


class TestSuppressCancelsPendingBatch:
    def test_full_peer_coverage_cancels_timer_and_removes_pkey(self):
        """L3 invariant: when every owned record in a pending batch
        is satisfied by a peer answer, the deferred response timer is
        cancelled and the pkey entry is removed.  This is the path
        that replaced the old _answer_history pruning."""
        reg = _registry_with(_a("h.local", "10.0.0.1"))
        sent: list[MDNSMessage] = []
        resp, loop = _responder_on_loop(reg, sent)
        try:
            # Schedule a QM response via the public handle_query path.
            query = MDNSMessage(
                questions=[MDNSQuestion("h.local", QType.A)],
            )
            resp.handle_query(query, ("10.0.0.50", 5353), interface_index=1)
            assert resp._pending, "scheduling path must populate _pending"
            (_, _, handle), = resp._pending.values()

            # Peer answers the same rdata — should cancel the timer.
            peer = MDNSMessage()
            peer.answers = [_a("h.local", "10.0.0.1")]
            resp.suppress_if_answered(peer)

            assert resp._pending == {}
            assert handle.cancelled()
            # No packet ever left the responder.
            assert sent == []
        finally:
            resp.cancel_all()
            loop.close()

    def test_partial_peer_coverage_shrinks_batch_keeps_timer(self):
        """When a peer answers some but not all pending records, the
        batch shrinks to the remaining records and the timer handle
        stays live."""
        r1 = _a("h.local", "10.0.0.1")
        r2 = _a("h.local", "10.0.0.2")
        reg = _registry_with(r1, r2)
        sent: list[MDNSMessage] = []
        resp, loop = _responder_on_loop(reg, sent)
        try:
            # Seed _pending directly via _schedule_response so both
            # OwnedRecords end up in a single batch.
            owned = reg.lookup("h.local", QType.A)
            resp._schedule_response(list(owned))
            assert len(resp._pending) == 1
            (pkey, (before, _, handle)), = resp._pending.items()
            assert len(before) == 2

            # Peer answers only 10.0.0.1.
            peer = MDNSMessage()
            peer.answers = [_a("h.local", "10.0.0.1")]
            resp.suppress_if_answered(peer)

            assert pkey in resp._pending
            after, _, _ = resp._pending[pkey]
            assert len(after) == 1
            remaining_addr = after[0].record.data
            assert isinstance(remaining_addr, ARecordData)
            assert str(remaining_addr.address) == "10.0.0.2"
            assert not handle.cancelled()
        finally:
            resp.cancel_all()
            loop.close()

    def test_suppress_is_noop_when_no_pending(self):
        """A peer answer that matches an owned record but has no
        associated pending batch must stamp the peer-answer timestamp
        without raising or touching other state."""
        reg = _registry_with(_a("h.local", "10.0.0.1"))
        sent: list[MDNSMessage] = []
        resp, loop = _responder_on_loop(reg, sent)
        try:
            assert resp._pending == {}
            peer = MDNSMessage()
            peer.answers = [_a("h.local", "10.0.0.1")]
            resp.suppress_if_answered(peer)

            ow = reg.lookup("h.local", QType.A)[0]
            assert ow.last_peer_answer > 0.0
            assert resp._pending == {}
            assert sent == []
        finally:
            resp.cancel_all()
            loop.close()


class TestPeerAnswerWindowBlocksScheduling:
    def test_recent_peer_answer_suppresses_new_schedule(self):
        """RFC 6762 s7.4: a record whose last_peer_answer is within
        the 500ms history window must be excluded from new batches."""
        reg = _registry_with(_a("h.local", "10.0.0.1"))
        sent: list[MDNSMessage] = []
        resp, loop = _responder_on_loop(reg, sent)
        try:
            ow = reg.lookup("h.local", QType.A)[0]
            ow.last_peer_answer = time.monotonic()

            resp._schedule_response([ow])
            assert resp._pending == {}
        finally:
            resp.cancel_all()
            loop.close()

    def test_peer_answer_past_window_permits_schedule(self):
        """Once ``_ANSWER_HISTORY_WINDOW`` has elapsed since the last
        peer answer, scheduling is allowed again."""
        reg = _registry_with(_a("h.local", "10.0.0.1"))
        sent: list[MDNSMessage] = []
        resp, loop = _responder_on_loop(reg, sent)
        try:
            ow = reg.lookup("h.local", QType.A)[0]
            ow.last_peer_answer = (
                time.monotonic() - _ANSWER_HISTORY_WINDOW - 0.050
            )
            # Ensure rate-limit gate is also clear.
            ow.last_multicast = time.monotonic() - MULTICAST_RATE_LIMIT - 0.050

            resp._schedule_response([ow])
            assert len(resp._pending) == 1
        finally:
            resp.cancel_all()
            loop.close()
