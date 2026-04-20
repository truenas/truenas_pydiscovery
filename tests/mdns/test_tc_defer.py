"""RFC 6762 §7.2: when a query arrives with the TC bit set, the
responder must defer its reply 400-500 ms so any follow-up
known-answer packets have time to arrive.  The normal QM defer is
20-120 ms; this test proves the TC path extends the window.
"""
from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    MDNSFlags,
    QType,
    RESPONSE_DEFER_MAX,
    TC_DEFER_MIN,
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


def _registry_with(*records: MDNSRecord) -> ServiceRegistry:
    group = EntryGroup()
    for r in records:
        group.add_record(r)
    reg = ServiceRegistry()
    reg.add_group(group)
    return reg


def _a(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


class TestTCBitDefer:
    def test_truncated_query_waits_past_normal_defer_window(self):
        """A TC=1 query must NOT fire at the 20-120 ms mark (which is
        the non-TC defer).  Prove it by polling just past that window
        and confirming the send still hasn't happened, then waiting
        to the TC window and observing the send."""
        reg = _registry_with(_a("tc.local", "10.0.0.1"))
        sent: list[MDNSMessage] = []
        loop = asyncio.new_event_loop()
        resp = Responder(sent.append, lambda msg, addr: None, reg)
        resp.start(loop)
        try:
            query = MDNSMessage(
                flags=MDNSFlags.TC.value,
                questions=[MDNSQuestion("tc.local", QType.A)],
            )
            resp.handle_query(query, ("10.0.0.50", 5353), interface_index=1)
            assert resp._pending, "TC query must still populate _pending"

            # Poll just past the non-TC max defer (120 ms) + jitter
            # buffer; nothing should have fired yet.
            loop.run_until_complete(
                asyncio.sleep(RESPONSE_DEFER_MAX + 0.050),
            )
            assert sent == [], (
                "TC response fired inside the normal defer window; "
                "expected the 400-500 ms TC window to apply."
            )

            # Wait out the full TC window and see the send arrive.
            loop.run_until_complete(
                asyncio.sleep(TC_DEFER_MIN - RESPONSE_DEFER_MAX - 0.050 + 0.150),
            )
            assert len(sent) == 1, (
                f"expected one send after TC defer, got {len(sent)}"
            )
        finally:
            resp.cancel_all()
            loop.close()

    def test_non_truncated_query_uses_short_defer(self):
        """Sanity: control path — a normal (non-TC) query fires
        within the 20-120 ms window, not the 400+ ms TC window."""
        reg = _registry_with(_a("ok.local", "10.0.0.1"))
        sent: list[MDNSMessage] = []
        loop = asyncio.new_event_loop()
        resp = Responder(sent.append, lambda msg, addr: None, reg)
        resp.start(loop)
        try:
            query = MDNSMessage(
                questions=[MDNSQuestion("ok.local", QType.A)],
            )
            t0 = time.monotonic()
            resp.handle_query(query, ("10.0.0.50", 5353), interface_index=1)
            loop.run_until_complete(
                asyncio.sleep(RESPONSE_DEFER_MAX + 0.100),
            )
            assert sent, "non-TC query did not fire in the normal window"
            elapsed = time.monotonic() - t0
            # Should fire well before the TC_DEFER_MIN threshold.
            assert elapsed < TC_DEFER_MIN, (
                f"non-TC query elapsed {elapsed:.3f}s, should be "
                f"under TC_DEFER_MIN={TC_DEFER_MIN}"
            )
        finally:
            resp.cancel_all()
            loop.close()
