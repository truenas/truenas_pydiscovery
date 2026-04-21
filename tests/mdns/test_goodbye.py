"""Goodbye packet sending per RFC 6762 s10.1: on shutdown, multicast
authoritative records with TTL=0 so peers flush their caches
immediately.  Repeated GOODBYE_COUNT times to survive packet loss.
"""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import GOODBYE_COUNT, QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.goodbye import send_goodbye


def _a(name: str, addr: str, ttl: int = 120) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


class TestSendGoodbye:
    def test_empty_records_is_noop(self):
        sent: list[MDNSMessage] = []
        send_goodbye(sent.append, [])
        assert sent == []

    def test_goodbye_emitted_count_times(self):
        sent: list[MDNSMessage] = []
        send_goodbye(sent.append, [_a("h.local", "10.0.0.1")])
        assert len(sent) == GOODBYE_COUNT

    def test_goodbye_wire_form_has_ttl_zero(self):
        """Build each goodbye message and decode it back through the
        wire format to prove the TTL lands as 0 in the actual bytes
        peers will see — not just in the dataclass field."""
        sent: list[MDNSMessage] = []
        send_goodbye(
            sent.append,
            [_a("h.local", "10.0.0.1", ttl=1800)],
        )
        assert sent
        wire = sent[0].to_wire()
        decoded = MDNSMessage.from_wire(wire)
        assert decoded.answers
        for rr in decoded.answers:
            assert rr.ttl == 0

    def test_all_copies_point_to_same_message_instance(self):
        """Implementation detail we care about: building the goodbye
        message once and resending N times avoids redundant encoding
        work.  Verify GOODBYE_COUNT references to the same object."""
        sent: list[MDNSMessage] = []
        send_goodbye(sent.append, [_a("h.local", "10.0.0.1")])
        assert len(sent) == GOODBYE_COUNT
        for msg in sent[1:]:
            assert msg is sent[0]
