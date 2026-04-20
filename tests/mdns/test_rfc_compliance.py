"""Tests for RFC 6762/6763 compliance fixes."""
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    GOODBYE_DELAY_TTL,
    MDNSFlags,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.cache import CacheEvent, RecordCache
from truenas_pymdns.server.core.entry_group import EntryGroup


def _a_record(name="h.local", addr="10.0.0.1", ttl=120, cache_flush=False):
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=cache_flush,
    )


class TestGoodbyeDelay:
    """RFC 6762 s10.1: goodbye should set TTL=1, not delete immediately."""

    def test_goodbye_sets_ttl_1(self):
        cache = RecordCache()
        cache.add(_a_record(), 100.0)
        goodbye = _a_record(ttl=0)
        event = cache.add(goodbye, 200.0)
        assert event == CacheEvent.REMOVE
        # Still in cache with TTL=1
        results = cache.lookup(MDNSRecordKey("h.local", QType.A), 200.0)
        assert len(results) == 1
        assert results[0].ttl == GOODBYE_DELAY_TTL

    def test_goodbye_expires_after_1s(self):
        cache = RecordCache()
        cache.add(_a_record(), 100.0)
        cache.add(_a_record(ttl=0), 200.0)
        expired = cache.expire(201.1)
        assert len(expired) == 1
        assert len(cache) == 0

    def test_goodbye_no_match(self):
        cache = RecordCache()
        cache.add(_a_record(addr="10.0.0.1"), 100.0)
        goodbye = _a_record(addr="10.0.0.99", ttl=0)
        event = cache.add(goodbye, 200.0)
        assert event == CacheEvent.NOOP


class TestTCBitTruncation:
    """RFC 6762 s7.2: TC bit set when message exceeds max_size."""

    def test_to_wire_sets_tc_on_overflow(self):
        records = []
        for i in range(100):
            records.append(MDNSRecord(
                key=MDNSRecordKey(f"host{i}.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address(f"10.0.{i // 256}.{i % 256}")),
            ))
        msg = MDNSMessage.build_response(records)
        wire = msg.to_wire(max_size=512)
        assert len(wire) <= 512
        parsed = MDNSMessage.from_wire(wire)
        assert parsed.flags & MDNSFlags.TC
        assert len(parsed.answers) < 100

    def test_to_wire_no_tc_when_fits(self):
        msg = MDNSMessage.build_response([_a_record()])
        wire = msg.to_wire(max_size=1460)
        parsed = MDNSMessage.from_wire(wire)
        assert not (parsed.flags & MDNSFlags.TC)
        assert len(parsed.answers) == 1

    def test_to_wire_unlimited(self):
        msg = MDNSMessage.build_response([_a_record()])
        wire = msg.to_wire()  # no max_size
        assert len(wire) > 0

    def test_is_truncated_property(self):
        msg = MDNSMessage(flags=int(MDNSFlags.TC))
        assert msg.is_truncated
        msg2 = MDNSMessage(flags=0)
        assert not msg2.is_truncated


class TestLegacyResponse:
    """RFC 6762 s6.7: legacy unicast response format."""

    def test_build_legacy_response(self):
        query = MDNSMessage(
            msg_id=0x1234,
            flags=0,
            questions=[MDNSQuestion("h.local", QType.A)],
        )
        answers = [_a_record(ttl=120)]
        resp = MDNSMessage.build_legacy_response(query, answers)

        assert resp.msg_id == 0x1234
        assert resp.is_response
        assert len(resp.questions) == 1
        # TTL capped at 10 seconds
        assert resp.answers[0].ttl == 10
        # Cache-flush bit must NOT be set
        assert not resp.answers[0].cache_flush

    def test_legacy_ttl_cap(self):
        query = MDNSMessage(msg_id=0x5678)
        answers = [_a_record(ttl=5)]  # already under cap
        resp = MDNSMessage.build_legacy_response(query, answers)
        assert resp.answers[0].ttl == 5


class TestSubtypes:
    """RFC 6763 s7.1: service subtype registration."""

    def test_add_service_with_subtypes(self):
        eg = EntryGroup()
        eg.add_service(
            instance="Printer",
            service_type="_http._tcp",
            domain="local",
            host="printer.local",
            port=80,
            subtypes=["_printer", "_colour"],
        )
        records = eg.records
        # meta-PTR, PTR, SRV, TXT, 2 subtype PTRs = 6
        assert len(records) == 6

        subtype_ptrs = [
            r for r in records
            if r.key.rtype == QType.PTR and "_sub." in r.key.name
        ]
        assert len(subtype_ptrs) == 2
        sub_names = {r.key.name for r in subtype_ptrs}
        assert "_printer._sub._http._tcp.local" in sub_names
        assert "_colour._sub._http._tcp.local" in sub_names
        for r in subtype_ptrs:
            assert r.data.target == "Printer._http._tcp.local"

    def test_add_service_no_subtypes(self):
        eg = EntryGroup()
        eg.add_service("X", "_tcp._tcp", "local", "h.local", 80)
        # No subtypes -> no _sub. PTR records
        assert not any(
            "_sub." in r.key.name for r in eg.records
        )
