"""Tests for DNS record dataclasses and wire serialisation."""
import struct

import pytest
from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.records import (
    ARecordData,
    AAAARecordData,
    MDNSRecord,
    PTRRecordData,
    MDNSRecordKey,
    SRVRecordData,
    TXTRecordData,
)


class TestMDNSRecordKey:
    def test_name_lowercased(self):
        key = MDNSRecordKey("MyHost.LOCAL", QType.A)
        assert key.name == "myhost.local"

    def test_equality(self):
        k1 = MDNSRecordKey("myhost.local", QType.A)
        k2 = MDNSRecordKey("MYHOST.LOCAL", QType.A)
        assert k1 == k2

    def test_hashable(self):
        k1 = MDNSRecordKey("test.local", QType.PTR)
        k2 = MDNSRecordKey("TEST.LOCAL", QType.PTR)
        assert hash(k1) == hash(k2)
        assert {k1, k2} == {k1}

    def test_ordering(self):
        k_a = MDNSRecordKey("a.local", QType.A)
        k_b = MDNSRecordKey("b.local", QType.A)
        assert k_a < k_b


class TestARecordData:
    def test_to_wire(self):
        rd = ARecordData(IPv4Address("192.168.1.100"))
        assert rd.to_wire() == b"\xc0\xa8\x01\x64"

    def test_from_wire(self):
        rd = ARecordData.from_wire(b"\xc0\xa8\x01\x64")
        assert rd.address == IPv4Address("192.168.1.100")

    def test_round_trip(self):
        orig = ARecordData(IPv4Address("10.0.0.1"))
        rd = ARecordData.from_wire(orig.to_wire())
        assert rd == orig

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="4 bytes"):
            ARecordData.from_wire(b"\x00\x00")


class TestAAAARecordData:
    def test_to_wire(self):
        rd = AAAARecordData(IPv6Address("fe80::1"))
        wire = rd.to_wire()
        assert len(wire) == 16

    def test_round_trip(self):
        orig = AAAARecordData(IPv6Address("2001:db8::1"))
        rd = AAAARecordData.from_wire(orig.to_wire())
        assert rd == orig

    def test_wrong_length(self):
        with pytest.raises(ValueError, match="16 bytes"):
            AAAARecordData.from_wire(b"\x00" * 4)


class TestPTRRecordData:
    def test_round_trip(self):
        orig = PTRRecordData("My NAS._smb._tcp.local")
        wire = orig.to_wire()
        # Build a fake message buffer that is just the wire encoding
        rd = PTRRecordData.from_wire(wire, wire, 0)
        assert rd.target == "My NAS._smb._tcp.local"


class TestSRVRecordData:
    def test_to_wire_structure(self):
        rd = SRVRecordData(0, 0, 445, "truenas.local")
        wire = rd.to_wire()
        # 6 bytes (priority, weight, port) + encoded name
        assert len(wire) > 6
        p, w, port = struct.unpack("!HHH", wire[:6])
        assert (p, w, port) == (0, 0, 445)

    def test_round_trip(self):
        orig = SRVRecordData(10, 20, 8080, "webserver.local")
        wire = orig.to_wire()
        rd = SRVRecordData.from_wire(wire, wire, 0)
        assert rd.priority == 10
        assert rd.weight == 20
        assert rd.port == 8080
        assert rd.target == "webserver.local"


class TestTXTRecordData:
    def test_from_dict(self):
        rd = TXTRecordData.from_dict({"path": "/index.html", "server": "TrueNAS"})
        assert b"path=/index.html" in rd.entries
        assert b"server=TrueNAS" in rd.entries

    def test_round_trip(self):
        orig = TXTRecordData(entries=(b"key1=val1", b"key2=val2"))
        wire = orig.to_wire()
        rd = TXTRecordData.from_wire(wire)
        assert rd.entries == orig.entries

    def test_empty_txt(self):
        orig = TXTRecordData(entries=())
        wire = orig.to_wire()
        assert wire == b"\x00"
        rd = TXTRecordData.from_wire(wire)
        assert rd.entries == (b"",)

    def test_complex_txt_values(self):
        """ADISK-style TXT records with commas and equals in values."""
        rd = TXTRecordData.from_dict({
            "sys": "waMa=0,adVF=0x100",
            "dk0": "adVN=TimeMachine,adVF=0x82,adVU=aabbccdd-1122",
        })
        wire = rd.to_wire()
        rd2 = TXTRecordData.from_wire(wire)
        assert rd2.entries == rd.entries

    def test_entry_too_long(self):
        rd = TXTRecordData(entries=(b"x" * 256,))
        with pytest.raises(ValueError, match="too long"):
            rd.to_wire()


class TestMDNSRecord:
    def _make_a_record(self, name="myhost.local", addr="192.168.1.100",
                       ttl=120, cache_flush=False):
        return MDNSRecord(
            key=MDNSRecordKey(name, QType.A),
            ttl=ttl,
            data=ARecordData(IPv4Address(addr)),
            cache_flush=cache_flush,
        )

    def test_round_trip_a(self):
        rec = self._make_a_record(cache_flush=True)
        buf = bytearray()
        rec.to_wire(buf)
        rec2, end = MDNSRecord.from_wire(bytes(buf), 0)
        assert rec2.key.name == "myhost.local"
        assert rec2.key.rtype == QType.A
        assert rec2.ttl == 120
        assert rec2.cache_flush is True
        assert rec2.data.address == IPv4Address("192.168.1.100")
        assert end == len(buf)

    def test_round_trip_aaaa(self):
        rec = MDNSRecord(
            key=MDNSRecordKey("truenas.local", QType.AAAA),
            ttl=120,
            data=AAAARecordData(IPv6Address("fe80::1")),
        )
        buf = bytearray()
        rec.to_wire(buf)
        rec2, _ = MDNSRecord.from_wire(bytes(buf), 0)
        assert rec2.data.address == IPv6Address("fe80::1")

    def test_round_trip_srv(self):
        rec = MDNSRecord(
            key=MDNSRecordKey("My NAS._smb._tcp.local", QType.SRV),
            ttl=4500,
            data=SRVRecordData(0, 0, 445, "truenas.local"),
        )
        buf = bytearray()
        rec.to_wire(buf)
        rec2, _ = MDNSRecord.from_wire(bytes(buf), 0)
        assert rec2.data.port == 445
        assert rec2.data.target == "truenas.local"

    def test_round_trip_ptr(self):
        rec = MDNSRecord(
            key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
            ttl=4500,
            data=PTRRecordData("My NAS._smb._tcp.local"),
        )
        buf = bytearray()
        rec.to_wire(buf)
        rec2, _ = MDNSRecord.from_wire(bytes(buf), 0)
        assert rec2.data.target == "My NAS._smb._tcp.local"

    def test_round_trip_txt(self):
        rec = MDNSRecord(
            key=MDNSRecordKey("My NAS._device-info._tcp.local", QType.TXT),
            ttl=4500,
            data=TXTRecordData.from_dict({"model": "MacPro7,1@ECOLOR=226,226,224"}),
        )
        buf = bytearray()
        rec.to_wire(buf)
        rec2, _ = MDNSRecord.from_wire(bytes(buf), 0)
        assert b"model=MacPro7,1@ECOLOR=226,226,224" in rec2.data.entries

    def test_is_expired(self):
        rec = self._make_a_record(ttl=120)
        rec.created_at = 1000.0
        assert not rec.is_expired(1100.0)
        assert rec.is_expired(1120.0)
        assert rec.is_expired(1200.0)

    def test_remaining_ttl(self):
        rec = self._make_a_record(ttl=120)
        rec.created_at = 1000.0
        assert rec.remaining_ttl(1000.0) == 120
        assert rec.remaining_ttl(1060.0) == 60
        assert rec.remaining_ttl(1200.0) == 0

    def test_lexicographic_cmp_same(self):
        r1 = self._make_a_record(addr="192.168.1.1")
        r2 = self._make_a_record(addr="192.168.1.1")
        assert r1.lexicographic_cmp(r2) == 0

    def test_lexicographic_cmp_different_rdata(self):
        r1 = self._make_a_record(addr="192.168.1.1")
        r2 = self._make_a_record(addr="192.168.1.2")
        assert r1.lexicographic_cmp(r2) < 0
        assert r2.lexicographic_cmp(r1) > 0

    def test_lexicographic_cmp_different_type(self):
        r1 = MDNSRecord(
            key=MDNSRecordKey("test.local", QType.A),
            ttl=120,
            data=ARecordData(IPv4Address("1.2.3.4")),
        )
        r2 = MDNSRecord(
            key=MDNSRecordKey("test.local", QType.AAAA),
            ttl=120,
            data=AAAARecordData(IPv6Address("::1")),
        )
        # A(1) < AAAA(28), so r1 wins (negative)
        assert r1.lexicographic_cmp(r2) < 0

    def test_next_refresh_time(self):
        rec = self._make_a_record(ttl=100)
        rec.created_at = 0.0
        rec.refresh_sent = 0
        assert rec.next_refresh_time() == 80.0
        rec.refresh_sent = 1
        assert rec.next_refresh_time() == 85.0
        rec.refresh_sent = 4
        assert rec.next_refresh_time() is None
