"""Identity-based equality and hashing for MDNSRecord.

Apple mDNSResponder's ``IdenticalResourceRecord``
(``mDNSCore/DNSCommon.h:317``) defines record identity as
``(name, class, type, rdata)``.  TTL, cache-flush, and
scheduling metadata are deliberately excluded.  Domain names in
rdata (PTR/SRV target) are compared case-insensitively per
RFC 6762 §16, while TXT values stay byte-exact per
RFC 6763 §6.5.

These tests pin the contract for our ``MDNSRecord`` and every
``RecordData`` subclass: ``__eq__`` and ``__hash__`` reflect
that identity predicate and nothing else.
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import QClass, QType
from truenas_pymdns.protocol.records import (
    AAAARecordData,
    ARecordData,
    GenericRecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)


def _host_a(addr: str = "10.0.0.1") -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey("host.local", QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


class TestMDNSRecordIdentity:
    def test_identity_ignores_ttl(self):
        a = _host_a()
        b = _host_a()
        b.ttl = 60
        assert a == b
        assert hash(a) == hash(b)

    def test_identity_ignores_cache_flush_and_lifecycle(self):
        a = _host_a()
        b = _host_a()
        b.cache_flush = False
        b.created_at = 999.0
        assert a == b
        assert hash(a) == hash(b)

    def test_hash_stable_across_ttl_mutation(self):
        a = _host_a()
        s = {a}
        a.ttl = 999
        a.created_at = 123.0
        # Set membership uses hash → __eq__.  Both must still
        # produce the same result after mutation of metadata.
        assert a in s

    def test_different_rdata_not_equal(self):
        a = _host_a("10.0.0.1")
        b = _host_a("10.0.0.2")
        assert a != b
        # Collisions are possible but vanishingly rare — assert
        # that for these two distinct IPs, hashes differ.
        assert hash(a) != hash(b)

    def test_different_class_not_equal(self):
        a = MDNSRecord(
            key=MDNSRecordKey("host.local", QType.A, QClass.IN),
            ttl=120, data=ARecordData(IPv4Address("10.0.0.1")),
        )
        b = MDNSRecord(
            key=MDNSRecordKey("host.local", QType.A, QClass.ANY),
            ttl=120, data=ARecordData(IPv4Address("10.0.0.1")),
        )
        assert a != b

    def test_different_type_not_equal(self):
        a = MDNSRecord(
            key=MDNSRecordKey("host.local", QType.A),
            ttl=120, data=ARecordData(IPv4Address("10.0.0.1")),
        )
        b = MDNSRecord(
            key=MDNSRecordKey("host.local", QType.PTR),
            ttl=120, data=PTRRecordData("other.local"),
        )
        assert a != b

    def test_record_as_set_member(self):
        """A bag of records with the same identity collapses to one
        entry regardless of TTL / metadata — the whole point of
        adding ``__hash__``."""
        records = [
            MDNSRecord(
                key=MDNSRecordKey("host.local", QType.A),
                ttl=ttl,
                data=ARecordData(IPv4Address("10.0.0.1")),
                cache_flush=(ttl % 2 == 0),
            )
            for ttl in range(1, 101)
        ]
        assert len(set(records)) == 1

    def test_record_as_dict_key(self):
        d: dict[MDNSRecord, str] = {}
        d[_host_a()] = "first"
        d[_host_a()] = "second"   # same identity, should overwrite
        assert len(d) == 1
        assert d[_host_a()] == "second"


class TestPTRIdentity:
    def test_case_insensitive_target(self):
        a = PTRRecordData("Host.local")
        b = PTRRecordData("host.local")
        c = PTRRecordData("HOST.LOCAL")
        assert a == b == c
        assert hash(a) == hash(b) == hash(c)

    def test_wire_preserves_original_case(self):
        a = PTRRecordData("Host.local")
        assert a.to_wire().startswith(b"\x04Host")   # original case on wire
        b = PTRRecordData("host.local")
        assert b.to_wire().startswith(b"\x04host")

    def test_different_target_not_equal(self):
        a = PTRRecordData("host.local")
        b = PTRRecordData("other.local")
        assert a != b


class TestSRVIdentity:
    def test_case_insensitive_target(self):
        a = SRVRecordData(0, 0, 445, "Host.local")
        b = SRVRecordData(0, 0, 445, "host.local")
        assert a == b
        assert hash(a) == hash(b)

    def test_port_differences_matter(self):
        a = SRVRecordData(0, 0, 80, "host.local")
        b = SRVRecordData(0, 0, 443, "host.local")
        assert a != b

    def test_priority_and_weight_matter(self):
        base = SRVRecordData(0, 0, 80, "host.local")
        assert base != SRVRecordData(1, 0, 80, "host.local")
        assert base != SRVRecordData(0, 1, 80, "host.local")


class TestTXTIdentity:
    def test_byte_exact_equality(self):
        a = TXTRecordData(entries=(b"key=Value",))
        b = TXTRecordData(entries=(b"key=Value",))
        assert a == b
        assert hash(a) == hash(b)

    def test_case_sensitive_values(self):
        """RFC 6763 §6.5: TXT values are case-sensitive.  Unlike
        domain names, differing only by case produces distinct
        records."""
        a = TXTRecordData(entries=(b"key=Value",))
        b = TXTRecordData(entries=(b"key=value",))
        assert a != b

    def test_entry_order_matters(self):
        a = TXTRecordData(entries=(b"a=1", b"b=2"))
        b = TXTRecordData(entries=(b"b=2", b"a=1"))
        assert a != b


class TestIPAddressIdentity:
    def test_a_record_packed_equality(self):
        a = ARecordData(IPv4Address("10.0.0.1"))
        b = ARecordData(IPv4Address("10.0.0.1"))
        assert a == b
        assert hash(a) == hash(b)

    def test_aaaa_record_packed_equality(self):
        a = AAAARecordData(IPv6Address("fe80::1"))
        b = AAAARecordData(IPv6Address("fe80::1"))
        assert a == b
        assert hash(a) == hash(b)


class TestGenericIdentity:
    def test_raw_byte_equality(self):
        a = GenericRecordData(raw=b"\x01\x02\x03")
        b = GenericRecordData(raw=b"\x01\x02\x03")
        assert a == b
        assert hash(a) == hash(b)

    def test_raw_bytes_must_match_exactly(self):
        a = GenericRecordData(raw=b"\x01\x02\x03")
        b = GenericRecordData(raw=b"\x01\x02\x04")
        assert a != b


class TestCrossTypeInequality:
    """Two different RecordData subclasses with superficially
    similar contents must never compare equal — isinstance check
    in each ``__eq__`` guards against this."""

    def test_ptr_vs_generic_not_equal(self):
        a = PTRRecordData("host.local")
        b = GenericRecordData(raw=a.to_wire())
        assert a != b
        assert b != a

    def test_a_vs_generic_not_equal(self):
        a = ARecordData(IPv4Address("10.0.0.1"))
        b = GenericRecordData(raw=a.to_wire())
        assert a != b
