"""Tests for core engine: entry_group, conflict."""
import pytest
from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import (
    DEFAULT_TTL_HOST_RECORD,
    EntryGroupState,
    QType,
)
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.conflict import (
    generate_alternative_name,
    lexicographic_compare,
)
from truenas_pymdns.server.core.entry_group import EntryGroup


def _a_record(name="myhost.local", addr="192.168.1.1", ttl=120,
              cache_flush=False):
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=cache_flush,
    )


class TestConflict:
    def test_same_records(self):
        r1 = [_a_record(addr="10.0.0.1")]
        r2 = [_a_record(addr="10.0.0.1")]
        assert lexicographic_compare(r1, r2) == 0

    def test_we_win(self):
        # Higher address wins
        ours = [_a_record(addr="10.0.0.2")]
        theirs = [_a_record(addr="10.0.0.1")]
        assert lexicographic_compare(ours, theirs) > 0

    def test_they_win(self):
        ours = [_a_record(addr="10.0.0.1")]
        theirs = [_a_record(addr="10.0.0.2")]
        assert lexicographic_compare(ours, theirs) < 0

    def test_longer_set_wins(self):
        ours = [_a_record(addr="10.0.0.1")]
        theirs = [_a_record(addr="10.0.0.1"), _a_record(addr="10.0.0.2")]
        assert lexicographic_compare(ours, theirs) < 0

    def test_alternative_name_hostname(self):
        assert generate_alternative_name("myhost") == "myhost-2"
        assert generate_alternative_name("myhost-2") == "myhost-3"
        assert generate_alternative_name("myhost-10") == "myhost-11"

    def test_alternative_name_instance(self):
        assert generate_alternative_name("My Service") == "My Service #2"
        assert generate_alternative_name("My Service #2") == "My Service #3"


class TestEntryGroup:
    def test_initial_state(self):
        eg = EntryGroup()
        assert eg.state == EntryGroupState.UNCOMMITTED
        assert eg.records == []

    def test_add_service(self):
        eg = EntryGroup()
        eg.add_service(
            instance="My NAS",
            service_type="_smb._tcp",
            domain="local",
            host="truenas.local",
            port=445,
            txt={"model": "MacPro7,1"},
        )
        records = eg.records
        # Should have: meta-PTR, service PTR, SRV, TXT = 4 records
        assert len(records) == 4

        types = [r.key.rtype for r in records]
        assert types.count(QType.PTR) == 2
        assert types.count(QType.SRV) == 1
        assert types.count(QType.TXT) == 1

        # Check SRV
        srv = [r for r in records if r.key.rtype == QType.SRV][0]
        assert srv.data.port == 445
        assert srv.data.target == "truenas.local"
        assert srv.ttl == DEFAULT_TTL_HOST_RECORD
        assert srv.cache_flush is True

        # Check TXT
        txt = [r for r in records if r.key.rtype == QType.TXT][0]
        assert b"model=MacPro7,1" in txt.data.entries

        # Check meta-PTR
        meta = [r for r in records
                if r.key.rtype == QType.PTR
                and "_services._dns-sd._udp" in r.key.name][0]
        assert meta.data.target == "_smb._tcp.local"

    def test_add_address_v4(self):
        eg = EntryGroup()
        eg.add_address("truenas.local", "192.168.1.100")
        records = eg.records
        # A record + reverse PTR = 2
        assert len(records) == 2
        a_rec = [r for r in records if r.key.rtype == QType.A][0]
        assert a_rec.data.address == IPv4Address("192.168.1.100")
        ptr_rec = [r for r in records if r.key.rtype == QType.PTR][0]
        assert "in-addr.arpa" in ptr_rec.key.name

    def test_add_address_v6(self):
        eg = EntryGroup()
        eg.add_address("truenas.local", "fe80::1")
        records = eg.records
        assert len(records) == 2
        aaaa_rec = [r for r in records if r.key.rtype == QType.AAAA][0]
        assert aaaa_rec.data.address == IPv6Address("fe80::1")

    def test_state_change(self):
        states = []
        eg = EntryGroup(on_state_change=states.append)
        eg.set_state(EntryGroupState.REGISTERING)
        eg.set_state(EntryGroupState.ESTABLISHED)
        assert states == [EntryGroupState.REGISTERING, EntryGroupState.ESTABLISHED]

    def test_cannot_add_after_commit(self):
        eg = EntryGroup()
        eg.set_state(EntryGroupState.REGISTERING)
        with pytest.raises(RuntimeError):
            eg.add_record(_a_record())

    def test_get_unique_records_returns_cache_flush_records(self):
        eg = EntryGroup()
        eg.add_service("Test", "_http._tcp", "local", "h.local", 80)
        unique = eg.get_unique_records()
        # SRV and TXT are unique (cache_flush=True), PTRs are shared.
        assert all(r.cache_flush for r in unique)
        assert len(unique) < len(eg.records)

    def test_interface_binding(self):
        eg = EntryGroup()
        eg.interfaces = [1, 2]
        eg.add_service("Test", "_http._tcp", "local", "h.local", 80)
        assert eg.interfaces == [1, 2]
