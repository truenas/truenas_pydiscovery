"""Tests for core engine: cache, entry_group, conflict."""
import pytest
from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import (
    DEFAULT_TTL_HOST_RECORD,
    EntryGroupState,
    QType,
)
from truenas_pymdns.protocol.records import (
    ARecordData,
    AAAARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.cache import CacheEvent, RecordCache
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


class TestRecordCache:
    def test_add_new(self):
        cache = RecordCache()
        rec = _a_record()
        event = cache.add(rec, 1000.0)
        assert event == CacheEvent.NEW
        assert len(cache) == 1

    def test_add_update(self):
        cache = RecordCache()
        rec1 = _a_record(ttl=120)
        cache.add(rec1, 1000.0)
        rec2 = _a_record(ttl=240)
        event = cache.add(rec2, 1050.0)
        assert event == CacheEvent.UPDATE
        assert len(cache) == 1

    def test_add_new_rdata(self):
        cache = RecordCache()
        rec1 = _a_record(addr="192.168.1.1")
        cache.add(rec1, 1000.0)
        rec2 = _a_record(addr="192.168.1.2")
        event = cache.add(rec2, 1000.0)
        assert event == CacheEvent.NEW
        assert len(cache) == 2

    def test_goodbye_delays_removal(self):
        """RFC 6762 s10.1: goodbye sets TTL=1, record expires 1s later."""
        cache = RecordCache()
        rec = _a_record()
        cache.add(rec, 1000.0)
        goodbye = _a_record(ttl=0)
        event = cache.add(goodbye, 1050.0)
        assert event == CacheEvent.REMOVE
        # Record still present with TTL=1 (not immediately deleted)
        assert len(cache) == 1
        # Expires after 1 second
        expired = cache.expire(1051.1)
        assert len(expired) == 1
        assert len(cache) == 0

    def test_expire(self):
        cache = RecordCache()
        rec = _a_record(ttl=60)
        cache.add(rec, 1000.0)
        assert len(cache) == 1
        expired = cache.expire(1059.0)
        assert len(expired) == 0
        expired = cache.expire(1061.0)
        assert len(expired) == 1
        assert len(cache) == 0

    def test_lookup(self):
        cache = RecordCache()
        rec = _a_record()
        cache.add(rec, 1000.0)
        results = cache.lookup(MDNSRecordKey("myhost.local", QType.A), 1000.0)
        assert len(results) == 1
        assert results[0].data.address == IPv4Address("192.168.1.1")

    def test_lookup_expired_excluded(self):
        cache = RecordCache()
        rec = _a_record(ttl=10)
        cache.add(rec, 1000.0)
        results = cache.lookup(MDNSRecordKey("myhost.local", QType.A), 1020.0)
        assert len(results) == 0

    def test_lookup_name(self):
        cache = RecordCache()
        cache.add(_a_record(), 1000.0)
        cache.add(MDNSRecord(
            key=MDNSRecordKey("myhost.local", QType.AAAA),
            ttl=120,
            data=AAAARecordData(IPv6Address("fe80::1")),
        ), 1000.0)
        results = cache.lookup_name("myhost.local", 1000.0)
        assert len(results) == 2

    def test_cache_flush_bit(self):
        cache = RecordCache()
        rec1 = _a_record(addr="192.168.1.1")
        cache.add(rec1, 1000.0)
        rec2 = _a_record(addr="192.168.1.2", cache_flush=True)
        cache.add(rec2, 1001.0)
        # rec1 should now have ttl=1 (about to expire)
        assert len(cache) == 2
        expired = cache.expire(1003.0)
        assert len(expired) == 1
        assert expired[0].data.address == IPv4Address("192.168.1.1")
        assert len(cache) == 1

    def test_max_entries_eviction(self):
        cache = RecordCache(max_entries=3)
        for i in range(5):
            rec = _a_record(addr=f"10.0.0.{i}")
            cache.add(rec, 1000.0 + i)
        assert len(cache) <= 3

    def test_poof(self):
        cache = RecordCache()
        key = MDNSRecordKey("test.local", QType.A)
        # POOF is only tracked for keys present in the cache
        rec = _a_record(name="test.local", ttl=120)
        cache.add(rec, 1000.0)
        cache.record_poof(key)
        assert cache.get_poof_candidates() == []
        cache.record_poof(key)
        assert key in cache.get_poof_candidates()
        cache.clear_poof(key)
        assert cache.get_poof_candidates() == []

    def test_known_answers(self):
        cache = RecordCache()
        rec = _a_record(ttl=120)
        cache.add(rec, 1000.0)
        # At 50% TTL should be included
        answers = cache.known_answers_for("myhost.local", QType.A, 1050.0)
        assert len(answers) == 1
        # At 90% TTL, remaining_ttl is 12 which is < 120//2=60, so excluded
        answers = cache.known_answers_for("myhost.local", QType.A, 1110.0)
        assert len(answers) == 0

    def test_refresh_candidates(self):
        cache = RecordCache()
        rec = _a_record(ttl=100)
        cache.add(rec, 0.0)
        candidates = cache.get_refresh_candidates(79.0)
        assert len(candidates) == 0
        candidates = cache.get_refresh_candidates(81.0)
        assert len(candidates) == 1


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
