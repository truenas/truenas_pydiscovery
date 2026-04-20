"""Conflict-rename helper (``_rename_group`` in server.server).

Covers RFC 6762 §9: when an entry group collides with a peer, its
primary name's first DNS label must be rewritten and every record
that references it (key.name on SRV/TXT/A/AAAA, PTR data.target on
service/subtype/reverse PTRs) must be updated in place, with
per-record scheduling state reset so the re-probe starts clean.
"""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.server import (
    _obsolete_shared_records,
    _rename_group,
)


def _service_group() -> EntryGroup:
    """_test._tcp instance 'nas' at host.local:445, with TXT + subtype."""
    g = EntryGroup()
    g.add_record(MDNSRecord(
        key=MDNSRecordKey("_services._dns-sd._udp.local", QType.PTR),
        ttl=4500, data=PTRRecordData("_test._tcp.local"),
    ))
    g.add_record(MDNSRecord(
        key=MDNSRecordKey("_test._tcp.local", QType.PTR),
        ttl=4500, data=PTRRecordData("nas._test._tcp.local"),
    ))
    g.add_record(MDNSRecord(
        key=MDNSRecordKey("nas._test._tcp.local", QType.SRV),
        ttl=1800,
        data=SRVRecordData(0, 0, 445, "host.local"),
        cache_flush=True,
    ))
    g.add_record(MDNSRecord(
        key=MDNSRecordKey("nas._test._tcp.local", QType.TXT),
        ttl=4500, data=TXTRecordData(entries=(b"k=v",)),
        cache_flush=True,
    ))
    g.add_record(MDNSRecord(
        key=MDNSRecordKey("_tm._sub._test._tcp.local", QType.PTR),
        ttl=4500, data=PTRRecordData("nas._test._tcp.local"),
    ))
    return g


def _host_group(fqdn: str = "myhost.local") -> EntryGroup:
    g = EntryGroup()
    g.add_record(MDNSRecord(
        key=MDNSRecordKey(fqdn, QType.A),
        ttl=1800,
        data=ARecordData(IPv4Address("10.0.0.1")),
        cache_flush=True,
    ))
    g.add_record(MDNSRecord(
        key=MDNSRecordKey("1.0.0.10.in-addr.arpa", QType.PTR),
        ttl=1800, data=PTRRecordData(fqdn),
        cache_flush=True,
    ))
    return g


class TestRenameServiceGroup:
    def test_srv_and_txt_keys_get_new_first_label(self):
        g = _service_group()
        old, new = _rename_group(g)
        assert old == "nas._test._tcp.local"
        assert new == "nas-2._test._tcp.local"

        names = {r.key.name for r in g.records}
        assert "nas-2._test._tcp.local" in names
        assert "nas._test._tcp.local" not in names
        # Parent PTR and _services meta-PTR unchanged.
        assert "_test._tcp.local" in names
        assert "_services._dns-sd._udp.local" in names

    def test_service_ptr_target_updated(self):
        g = _service_group()
        _rename_group(g)
        ptr_targets = {
            r.data.target for r in g.records
            if r.key.rtype == QType.PTR
            and isinstance(r.data, PTRRecordData)
            and r.key.name == "_test._tcp.local"
        }
        assert ptr_targets == {"nas-2._test._tcp.local"}

    def test_subtype_ptr_target_updated(self):
        g = _service_group()
        _rename_group(g)
        subtype_ptr = next(
            r for r in g.records
            if r.key.name == "_tm._sub._test._tcp.local"
        )
        assert isinstance(subtype_ptr.data, PTRRecordData)
        assert subtype_ptr.data.target == "nas-2._test._tcp.local"

    def test_srv_target_host_is_preserved(self):
        """SRV.target points to the host FQDN, which is a separate
        name — conflict rename must NOT touch it."""
        g = _service_group()
        _rename_group(g)
        srv = next(
            r for r in g.records if r.key.rtype == QType.SRV
        )
        assert isinstance(srv.data, SRVRecordData)
        assert srv.data.target == "host.local"

    def test_scheduling_state_reset(self):
        g = _service_group()
        for ow in g.owned_records:
            ow.last_multicast = 123.0
            ow.last_peer_answer = 456.0
        _rename_group(g)
        for ow in g.owned_records:
            assert ow.last_multicast == 0.0
            assert ow.last_peer_answer == 0.0

    def test_second_rename_increments_suffix(self):
        """After one rename, a second collision must yield `-3`,
        proving the suffix math works on already-renamed names."""
        g = _service_group()
        _rename_group(g)   # -> -2
        old, new = _rename_group(g)  # -> -3
        assert old == "nas-2._test._tcp.local"
        assert new == "nas-3._test._tcp.local"


class TestRenameHostGroup:
    def test_host_a_and_reverse_ptr_updated(self):
        g = _host_group()
        old, new = _rename_group(g)
        assert old == "myhost.local"
        assert new == "myhost-2.local"

        a_names = {
            r.key.name for r in g.records if r.key.rtype == QType.A
        }
        assert a_names == {"myhost-2.local"}

        rev_ptr = next(
            r for r in g.records if r.key.rtype == QType.PTR
        )
        assert isinstance(rev_ptr.data, PTRRecordData)
        assert rev_ptr.data.target == "myhost-2.local"


class TestObsoleteSharedRecords:
    """Coverage for the RFC 6762 §8.4 / BCT II.16 goodbye-on-rename
    selector: shared records whose name or PTR target references the
    old primary MUST get a TTL=0 goodbye; unique records (cache-flush
    set) and shared records unrelated to the rename MUST NOT."""

    def test_service_ptr_pointing_at_old_primary_is_obsolete(self):
        g = _service_group()
        pre = [ow.record for ow in g.owned_records]
        obs = _obsolete_shared_records(pre, "nas._test._tcp.local")
        # Service PTR `_test._tcp.local -> nas._test._tcp.local` and
        # subtype PTR `_tm._sub._test._tcp.local -> nas._test._tcp.local`
        # both reference the old primary and are shared.
        obs_keys = {(r.key.name, r.data.target) for r in obs}
        assert ("_test._tcp.local", "nas._test._tcp.local") in obs_keys
        assert (
            "_tm._sub._test._tcp.local", "nas._test._tcp.local",
        ) in obs_keys

    def test_meta_ptr_unrelated_to_primary_is_not_obsolete(self):
        """`_services._dns-sd._udp.local -> _test._tcp.local` never
        references the service-instance name, so a rename of the
        instance must not goodbye this meta-PTR."""
        g = _service_group()
        pre = [ow.record for ow in g.owned_records]
        obs = _obsolete_shared_records(pre, "nas._test._tcp.local")
        assert all(
            r.key.name != "_services._dns-sd._udp.local" for r in obs
        )

    def test_unique_records_excluded(self):
        """SRV/TXT have cache_flush=True; the new announcement's
        cache-flush bit handles cache eviction, so they must NOT be
        in the goodbye list (matches mDNSResponder's
        kDNSRecordTypeShared-only check at mDNSCore/mDNS.c:2231)."""
        g = _service_group()
        pre = [ow.record for ow in g.owned_records]
        obs = _obsolete_shared_records(pre, "nas._test._tcp.local")
        assert all(r.cache_flush is False for r in obs)
        assert all(r.key.rtype != QType.SRV for r in obs)
        assert all(r.key.rtype != QType.TXT for r in obs)

    def test_host_rename_reverse_ptr_is_unique_not_obsolete(self):
        """Reverse PTR (in-addr.arpa -> hostname) carries cache_flush
        because each IP has one host — treat as unique, no goodbye."""
        g = _host_group()
        pre = [ow.record for ow in g.owned_records]
        obs = _obsolete_shared_records(pre, "myhost.local")
        assert obs == []


class TestEmptyGroup:
    def test_group_without_srv_or_a_returns_none(self):
        """Groups with only unrelated records (should not happen in
        practice) must not crash — just return (None, None)."""
        g = EntryGroup()
        g.add_record(MDNSRecord(
            key=MDNSRecordKey("_services._dns-sd._udp.local", QType.PTR),
            ttl=4500, data=PTRRecordData("_foo._tcp.local"),
        ))
        old, new = _rename_group(g)
        assert old is None
        assert new is None
