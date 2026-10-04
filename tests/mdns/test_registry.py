"""ServiceRegistry: the record store the responder answers from."""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.service.registry import ServiceRegistry


def _group() -> EntryGroup:
    group = EntryGroup()
    group.add_record(MDNSRecord(
        key=MDNSRecordKey("nas.local", QType.A),
        ttl=120,
        data=ARecordData(IPv4Address("192.0.2.10")),
        cache_flush=True,
    ))
    return group


class TestAddGroup:
    def test_a_group_registered_twice_is_answered_once(self):
        """Two probes of one group that end together both register it;
        its records must still be answered once."""
        registry = ServiceRegistry()
        group = _group()
        registry.add_group(group)
        registry.add_group(group)
        assert len(registry.get_all_records()) == len(group.records)

    def test_remove_drops_a_group_registered_twice(self):
        registry = ServiceRegistry()
        group = _group()
        registry.add_group(group)
        registry.add_group(group)
        registry.remove_group(group)
        assert registry.get_all_records() == []
