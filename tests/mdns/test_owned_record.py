"""Per-record scheduling state on ``OwnedRecord``.

Mirrors mDNSResponder's ``AuthRecord.LastMCTime`` /
``ShouldSuppressKnownAnswer`` and avahi's
``avahi_record_equal_no_ttl``: rate-limit and peer-answer state ride
on the owned record, keyed per-rdata (not just (name, rtype)).
"""
from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup, OwnedRecord
from truenas_pymdns.server.query.responder import Responder
from truenas_pymdns.server.service.registry import ServiceRegistry


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


def _responder(registry: ServiceRegistry) -> Responder:
    r = Responder(
        lambda msg: None,
        lambda msg, addr: None,
        registry,
    )
    r.start(asyncio.new_event_loop())
    return r


def _addr(ow: OwnedRecord) -> str:
    assert isinstance(ow.record.data, ARecordData)
    return str(ow.record.data.address)


class TestOwnedRecordShape:
    def test_defaults_zero(self):
        ow = OwnedRecord(_a("h.local", "10.0.0.1"))
        assert ow.last_multicast == 0.0
        assert ow.last_peer_answer == 0.0

    def test_entry_group_wraps_on_add(self):
        group = EntryGroup()
        rec = _a("h.local", "10.0.0.1")
        group.add_record(rec)
        owned = group.owned_records
        assert len(owned) == 1
        assert owned[0].record is rec
        assert owned[0].last_multicast == 0.0

    def test_entry_group_records_property_unwraps(self):
        group = EntryGroup()
        rec = _a("h.local", "10.0.0.1")
        group.add_record(rec)
        assert group.records == [rec]


class TestSuppressIfAnsweredPerRdata:
    def test_rdata_match_stamps_only_matching_wrapper(self):
        """Per-rdata suppression, matching avahi/mDNSResponder."""
        r1 = _a("multi.local", "10.0.0.1")
        r2 = _a("multi.local", "10.0.0.2")
        reg = _registry_with(r1, r2)
        resp = _responder(reg)

        peer = MDNSMessage()
        peer.answers = [_a("multi.local", "10.0.0.1")]
        resp.suppress_if_answered(peer)

        owned = reg.lookup("multi.local", QType.A)
        by_ip = {_addr(ow): ow for ow in owned}

        assert by_ip["10.0.0.1"].last_peer_answer > 0.0
        assert by_ip["10.0.0.2"].last_peer_answer == 0.0

    def test_peer_answer_for_unowned_name_is_dropped(self):
        reg = _registry_with(_a("ours.local", "10.0.0.1"))
        resp = _responder(reg)

        peer = MDNSMessage()
        peer.answers = [_a("theirs.local", "10.0.0.9")]
        # Must not raise; nothing to stamp.
        resp.suppress_if_answered(peer)

        owned = reg.lookup("ours.local", QType.A)
        assert owned[0].last_peer_answer == 0.0


class TestScheduleRateLimit:
    def test_recent_multicast_blocks_reschedule(self):
        """MULTICAST_RATE_LIMIT gate reads ow.last_multicast directly."""
        rec = _a("h.local", "10.0.0.1")
        reg = _registry_with(rec)
        resp = _responder(reg)

        ow = reg.lookup("h.local", QType.A)[0]
        ow.last_multicast = time.monotonic()

        resp._schedule_response([ow])
        assert not resp._pending

    def test_same_key_different_rdata_schedule_independently(self):
        """Two records with same (name, rtype) but different rdata
        track independent timestamps — unlike the old name|rtype dict
        which would have collapsed them."""
        r1 = _a("h.local", "10.0.0.1")
        r2 = _a("h.local", "10.0.0.2")
        reg = _registry_with(r1, r2)
        resp = _responder(reg)

        owned = reg.lookup("h.local", QType.A)
        ow1 = next(ow for ow in owned if _addr(ow) == "10.0.0.1")
        ow2 = next(ow for ow in owned if _addr(ow) == "10.0.0.2")

        ow1.last_multicast = time.monotonic()

        resp._schedule_response([ow1, ow2])
        assert resp._pending

        (only_owned, _, _) = next(iter(resp._pending.values()))
        assert only_owned == [ow2]
