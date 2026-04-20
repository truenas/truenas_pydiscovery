"""Deadline accessors that drive adaptive maintenance scheduling."""
from __future__ import annotations

import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.cache import RecordCache
from truenas_pymdns.server.query.scheduler import QueryScheduler


def _a(name: str, addr: str, ttl: int = 120) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
    )


class TestCacheNextEventAt:
    def test_empty_cache_returns_none(self):
        assert RecordCache().next_event_at() is None

    def test_single_record_returns_earliest_refresh(self):
        c = RecordCache()
        c.add(_a("h.local", "10.0.0.1", ttl=120), 1000.0)
        # RFC 6762 s5.2: first refresh at 80% of TTL => 1000 + 96 = 1096
        assert c.next_event_at() == 1096.0

    def test_returns_min_across_records(self):
        c = RecordCache()
        c.add(_a("a.local", "10.0.0.1", ttl=600), 1000.0)   # refresh @ 1480
        c.add(_a("b.local", "10.0.0.2", ttl=120), 2000.0)   # refresh @ 2096
        # The earlier deadline wins.
        assert c.next_event_at() == 1480.0

    def test_falls_back_to_expiry_when_refreshes_exhausted(self):
        c = RecordCache()
        rec = _a("h.local", "10.0.0.1", ttl=120)
        c.add(rec, 1000.0)
        rec.refresh_sent = 4   # no more refresh points
        # Only the hard expiry remains: 1000 + 120 = 1120
        assert c.next_event_at() == 1120.0


class TestSchedulerNextSweepAt:
    def _s(self) -> QueryScheduler:
        return QueryScheduler(lambda msg: None, RecordCache())

    def test_empty_returns_none(self):
        assert self._s().next_sweep_at() is None

    def test_returns_oldest_plus_two_seconds(self):
        sch = self._s()
        sch._seen_questions["a.local|1"] = 1000.0
        sch._seen_questions["b.local|1"] = 1001.5
        assert sch.next_sweep_at() == 1002.0

    def test_updates_when_entries_added(self):
        sch = self._s()
        sch.on_network_question(MDNSQuestion("a.local", QType.A))
        first = sch.next_sweep_at()
        assert first is not None
        # A slightly later entry doesn't pull the deadline earlier.
        time.sleep(0.001)
        sch.on_network_question(MDNSQuestion("b.local", QType.A))
        assert sch.next_sweep_at() == first
