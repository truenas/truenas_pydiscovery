"""RFC 6762 §10.5 Passive Observation Of Failure (POOF) end-to-end.

When a peer queries a cached name and no response arrives, we bump
the record's POOF counter.  Once the counter crosses
``POOF_THRESHOLD``, the maintenance loop evicts the record.  A fresh
response clears the counter.

This test exercises both halves: the detection path in
``_handle_message`` that was added alongside the eviction pipeline
at ``server.py`` maintenance loop, and the cache accessors
``record_poof`` / ``clear_poof`` / ``get_poof_candidates`` /
``remove``.
"""
from __future__ import annotations

import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    MDNSFlags,
    POOF_THRESHOLD,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.cache import RecordCache


class _FakeResponder:
    """No-op stand-in for Responder so ``_handle_message`` doesn't
    crash on the query path."""
    def handle_query(self, *a, **kw) -> None:
        pass

    def handle_probe_query(self, *a, **kw) -> None:
        pass

    def suppress_if_answered(self, *a, **kw) -> None:
        pass


class _FakeScheduler:
    def on_network_question(self, *a, **kw) -> None:
        pass


class _FakeProber:
    def handle_incoming(self, *a, **kw) -> None:
        pass


class _FakeIfState:
    def __init__(self) -> None:
        self.cache = RecordCache()
        self.responder = _FakeResponder()
        self.query_scheduler = _FakeScheduler()
        self.prober = _FakeProber()
        self.announcer = None


def _a(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
    )


def _server_with_cache() -> tuple[object, _FakeIfState]:
    from truenas_pymdns.server.server import MDNSServer
    from truenas_pymdns.server.service.registry import ServiceRegistry

    state = _FakeIfState()
    server = MDNSServer.__new__(MDNSServer)
    server._interfaces = {1: state}
    server._registry = ServiceRegistry()

    class _NoopStatus:
        def inc(self, *_args, **_kwargs):
            pass

    server._status = _NoopStatus()

    class _NoopWake:
        def set(self) -> None:
            pass

    server._wake = _NoopWake()
    return server, state


def _query_for(name: str) -> MDNSMessage:
    return MDNSMessage(
        flags=0, questions=[MDNSQuestion(name, QType.A)],
    )


def _response_for(rec: MDNSRecord) -> MDNSMessage:
    return MDNSMessage(
        flags=MDNSFlags.QR.value | MDNSFlags.AA.value,
        answers=[rec],
    )


class TestPOOFDetection:
    def test_query_for_cached_name_bumps_poof_counter(self):
        server, state = _server_with_cache()
        rec = _a("poof.local", "10.0.0.1")
        state.cache.add(rec, now=time.monotonic())

        server._handle_message(_query_for("poof.local"), ("10.0.0.9", 5353), 1)
        assert state.cache.get_poof_candidates() == []

        # Second query pushes us to POOF_THRESHOLD.
        for _ in range(POOF_THRESHOLD - 1):
            server._handle_message(
                _query_for("poof.local"), ("10.0.0.9", 5353), 1,
            )

        candidates = state.cache.get_poof_candidates()
        assert rec.key in candidates

    def test_query_for_unknown_name_does_nothing(self):
        server, state = _server_with_cache()
        state.cache.add(_a("cached.local", "10.0.0.1"), now=time.monotonic())
        server._handle_message(
            _query_for("other.local"), ("10.0.0.9", 5353), 1,
        )
        assert state.cache.get_poof_candidates() == []

    def test_response_clears_poof_counter(self):
        server, state = _server_with_cache()
        rec = _a("clear.local", "10.0.0.1")
        state.cache.add(rec, now=time.monotonic())

        for _ in range(POOF_THRESHOLD):
            server._handle_message(
                _query_for("clear.local"), ("10.0.0.9", 5353), 1,
            )
        assert rec.key in state.cache.get_poof_candidates()

        server._handle_message(_response_for(rec), ("10.0.0.9", 5353), 1)
        assert state.cache.get_poof_candidates() == []


class TestPOOFEvictionPipeline:
    def test_candidates_removed_by_cache_remove(self):
        """The maintenance loop calls cache.remove() for every POOF
        candidate; verify the end-state in isolation."""
        cache = RecordCache()
        rec = _a("evict.local", "10.0.0.1")
        cache.add(rec, now=time.monotonic())
        for _ in range(POOF_THRESHOLD):
            cache.record_poof(rec.key)

        candidates = cache.get_poof_candidates()
        assert rec.key in candidates
        for key in candidates:
            cache.remove(key)

        assert cache.get_poof_candidates() == []
        assert cache.lookup(rec.key, time.monotonic()) == []
