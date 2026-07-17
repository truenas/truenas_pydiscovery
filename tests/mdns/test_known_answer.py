"""RFC 6762 §7.1 known-answer suppression honours the half-TTL rule.

A responder MUST NOT answer when the querier's known answer carries
an RR TTL at least half the true value, but MUST answer when the
known answer has decayed below half — to refresh the querier before
the record expires (docs/specs/rfc6762.txt:1243-1249).  Real
registry + Responder, no mocks; scheduling into ``_pending`` is the
observable "we will answer" signal.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.query.responder import Responder
from truenas_pymdns.server.service.registry import ServiceRegistry

IFACE = 1


def _a(name: str, addr: str, ttl: int = 120) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


def _responder(reg: ServiceRegistry) -> Responder:
    resp = Responder(lambda m: None, lambda m, a: None, reg)
    resp.start(asyncio.new_event_loop())
    return resp


def _registry_with(*recs: MDNSRecord) -> ServiceRegistry:
    g = EntryGroup()
    for r in recs:
        g.add_record(r)
    reg = ServiceRegistry()
    reg.add_group(g)
    return reg


def _qm_with_known(name: str, known: MDNSRecord) -> MDNSMessage:
    q = MDNSMessage(questions=[MDNSQuestion(name, QType.A)])
    q.answers = [known]
    return q


class TestKnownAnswerHalfTTL:
    def test_full_ttl_known_answer_suppresses(self):
        reg = _registry_with(_a("h.local", "10.0.0.1", ttl=120))
        resp = _responder(reg)
        q = _qm_with_known("h.local", _a("h.local", "10.0.0.1", ttl=120))
        resp.handle_query(q, ("10.0.0.9", 5353), IFACE)
        assert resp._pending == {}, "known TTL >= half → MUST NOT answer"

    def test_just_above_half_suppresses(self):
        reg = _registry_with(_a("h.local", "10.0.0.1", ttl=120))
        resp = _responder(reg)
        # 61 >= 60 (== 120 // 2) → suppress.
        q = _qm_with_known("h.local", _a("h.local", "10.0.0.1", ttl=61))
        resp.handle_query(q, ("10.0.0.9", 5353), IFACE)
        assert resp._pending == {}

    def test_below_half_still_answers(self):
        reg = _registry_with(_a("h.local", "10.0.0.1", ttl=120))
        resp = _responder(reg)
        # 59 < 60 → MUST answer to refresh the querier's cache.
        q = _qm_with_known("h.local", _a("h.local", "10.0.0.1", ttl=59))
        resp.handle_query(q, ("10.0.0.9", 5353), IFACE)
        assert resp._pending, "known TTL below half → MUST answer"

    def test_no_known_answer_answers(self):
        reg = _registry_with(_a("h.local", "10.0.0.1", ttl=120))
        resp = _responder(reg)
        q = MDNSMessage(questions=[MDNSQuestion("h.local", QType.A)])
        resp.handle_query(q, ("10.0.0.9", 5353), IFACE)
        assert resp._pending, "no known answer → answer normally"
