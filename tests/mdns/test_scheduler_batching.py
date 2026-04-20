"""QueryScheduler batching, known-answer suppression, and
exponential-backoff cap per RFC 6762 s5.2 / s7.1 / s7.3.

Complements ``test_scheduler_leak.py`` (sweep pruning) and
``test_maintenance_deadlines.py`` (next_sweep_at accessor).
"""
from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.cache import RecordCache
from truenas_pymdns.server.query.scheduler import (
    QueryScheduler,
    _MAX_QUERY_INTERVAL,
)


def _scheduler_on_loop(
    cache: RecordCache | None = None,
) -> tuple[QueryScheduler, list[MDNSMessage], asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    sent: list[MDNSMessage] = []
    sch = QueryScheduler(sent.append, cache or RecordCache())
    sch.start(loop)
    return sch, sent, loop


def _q(name: str, qtype: QType = QType.A) -> MDNSQuestion:
    return MDNSQuestion(name=name, qtype=qtype)


class TestBatching:
    def test_three_schedule_query_calls_flush_in_one_send(self):
        """Rapid successive schedule_query calls are batched into a
        single outgoing message at the end of the 20-120ms defer."""
        sch, sent, loop = _scheduler_on_loop()
        try:
            sch.schedule_query(_q("a.local"))
            sch.schedule_query(_q("b.local"))
            sch.schedule_query(_q("c.local"))
            # Wait past the maximum defer window.
            loop.run_until_complete(asyncio.sleep(0.200))
            assert len(sent) == 1
            names = {q.name for q in sent[0].questions}
            assert names == {"a.local", "b.local", "c.local"}
        finally:
            sch.cancel_all()
            loop.close()

    def test_duplicate_schedule_query_for_same_qkey_dedupes(self):
        """Scheduling the same (name, qtype) twice results in one
        question in the outgoing batch, not two."""
        sch, sent, loop = _scheduler_on_loop()
        try:
            sch.schedule_query(_q("dup.local"))
            sch.schedule_query(_q("dup.local"))
            loop.run_until_complete(asyncio.sleep(0.200))
            assert len(sent) == 1
            assert len(sent[0].questions) == 1
        finally:
            sch.cancel_all()
            loop.close()


class TestKnownAnswerSuppression:
    def test_cache_record_above_half_ttl_is_attached_as_known_answer(self):
        """RFC 6762 s7.1: include cached records whose remaining TTL
        is greater than 50% of the original TTL in the query answer
        section so peers can suppress their responses."""
        cache = RecordCache()
        key = MDNSRecordKey("ka.local", QType.A)
        # Fresh record: remaining TTL == 120 > 60 (half of 120).
        rec = MDNSRecord(
            key=key, ttl=120,
            data=ARecordData(IPv4Address("10.0.0.1")),
        )
        cache.add(rec, now=time.monotonic())

        sch, sent, loop = _scheduler_on_loop(cache)
        try:
            sch.schedule_query(_q("ka.local"))
            loop.run_until_complete(asyncio.sleep(0.200))
            assert len(sent) == 1
            assert len(sent[0].answers) == 1
            assert sent[0].answers[0].key.name == "ka.local"
        finally:
            sch.cancel_all()
            loop.close()

    def test_cache_record_below_half_ttl_is_not_attached(self):
        """Records past the half-TTL mark must be re-queried rather
        than asserted as known — omit them from the outgoing answer
        section."""
        cache = RecordCache()
        key = MDNSRecordKey("stale.local", QType.A)
        # Stale: created 100s ago with ttl=120 → remaining 20 < 60.
        rec = MDNSRecord(
            key=key, ttl=120,
            data=ARecordData(IPv4Address("10.0.0.1")),
        )
        cache.add(rec, now=time.monotonic() - 100)

        sch, sent, loop = _scheduler_on_loop(cache)
        try:
            sch.schedule_query(_q("stale.local"))
            loop.run_until_complete(asyncio.sleep(0.200))
            assert len(sent) == 1
            assert sent[0].answers == []
        finally:
            sch.cancel_all()
            loop.close()


class TestSeenQuestionSuppression:
    def test_on_network_question_drops_matching_pending(self):
        """RFC 6762 s7.3: when we receive the same question from a
        peer, drop our pending one to avoid duplicate queries."""
        sch, sent, loop = _scheduler_on_loop()
        try:
            sch.schedule_query(_q("seen.local"))
            sch.on_network_question(_q("seen.local"))
            loop.run_until_complete(asyncio.sleep(0.200))
            # Pending was dropped → flush sends an empty query, but
            # the test has already captured the suppression intent.
            # Verify _pending is empty and no outgoing question.
            assert sch._pending == {}
            # Flush still fires but has no questions in the batch.
            assert not sent or sent[0].questions == []
        finally:
            sch.cancel_all()
            loop.close()

    def test_recent_network_question_suppresses_new_schedule(self):
        """After seeing a network question, scheduling the same key
        within the 1s window is a no-op."""
        sch, sent, loop = _scheduler_on_loop()
        try:
            sch.on_network_question(_q("block.local"))
            sch.schedule_query(_q("block.local"))
            assert sch._pending == {}
            loop.run_until_complete(asyncio.sleep(0.200))
            assert sent == []
        finally:
            sch.cancel_all()
            loop.close()


class TestContinuousBackoffCap:
    def test_continuous_interval_doubles_up_to_cap(self):
        """RFC 6762 s5.2: continuous query intervals MUST at least
        double, with an implementation-chosen cap.  This implementation
        caps at ``_MAX_QUERY_INTERVAL`` (3600 s)."""
        sch, _, loop = _scheduler_on_loop()
        try:
            q = _q("backoff.local")
            sch.schedule_continuous(q)
            qkey = f"{q.name.lower()}|{q.qtype.value}"
            assert qkey in sch._continuous

            # Direct-call the tick with an already-past-cap next_interval
            # to confirm the saturation behaviour.
            sch._continuous_tick(qkey, q, _MAX_QUERY_INTERVAL + 100.0)
            new_interval, _handle = sch._continuous[qkey]
            assert new_interval == _MAX_QUERY_INTERVAL

            # And that the invariant is preserved across a second tick.
            sch._continuous_tick(qkey, q, _MAX_QUERY_INTERVAL)
            new_interval2, _ = sch._continuous[qkey]
            assert new_interval2 == _MAX_QUERY_INTERVAL
        finally:
            sch.cancel_all()
            loop.close()

    def test_stop_continuous_cancels_timer_and_clears_entry(self):
        sch, _, loop = _scheduler_on_loop()
        try:
            q = _q("stopme.local")
            sch.schedule_continuous(q)
            qkey = f"{q.name.lower()}|{q.qtype.value}"
            _, handle = sch._continuous[qkey]

            sch.stop_continuous(q.name, q.qtype.value)
            assert qkey not in sch._continuous
            assert handle.cancelled()
        finally:
            sch.cancel_all()
            loop.close()
