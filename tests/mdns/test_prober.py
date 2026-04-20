"""Prober state machine for RFC 6762 s8 probing.

Covers the probe sequence (3 probes at 250ms intervals), session
aggregation of concurrent probes, conflict resolution via lexicographic
compare, and the s8.1 conflict rate-limit backoff.
"""
from __future__ import annotations

import asyncio
import collections
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    CONFLICT_RATE_MAX,
    PROBE_COUNT,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
)
from truenas_pymdns.server.core.prober import Prober


def _a(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


def _prober(
    sent: list[MDNSMessage] | None = None,
    conflicts: list[list[MDNSRecord]] | None = None,
) -> Prober:
    return Prober(
        send_fn=(sent.append if sent is not None else (lambda m: None)),
        on_conflict=(
            conflicts.append if conflicts is not None else (lambda r: None)
        ),
    )


def _run(coro, timeout: float = 3.0) -> object:
    """Run *coro* on a fresh loop and return its result.

    After the main coroutine finishes, cancel any still-pending tasks
    (typically the aggregated ``_run_probe_cycle`` task still in its
    post-probe wait window) and drive the loop until they complete.
    Otherwise those tasks leak into GC in a later test, which raises
    ``GeneratorExit`` inside their finally block and emits a
    ``coroutine was never awaited`` RuntimeWarning.
    """
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        return result
    finally:
        loop.close()


class TestBasicProbe:
    def test_empty_records_returns_true_immediately(self):
        p = _prober()
        assert _run(p.probe([])) is True

    def test_exceeds_max_restarts_returns_false_without_sending(self):
        """Once ``_probe_restart_count`` has hit the cap, ``probe``
        short-circuits and no packets go on the wire."""
        sent: list[MDNSMessage] = []
        p = _prober(sent)
        p._probe_restart_count = 20  # MAX_PROBE_RESTARTS

        assert _run(p.probe([_a("h.local", "10.0.0.1")])) is False
        assert sent == []


class TestProbeCycleSendsThreePackets:
    def test_successful_probe_sends_probe_count_packets(self):
        """RFC 6762 s8.1: three probe messages are sent for a single
        record set when no conflict arrives."""
        sent: list[MDNSMessage] = []
        p = _prober(sent)
        rec = _a("probe-ok.local", "10.0.0.1")

        assert _run(p.probe([rec])) is True
        assert len(sent) == PROBE_COUNT
        # Every probe carries the record in authorities and a question
        # with the QU bit set (unicast_response=True).  RFC 6762 s8.1:
        # probe Authority records MUST have the cache-flush bit clear,
        # even when the registered record has it set.
        assert rec.cache_flush is True, "the source record keeps its flag"
        for msg in sent:
            assert len(msg.authorities) == 1
            assert msg.authorities[0].key.name == "probe-ok.local"
            assert msg.authorities[0].cache_flush is False
            assert len(msg.questions) == 1
            assert msg.questions[0].unicast_response is True


class TestProbeAggregation:
    def test_concurrent_probes_share_single_probe_cycle(self):
        """Two ``probe()`` calls that overlap inside the aggregation
        window must be served by one probe cycle — PROBE_COUNT total
        packets, each mentioning both names."""
        sent: list[MDNSMessage] = []
        p = _prober(sent)

        async def run_pair() -> tuple[bool, bool]:
            t1 = asyncio.create_task(p.probe([_a("ag-a.local", "10.0.0.1")]))
            await asyncio.sleep(0.010)
            t2 = asyncio.create_task(p.probe([_a("ag-b.local", "10.0.0.2")]))
            return await asyncio.gather(t1, t2)

        results = _run(run_pair(), timeout=4.0)
        assert results == [True, True]
        assert len(sent) == PROBE_COUNT

        for msg in sent:
            names = {q.name for q in msg.questions}
            assert names == {"ag-a.local", "ag-b.local"}
            auth_names = {rr.key.name for rr in msg.authorities}
            assert auth_names == {"ag-a.local", "ag-b.local"}


class TestConflictResolution:
    def test_two_conflicts_trigger_rename(self):
        """RFC 6762 §8.2: the first conflict starts a 1s defer +
        same-name retry (stale-packet tolerance).  Only the second
        conflict declares a real peer and triggers rename via the
        ``on_conflict`` callback."""
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(conflicts=conflicts)
        # RFC 6762 §8.2: the GREATER rdata wins the tiebreak.  For
        # our prober to rename itself, our rdata must be LESS than
        # the peer's — i.e. our A record has the lower address.
        our = _a("claim.local", "10.0.0.1")
        peer = _a("claim.local", "10.0.0.99")

        async def run() -> bool:
            task = asyncio.create_task(p.probe([our]))
            # Let the aggregation jitter kick off the cycle so
            # _sessions is populated before we feed the conflict.
            await asyncio.sleep(0.020)
            peer_msg = MDNSMessage()
            peer_msg.flags = 0x8400  # QR | AA
            peer_msg.answers = [peer]
            # 1st conflict: triggers defer + same-name retry; future
            # stays pending.
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            # 2nd conflict: exceeds MAX_PROBING_CONFLICT_RETRIES,
            # resolves future to False and fires on_conflict.
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            result = await task
            p.cancel_all()
            return result

        assert _run(run()) is False
        assert conflicts == [[our]]

    def test_case_flipped_peer_rdata_ties_not_conflicts(self):
        """BCT Phase II (guideline line 820) actively mutates
        case on tiebreaking replies — "the device must match
        mDNS names case-insensitively."  A peer asserting an
        uppercase version of our lowercase PTR target must
        tiebreak as equal (cmp == 0), NOT trigger a rename.

        Regression guard for the identity-based lex compare
        introduced alongside ``_identity``."""
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(conflicts=conflicts)
        our = MDNSRecord(
            key=MDNSRecordKey("36.161.123.10.in-addr.arpa", QType.PTR),
            ttl=120,
            data=PTRRecordData(target="myhost.local"),
            cache_flush=True,
        )
        peer = MDNSRecord(
            key=MDNSRecordKey("36.161.123.10.in-addr.arpa", QType.PTR),
            ttl=120,
            # Same target, BCT-style case flip.
            data=PTRRecordData(target="MYHOST.LOCAL"),
            cache_flush=True,
        )

        async def run() -> bool:
            task = asyncio.create_task(p.probe([our]))
            await asyncio.sleep(0.020)
            peer_msg = MDNSMessage()
            peer_msg.flags = 0x8400
            peer_msg.answers = [peer]
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            # Cancel explicitly — if the fix is correct, no
            # conflict was registered and the probe is still
            # cycling; we don't need to wait for it.
            p.cancel_all()
            try:
                return await task
            except asyncio.CancelledError:
                return False

        _run(run(), timeout=2.0)
        assert conflicts == [], (
            "case-flipped peer rdata must not fire the conflict "
            "callback; tiebreak should score as equal"
        )

    def test_single_conflict_triggers_defer_without_rename(self):
        """RFC 6762 §8.2: first conflict sets a 1s suppression window
        and keeps the same name — does NOT invoke ``on_conflict``."""
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(conflicts=conflicts)
        our = _a("claim.local", "10.0.0.1")
        peer = _a("claim.local", "10.0.0.99")

        async def run() -> None:
            task = asyncio.create_task(p.probe([our]))
            await asyncio.sleep(0.020)
            peer_msg = MDNSMessage()
            peer_msg.flags = 0x8400
            peer_msg.answers = [peer]
            before = time.monotonic()
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))

            # Suppression window bumped out ~1s; on_conflict NOT called
            # (rename deferred).  Session still alive, future pending.
            session_key = "claim.local"
            session = p._sessions[session_key]
            assert session.conflicts_seen == 1
            assert p._suppress_probes_until >= before + 0.95
            assert conflicts == [], (
                "rename must not fire on first conflict per s8.2"
            )
            assert session.future is not None
            assert not session.future.done()

            p.cancel_all()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(run(), timeout=2.0)


class TestLexicographicMultiRecordTiebreak:
    """RFC 6762 §8.2: when two probers propose the SAME primary name
    but differ in the set of records attached to it, compare the
    sorted sets element by element, falling through to a length
    comparison.  The GREATER set wins the tiebreak; the LESSER set
    must rename.
    """

    def _run_probe_with_peer(
        self, our_records: list[MDNSRecord],
        peer_records: list[MDNSRecord],
    ) -> tuple[bool, list[list[MDNSRecord]]]:
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(conflicts=conflicts)

        async def run() -> bool:
            task = asyncio.create_task(p.probe(our_records))
            await asyncio.sleep(0.020)
            peer_msg = MDNSMessage()
            peer_msg.flags = 0x8400
            peer_msg.answers = peer_records
            # RFC 6762 §8.2: two conflicts required to trigger rename
            # (first is absorbed by stale-packet tolerance).
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            result = await task
            p.cancel_all()
            return result

        return _run(run()), conflicts

    def test_first_differing_rdata_decides_tiebreak(self):
        """Both sides have two records; the first by sort order is
        identical, the second differs.  The side with the lesser
        second rdata loses."""
        ours = [
            _a("multi.local", "10.0.0.1"),
            _a("multi.local", "10.0.0.5"),  # lesser than peer's 10.0.0.9
        ]
        peer = [
            _a("multi.local", "10.0.0.1"),
            _a("multi.local", "10.0.0.9"),
        ]
        result, conflicts = self._run_probe_with_peer(ours, peer)
        assert result is False
        assert conflicts == [ours]

    def test_shorter_set_loses_tiebreak(self):
        """When all compared elements tie, the SHORTER set loses
        per RFC 6762 §8.2 (it is padded with null bytes and is
        therefore lexicographically earlier)."""
        ours = [_a("multi.local", "10.0.0.1")]
        peer = [
            _a("multi.local", "10.0.0.1"),
            _a("multi.local", "10.0.0.2"),
        ]
        result, conflicts = self._run_probe_with_peer(ours, peer)
        assert result is False
        assert conflicts == [ours]

    def test_longer_set_wins_even_when_first_element_ties(self):
        """If we're the LONGER set, we should WIN — no rename."""
        ours = [
            _a("multi.local", "10.0.0.1"),
            _a("multi.local", "10.0.0.2"),
        ]
        peer = [_a("multi.local", "10.0.0.1")]

        p = _prober()

        async def run() -> bool:
            task = asyncio.create_task(p.probe(ours))
            await asyncio.sleep(0.020)
            peer_msg = MDNSMessage()
            peer_msg.flags = 0x8400
            peer_msg.answers = peer
            p.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            # Don't wait for the full probe cycle — just confirm no
            # conflict was scheduled within the aggregation window.
            await asyncio.sleep(0.040)
            p.cancel_all()
            try:
                return await task
            except asyncio.CancelledError:
                return False

        # Run the coroutine; whether it returns True or raises is
        # less interesting than whether the conflict future was
        # resolved to False.  What matters is ``_on_conflict`` was
        # NOT invoked.  Use the conflict-capture form.
        conflicts: list[list[MDNSRecord]] = []
        p2 = Prober(
            send_fn=lambda m: None,
            on_conflict=conflicts.append,
        )

        async def run2() -> None:
            task = asyncio.create_task(p2.probe(ours))
            await asyncio.sleep(0.020)
            peer_msg = MDNSMessage()
            peer_msg.flags = 0x8400
            peer_msg.answers = peer
            p2.handle_incoming(peer_msg, ("10.0.0.99", 5353))
            await asyncio.sleep(0.040)
            p2.cancel_all()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(run2(), timeout=2.0)
        assert conflicts == [], "longer set must not trigger a conflict"


class TestSimultaneousProbeDefer:
    """RFC 6762 §8.2: _wait_if_probes_suppressed blocks until the
    suppression clock has passed."""

    def test_wait_blocks_until_suppress_expires(self):
        """A fresh cycle invoked within the suppression window MUST
        sleep until that window expires before the first probe goes
        on the wire.  Use asyncio.wait_for with a short deadline to
        detect the wait without paying the full 1s."""
        p = _prober()
        p._suppress_probes_until = time.monotonic() + 1.0

        import pytest
        with pytest.raises(asyncio.TimeoutError):
            _run(p._wait_if_probes_suppressed(), timeout=0.3)

    def test_wait_is_noop_when_no_conflict(self):
        """With no outstanding suppression, the helper returns
        immediately so normal probing is not penalized."""
        p = _prober()
        start = time.monotonic()
        _run(p._wait_if_probes_suppressed())
        elapsed = time.monotonic() - start
        assert elapsed < 0.050, f"unexpected wait: {elapsed:.3f}s"


class TestConflictRateLimit:
    def test_under_threshold_returns_without_sleeping(self):
        p = _prober()
        now = time.monotonic()
        for _ in range(CONFLICT_RATE_MAX - 1):
            p._conflict_times.append(now)

        start = time.monotonic()
        _run(p._wait_if_rate_limited())
        elapsed = time.monotonic() - start
        assert elapsed < 0.050, f"unexpectedly slow: {elapsed:.3f}s"

    def test_at_threshold_triggers_backoff_sleep(self):
        """When >= CONFLICT_RATE_MAX recent conflicts are queued,
        ``_wait_if_rate_limited`` must sleep the full backoff.  We
        don't wait 5 s in the test — we just assert that
        ``asyncio.wait_for`` with a 0.3 s deadline times out, which
        proves the method was sleeping longer than that."""
        p = _prober()
        now = time.monotonic()
        p._conflict_times = collections.deque([now] * CONFLICT_RATE_MAX)

        import pytest
        with pytest.raises(asyncio.TimeoutError):
            _run(p._wait_if_rate_limited(), timeout=0.3)
