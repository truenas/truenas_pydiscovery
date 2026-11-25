"""Prober state machine for RFC 6762 s8 probing.

Covers the probe sequence (3 probes at 250ms intervals), session
aggregation of concurrent probes, what counts as a conflict -- a
response naming a probed name (s8.1), a simultaneous probe that wins
the lexicographic tiebreak (s8.2), never the host's own records
(s9, s14) -- and the s8.1 conflict rate-limit backoff.
"""
from __future__ import annotations

import asyncio
import collections
import gc
import time
import warnings
from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import (
    CONFLICT_RATE_MAX,
    PROBE_COUNT,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    AAAARecordData,
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.core.prober import Prober

PEER = ("10.0.0.99", 5353)


def _a(name: str, addr: str, ttl: int = 120) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


def _aaaa(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.AAAA),
        ttl=120,
        data=AAAARecordData(IPv6Address(addr)),
        cache_flush=True,
    )


def _answer(*records: MDNSRecord) -> MDNSMessage:
    """A response asserting *records*, as a host that owns them sends."""
    return MDNSMessage.build_response(list(records))


def _peer_probe(name: str, *records: MDNSRecord) -> MDNSMessage:
    """Another host's probe for *name*, proposing *records*."""
    return MDNSMessage.build_probe(
        [MDNSQuestion(name, QType.ANY, unicast_response=True)],
        list(records),
    )


async def _probes_sent(sent: list[MDNSMessage], count: int) -> None:
    """Wait until *count* probes in all have gone through ``send_fn``."""
    while len(sent) < count:
        await asyncio.sleep(0.005)


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
    post-probe wait window) and drive the loop until they complete,
    so no task outlives the loop it was created on.
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

    def test_sequential_probes_keep_succeeding(self):
        """A reused Prober has no cumulative giveup cap: it keeps
        probing successfully across repeated registrations / re-probes.
        Neither avahi nor mDNSResponder permanently disables probing
        for an interface, so neither do we."""
        p = _prober()

        async def run() -> list[bool]:
            return [
                await p.probe([_a(f"seq{i}.local", "10.0.0.1")])
                for i in range(4)
            ]

        assert _run(run(), timeout=8.0) == [True, True, True, True]


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
        """RFC 6762 §8.1: a probing host MUST defer to a host that
        answers for the name.  The first answer starts a 1s defer and a
        same-name re-probe (stale-packet tolerance); an answer to the
        re-probe declares a real peer and fires ``on_conflict``."""
        sent: list[MDNSMessage] = []
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(sent, conflicts)
        our = _a("claim.local", "10.0.0.1")
        answer = _answer(_a("claim.local", "10.0.0.99"))

        async def run() -> bool:
            task = asyncio.create_task(p.probe([our]))
            await _probes_sent(sent, 1)
            p.handle_incoming(answer, PEER)
            assert not task.done()
            # The peer answers the re-probe that follows the defer too.
            await _probes_sent(sent, len(sent) + 1)
            p.handle_incoming(answer, PEER)
            return await task

        assert _run(run(), timeout=5.0) is False
        assert conflicts == [[our]]

    def test_case_flipped_peer_rdata_is_not_a_conflict(self):
        """BCT Phase II (guideline line 820) actively mutates
        case on tiebreaking replies — "the device must match
        mDNS names case-insensitively."  A peer asserting an
        uppercase version of our lowercase PTR target asserts
        a record identical to ours (RFC 6762 §16), which RFC 6762
        §9 never counts as inconsistent: probing must succeed.

        Regression guard for the identity-based record compare
        introduced alongside ``_identity``."""
        sent: list[MDNSMessage] = []
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(sent, conflicts)
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
            await _probes_sent(sent, 1)
            p.handle_incoming(_answer(peer), PEER)
            return await task

        assert _run(run()) is True
        assert conflicts == [], (
            "case-flipped peer rdata must not fire the conflict "
            "callback; the records are identical"
        )

    def test_single_conflict_triggers_defer_without_rename(self):
        """RFC 6762 §8.2: first conflict sets a 1s suppression window
        and keeps the same name — does NOT invoke ``on_conflict``."""
        sent: list[MDNSMessage] = []
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(sent, conflicts)
        our = _a("claim.local", "10.0.0.1")
        peer = _a("claim.local", "10.0.0.99")

        async def run() -> None:
            task = asyncio.create_task(p.probe([our]))
            await _probes_sent(sent, 1)
            before = time.monotonic()
            p.handle_incoming(_answer(peer), PEER)

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


class TestResponseWhileProbing:
    """RFC 6762 §8.1: "During probing, from the time the first probe
    packet is sent until 250 ms after the third probe, if any
    conflicting Multicast DNS response is received, then the probing
    host MUST defer to the existing host".

    A host that answers already owns the name: unlike a simultaneous
    probe (§8.2), an answer is not settled by comparing rdata.
    """

    def _conflicts_after(
        self, our: list[MDNSRecord], *messages: MDNSMessage,
        prober: Prober | None = None,
        sent: list[MDNSMessage] | None = None,
    ) -> int:
        """Feed *messages* once the first probe for *our* is out;
        return how many conflicts the session counted."""
        if prober is None:
            sent = []
            prober = _prober(sent)
        assert sent is not None
        p = prober

        async def run() -> int:
            task = asyncio.create_task(p.probe(our))
            await _probes_sent(sent, 1)
            for message in messages:
                p.handle_incoming(message, PEER)
            counted = p._sessions[our[0].key.name].conflicts_seen
            p.cancel_all()
            await task
            return counted

        return _run(run())

    def test_answer_with_earlier_rdata_still_conflicts(self):
        """The peer's address sorts BEFORE ours.  A §8.2 tiebreak would
        let us win and take a name another host is using."""
        our = [_a("claim.local", "10.0.0.99")]
        assert self._conflicts_after(
            our, _answer(_a("claim.local", "10.0.0.1")),
        ) == 1

    def test_answer_of_another_type_conflicts(self):
        """We probe with type ANY, so "any answer containing a record
        with that name, of any type, MUST be considered a conflicting
        response"."""
        our = [_a("claim.local", "10.0.0.1")]
        assert self._conflicts_after(
            our, _answer(_aaaa("claim.local", "2001:db8::99")),
        ) == 1

    def test_answer_before_the_first_probe_is_ignored(self):
        """Responses "received *before* the first probe packet is sent
        MUST be silently ignored"."""
        sent: list[MDNSMessage] = []
        p = _prober(sent)
        our = _a("claim.local", "10.0.0.1")

        async def run() -> int:
            task = asyncio.create_task(p.probe([our]))
            # The session exists; the cycle is in its initial jitter.
            await asyncio.sleep(0)
            assert sent == []
            p.handle_incoming(_answer(_a("claim.local", "10.0.0.99")), PEER)
            counted = p._sessions["claim.local"].conflicts_seen
            p.cancel_all()
            await task
            return counted

        assert _run(run()) == 0

    def test_second_copy_of_an_answer_counts_once(self):
        """A conflict starts the probe sequence over, so the same answer
        arriving again before the re-probe -- its copy over the other
        address family, say -- cannot count a second time and skip the
        stale-packet retry."""
        conflicts: list[list[MDNSRecord]] = []
        sent: list[MDNSMessage] = []
        p = _prober(sent, conflicts)
        answer = _answer(_a("claim.local", "10.0.0.99"))
        assert self._conflicts_after(
            [_a("claim.local", "10.0.0.1")], answer, answer,
            prober=p, sent=sent,
        ) == 1
        assert conflicts == []

    def test_goodbye_is_not_a_conflict(self):
        """A TTL=0 record withdraws, it does not assert (§10.1)."""
        our = [_a("claim.local", "10.0.0.1")]
        assert self._conflicts_after(
            our, _answer(_a("claim.local", "10.0.0.99", ttl=0)),
        ) == 0

    def test_own_record_from_another_interface_is_not_a_conflict(self):
        """RFC 6762 §14: with two interfaces on one link, "packets the
        host sends on one interface will arrive on the other interface
        a few milliseconds later".  The interface that probed first
        answers the other's probe with its own addresses; ``owns``
        vouches for them, so the second interface keeps the name.

        This is the multihomed rename loop: the AAAA-only answer sorts
        after our A record and used to win the §8.2 tiebreak."""
        sibling = EntryGroup()
        sibling.add_address("nas.local", "192.0.2.3")
        sibling.add_address("nas.local", "2001:db8::3")
        ours = EntryGroup()
        ours.add_address("nas.local", "192.0.2.4")
        ours.add_address("nas.local", "2001:db8::4")
        sibling_a = [r for r in sibling.records if r.key.rtype == QType.A]
        sibling_aaaa = [
            r for r in sibling.records if r.key.rtype == QType.AAAA
        ]
        sent: list[MDNSMessage] = []
        conflicts: list[list[MDNSRecord]] = []
        p = Prober(
            sent.append, conflicts.append,
            owns=set(sibling.records).__contains__,
        )

        async def run() -> bool:
            task = asyncio.create_task(p.probe(ours.get_unique_records()))
            await _probes_sent(sent, 1)
            p.handle_incoming(_answer(*sibling_a), PEER)
            p.handle_incoming(_answer(*sibling_aaaa), PEER)
            return await task

        assert _run(run()) is True
        assert conflicts == []

        # Without ``owns`` the same answer is a peer's: the control.
        assert self._conflicts_after(
            ours.get_unique_records(), _answer(*sibling_aaaa),
        ) == 1


class TestLexicographicMultiRecordTiebreak:
    """RFC 6762 §8.2: when another host probes for the same name at
    the same time, compare the sorted record sets proposed in the two
    Authority Sections element by element, falling through to a
    length comparison.  The GREATER set wins the tiebreak; the LESSER
    set must defer (and, losing again, rename).
    """

    def _run_probe_with_peer(
        self, our_records: list[MDNSRecord],
        peer_records: list[MDNSRecord],
    ) -> tuple[bool, list[list[MDNSRecord]]]:
        conflicts: list[list[MDNSRecord]] = []
        p = _prober(conflicts=conflicts)
        probe = _peer_probe(our_records[0].key.name, *peer_records)

        async def run() -> bool:
            task = asyncio.create_task(p.probe(our_records))
            await asyncio.sleep(0)
            # Two lost tiebreaks: the first defers (stale-packet
            # tolerance), the second renames.
            p.handle_incoming(probe, PEER)
            p.handle_incoming(probe, PEER)
            return await task

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
        result, conflicts = self._run_probe_with_peer(
            ours, [_a("multi.local", "10.0.0.1")],
        )
        assert result is True
        assert conflicts == [], "longer set must not trigger a conflict"

    def test_earlier_peer_probe_loses_to_us(self):
        """The tiebreak still decides between two probes: the peer's
        address sorts before ours, so ours wins and probing goes on.
        Compare ``test_answer_with_earlier_rdata_still_conflicts``."""
        result, conflicts = self._run_probe_with_peer(
            [_a("claim.local", "10.0.0.99")],
            [_a("claim.local", "10.0.0.1")],
        )
        assert result is True
        assert conflicts == []

    def test_own_probe_from_another_interface_is_not_a_competitor(self):
        """Our own probe, sent on another interface on the same link
        (RFC 6762 §14), proposes records ``owns`` vouches for.  It would
        win the tiebreak -- 192.0.2.4 sorts after 192.0.2.3 -- but is
        no other host's claim."""
        ours = [_a("nas.local", "192.0.2.3")]
        sibling = [_a("nas.local", "192.0.2.4")]
        conflicts: list[list[MDNSRecord]] = []
        p = Prober(
            lambda m: None, conflicts.append,
            owns=set(sibling).__contains__,
        )
        probe = _peer_probe("nas.local", *sibling)

        async def run() -> bool:
            task = asyncio.create_task(p.probe(ours))
            await asyncio.sleep(0)
            p.handle_incoming(probe, PEER)
            p.handle_incoming(probe, PEER)
            return await task

        assert _run(run()) is True
        assert conflicts == []


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


class TestTaskCancellation:
    """``task.cancel()`` on a task awaiting ``probe`` must actually
    cancel it: the daemon's shutdown and reload paths rely on it to
    stop conflict tasks mid-probe."""

    def test_task_cancel_propagates(self):
        p = _prober()

        async def scenario() -> asyncio.Task:
            task = asyncio.get_running_loop().create_task(
                p.probe([_a("cancelme.local", "192.0.2.1")])
            )
            # Park the probe on its session future.
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return task

        task = _run(scenario())
        assert task.cancelled()

    def test_cancel_all_resolves_probe_to_false(self):
        """A session-level abort is not a task cancellation: the
        awaiting task keeps running and sees a failed probe."""
        p = _prober()

        async def scenario() -> bool:
            task = asyncio.get_running_loop().create_task(
                p.probe([_a("abortme.local", "192.0.2.1")])
            )
            await asyncio.sleep(0.05)
            p.cancel_all()
            return await task

        assert _run(scenario()) is False


class TestCycleClosedOutsideLoop:
    """A probe cycle whose coroutine is closed while no loop is running
    — as GC closes the coroutine of a task abandoned with its loop —
    has nothing to schedule a follow-up cycle on."""

    def test_pending_sessions_dropped_without_unawaited_coroutine(self):
        p = _prober()
        loop = asyncio.new_event_loop()
        try:
            async def start() -> None:
                asyncio.get_running_loop().create_task(
                    p.probe([_a("orphan.local", "192.0.2.1")]),
                )
                # The first yield runs probe() up to queueing its
                # session and scheduling the cycle; the second lets
                # the cycle park in its s8.1 initial jitter.
                await asyncio.sleep(0)
                await asyncio.sleep(0)

            loop.run_until_complete(start())
            cycle = p._probe_task
            assert cycle is not None and not cycle.done()
            assert p._pending_sessions

            asyncio.set_event_loop(None)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                cycle.get_coro().close()
                gc.collect()

            assert not [
                w for w in caught if "never awaited" in str(w.message)
            ]
            assert p._probe_task is None
            assert p._pending_sessions == []
        finally:
            leftovers = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in leftovers:
                task.cancel()
            loop.run_until_complete(
                asyncio.gather(*leftovers, return_exceptions=True)
            )
            loop.close()
