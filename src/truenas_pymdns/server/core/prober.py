"""mDNS probing state machine per RFC 6762 Section 8.

Probing sequence (RFC 6762 s8.1):
  1. Wait random 0-250ms
  2. Send probe (QD=questions with QU bit, NS=proposed records)
  3. Wait 250ms, repeat (3 probes total)
  4. If no conflict by 250ms after third probe, probing succeeds
  5. If conflict detected, defer and choose new name

What counts as a conflict:
  - A response naming a probed name, once the first probe is out
    (s8.1): the responder already holds the name, and we defer to it
    whatever its rdata.
  - A simultaneous probe for the name whose proposed records are
    lexicographically later than ours (s8.2 tiebreak).
  - Never a record this host itself publishes, on this or any other
    interface (s9, s14) -- see ``Prober._is_ours``.

Probe aggregation (like avahi-core/probe-sched.c):
  Multiple concurrent probe() calls are batched into single
  probe messages to reduce wire traffic at startup when
  registering many services simultaneously.

Rate limiting (RFC 6762 s8.1):
  If 15 conflicts in any 10-second window, MUST wait >= 5 seconds
  before each successive probe attempt.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import random
import time
from dataclasses import dataclass, replace
from typing import Callable

from truenas_pymdns.protocol.constants import (
    CONFLICT_RATE_BACKOFF,
    CONFLICT_RATE_MAX,
    CONFLICT_RATE_WINDOW,
    MAX_PROBING_CONFLICT_RETRIES,
    PROBE_COUNT,
    PROBE_INITIAL_RANDOM_MAX,
    PROBE_INTERVAL,
    QType,
    SIMULTANEOUS_PROBE_DEFER,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import MDNSRecord
from .conflict import lexicographic_compare

logger = logging.getLogger(__name__)


def _owns_nothing(record: MDNSRecord) -> bool:
    """Ownership check for a prober with no registry behind it."""
    return False


@dataclass
class ProbingSession:
    """Tracks state for one in-flight probing attempt."""
    records: list[MDNSRecord]
    names: set[str]
    future: asyncio.Future
    # Probes sent since the sequence last (re)started.  Zero means no
    # probe of this sequence is out yet, and RFC 6762 §8.1 ignores the
    # responses that arrive then (``_response_conflicts``).
    probes_sent: int = 0
    # RFC 6762 s8.2 stale-packet tolerance: conflicts observed so far
    # for this session.  <= MAX_PROBING_CONFLICT_RETRIES triggers a
    # 1-second defer + re-probe with the SAME name; exceeding it
    # triggers rename per s9.  Matches Apple mDNSResponder's
    # ``AuthRecord.ProbingConflictCount`` (mDNSCore/mDNS.c).
    conflicts_seen: int = 0


class Prober:
    """Manages probing for new records before announcing them.

    Implements the full probing algorithm from RFC 6762 s8.1
    including simultaneous probe tiebreaking (s8.2), probe
    aggregation, and conflict rate limiting.
    """

    def __init__(
        self,
        send_fn: Callable[[MDNSMessage], None],
        on_conflict: Callable[[list[MDNSRecord]], None],
        owns: Callable[[MDNSRecord], bool] = _owns_nothing,
    ) -> None:
        self._send = send_fn
        self._on_conflict = on_conflict
        # True for a record this host publishes anywhere, on any
        # interface; the server passes ``MDNSServer._owns_record``.
        self._owns = owns
        self._sessions: dict[str, ProbingSession] = {}
        # RFC 6762 s8.1: conflict rate limiting
        self._conflict_times: collections.deque[float] = collections.deque()
        # Aggregation: sessions waiting for the first probe cycle
        self._pending_sessions: list[ProbingSession] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._probe_task: asyncio.Task | None = None
        # RFC 6762 s8.2: global "no probes until this monotonic time"
        # clock, bumped by SIMULTANEOUS_PROBE_DEFER seconds whenever a
        # session loses a probe tiebreak.  Modeled on Apple
        # mDNSResponder's ``m->SuppressProbes`` (mDNSCore/mDNS.c).
        self._suppress_probes_until: float = 0.0

    async def probe(self, records: list[MDNSRecord]) -> bool:
        """Probe for a set of records.  Returns True if probing succeeds.

        Multiple concurrent probe() calls are aggregated: their records
        are packed into shared probe messages (like avahi's probe-sched.c).

        Returns False if a conflict forces a rename (RFC 6762 §8.2/§9);
        the caller re-registers under an alternative name.  Runaway
        re-probing is bounded by the §8.1 conflict rate limit
        (``_wait_if_rate_limited``) and per-session
        ``conflicts_seen`` → rename, matching avahi (unbounded rename)
        and mDNSResponder (``ProbingConflictCount`` → rename); neither
        reference permanently disables probing for a whole interface.

        Cancelling the awaiting *task* propagates ``CancelledError``
        — shutdown and the reload paths rely on ``task.cancel()``
        actually stopping a conflict task parked here.  Only
        ``cancel_all`` (a session-level abort) turns into a False
        return.
        """
        if not records:
            return True

        await self._wait_if_rate_limited()

        loop = asyncio.get_running_loop()
        self._loop = loop
        future: asyncio.Future[bool] = loop.create_future()

        names = {r.key.name for r in records}
        session_key = "|".join(sorted(names))
        session = ProbingSession(
            records=records, names=names, future=future,
        )
        self._sessions[session_key] = session

        # Add to aggregation batch
        self._pending_sessions.append(session)
        self._ensure_probe_cycle()

        try:
            return await future
        except asyncio.CancelledError:
            # The awaiting task was cancelled (daemon shutdown, full
            # rebuild) — not a probe outcome.  Cancel the session
            # future so the aggregated probe cycle drops the session,
            # and re-raise per the contract above.  A session-level
            # abort (``cancel_all``) resolves ``future`` with False
            # instead and never raises here.
            if not future.done():
                future.cancel()
            raise
        finally:
            self._sessions.pop(session_key, None)

    def handle_incoming(self, message: MDNSMessage, source: tuple) -> None:
        """Check *message* against every probe in flight.

        A response is a conflict on the terms of RFC 6762 §8.1
        (``_response_conflicts``); a probe -- a query proposing records
        in its Authority Section -- is settled by the §8.2 tiebreak
        (``_loses_tiebreak``).  Neither counts a record this host
        publishes itself (``_is_ours``).
        """
        if not self._sessions:
            return

        for session in list(self._sessions.values()):
            if session.future.done():
                continue
            if message.is_response:
                lost = self._response_conflicts(session, message)
            else:
                lost = self._loses_tiebreak(session, message)
            if lost:
                self._lose(session, source)

    def _is_ours(self, session: ProbingSession, record: MDNSRecord) -> bool:
        """True if *record* is identical to one this host publishes.

        RFC 6762 §9: "resource records with identical rdata are never
        considered inconsistent, even if they originate from different
        hosts" -- so neither a record we are probing for, nor one we
        publish on another interface, is a conflict.  The second kind
        is what a host hears when two of its interfaces share a link:
        "packets the host sends on one interface will arrive on the
        other interface a few milliseconds later" (§14), carrying the
        other interface's addresses (see ``MDNSServer._owns_record``).
        """
        return record in session.records or self._owns(record)

    def _response_conflicts(
        self, session: ProbingSession, message: MDNSMessage,
    ) -> bool:
        """RFC 6762 §8.1: a response heard while probing.

        "During probing, from the time the first probe packet is sent
        until 250 ms after the third probe, if any conflicting
        Multicast DNS response is received, then the probing host MUST
        defer to the existing host" -- a host that answers already owns
        the name, so there is no tiebreak, and the order of the two
        rdata does not matter.  Our probes ask for type ANY, so "any
        answer containing a record with that name, of any type, MUST be
        considered a conflicting response".  Not counted:

        * responses before the first probe: they "MUST be silently
          ignored".  A conflict starts the sequence over
          (``probes_sent`` back to 0, ``_lose``), so a second copy of
          the same answer -- over the other address family, say --
          cannot count again before the re-probe.  mDNSResponder's
          ``mDNSCoreReceiveResponse`` skips a response "received
          before we even began probing" in the same way
          (``mDNS.c:10306``);
        * a goodbye (TTL 0, §10.1), which withdraws a record rather
          than asserting it -- mDNSResponder tests ``rroriginalttl >
          0`` before ``PacketRRConflict`` (``mDNS.c:10274``);
        * a record this host publishes (``_is_ours``).
        """
        if session.probes_sent == 0:
            return False
        names = {n.lower() for n in session.names}
        return any(
            rr.key.name in names
            and rr.ttl > 0
            and not self._is_ours(session, rr)
            for rr in message.answers
        )

    def _loses_tiebreak(
        self, session: ProbingSession, message: MDNSMessage,
    ) -> bool:
        """RFC 6762 §8.2: another host probing for one of our names.

        The records proposed in its Authority Section are compared
        with ours, and "the lexicographically later data wins".  A
        probe whose records are all this host's own is its own probe,
        looped back or arriving from another of its interfaces on the
        same link, and is not a competitor -- avahi's
        ``incoming_probe`` (``server.c:196``) treats a probe matching
        one of its entries on any interface the same way.
        """
        names = {n.lower() for n in session.names}
        theirs = [rr for rr in message.authorities if rr.key.name in names]
        if not theirs or all(self._is_ours(session, rr) for rr in theirs):
            return False
        our_unique = [r for r in session.records if r.cache_flush]
        # ``lexicographic_compare`` returns the sign of ``ours -
        # theirs``: below zero our data is the earlier one, and loses.
        return lexicographic_compare(our_unique, theirs) < 0

    def _lose(self, session: ProbingSession, source: tuple) -> None:
        """*session* met a conflict: defer and probe again, or rename."""
        self._record_conflict()
        session.conflicts_seen += 1

        if session.conflicts_seen <= MAX_PROBING_CONFLICT_RETRIES:
            # RFC 6762 §8.2: "The logic for waiting one second and
            # then trying again is to guard against stale probe
            # packets on the network (possibly even stale probe
            # packets sent moments ago by this host itself, before
            # some configuration change, which may be echoed back
            # after a short delay by some Ethernet switches and some
            # 802.11 base stations)."  Pause all probes for 1s, then
            # re-probe the SAME name.  A real peer will answer our
            # re-probe and we'll rename on the next conflict; a stale
            # echo will go unanswered and the re-probe will succeed.
            #
            # Mirrors Apple mDNSResponder, which pauses for one second
            # after a lost tiebreak (``ResolveSimultaneousProbe`` at
            # ``mDNS.c:8056``) and after a "possibly spurious multicast
            # conflict" in a response (``mDNSCoreReceiveResponse`` at
            # ``mDNS.c:10343``, up to ``kMaxAllowedMCastProbingConflicts``),
            # resetting ``ProbeCount`` either way.
            logger.info(
                "Probe conflict for %s from %s "
                "(retry %d/%d after %.1fs)",
                session.names, source,
                session.conflicts_seen,
                MAX_PROBING_CONFLICT_RETRIES + 1,
                SIMULTANEOUS_PROBE_DEFER,
            )
            self._suppress_probes_until = (
                time.monotonic() + SIMULTANEOUS_PROBE_DEFER
            )
            session.probes_sent = 0
            if session not in self._pending_sessions:
                self._pending_sessions.append(session)
            # Cancel the in-flight cycle so no more probes go on the
            # wire during the defer window; the cycle's except/finally
            # re-queues any other active sessions and chains a new
            # cycle that honors _suppress_probes_until.
            if self._probe_task and not self._probe_task.done():
                self._probe_task.cancel()
        else:
            # Exceeded the retry allowance — a real peer owns this
            # name.  Rename per RFC 6762 s9.  Matches mDNSResponder's
            # `else` branch that calls
            # ``mDNS_Deregister_internal(..., mDNS_Dereg_conflict)``.
            logger.info(
                "Probe conflict for %s from %s "
                "(exceeded %d retries — renaming per RFC 6762 s9)",
                session.names, source,
                MAX_PROBING_CONFLICT_RETRIES,
            )
            if not session.future.done():
                session.future.set_result(False)
            self._on_conflict(session.records)

    def cancel_all(self) -> None:
        """Cancel all active probing sessions."""
        if self._probe_task:
            self._probe_task.cancel()
            self._probe_task = None
        for session in self._sessions.values():
            if not session.future.done():
                session.future.set_result(False)
        self._sessions.clear()
        self._pending_sessions.clear()

    # -- Aggregation ----------------------------------------------------------

    def _ensure_probe_cycle(self) -> None:
        """Start a probe cycle if one isn't already running."""
        if self._probe_task is None or self._probe_task.done():
            self._probe_task = asyncio.ensure_future(
                self._run_probe_cycle()
            )

    async def _run_probe_cycle(self) -> None:
        """Run a single aggregated probe cycle for all pending sessions.

        Waits a short aggregation window to collect concurrent probe()
        calls, then sends PROBE_COUNT aggregated probe messages at
        PROBE_INTERVAL apart, then resolves all surviving futures.

        The ``finally`` block always checks ``_pending_sessions`` and
        chains to another cycle if any session arrived late — otherwise
        early returns (e.g. when every batched session already has a
        resolved future) would leave the late arrivals stuck.
        """
        batch: list[ProbingSession] = []
        active: list[ProbingSession] = []
        try:
            # Pre-probe wait: either the RFC 6762 s8.2 suppression
            # window (after a conflict) OR the s8.1 random 0-250ms
            # anti-collision jitter for a fresh startup — never both.
            # The s8.1 jitter exists to desynchronize simultaneous
            # boots, which the s8.2 1-second defer already subsumes.
            # Matches mDNSResponder's scheduler, which picks
            # max(m->SuppressProbes, LastAPTime + ThisAPInterval) so
            # the 1-second suppress dominates any per-record jitter
            # (mDNSCore/mDNS.c).
            if not await self._wait_if_probes_suppressed():
                await asyncio.sleep(
                    random.uniform(0, PROBE_INITIAL_RANDOM_MAX),
                )

            # Collect all sessions that were added during jitter window
            batch = list(self._pending_sessions)
            self._pending_sessions.clear()

            if not batch:
                return

            active = [s for s in batch if not s.future.done()]
            if not active:
                return

            for i in range(PROBE_COUNT):
                # Re-check which sessions are still active (not conflicted)
                active = [s for s in active if not s.future.done()]
                if not active:
                    return

                # Counted before the send: a reply can be handled before
                # the send returns, and RFC 6762 §8.1 counts responses
                # "from the time the first probe packet is sent".  A
                # conflict it raises resets the count (``_lose``),
                # which an increment after the send would undo.
                for s in active:
                    s.probes_sent += 1
                self._send_aggregated_probe(active)

                if i < PROBE_COUNT - 1:
                    await asyncio.sleep(PROBE_INTERVAL)

            # Wait one more interval for conflict responses
            await asyncio.sleep(PROBE_INTERVAL)

            # All surviving sessions succeed
            for s in active:
                if not s.future.done():
                    s.future.set_result(True)
        except asyncio.CancelledError:
            # handle_incoming cancels us on a conflict (RFC 6762 s8.2
            # defer path).  Re-queue any still-unresolved sessions so
            # the chained cycle re-probes them after the suppression
            # window expires.
            for s in (active or batch):
                if (
                    not s.future.done()
                    and s not in self._pending_sessions
                ):
                    self._pending_sessions.append(s)
            raise
        finally:
            # With no running loop (this coroutine is being closed
            # after its loop went away) nothing can be scheduled, so
            # the pending sessions are dropped.  The loop is looked up
            # before the chained coroutine is created, so no coroutine
            # is ever left unawaited.
            if self._pending_sessions:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    self._probe_task = None
                    self._pending_sessions.clear()
                else:
                    self._probe_task = loop.create_task(
                        self._run_probe_cycle()
                    )
            else:
                self._probe_task = None

    def _send_aggregated_probe(
        self, sessions: list[ProbingSession]
    ) -> None:
        """Build and send a single probe message for all active sessions.

        Aggregates questions and authority records from all sessions
        into one packet (like avahi's probe-sched.c).
        """
        all_questions: list[MDNSQuestion] = []
        seen_names: set[str] = set()
        # Collapse duplicates across sessions — when two concurrent
        # probes mention the same record (reverse-PTR on a shared IP,
        # etc.) a set keeps one copy instead of emitting duplicate
        # wire records.  ``MDNSRecord.__eq__`` is identity-based
        # (RFC 6762 §10.2), so set semantics are exactly right here.
        auth_set: set[MDNSRecord] = set()

        for session in sessions:
            for name in session.names:
                name_lower = name.lower()
                if name_lower not in seen_names:
                    seen_names.add(name_lower)
                    all_questions.append(
                        MDNSQuestion(name, QType.ANY, unicast_response=True)
                    )
            # RFC 6762 s8.1: "Cache Flush Bit Not Set in Proposed Answer
            # of Probes" — clear the unique-RRSet bit on records sent in
            # the Authority section.  mDNSResponder's ``SendQueries``
            # (mDNSCore/mDNS.c:4519-4534) writes probe Authority records without
            # the `rrclass |= kDNSClass_UniqueRRSet` flip it uses for
            # Answer-section writes.
            auth_set.update(
                replace(r, cache_flush=False) for r in session.records
            )

        # Sort for deterministic wire ordering so packet captures diff
        # cleanly across runs.  Key mirrors the §8.2.1 tiebreak sort.
        all_authority = sorted(
            auth_set,
            key=lambda r: (
                r.key.rclass.value, r.key.rtype.value, r.data._identity,
            ),
        )

        msg = MDNSMessage.build_probe(all_questions, all_authority)
        self._send(msg)

    # -- Conflict rate limiting -----------------------------------------------

    def _record_conflict(self) -> None:
        now = time.monotonic()
        self._conflict_times.append(now)
        cutoff = now - CONFLICT_RATE_WINDOW
        while self._conflict_times and self._conflict_times[0] < cutoff:
            self._conflict_times.popleft()

    async def _wait_if_probes_suppressed(self) -> bool:
        """RFC 6762 s8.2 simultaneous-probe defer.

        After losing a tiebreak, we MUST wait one second before
        re-probing to let any real competing peer finish its probing
        (and answer back on our re-probe so we rename) while stale
        packets on the network go unanswered.  This helper blocks
        until ``_suppress_probes_until`` has passed.

        Returns True if a wait actually happened — callers use this
        to skip the §8.1 startup jitter, which is subsumed by the
        §8.2 defer.

        Matches Apple mDNSResponder's global ``m->SuppressProbes``
        clock in ``ResolveSimultaneousProbe`` (mDNSCore/mDNS.c).
        """
        now = time.monotonic()
        if self._suppress_probes_until > now:
            wait = self._suppress_probes_until - now
            logger.debug(
                "Simultaneous-probe suppression: sleeping %.3fs "
                "(RFC 6762 s8.2)", wait,
            )
            await asyncio.sleep(wait)
            return True
        return False

    async def _wait_if_rate_limited(self) -> None:
        """RFC 6762 s8.1: if 15 conflicts in 10s, wait 5s."""
        now = time.monotonic()
        cutoff = now - CONFLICT_RATE_WINDOW
        while self._conflict_times and self._conflict_times[0] < cutoff:
            self._conflict_times.popleft()

        if len(self._conflict_times) >= CONFLICT_RATE_MAX:
            logger.warning(
                "Conflict rate limit: %d conflicts in %.0fs, "
                "backing off %.0fs",
                len(self._conflict_times),
                CONFLICT_RATE_WINDOW,
                CONFLICT_RATE_BACKOFF,
            )
            await asyncio.sleep(CONFLICT_RATE_BACKOFF)
