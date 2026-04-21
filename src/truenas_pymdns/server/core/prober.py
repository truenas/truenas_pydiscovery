"""mDNS probing state machine per RFC 6762 Section 8.

Probing sequence (RFC 6762 s8.1):
  1. Wait random 0-250ms
  2. Send probe (QD=questions with QU bit, NS=proposed records)
  3. Wait 250ms, repeat (3 probes total)
  4. If no conflict by 250ms after third probe, probing succeeds
  5. If conflict detected, defer and choose new name

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
    MAX_PROBE_RESTARTS,
    MAX_PROBING_CONFLICT_RETRIES,
    PROBE_COUNT,
    PROBE_INTERVAL,
    QType,
    SIMULTANEOUS_PROBE_DEFER,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import MDNSRecord
from .conflict import lexicographic_compare

logger = logging.getLogger(__name__)

# How long to collect concurrent probes before sending the first
# aggregated probe message (avahi uses PROBE_DEFER_MSEC=50ms).
_PROBE_AGGREGATION_WINDOW = 0.050


@dataclass
class ProbingSession:
    """Tracks state for one in-flight probing attempt."""
    records: list[MDNSRecord]
    names: set[str]
    probes_sent: int = 0
    future: asyncio.Future | None = None
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
    ) -> None:
        self._send = send_fn
        self._on_conflict = on_conflict
        self._sessions: dict[str, ProbingSession] = {}
        # RFC 6762 s8.1: conflict rate limiting
        self._conflict_times: collections.deque[float] = collections.deque()
        self._probe_restart_count: int = 0
        # Aggregation: sessions waiting for the first probe cycle
        self._pending_sessions: list[ProbingSession] = []
        self._aggregation_handle: asyncio.TimerHandle | None = None
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

        Returns False if MAX_PROBE_RESTARTS has been exceeded.
        """
        if not records:
            return True

        if self._probe_restart_count >= MAX_PROBE_RESTARTS:
            names = {r.key.name for r in records}
            logger.error(
                "Exceeded %d probe restarts for %s, giving up — "
                "these services will not be discoverable on the "
                "network until the daemon is restarted",
                MAX_PROBE_RESTARTS, names,
            )
            return False

        self._probe_restart_count += 1
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
            if not future.done():
                future.set_result(False)
            return False
        finally:
            self._sessions.pop(session_key, None)

    def handle_incoming(self, message: MDNSMessage, source: tuple) -> None:
        """Check incoming messages for conflicts with active probes.

        RFC 6762 s8.2: compare authority records lexicographically.
        """
        if not self._sessions:
            return

        conflict_records = (
            message.answers if message.is_response
            else message.authorities
        )

        for session_key, session in list(self._sessions.items()):
            if session.future and session.future.done():
                continue

            their_records: list[MDNSRecord] = []
            our_names = {n.lower() for n in session.names}
            for rr in conflict_records:
                if rr.key.name.lower() in our_names:
                    their_records.append(rr)

            if not their_records:
                continue

            our_unique = [r for r in session.records if r.cache_flush]
            cmp = lexicographic_compare(our_unique, their_records)

            # RFC 6762 §8.2: the record with lexicographically GREATER
            # rdata wins.  ``lexicographic_compare`` returns the sign
            # of ``ours - theirs``, so ``cmp < 0`` means ours is
            # smaller — we lose the tiebreak.
            if cmp < 0:
                self._record_conflict()
                session.conflicts_seen += 1

                if session.conflicts_seen <= MAX_PROBING_CONFLICT_RETRIES:
                    # RFC 6762 §8.2: "The logic for waiting one second
                    # and then trying again is to guard against stale
                    # probe packets on the network (possibly even stale
                    # probe packets sent moments ago by this host
                    # itself, before some configuration change, which
                    # may be echoed back after a short delay by some
                    # Ethernet switches and some 802.11 base stations)."
                    # Pause all probes for 1s, then re-probe the SAME
                    # name.  A real peer will answer our re-probe and
                    # we'll rename on the next conflict; a stale echo
                    # will go unanswered and the re-probe will succeed.
                    #
                    # Mirrors Apple mDNSResponder's
                    # ``ResolveSimultaneousProbe`` (mDNSCore/mDNS.c),
                    # which sets ``m->SuppressProbes = timenow +
                    # mDNSPlatformOneSecond`` and resets ``ProbeCount``.
                    logger.info(
                        "Probe conflict for %s from %s "
                        "(retry %d/%d after %.1fs per RFC 6762 s8.2)",
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
                    # Cancel the in-flight cycle so no more probes go
                    # on the wire during the defer window; the cycle's
                    # except/finally re-queues any other active
                    # sessions and chains a new cycle that honors
                    # _suppress_probes_until.
                    if self._probe_task and not self._probe_task.done():
                        self._probe_task.cancel()
                else:
                    # Exceeded the retry allowance — a real peer owns
                    # this name.  Rename per RFC 6762 s9.  Matches
                    # mDNSResponder's `else` branch that calls
                    # ``mDNS_Deregister_internal(..., mDNS_Dereg_conflict)``.
                    logger.info(
                        "Probe conflict for %s from %s "
                        "(exceeded %d retries — renaming per RFC 6762 s9)",
                        session.names, source,
                        MAX_PROBING_CONFLICT_RETRIES,
                    )
                    if session.future and not session.future.done():
                        session.future.set_result(False)
                    self._on_conflict(session.records)

    def cancel_all(self) -> None:
        """Cancel all active probing sessions."""
        if self._aggregation_handle:
            self._aggregation_handle.cancel()
            self._aggregation_handle = None
        if self._probe_task:
            self._probe_task.cancel()
            self._probe_task = None
        for session in self._sessions.values():
            if session.future and not session.future.done():
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
                await asyncio.sleep(random.uniform(0, PROBE_INTERVAL))

            # Collect all sessions that were added during jitter window
            batch = list(self._pending_sessions)
            self._pending_sessions.clear()

            if not batch:
                return

            active = [
                s for s in batch if s.future and not s.future.done()
            ]
            if not active:
                return

            for i in range(PROBE_COUNT):
                # Re-check which sessions are still active (not conflicted)
                active = [
                    s for s in active
                    if s.future and not s.future.done()
                ]
                if not active:
                    return

                self._send_aggregated_probe(active)
                for s in active:
                    s.probes_sent += 1

                if i < PROBE_COUNT - 1:
                    await asyncio.sleep(PROBE_INTERVAL)

            # Wait one more interval for conflict responses
            await asyncio.sleep(PROBE_INTERVAL)

            # All surviving sessions succeed
            for s in active:
                if s.future and not s.future.done():
                    s.future.set_result(True)
        except asyncio.CancelledError:
            # handle_incoming cancels us on a conflict (RFC 6762 s8.2
            # defer path).  Re-queue any still-unresolved sessions so
            # the chained cycle re-probes them after the suppression
            # window expires.
            for s in (active or batch):
                if (
                    s.future and not s.future.done()
                    and s not in self._pending_sessions
                ):
                    self._pending_sessions.append(s)
            raise
        finally:
            # If the event loop is already closed (tests tear-down
            # between cycles), we can't schedule anything — just
            # drop state and return.
            if self._pending_sessions:
                try:
                    self._probe_task = asyncio.ensure_future(
                        self._run_probe_cycle()
                    )
                except RuntimeError:
                    self._probe_task = None
                    self._pending_sessions.clear()
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
            # the Authority section.  mDNSResponder's SendQueries
            # (mDNSCore/mDNS.c:4519-4534) writes probe Authority records
            # without the `rrclass |= kDNSClass_UniqueRRSet` flip it uses
            # for Answer-section writes.
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
