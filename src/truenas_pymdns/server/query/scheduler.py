"""Query scheduling with batching, known-answer suppression, and exponential backoff.

RFC 6762 s5.2: continuous querying intervals MUST increase by at least 2x.
RFC 6762 s7.1: known-answer suppression in query answer section.
RFC 6762 s7.2: TC bit when known-answers don't fit in one packet.
RFC 6762 s7.3: suppress query if identical question seen from network.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import TYPE_CHECKING, Callable

from truenas_pymdns.protocol.constants import (
    QUERY_DEFER_MAX,
    QUERY_DEFER_MIN,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import MDNSRecord

if TYPE_CHECKING:
    from ..core.cache import RecordCache

logger = logging.getLogger(__name__)

# Max continuous query interval cap (RFC 6762 s5.2)
_MAX_QUERY_INTERVAL = 3600.0


class QueryScheduler:
    """Batches, defers, and retries outgoing mDNS queries per RFC 6762."""

    def __init__(
        self,
        send_fn: Callable[[MDNSMessage], None],
        cache: 'RecordCache',
    ) -> None:
        self._send = send_fn
        self._cache = cache
        self._pending: dict[str, MDNSQuestion] = {}
        self._defer_handle: asyncio.TimerHandle | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        # Continuous query tracking: qkey -> (next_interval, timer_handle)
        self._continuous: dict[str, tuple[float, asyncio.TimerHandle]] = {}
        # RFC 6762 s7.3: recently seen questions from network
        self._seen_questions: dict[str, float] = {}

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Bind to the event loop so deferred queries can be scheduled."""
        self._loop = loop

    def schedule_query(self, question: MDNSQuestion) -> None:
        """Schedule a one-shot query, deferred 20-120ms for batching."""
        qkey = f"{question.name.lower()}|{question.qtype.value}"

        # RFC 6762 s7.3: suppress if we saw this from network recently
        now = time.monotonic()
        if qkey in self._seen_questions:
            if now - self._seen_questions[qkey] < 1.0:
                return

        self._pending[qkey] = question

        if self._defer_handle is None and self._loop:
            # RFC 6762 s5.2: random 20-120ms initial delay
            delay = random.uniform(QUERY_DEFER_MIN, QUERY_DEFER_MAX)
            self._defer_handle = self._loop.call_later(
                delay, self._flush_queries
            )

    def schedule_continuous(self, question: MDNSQuestion) -> None:
        """Start a continuous query with exponential backoff (RFC 6762 s5.2).

        First query fires after batch defer, then repeats at 1s, 2s,
        4s, 8s... up to 60 minutes.
        """
        qkey = f"{question.name.lower()}|{question.qtype.value}"
        if qkey in self._continuous:
            return
        self.schedule_query(question)
        if self._loop:
            handle = self._loop.call_later(
                1.0, self._continuous_tick, qkey, question, 2.0
            )
            self._continuous[qkey] = (2.0, handle)

    def stop_continuous(self, name: str, qtype: int) -> None:
        """Stop a continuous query."""
        qkey = f"{name.lower()}|{qtype}"
        entry = self._continuous.pop(qkey, None)
        if entry:
            _, handle = entry
            handle.cancel()

    def on_network_question(self, question: MDNSQuestion) -> None:
        """RFC 6762 s7.3: record a question seen from the network.

        Suppresses our pending duplicate if we have one.  Growth of
        ``_seen_questions`` is bounded by a periodic ``sweep`` driven
        from ``MDNSServer._maintenance_loop``; nothing to prune here.
        """
        qkey = f"{question.name.lower()}|{question.qtype.value}"
        self._seen_questions[qkey] = time.monotonic()
        self._pending.pop(qkey, None)

    def sweep(self, now: float) -> None:
        """Drop ``_seen_questions`` entries older than 2 s.

        The suppression window consulted in ``schedule_query`` is 1 s;
        2 s of prune grace keeps one window of slack.
        """
        cutoff = now - 2.0
        self._seen_questions = {
            k: v for k, v in self._seen_questions.items() if v > cutoff
        }

    def next_sweep_at(self) -> float | None:
        """Return the monotonic time at which the next sweep would
        evict something, or ``None`` if no entries are tracked."""
        if not self._seen_questions:
            return None
        return min(self._seen_questions.values()) + 2.0

    def cancel_all(self) -> None:
        """Cancel any pending deferred and continuous queries."""
        if self._defer_handle:
            self._defer_handle.cancel()
            self._defer_handle = None
        self._pending.clear()
        for _, handle in self._continuous.values():
            handle.cancel()
        self._continuous.clear()

    def _flush_queries(self) -> None:
        """Send all pending queries with known-answer suppression."""
        self._defer_handle = None
        if not self._pending:
            return

        questions = list(self._pending.values())
        self._pending.clear()

        now = time.monotonic()

        # RFC 6762 s7.1: collect known answers for suppression
        known_answers: list[MDNSRecord] = []
        for q in questions:
            answers = self._cache.known_answers_for(
                q.name, q.qtype.value, now
            )
            known_answers.extend(answers)

        msg = MDNSMessage.build_query(questions, known_answers or None)
        self._send(msg)

        logger.debug(
            "Sent query with %d questions, %d known answers",
            len(questions), len(known_answers),
        )

    def _continuous_tick(
        self, qkey: str, question: MDNSQuestion, next_interval: float
    ) -> None:
        """Fire the next continuous query and double the interval."""
        if qkey not in self._continuous:
            return
        self.schedule_query(question)
        # RFC 6762 s5.2: double the interval, cap at 60 min
        doubled = min(next_interval * 2, _MAX_QUERY_INTERVAL)
        if self._loop:
            handle = self._loop.call_later(
                next_interval, self._continuous_tick, qkey, question, doubled
            )
            self._continuous[qkey] = (doubled, handle)
