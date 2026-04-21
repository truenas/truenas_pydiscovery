"""mDNS announcement scheduler per RFC 6762 Section 8.3."""
from __future__ import annotations

import asyncio
import logging
from typing import Callable

from truenas_pymdns.protocol.constants import ANNOUNCE_COUNT, ANNOUNCE_INTERVAL_INITIAL
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import MDNSRecord

logger = logging.getLogger(__name__)


class Announcer:
    """Sends announcement packets after successful probing.

    Sends ANNOUNCE_COUNT announcements at doubling intervals
    (1s, 2s, 4s).  Records have cache-flush bit set.
    """

    def __init__(self, send_fn: Callable[[MDNSMessage], None]) -> None:
        self._send = send_fn
        self._tasks: list[asyncio.Task] = []

    async def announce(
        self, records: list[MDNSRecord], count: int = ANNOUNCE_COUNT,
    ) -> None:
        """Send the announcement sequence for a set of records.

        *count* defaults to ``ANNOUNCE_COUNT`` (3).  Callers reacting to
        a flapping interface (BCT II.17 / mDNSCore/mDNS.c:14262) pass
        ``LINK_FLAP_ANNOUNCE_COUNT`` (1) to cut multicast traffic.
        """
        delay = ANNOUNCE_INTERVAL_INITIAL
        for i in range(count):
            # Build response with cache-flush bit
            announce_records = []
            for r in records:
                ar = MDNSRecord(
                    key=r.key, ttl=r.ttl, data=r.data, cache_flush=True,
                )
                announce_records.append(ar)

            msg = MDNSMessage.build_response(announce_records)
            self._send(msg)
            logger.debug("Announcement %d/%d sent (%d records)",
                         i + 1, count, len(records))

            if i < count - 1:
                await asyncio.sleep(delay)
                delay *= 2

    def schedule_announce(
        self, records: list[MDNSRecord], count: int = ANNOUNCE_COUNT,
    ) -> asyncio.Task:
        """Schedule an announcement sequence as a background task."""
        task = asyncio.create_task(self.announce(records, count=count))
        self._tasks.append(task)
        task.add_done_callback(lambda t: self._tasks.remove(t) if t in self._tasks else None)
        return task

    def cancel_all(self) -> None:
        """Cancel all in-progress announcement tasks."""
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
