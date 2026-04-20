"""Announcer per RFC 6762 s8.3 — sends ANNOUNCE_COUNT packets at
doubling intervals (1s, 2s) with the cache-flush bit set on every
record.
"""
from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    ANNOUNCE_COUNT,
    ANNOUNCE_INTERVAL_INITIAL,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.announcer import Announcer


def _a(name: str, addr: str, cache_flush: bool = False) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=cache_flush,
    )


def _run(coro) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestAnnounceSendsCountPackets:
    def test_emits_exactly_announce_count_messages(self):
        """A full ``announce()`` coroutine emits ANNOUNCE_COUNT packets
        (one immediately, one after 1s, one after 2s more)."""
        sent: list[MDNSMessage] = []
        a = Announcer(sent.append)

        _run(a.announce([_a("h.local", "10.0.0.1")]))

        assert len(sent) == ANNOUNCE_COUNT


class TestAnnouncementContent:
    def test_every_emitted_record_has_cache_flush_set(self):
        """RFC 6762 s10.2: announcement records MUST have the
        cache-flush bit so peers replace their stale cached copies.
        Announcer must set it even if the source record didn't."""
        sent: list[MDNSMessage] = []
        a = Announcer(sent.append)
        src = _a("plain.local", "10.0.0.1", cache_flush=False)

        _run(a.announce([src]))

        assert sent
        for msg in sent:
            assert msg.answers
            for rr in msg.answers:
                assert rr.cache_flush is True

    def test_source_record_not_mutated(self):
        """Announcer builds new records with cache_flush=True rather
        than mutating the caller's record."""
        sent: list[MDNSMessage] = []
        a = Announcer(sent.append)
        src = _a("plain.local", "10.0.0.1", cache_flush=False)

        _run(a.announce([src]))
        assert src.cache_flush is False


class TestAnnouncementTiming:
    def test_first_packet_is_sent_immediately(self):
        """The initial announcement must not be deferred — probing
        has already provided the required pre-announce delay."""
        stamps: list[float] = []
        a = Announcer(lambda msg: stamps.append(time.monotonic()))

        async def drive() -> None:
            task = asyncio.create_task(
                a.announce([_a("early.local", "10.0.0.1")])
            )
            t0 = time.monotonic()
            # Yield long enough for the first send to run, then cancel
            # before the 1 s sleep finishes.
            await asyncio.sleep(0.050)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            assert stamps, "first announcement did not fire"
            assert stamps[0] - t0 < 0.050

        _run(drive())

    def test_gap_between_first_two_sends_matches_initial_interval(self):
        """Gap between the 1st and 2nd announcement packets is
        ANNOUNCE_INTERVAL_INITIAL (1 s)."""
        stamps: list[float] = []
        a = Announcer(lambda msg: stamps.append(time.monotonic()))

        async def drive() -> None:
            task = asyncio.create_task(
                a.announce([_a("gap.local", "10.0.0.1")])
            )
            # Wait past the 1st-to-2nd gap, then cancel so the 2s
            # gap to the 3rd packet doesn't run.
            await asyncio.sleep(ANNOUNCE_INTERVAL_INITIAL + 0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(drive())
        assert len(stamps) >= 2
        gap = stamps[1] - stamps[0]
        # Allow generous tolerance for CI jitter.
        assert 0.85 <= gap <= 1.35, f"gap {gap:.3f}s outside tolerance"


class TestCancelAll:
    def test_cancel_all_aborts_in_flight_sequence(self):
        sent: list[MDNSMessage] = []
        a = Announcer(sent.append)

        async def drive() -> None:
            a.schedule_announce([_a("stop.local", "10.0.0.1")])
            await asyncio.sleep(0.050)
            a.cancel_all()
            await asyncio.sleep(ANNOUNCE_INTERVAL_INITIAL + 0.2)

        _run(drive())
        assert len(sent) == 1, f"expected 1 pre-cancel send, got {len(sent)}"
