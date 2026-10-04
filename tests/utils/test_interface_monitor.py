"""InterfaceMonitor: netlink parsing, link-up transitions, settling.

Hand-built rtnetlink frames go through the real parser and the real
monitor (``handle_messages``), and ``SettleTimer`` runs on a real event
loop.  The last class opens the monitor's netlink socket and, where the
process may change interfaces, creates a dummy link to watch real
kernel messages arrive.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import socket
import struct
import subprocess
import time
from typing import Iterator

import pytest

from truenas_pydiscovery_utils.interface_monitor import (
    IFF_LOWER_UP,
    IFF_RUNNING,
    IFF_UP,
    RTM_DELADDR,
    RTM_DELLINK,
    RTM_NEWADDR,
    RTM_NEWLINK,
    InterfaceMonitor,
    NetlinkEvent,
    NetlinkEventKind,
    SettleTimer,
    parse_netlink_buffer,
    read_interface_state,
    read_link_states,
)

_NLMSGHDR = struct.Struct("=IHHII")
_IFINFOMSG = struct.Struct("=BxHiII")
_IFADDRMSG = struct.Struct("=BBBBI")

_UP = IFF_UP | IFF_RUNNING | IFF_LOWER_UP


def _message(msg_type: int, body: bytes) -> bytes:
    total = _NLMSGHDR.size + len(body)
    return _NLMSGHDR.pack(total, msg_type, 0, 0, 0) + body + bytes(-total & 3)


def _link(msg_type: int, ifindex: int, flags: int) -> bytes:
    return _message(msg_type, _IFINFOMSG.pack(0, 0, ifindex, flags, 0))


def _address(msg_type: int, ifindex: int) -> bytes:
    return _message(
        msg_type, _IFADDRMSG.pack(socket.AF_INET, 24, 0, 0, ifindex),
    )


class TestParseNetlinkBuffer:
    def test_link_up_needs_running_and_lower_up(self):
        """Some drivers raise IFF_RUNNING before the link has carrier;
        like mDNSResponder, both flags are required."""
        assert parse_netlink_buffer(_link(RTM_NEWLINK, 7, _UP)) == [
            NetlinkEvent(NetlinkEventKind.LINK, 7, up=True),
        ]
        assert parse_netlink_buffer(
            _link(RTM_NEWLINK, 3, IFF_UP | IFF_RUNNING),
        ) == [NetlinkEvent(NetlinkEventKind.LINK, 3, up=False)]

    def test_dellink(self):
        assert parse_netlink_buffer(_link(RTM_DELLINK, 9, _UP)) == [
            NetlinkEvent(NetlinkEventKind.LINK_REMOVED, 9),
        ]

    def test_address_messages(self):
        frame = _address(RTM_NEWADDR, 4) + _address(RTM_DELADDR, 5)
        assert parse_netlink_buffer(frame) == [
            NetlinkEvent(NetlinkEventKind.ADDRESS, 4),
            NetlinkEvent(NetlinkEventKind.ADDRESS, 5),
        ]

    def test_other_message_types_are_skipped(self):
        assert parse_netlink_buffer(_message(24, bytes(12))) == []

    def test_truncated_buffer_yields_nothing(self):
        assert parse_netlink_buffer(b"\x00\x00\x00") == []
        frame = _link(RTM_NEWLINK, 1, _UP)
        assert parse_netlink_buffer(frame[:-4]) == []

    def test_several_messages_in_one_buffer(self):
        frame = (
            _link(RTM_NEWLINK, 1, _UP)
            + _link(RTM_DELLINK, 2, 0)
            + _address(RTM_NEWADDR, 3)
        )
        assert [e.kind for e in parse_netlink_buffer(frame)] == [
            NetlinkEventKind.LINK,
            NetlinkEventKind.LINK_REMOVED,
            NetlinkEventKind.ADDRESS,
        ]


def _monitor(link_ups: list[int]) -> InterfaceMonitor:
    async def on_link_up(ifindex: int) -> None:
        link_ups.append(ifindex)

    monitor = InterfaceMonitor(on_link_up, lambda: None)
    # The socket half is exercised in TestRealNetlink; these tests
    # feed ``handle_messages`` directly on a running loop.
    monitor._loop = asyncio.get_running_loop()
    return monitor


class TestLinkUp:
    """``on_link_up`` fires when a link reported down comes up."""

    def _drive(self, frames: list[bytes],
               seeded: dict[int, bool] | None = None) -> list[int]:
        link_ups: list[int] = []

        async def scenario() -> None:
            monitor = _monitor(link_ups)
            monitor._link_up = dict(seeded or {})
            for frame in frames:
                monitor.handle_messages(frame)
            await asyncio.sleep(0)
            monitor.stop()

        asyncio.run(scenario())
        return link_ups

    def test_first_report_of_an_unknown_link_does_not_fire(self):
        assert self._drive([_link(RTM_NEWLINK, 1, _UP)]) == []

    def test_link_seen_down_at_start_fires_when_it_comes_up(self):
        """Link states are read when the monitor starts, so a link that
        was down then is caught coming up."""
        assert self._drive([_link(RTM_NEWLINK, 5, _UP)], {5: False}) == [5]

    def test_down_then_up_fires_once(self):
        frames = [
            _link(RTM_NEWLINK, 1, IFF_UP),
            _link(RTM_NEWLINK, 1, _UP),
            _link(RTM_NEWLINK, 1, _UP),
        ]
        assert self._drive(frames) == [1]

    def test_links_are_tracked_independently(self):
        frames = [
            _link(RTM_NEWLINK, 1, IFF_UP),
            _link(RTM_NEWLINK, 2, IFF_UP),
            _link(RTM_NEWLINK, 2, _UP),
            _link(RTM_NEWLINK, 1, _UP),
        ]
        assert self._drive(frames) == [2, 1]

    def test_stop_cancels_a_running_callback(self):
        cancelled = asyncio.Event()

        async def scenario() -> None:
            started = asyncio.Event()

            async def slow(ifindex: int) -> None:
                started.set()
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    cancelled.set()
                    raise

            monitor = InterfaceMonitor(slow, lambda: None)
            monitor._loop = asyncio.get_running_loop()
            monitor._link_up = {7: False}
            monitor.handle_messages(_link(RTM_NEWLINK, 7, _UP))
            await started.wait()
            monitor.stop()
            await asyncio.sleep(0)

        asyncio.run(scenario())
        assert cancelled.is_set()


class TestSettleTimer:
    """One callback per burst: ``quiet`` after its last note, and no
    later than ``maximum`` after its first."""

    @staticmethod
    def _fired(notes_at: list[float], quiet: float = 0.05,
               maximum: float = 0.2, run_for: float = 0.5) -> list[float]:
        """Note at each offset in *notes_at* (seconds from the start);
        return when the callback fired, as offsets too."""
        fired: list[float] = []

        async def scenario() -> None:
            loop = asyncio.get_running_loop()
            started = loop.time()
            timer = SettleTimer(
                loop, quiet, maximum,
                lambda: fired.append(loop.time() - started),
            )
            for offset in notes_at:
                await asyncio.sleep(max(0.0, started + offset - loop.time()))
                timer.note()
            await asyncio.sleep(max(0.0, started + run_for - loop.time()))
            timer.cancel()

        asyncio.run(scenario())
        return fired

    def test_burst_fires_once_after_the_quiet_period(self):
        fired = self._fired([0.0, 0.01, 0.02, 0.03])
        assert len(fired) == 1
        assert fired[0] >= 0.03 + 0.05 - 0.005

    def test_steady_stream_fires_by_the_maximum(self):
        fired = self._fired(
            [i * 0.02 for i in range(25)], quiet=0.05, maximum=0.2,
            run_for=0.7,
        )
        assert fired and fired[0] < 0.25
        assert len(fired) >= 2

    def test_notes_after_a_burst_start_another(self):
        assert len(self._fired([0.0, 0.2])) == 2

    def test_cancel_drops_the_pending_burst(self):
        fired: list[float] = []

        async def scenario() -> None:
            loop = asyncio.get_running_loop()
            timer = SettleTimer(loop, 0.05, 0.2, lambda: fired.append(0.0))
            timer.note()
            assert timer.pending
            timer.cancel()
            assert not timer.pending
            await asyncio.sleep(0.15)

        asyncio.run(scenario())
        assert fired == []


class TestMessagesStartABurst:
    def _pending_after(self, frame: bytes) -> bool:
        async def scenario() -> bool:
            loop = asyncio.get_running_loop()
            monitor = InterfaceMonitor(
                lambda ifindex: asyncio.sleep(0), lambda: None,
            )
            monitor._loop = loop
            monitor._settle = SettleTimer(loop, 1.0, 5.0, lambda: None)
            monitor.handle_messages(frame)
            pending = monitor._settle.pending
            monitor.stop()
            return pending

        return asyncio.run(scenario())

    def test_link_and_address_messages_do(self):
        assert self._pending_after(_address(RTM_NEWADDR, 2))
        assert self._pending_after(_link(RTM_NEWLINK, 2, IFF_UP))
        assert self._pending_after(_link(RTM_DELLINK, 2, 0))

    def test_other_messages_do_not(self):
        assert not self._pending_after(_message(24, bytes(12)))


needs_link_changes = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("ip") is None,
    reason="creating a dummy link needs root and iproute2",
)


def _ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True)


async def _until(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.01)


@pytest.fixture
def dummy_link() -> Iterator[str]:
    """A dummy link, down and without addresses; removed afterwards."""
    name = f"pdmon{os.getpid() % 10000}"
    _ip("link", "add", name, "type", "dummy")
    try:
        yield name
    finally:
        subprocess.run(["ip", "link", "del", name], capture_output=True)


class TestRealNetlink:
    def test_reads_the_current_link_states(self):
        states = read_link_states()
        assert states[socket.if_nametoindex("lo")] is True

    def test_reads_the_current_interface_state(self):
        names, addresses = read_interface_state()
        assert (socket.if_nametoindex("lo"), "lo") in names
        assert read_interface_state() == (names, addresses)

    def test_start_and_stop(self):
        async def scenario() -> None:
            monitor = InterfaceMonitor(
                lambda ifindex: asyncio.sleep(0), lambda: None,
            )
            monitor.start(asyncio.get_running_loop())
            assert monitor._sock is not None
            assert socket.if_nametoindex("lo") in monitor._link_up
            monitor.stop()
            assert monitor._sock is None

        asyncio.run(scenario())

    @needs_link_changes
    def test_address_changes_are_reported_once_settled(self, dummy_link):
        """An address added or removed is one change.  The kernel
        repeating RTM_NEWADDR for an address the interface already has,
        as it does on each IPv6 Router Advertisement, starts a burst
        but changes nothing."""
        changes: list[float] = []

        async def scenario() -> None:
            loop = asyncio.get_running_loop()
            monitor = InterfaceMonitor(
                lambda ifindex: asyncio.sleep(0),
                lambda: changes.append(loop.time()),
                settle_quiet=0.1, settle_max=0.5,
            )
            monitor.start(loop)
            try:
                _ip("addr", "add", "203.0.113.9/24", "dev", dummy_link)
                await _until(lambda: len(changes) == 1)
                _ip("addr", "replace", "203.0.113.9/24", "dev", dummy_link)
                await _until(lambda: monitor._settle.pending)
                await _until(lambda: not monitor._settle.pending)
                await asyncio.sleep(0.2)
                assert len(changes) == 1
                _ip("addr", "del", "203.0.113.9/24", "dev", dummy_link)
                await _until(lambda: len(changes) == 2)
            finally:
                monitor.stop()

        asyncio.run(scenario())

    @needs_link_changes
    def test_link_coming_up_is_reported(self, dummy_link):
        """The dummy link is down when the monitor starts, so setting
        it up reports it coming up, and so does doing so again."""
        link_ups: list[int] = []
        index = socket.if_nametoindex(dummy_link)

        async def on_link_up(ifindex: int) -> None:
            link_ups.append(ifindex)

        async def scenario() -> None:
            monitor = InterfaceMonitor(on_link_up, lambda: None)
            monitor.start(asyncio.get_running_loop())
            try:
                assert monitor._link_up[index] is False
                _ip("link", "set", dummy_link, "up")
                await _until(lambda: link_ups == [index])
                _ip("link", "set", dummy_link, "down")
                _ip("link", "set", dummy_link, "up")
                await _until(lambda: link_ups == [index, index])
            finally:
                monitor.stop()

        asyncio.run(scenario())
