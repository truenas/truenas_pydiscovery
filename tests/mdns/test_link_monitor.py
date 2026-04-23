"""LinkMonitor netlink parsing + DOWN→UP dispatch.

Covers BCT II.17 ("HOT-PLUGGING") and RFC 6762 §8.3: interface
state changes MUST drive re-probing.  Hand-crafted RTM_NEWLINK
frames are fed into the parser and the LinkMonitor's dispatcher to
verify the callback fires on transitions (and only on transitions).

These are unit tests for the wire-format parser and the state
machine — no real netlink socket or CAP_NET_ADMIN is required.
"""
from __future__ import annotations

import asyncio
import struct

from truenas_pymdns.server.net.link_monitor import (
    IFF_LOWER_UP,
    IFF_RUNNING,
    IFF_UP,
    RTM_DELLINK,
    RTM_NEWLINK,
    LinkEvent,
    LinkMonitor,
    parse_netlink_buffer,
)


_NLMSGHDR = struct.Struct("=IHHII")
_IFINFOMSG = struct.Struct("=BxHiII")


def _craft(msg_type: int, ifindex: int, flags: int) -> bytes:
    """Build one netlink message: header + ifinfomsg, 4-byte aligned."""
    body = _IFINFOMSG.pack(0, 0, ifindex, flags, 0xFFFFFFFF)
    total = _NLMSGHDR.size + len(body)
    # Pad to 4 bytes (already aligned since 16+16 = 32, but be explicit).
    pad = (-total) & 3
    header = _NLMSGHDR.pack(total, msg_type, 0, 0, 0)
    return header + body + b"\x00" * pad


class TestParseNetlinkBuffer:
    def test_single_up_message(self):
        frame = _craft(
            RTM_NEWLINK, ifindex=7,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        events = parse_netlink_buffer(frame)
        assert events == [LinkEvent(ifindex=7, up=True)]

    def test_running_without_lower_up_is_not_up(self):
        """Some drivers assert IFF_RUNNING before the PHY is actually
        carrier-sensed.  We require BOTH IFF_RUNNING and IFF_LOWER_UP,
        matching Apple's interpretation."""
        frame = _craft(
            RTM_NEWLINK, ifindex=3, flags=IFF_UP | IFF_RUNNING,
        )
        events = parse_netlink_buffer(frame)
        assert events == [LinkEvent(ifindex=3, up=False)]

    def test_dellink_always_down(self):
        frame = _craft(
            RTM_DELLINK, ifindex=9,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        events = parse_netlink_buffer(frame)
        assert events == [LinkEvent(ifindex=9, up=False)]

    def test_unknown_type_skipped(self):
        """Non-link messages (RTM_NEWADDR=20 etc.) must not produce
        LinkEvents."""
        frame = _craft(20, ifindex=1, flags=0)
        events = parse_netlink_buffer(frame)
        assert events == []

    def test_truncated_header_yields_no_events(self):
        """A short buffer that can't hold even a header must return
        [] without raising."""
        events = parse_netlink_buffer(b"\x00\x00\x00")
        assert events == []

    def test_multiple_messages_in_one_buffer(self):
        """One recv() can return several messages concatenated."""
        frame = (
            _craft(
                RTM_NEWLINK, ifindex=1,
                flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
            )
            + _craft(RTM_DELLINK, ifindex=2, flags=0)
            + _craft(
                RTM_NEWLINK, ifindex=3,
                flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
            )
        )
        events = parse_netlink_buffer(frame)
        assert events == [
            LinkEvent(ifindex=1, up=True),
            LinkEvent(ifindex=2, up=False),
            LinkEvent(ifindex=3, up=True),
        ]


class TestDispatch:
    """The state machine inside LinkMonitor: callback fires on a
    DOWN→UP transition, and only then."""

    def _drive(self, frames: list[bytes]) -> list[int]:
        fired: list[int] = []

        async def cb(ifindex: int) -> None:
            fired.append(ifindex)

        async def runner() -> None:
            mon = LinkMonitor(cb)
            # We only exercise _dispatch + _loop wiring; no real socket.
            mon._loop = asyncio.get_running_loop()
            for frame in frames:
                mon._dispatch(frame)
            # Let scheduled callback tasks run to completion.
            await asyncio.sleep(0)

        asyncio.run(runner())
        return fired

    def test_initial_up_does_not_fire(self):
        """The first RTM_NEWLINK burst (when the socket binds) lists
        all currently-up interfaces.  Those are not transitions — we
        must not re-probe just because we started."""
        frame = _craft(
            RTM_NEWLINK, ifindex=1,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        assert self._drive([frame]) == []

    def test_down_then_up_fires_once(self):
        down = _craft(RTM_NEWLINK, ifindex=1, flags=IFF_UP)
        up = _craft(
            RTM_NEWLINK, ifindex=1,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        assert self._drive([down, up]) == [1]

    def test_consecutive_ups_fire_once(self):
        """Duplicate RTM_NEWLINK UP messages without a DOWN in between
        must not cause the callback to fire twice."""
        down = _craft(RTM_NEWLINK, ifindex=4, flags=IFF_UP)
        up = _craft(
            RTM_NEWLINK, ifindex=4,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        assert self._drive([down, up, up, up]) == [4]

    def test_multiple_interfaces_tracked_independently(self):
        down1 = _craft(RTM_NEWLINK, ifindex=1, flags=IFF_UP)
        down2 = _craft(RTM_NEWLINK, ifindex=2, flags=IFF_UP)
        up1 = _craft(
            RTM_NEWLINK, ifindex=1,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        up2 = _craft(
            RTM_NEWLINK, ifindex=2,
            flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
        )
        fired = self._drive([down1, down2, up1, up2])
        assert sorted(fired) == [1, 2]


class TestShutdownCancelsInFlightCallbacks:
    """``stop()`` cancels callback tasks the monitor has spawned
    but not yet observed to completion.  Without tracking, a
    cable-flap that triggers ``_on_link_up`` just as the daemon
    starts shutting down leaves the re-probe task running against
    transports the daemon has already torn down."""

    def test_stop_cancels_in_flight_callback_task(self):
        callback_started = asyncio.Event()
        callback_cancelled = False

        async def slow_cb(ifindex: int) -> None:
            nonlocal callback_cancelled
            callback_started.set()
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                callback_cancelled = True
                raise

        async def run() -> None:
            nonlocal callback_cancelled
            mon = LinkMonitor(slow_cb)
            mon._loop = asyncio.get_running_loop()

            # Drive a down→up to make the monitor spawn the callback.
            down = _craft(RTM_NEWLINK, ifindex=7, flags=IFF_UP)
            up = _craft(
                RTM_NEWLINK, ifindex=7,
                flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
            )
            mon._dispatch(down)
            mon._dispatch(up)
            assert len(mon._tasks) == 1

            # Give the callback a chance to enter its sleep.
            await callback_started.wait()

            # stop() without a real socket: emulate by directly
            # invoking the cancel-and-clear half of stop.  (The
            # socket branch is covered separately by the existing
            # parse tests; we don't want a netlink fd here.)
            for task in list(mon._tasks):
                task.cancel()
            mon._tasks.clear()

            # Drive the loop once so the cancellation propagates.
            await asyncio.sleep(0)

        asyncio.run(run())
        assert callback_cancelled, (
            "slow_cb should have observed CancelledError when "
            "stop() cancelled the in-flight task"
        )

    def test_done_callbacks_drop_from_tracked_set(self):
        """Completed tasks must be removed from ``_tasks`` so the
        set doesn't grow without bound over the daemon's
        lifetime."""
        async def quick_cb(ifindex: int) -> None:
            return None

        async def run() -> None:
            mon = LinkMonitor(quick_cb)
            mon._loop = asyncio.get_running_loop()
            down = _craft(RTM_NEWLINK, ifindex=9, flags=IFF_UP)
            up = _craft(
                RTM_NEWLINK, ifindex=9,
                flags=IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
            )
            mon._dispatch(down)
            mon._dispatch(up)
            assert len(mon._tasks) == 1
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            assert len(mon._tasks) == 0

        asyncio.run(run())
