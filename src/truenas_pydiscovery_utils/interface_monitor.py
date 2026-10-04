"""Linux netlink monitor for interface and address changes.

One ``AF_NETLINK`` socket subscribed to ``RTMGRP_LINK``,
``RTMGRP_IPV4_IFADDR`` and ``RTMGRP_IPV6_IFADDR``, the groups avahi
(``avahi_netlink_new`` in avahi-core/iface-linux.c), mDNSResponder
(``OpenIfNotifySocket`` in mDNSPosix/mDNSPosix.c), wsdd
(``NetlinkAddressMonitor``) and wsdd-native subscribe to, serves every
protocol through two callbacks:

* ``on_link_up(ifindex)``, as soon as an interface comes up: it reports
  ``IFF_RUNNING`` and ``IFF_LOWER_UP`` after last being seen without
  them, which a cable plugged back in does as well as ``ip link set
  up``.  mDNS probes and announces on it again (RFC 6762 §8.3).
* ``on_change()``, once a burst of link and address messages has
  settled and left the interfaces or their usable addresses different
  from before.  The subscribers then read the interfaces and addresses
  themselves (``netlink_addr.enumerate_all_addresses``) and bring their
  state in line; a message only says that something may have changed.

Settling: the references act on each message, avahi and wsdd per
address, mDNSResponder by draining the messages already queued and then
rebuilding its interface list (``InterfaceChangeCallback``,
``mDNSPlatformPosixRefreshInterfaceList``).  Our protocols reconcile
whole interfaces or subnets, so a burst (a DHCP renewal, a VLAN coming
up, SLAAC followed by duplicate address detection) has to cost one
reconcile, not one per message.  A burst is over once the socket has
been quiet for ``settle_quiet`` seconds, and never later than
``settle_max`` seconds after its first message.

Comparing: at the end of a burst the interface names and usable
addresses are read again (``read_interface_state``) and ``on_change``
fires only if they differ from what was read before.  The kernel
repeats ``RTM_NEWADDR`` for IPv6 addresses it already has, as often as
each Router Advertisement; mDNSResponder's
``ProcessRoutingNotification`` ignores those for the same reason ("We
don't want to completely rebuild and re-advertise all our host records
in this case"), and nmbd reloads its interfaces only when
``interfaces_changed`` finds the probed list different.  Addresses that
are tentative, failed DAD or are deprecated are not usable, so the
message that clears or sets one of those flags changes the state.

A message lost to a receive-buffer overrun (``ENOBUFS``) or truncated
(``MSG_TRUNC``) counts as a possible change: the comparison decides.
"""
from __future__ import annotations

import asyncio
import enum
import errno
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Any, Callable, Coroutine

from .netlink_addr import enumerate_all_addresses, netlink_dump

logger = logging.getLogger(__name__)

# netlink protocol and rtnetlink multicast groups (linux/netlink.h,
# linux/rtnetlink.h)
NETLINK_ROUTE = 0
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV6_IFADDR = 0x100

# rtnetlink message types (linux/rtnetlink.h)
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_GETLINK = 18
RTM_NEWADDR = 20
RTM_DELADDR = 21

# interface flags (linux/if.h)
IFF_UP = 0x1
IFF_RUNNING = 0x40
IFF_LOWER_UP = 0x10000
_UP_FLAGS = IFF_RUNNING | IFF_LOWER_UP

# Settling (see the module docstring).
SETTLE_QUIET = 1.0
SETTLE_MAX = 5.0

# struct nlmsghdr: len, type, flags, seq, pid
_NLMSGHDR = struct.Struct("=IHHII")
# struct ifinfomsg: family, pad, type, index, flags, change
_IFINFOMSG = struct.Struct("=BxHiII")
# struct ifaddrmsg: family, prefixlen, flags, scope, index
_IFADDRMSG = struct.Struct("=BBBBI")

_RECV_BUF_SIZE = 65536


class NetlinkEventKind(enum.Enum):
    """What an rtnetlink message reports."""
    LINK = enum.auto()          # RTM_NEWLINK: a link appeared or changed
    LINK_REMOVED = enum.auto()  # RTM_DELLINK
    ADDRESS = enum.auto()       # RTM_NEWADDR or RTM_DELADDR


@dataclass(slots=True, frozen=True)
class NetlinkEvent:
    """One rtnetlink message, reduced to what the monitor acts on.

    ``up`` is meaningful for ``LINK`` only: both ``IFF_RUNNING``
    (operationally up) and ``IFF_LOWER_UP`` (carrier) are set.
    """
    kind: NetlinkEventKind
    ifindex: int
    up: bool = False


def parse_netlink_buffer(buf: bytes) -> list[NetlinkEvent]:
    """Parse the rtnetlink messages in one ``recv`` buffer.

    Other message types are skipped; a truncated or malformed message
    ends the parse.
    """
    events: list[NetlinkEvent] = []
    offset = 0
    while offset + _NLMSGHDR.size <= len(buf):
        msg_len, msg_type, _flags, _seq, _pid = _NLMSGHDR.unpack_from(
            buf, offset,
        )
        if msg_len < _NLMSGHDR.size or offset + msg_len > len(buf):
            break
        payload = offset + _NLMSGHDR.size
        end = offset + msg_len
        if (
            msg_type in (RTM_NEWLINK, RTM_DELLINK)
            and payload + _IFINFOMSG.size <= end
        ):
            _family, _type, ifindex, flags, _change = (
                _IFINFOMSG.unpack_from(buf, payload)
            )
            if msg_type == RTM_NEWLINK:
                events.append(NetlinkEvent(
                    NetlinkEventKind.LINK, ifindex,
                    up=(flags & _UP_FLAGS) == _UP_FLAGS,
                ))
            else:
                events.append(
                    NetlinkEvent(NetlinkEventKind.LINK_REMOVED, ifindex),
                )
        elif (
            msg_type in (RTM_NEWADDR, RTM_DELADDR)
            and payload + _IFADDRMSG.size <= end
        ):
            *_header, ifindex = _IFADDRMSG.unpack_from(buf, payload)
            events.append(NetlinkEvent(NetlinkEventKind.ADDRESS, ifindex))
        # Netlink messages are aligned to 4-byte boundaries.
        offset += (msg_len + 3) & ~3
    return events


def read_link_states() -> dict[int, bool]:
    """Whether each interface is up now, from an ``RTM_GETLINK`` dump."""
    body = _IFINFOMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0)
    return {
        event.ifindex: event.up
        for event in parse_netlink_buffer(netlink_dump(RTM_GETLINK, body))
        if event.kind is NetlinkEventKind.LINK
    }


# The interfaces by index and name, and the usable addresses (with
# their prefixes) of each interface that has any.
InterfaceState = tuple[frozenset, frozenset]


def read_interface_state() -> InterfaceState:
    """What the subscribers act on: interface names and usable
    addresses, as ``enumerate_all_addresses`` reports them."""
    return (
        frozenset(socket.if_nameindex()),
        frozenset(
            (index, frozenset(addresses.v4), frozenset(addresses.v6))
            for index, addresses in enumerate_all_addresses().items()
        ),
    )


class SettleTimer:
    """Calls *callback* once per burst of ``note`` calls: *quiet*
    seconds after the last of them, and no later than *maximum* seconds
    after the first."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        quiet: float,
        maximum: float,
        callback: Callable[[], None],
    ) -> None:
        self._loop = loop
        self._quiet = quiet
        self._maximum = maximum
        self._callback = callback
        self._burst_started: float | None = None
        self._timer: asyncio.TimerHandle | None = None

    @property
    def pending(self) -> bool:
        return self._timer is not None

    def note(self) -> None:
        now = self._loop.time()
        if self._burst_started is None:
            self._burst_started = now
        fire_at = min(now + self._quiet, self._burst_started + self._maximum)
        if self._timer is not None:
            self._timer.cancel()
        self._timer = self._loop.call_at(fire_at, self._fire)

    def cancel(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        self._timer = None
        self._burst_started = None

    def _fire(self) -> None:
        self._timer = None
        self._burst_started = None
        self._callback()


LinkUpCallback = Callable[[int], Coroutine[Any, Any, None]]


class InterfaceMonitor:
    """asyncio-integrated listener for link and address changes.

    ``on_link_up`` is a coroutine function, run as a task per link that
    comes up; ``stop`` cancels those still running.  ``on_change`` is a
    plain function, called after a burst that changed the interfaces or
    their usable addresses.
    """

    def __init__(
        self,
        on_link_up: LinkUpCallback,
        on_change: Callable[[], None],
        *,
        settle_quiet: float = SETTLE_QUIET,
        settle_max: float = SETTLE_MAX,
    ) -> None:
        self._on_link_up = on_link_up
        self._on_change = on_change
        self._settle_quiet = settle_quiet
        self._settle_max = settle_max
        self._sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._settle: SettleTimer | None = None
        # ifindex -> whether it was up when last reported.  Read at
        # start, so the first report of a link that was down then counts
        # as it coming up.
        self._link_up: dict[int, bool] = {}
        # What the subscribers last had reason to act on.
        self._state: InterfaceState = (frozenset(), frozenset())
        self._tasks: set[asyncio.Task] = set()

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Subscribe, read the current state, and start listening.

        The socket subscribes before the state is read, so a change
        made in between is queued on it rather than lost.  Raises
        ``OSError`` where netlink is unavailable.
        """
        sock = socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE,
        )
        try:
            sock.setblocking(False)
            # Port id 0: the kernel assigns one (netlink(7)), so this
            # socket cannot collide with another netlink socket of the
            # process.
            sock.bind(
                (0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR),
            )
            self._link_up = read_link_states()
            self._state = read_interface_state()
        except OSError:
            sock.close()
            raise
        self._sock = sock
        self._loop = loop
        self._settle = SettleTimer(
            loop, self._settle_quiet, self._settle_max, self._settled,
        )
        loop.add_reader(sock.fileno(), self._on_readable)
        logger.info(
            "Monitoring %d interfaces for link and address changes",
            len(self._link_up),
        )

    def stop(self) -> None:
        """Stop listening, drop a pending burst and cancel the
        callback tasks still running."""
        if self._settle is not None:
            self._settle.cancel()
            self._settle = None
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        if self._sock is not None and self._loop is not None:
            try:
                self._loop.remove_reader(self._sock.fileno())
            except (ValueError, RuntimeError):
                pass
        if self._sock is not None:
            self._sock.close()
        self._sock = None
        self._loop = None

    def _on_readable(self) -> None:
        while self._sock is not None:
            try:
                data, _ancillary, msg_flags, _address = self._sock.recvmsg(
                    _RECV_BUF_SIZE,
                )
            except BlockingIOError:
                return
            except OSError as e:
                if e.errno == errno.ENOBUFS:
                    logger.warning(
                        "Netlink receive buffer overrun; reading the "
                        "interfaces again",
                    )
                    self._note_change()
                    continue
                logger.error("netlink recv failed: %s", e)
                return
            if msg_flags & socket.MSG_TRUNC:
                self._note_change()
            self.handle_messages(data)

    def handle_messages(self, data: bytes) -> None:
        """Act on one buffer of rtnetlink messages."""
        events = parse_netlink_buffer(data)
        for event in events:
            if event.kind is NetlinkEventKind.LINK:
                was_up = self._link_up.get(event.ifindex)
                self._link_up[event.ifindex] = event.up
                if event.up and was_up is False:
                    self._link_came_up(event.ifindex)
            elif event.kind is NetlinkEventKind.LINK_REMOVED:
                self._link_up.pop(event.ifindex, None)
        if events:
            self._note_change()

    def _link_came_up(self, ifindex: int) -> None:
        if self._loop is None:
            return
        logger.info("Interface %d came up", ifindex)
        self._track(self._loop.create_task(self._on_link_up(ifindex)))

    def _note_change(self) -> None:
        if self._settle is not None:
            self._settle.note()

    def _settled(self) -> None:
        if self._loop is not None:
            self._track(self._loop.create_task(self._report_if_changed()))

    async def _report_if_changed(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            state = await loop.run_in_executor(None, read_interface_state)
        except OSError as e:
            # Let the subscribers read the interfaces themselves.
            logger.warning("Cannot read the interfaces: %s", e)
            self._on_change()
            return
        if state == self._state:
            logger.debug("Interface notifications left nothing changed")
            return
        self._state = state
        self._on_change()

    def _track(self, task: asyncio.Task) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
