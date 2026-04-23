"""Linux netlink link-state monitor for hot-plug re-probing.

RFC 6762 §8.3 / §13 require a Multicast DNS responder to re-probe and
re-announce when its network connectivity changes.  Cable unplug +
replug (BCT II.17 "HOT-PLUGGING") is the canonical trigger.

Apple mDNSResponder's Linux port opens a NETLINK_ROUTE socket bound to
RTMGRP_LINK + RTMGRP_IPV4_IFADDR + RTMGRP_IPV6_IFADDR and feeds each
event into ``mDNS_RegisterInterface``, whose comment at
``mDNSCore/mDNS.c:14251`` is explicit: *"we want to re-trigger our
questions and re-probe our Resource Records, even if we believe that
we previously had an active representative of this interface."*
See also ``mDNSPosix/mDNSPosix.c:1620``.

This module exposes a stdlib-only equivalent: a parser for the
netlink ifinfomsg stream and an asyncio-integrated ``LinkMonitor``
that fires a callback on DOWN→UP transitions.
"""
from __future__ import annotations

import asyncio
import errno
import logging
import os
import socket
import struct
from dataclasses import dataclass
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# netlink constants (linux/netlink.h)
NETLINK_ROUTE = 0

# rtnetlink multicast groups (linux/rtnetlink.h) — we only need LINK
# for BCT II.17; Apple also listens to IFADDR groups but for our
# purposes a link state transition is enough to drive re-probing.
RTMGRP_LINK = 1

# rtnetlink message types (linux/rtnetlink.h)
RTM_NEWLINK = 16
RTM_DELLINK = 17

# interface flags (linux/if.h)
IFF_UP = 0x1
IFF_RUNNING = 0x40
IFF_LOWER_UP = 0x10000

# netlink header sizes (all little-endian on Linux)
_NLMSGHDR = struct.Struct("=IHHII")       # len, type, flags, seq, pid
_IFINFOMSG = struct.Struct("=BxHiII")     # family, pad, type, index, flags, change


@dataclass(slots=True, frozen=True)
class LinkEvent:
    """A single RTM_NEWLINK / RTM_DELLINK event parsed off the wire."""
    ifindex: int
    up: bool


def parse_netlink_buffer(buf: bytes) -> list[LinkEvent]:
    """Parse a netlink recv buffer into a list of ``LinkEvent``s.

    The "up" flag is set iff the message is RTM_NEWLINK *and* the
    interface carries both ``IFF_RUNNING`` and ``IFF_LOWER_UP``.  Apple
    uses the same conjunction — ``IFF_RUNNING`` alone is not sufficient
    since some drivers set it before the physical layer is actually
    ready.

    Non-link message types and malformed frames are skipped silently.
    """
    events: list[LinkEvent] = []
    offset = 0
    while offset + _NLMSGHDR.size <= len(buf):
        msg_len, msg_type, _flags, _seq, _pid = _NLMSGHDR.unpack_from(
            buf, offset,
        )
        if msg_len < _NLMSGHDR.size or offset + msg_len > len(buf):
            break
        payload_start = offset + _NLMSGHDR.size
        if (
            msg_type in (RTM_NEWLINK, RTM_DELLINK)
            and payload_start + _IFINFOMSG.size <= offset + msg_len
        ):
            _fam, _typ, ifindex, flags, _change = _IFINFOMSG.unpack_from(
                buf, payload_start,
            )
            up = (
                msg_type == RTM_NEWLINK
                and bool(flags & IFF_RUNNING)
                and bool(flags & IFF_LOWER_UP)
            )
            events.append(LinkEvent(ifindex=ifindex, up=up))
        # Netlink messages are aligned to 4-byte boundaries.
        offset += (msg_len + 3) & ~3
    return events


class LinkMonitor:
    """asyncio-integrated netlink listener for interface state changes.

    Opens ``AF_NETLINK / SOCK_RAW / NETLINK_ROUTE`` bound to
    ``RTMGRP_LINK`` and calls ``callback(ifindex)`` whenever an
    interface transitions from "not up" to "up" (``IFF_RUNNING`` +
    ``IFF_LOWER_UP``).  Initial RTM_NEWLINK bursts emitted by the
    kernel when the socket first binds do NOT trigger the callback
    for interfaces that were already up — only observed transitions.
    """

    def __init__(
        self,
        callback: Callable[[int], Coroutine[Any, Any, None]],
    ) -> None:
        self._callback = callback
        self._sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        # ifindex -> last-known up/down state.  Unknown => first event
        # seen; we don't fire the callback on the initial dump because
        # those interfaces were already up when we started.
        self._state: dict[int, bool] = {}
        # Tasks spawned for callback invocations.  Tracked so
        # ``stop()`` can cancel in-flight re-probe work — otherwise
        # the callback task outlives the daemon on shutdown and
        # touches state (``self._interfaces``, transports) that
        # has already been torn down.
        self._tasks: set[asyncio.Task] = set()

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Open the netlink socket and register its fd with *loop*."""
        sock = socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE,
        )
        sock.setblocking(False)
        sock.bind((os.getpid(), RTMGRP_LINK))
        self._sock = sock
        self._loop = loop
        loop.add_reader(sock.fileno(), self._on_readable)
        logger.info("LinkMonitor started (AF_NETLINK / RTMGRP_LINK)")

    def stop(self) -> None:
        """Unregister the fd, cancel in-flight callback tasks, close the socket."""
        if self._sock is not None and self._loop is not None:
            try:
                self._loop.remove_reader(self._sock.fileno())
            except (ValueError, RuntimeError):
                pass
            for task in list(self._tasks):
                if not task.done():
                    task.cancel()
            self._tasks.clear()
            self._sock.close()
            self._sock = None
            self._loop = None

    def _on_readable(self) -> None:
        if self._sock is None or self._loop is None:
            return
        try:
            data = self._sock.recv(65536)
        except OSError as e:
            if e.errno == errno.EAGAIN:
                return
            logger.error("netlink recv failed: %s", e)
            return
        self._dispatch(data)

    def _dispatch(self, data: bytes) -> None:
        """Parse *data* and fire callbacks for UP transitions."""
        if self._loop is None:
            return
        for event in parse_netlink_buffer(data):
            prev = self._state.get(event.ifindex)
            self._state[event.ifindex] = event.up
            # Fire only on a down→up transition.  `prev is None` means
            # this is the initial RTM_NEWLINK burst; if the interface
            # is already up at that point we don't need to re-probe.
            if event.up and prev is False:
                logger.info(
                    "Interface %d transitioned up — triggering re-probe "
                    "(RFC 6762 §8.3 / BCT II.17)",
                    event.ifindex,
                )
                task = self._loop.create_task(
                    self._callback(event.ifindex),
                )
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
