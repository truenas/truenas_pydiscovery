"""Asyncio WSD transport using UDP multicast on port 3702.

Creates per-interface sockets for both IPv4 (239.255.255.250)
and IPv6 (ff02::c) multicast groups.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Callable

from truenas_pywsd.protocol.constants import (
    WSD_MAX_LEN,
    WSD_MCAST_V4,
    WSD_MCAST_V4_ADDR,
    WSD_MCAST_V6,
    WSD_MCAST_V6_ADDR,
    WSD_UDP_PORT,
)

logger = logging.getLogger(__name__)

# Restrict multicast reception to explicitly joined groups only (Linux)
_IP_MULTICAST_ALL = 49
_IPV6_MULTICAST_ALL = 29

MessageHandler = Callable[[bytes, tuple, str], None]


class WSDTransport:
    """Manages WSD multicast sockets for a single network interface."""

    def __init__(
        self,
        interface_index: int,
        interface_name: str,
        interface_addr_v4: str | None = None,
        *,
        use_ipv4: bool = True,
        use_ipv6: bool = True,
    ) -> None:
        self._ifindex = interface_index
        self._ifname = interface_name
        self._ifaddr_v4 = interface_addr_v4
        self._use_ipv4 = use_ipv4 and interface_addr_v4 is not None
        self._use_ipv6 = use_ipv6
        self._sock_v4: socket.socket | None = None
        self._sock_v6: socket.socket | None = None
        self._handler: MessageHandler | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(
        self, loop: asyncio.AbstractEventLoop, handler: MessageHandler,
    ) -> None:
        self._loop = loop
        self._handler = handler

        if self._use_ipv4 and self._ifaddr_v4:
            try:
                self._sock_v4 = self._create_v4_socket()
                loop.add_reader(
                    self._sock_v4.fileno(), self._on_readable_v4,
                )
                logger.info(
                    "WSD IPv4 transport up on %s (%s)",
                    self._ifname, self._ifaddr_v4,
                )
            except OSError as e:
                logger.error(
                    "Failed to start WSD IPv4 on %s: %s",
                    self._ifname, e,
                )
                if self._sock_v4:
                    self._sock_v4.close()
                    self._sock_v4 = None

        if self._use_ipv6:
            try:
                self._sock_v6 = self._create_v6_socket()
                loop.add_reader(
                    self._sock_v6.fileno(), self._on_readable_v6,
                )
                logger.info("WSD IPv6 transport up on %s", self._ifname)
            except OSError as e:
                logger.error(
                    "Failed to start WSD IPv6 on %s: %s",
                    self._ifname, e,
                )
                if self._sock_v6:
                    self._sock_v6.close()
                    self._sock_v6 = None

    async def stop(self) -> None:
        if self._loop is None:
            return
        for sock in (self._sock_v4, self._sock_v6):
            if sock is not None:
                try:
                    self._loop.remove_reader(sock.fileno())
                except Exception:
                    pass
                sock.close()
        self._sock_v4 = None
        self._sock_v6 = None

    @property
    def is_active(self) -> bool:
        return self._sock_v4 is not None or self._sock_v6 is not None

    # -- Send ---------------------------------------------------------------

    def send_multicast(self, data: bytes) -> None:
        """Send data to both multicast groups."""
        if self._sock_v4 is not None:
            try:
                self._sock_v4.sendto(data, WSD_MCAST_V4_ADDR)
            except OSError as e:
                logger.debug(
                    "IPv4 multicast send failed on %s: %s",
                    self._ifname, e,
                )
        if self._sock_v6 is not None:
            try:
                self._sock_v6.sendto(data, WSD_MCAST_V6_ADDR)
            except OSError as e:
                logger.debug(
                    "IPv6 multicast send failed on %s: %s",
                    self._ifname, e,
                )

    def send_unicast(self, data: bytes, addr: tuple) -> None:
        """Send data to a specific address."""
        if ":" in addr[0]:
            sock = self._sock_v6
        else:
            sock = self._sock_v4
        if sock is not None:
            try:
                sock.sendto(data, addr)
            except OSError as e:
                logger.debug(
                    "Unicast send failed on %s: %s", self._ifname, e,
                )

    # -- Receive callbacks --------------------------------------------------

    def _on_readable_v4(self) -> None:
        """Read one datagram from the IPv4 socket and dispatch to handler."""
        if self._sock_v4 is None or self._handler is None:
            return
        try:
            data, addr = self._sock_v4.recvfrom(WSD_MAX_LEN)
        except OSError:
            return
        self._handler(data, addr, self._ifname)

    def _on_readable_v6(self) -> None:
        """Read one datagram from the IPv6 socket and dispatch to handler."""
        if self._sock_v6 is None or self._handler is None:
            return
        try:
            data, addr = self._sock_v6.recvfrom(WSD_MAX_LEN)
        except OSError:
            return
        self._handler(data, addr, self._ifname)

    # -- Socket creation ----------------------------------------------------

    def _create_v4_socket(self) -> socket.socket:
        """Create an IPv4 UDP socket, join multicast group, set TTL=1."""
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1,
            )
            # Cap unicast replies to one hop.  This is the second layer
            # of the UDP-reflection / amplification defence (first
            # layer: ``_is_on_link`` in ``core/responder.py``).  The
            # attack is: adversary sends a spoofed Probe with
            # ``src = victim`` to our port; we reply
            # ``UNICAST_UDP_REPEAT`` times to ``victim``, using this
            # host as an amplifying reflector against a third party.
            # ``_is_on_link`` refuses off-link sources; TTL=1 is the
            # backstop — even if an attacker forges an on-link source
            # address and slips past the subnet filter, the reply
            # cannot be routed beyond the local link, so no off-link
            # victim is reachable.  Spec hooks: SOAP-over-UDP 1.1 §3.3
            # RECOMMENDS TTL=1 in a multicast-scoping context; we
            # extend the same bound to unicast because WS-Discovery
            # 1.1 is link-scoped by design (§3.1.1 — ``ff02::c`` is
            # link-local, ``239.255.255.250`` is paired with §3.3's
            # TTL=1 recommendation).
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            if self._ifaddr_v4:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(self._ifaddr_v4),
                )
            # Join multicast group
            mreq = (
                socket.inet_aton(WSD_MCAST_V4)
                + socket.inet_aton(self._ifaddr_v4 or "0.0.0.0")
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            try:
                sock.setsockopt(socket.IPPROTO_IP, _IP_MULTICAST_ALL, 0)
            except OSError:
                pass
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self._ifname.encode() + b"\0",
            )
            sock.setblocking(False)
            sock.bind(("", WSD_UDP_PORT))
            return sock
        except BaseException:
            sock.close()
            raise

    def _create_v6_socket(self) -> socket.socket:
        """Create an IPv6 UDP socket, join multicast group, set hop limit=1."""
        sock = socket.socket(
            socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1,
            )
            # Cap unicast replies to one hop — same UDP-reflection
            # defence rationale as the IPv4 socket above.  ``ff02::c``
            # is normatively link-local (WS-Discovery 1.1 §3.1.1), so
            # a legitimate unicast reply never needs to cross a
            # router; an off-link victim therefore can't be reached
            # even if an attacker forges an on-link source.
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1,
            )
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0,
            )
            sock.setsockopt(
                socket.IPPROTO_IPV6,
                socket.IPV6_MULTICAST_IF,
                struct.pack("!I", self._ifindex),
            )
            # Join multicast group
            group_bin = socket.inet_pton(socket.AF_INET6, WSD_MCAST_V6)
            mreq = group_bin + struct.pack("!I", self._ifindex)
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq,
            )
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_MULTICAST_ALL, 0)
            except OSError:
                pass
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self._ifname.encode() + b"\0",
            )
            sock.setblocking(False)
            sock.bind(("", WSD_UDP_PORT))
            return sock
        except BaseException:
            sock.close()
            raise
