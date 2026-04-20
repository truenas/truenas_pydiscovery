"""Asyncio mDNS transport using add_reader + recvmsg for TTL validation."""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Callable

from truenas_pymdns.protocol.constants import (
    CMSG_BUFSIZE,
    MDNS_IPV4_ADDR,
    MDNS_IPV6_ADDR,
    MDNS_PORT,
    MDNS_RECV_BUFSIZE,
    MDNS_TTL,
)
from truenas_pymdns.protocol.message import MDNSMessage
from .multicast import (
    IP_RECVTTL,
    create_v4_socket,
    create_v6_socket,
    join_multicast_v4,
    join_multicast_v6,
    leave_multicast_v4,
    leave_multicast_v6,
)

logger = logging.getLogger(__name__)


# Message handler signature: (message, source_addr, interface_index)
MessageHandler = Callable[[MDNSMessage, tuple, int], None]


class MDNSTransport:
    """Manages mDNS multicast sockets for a single network interface.

    Uses ``loop.add_reader()`` with ``sock.recvmsg()`` instead of
    ``create_datagram_endpoint()`` because we need ancillary data
    (IP_RECVTTL / IPV6_RECVHOPLIMIT) for TTL==255 validation
    per RFC 6762 Section 11.
    """

    def __init__(
        self,
        interface_index: int,
        interface_name: str,
        interface_addr_v4: str | None = None,
        use_ipv4: bool = True,
        use_ipv6: bool = True,
    ):
        self._ifindex = interface_index
        self._ifname = interface_name
        self._ifaddr_v4 = interface_addr_v4
        self._use_ipv4 = use_ipv4 and interface_addr_v4 is not None
        self._use_ipv6 = use_ipv6
        self._sock_v4: socket.socket | None = None
        self._sock_v6: socket.socket | None = None
        self._handler: MessageHandler | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._joined_v4 = False
        self._joined_v6 = False

    async def start(
        self, loop: asyncio.AbstractEventLoop, handler: MessageHandler
    ) -> None:
        """Open multicast sockets, join mDNS groups, and begin receiving."""
        self._loop = loop
        self._handler = handler

        if self._use_ipv4 and self._ifaddr_v4:
            try:
                self._sock_v4 = create_v4_socket(self._ifname, self._ifaddr_v4)
                join_multicast_v4(self._sock_v4, self._ifaddr_v4)
                self._joined_v4 = True
                loop.add_reader(self._sock_v4.fileno(), self._on_readable_v4)
                logger.info(
                    "mDNS IPv4 transport up on %s (%s)",
                    self._ifname, self._ifaddr_v4,
                )
            except OSError as e:
                logger.error("Failed to start IPv4 on %s: %s", self._ifname, e)
                if self._sock_v4:
                    self._sock_v4.close()
                    self._sock_v4 = None

        if self._use_ipv6:
            try:
                self._sock_v6 = create_v6_socket(self._ifindex, self._ifname)
                join_multicast_v6(self._sock_v6, self._ifindex)
                self._joined_v6 = True
                loop.add_reader(self._sock_v6.fileno(), self._on_readable_v6)
                logger.info("mDNS IPv6 transport up on %s", self._ifname)
            except OSError as e:
                logger.error("Failed to start IPv6 on %s: %s", self._ifname, e)
                if self._sock_v6:
                    self._sock_v6.close()
                    self._sock_v6 = None

    async def stop(self) -> None:
        """Leave multicast groups and close all sockets."""
        if self._loop is None:
            return

        if self._sock_v4 is not None:
            try:
                self._loop.remove_reader(self._sock_v4.fileno())
            except Exception:
                pass
            if self._joined_v4 and self._ifaddr_v4:
                try:
                    leave_multicast_v4(self._sock_v4, self._ifaddr_v4)
                except OSError:
                    pass
            self._sock_v4.close()
            self._sock_v4 = None

        if self._sock_v6 is not None:
            try:
                self._loop.remove_reader(self._sock_v6.fileno())
            except Exception:
                pass
            if self._joined_v6:
                try:
                    leave_multicast_v6(self._sock_v6, self._ifindex)
                except OSError:
                    pass
            self._sock_v6.close()
            self._sock_v6 = None

    @property
    def is_active(self) -> bool:
        """True if at least one socket (v4 or v6) is open."""
        return self._sock_v4 is not None or self._sock_v6 is not None

    @property
    def has_ipv4(self) -> bool:
        """True if the IPv4 socket is open."""
        return self._sock_v4 is not None

    @property
    def has_ipv6(self) -> bool:
        """True if the IPv6 socket is open."""
        return self._sock_v6 is not None

    def send_message(
        self, message: MDNSMessage, unicast_addr: tuple | None = None
    ) -> None:
        """Send a message via multicast, or unicast if *unicast_addr* is given."""
        wire = message.to_wire()

        if unicast_addr is not None:
            # Unicast response — send on whichever socket matches the address family
            if ":" in unicast_addr[0] and self._sock_v6:
                self._sock_v6.sendto(wire, unicast_addr)
            elif self._sock_v4:
                self._sock_v4.sendto(wire, unicast_addr)
            return

        # Multicast — send on both v4 and v6
        if self._sock_v4 is not None:
            try:
                self._sock_v4.sendto(wire, MDNS_IPV4_ADDR)
            except OSError as e:
                logger.debug("IPv4 sendto failed on %s: %s", self._ifname, e)

        if self._sock_v6 is not None:
            try:
                self._sock_v6.sendto(wire, MDNS_IPV6_ADDR)
            except OSError as e:
                logger.debug("IPv6 sendto failed on %s: %s", self._ifname, e)

    # -- Receive callbacks ---------------------------------------------------

    def _on_readable_v4(self) -> None:
        self._recv_from_sock(self._sock_v4, socket.AF_INET)

    def _on_readable_v6(self) -> None:
        self._recv_from_sock(self._sock_v6, socket.AF_INET6)

    def _recv_from_sock(
        self, sock: socket.socket | None, family: int
    ) -> None:
        if sock is None:
            return
        try:
            data, ancdata, _flags, addr = sock.recvmsg(MDNS_RECV_BUFSIZE, CMSG_BUFSIZE)
        except (OSError, BlockingIOError):
            return

        # RFC 6762 s11: validate TTL == 255 from ancillary data
        ttl = self._extract_ttl(ancdata, family)
        if ttl is None:
            logger.debug(
                "No TTL in ancillary data from %s — cannot validate",
                addr,
            )
        elif ttl != MDNS_TTL:
            logger.debug(
                "Dropping packet with TTL %d from %s (expected 255)",
                ttl, addr,
            )
            return

        try:
            message = MDNSMessage.from_wire(data)
        except (ValueError, IndexError) as e:
            logger.debug("Failed to parse mDNS packet from %s: %s", addr, e)
            return

        # RFC 6762 s6: responses MUST have source port 5353.
        # Non-5353 source port on a query = legacy unicast query (s6.7).
        source_port = addr[1]
        if message.is_response and source_port != MDNS_PORT:
            logger.debug(
                "Dropping response from non-5353 port %d (%s)",
                source_port, addr,
            )
            return

        if self._handler:
            self._handler(message, addr, self._ifindex)

    @staticmethod
    def _extract_ttl(
        ancdata: list[tuple[int, int, bytes]], family: int
    ) -> int | None:
        """Extract the TTL/hop-limit from ancillary data."""
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if family == socket.AF_INET:
                # Linux: IPPROTO_IP, IP_RECVTTL (12), 4-byte int
                if cmsg_level == socket.IPPROTO_IP and cmsg_type == IP_RECVTTL:
                    if len(cmsg_data) >= 4:
                        return struct.unpack("=i", cmsg_data[:4])[0]
                    elif len(cmsg_data) >= 1:
                        return cmsg_data[0]
            elif family == socket.AF_INET6:
                if (
                    cmsg_level == socket.IPPROTO_IPV6
                    and cmsg_type == socket.IPV6_HOPLIMIT
                ):
                    if len(cmsg_data) >= 4:
                        return struct.unpack("=i", cmsg_data[:4])[0]
        return None
