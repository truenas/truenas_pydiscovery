"""Daemon-level NetBIOS NS broadcast-catchall receiver.

Mirrors Samba 4.23 nmbd's ``ClientNMB`` / ``ClientDGRAM`` global
sockets, opened once per daemon at startup in
``source3/nmbd/nmbd.c:open_sockets()`` (lines 708-774 of Samba
4.23) and bound to ``0.0.0.0`` on ports 137 and 138:

    /*
     * The sockets opened here will be used to receive broadcast
     * packets *only*.  Interface specific sockets are opened in
     * make_subnet() in namedbsubnet.c.  Thus we bind to the
     * address "0.0.0.0". ...
     */

These sockets catch:

- Limited broadcasts (destination 255.255.255.255) — which no
  specific-IP bind matches.
- Any other packet whose destination address isn't bound by a
  per-interface ``NBNSTransport`` socket (catchall).

Per-packet dispatch is by source IP → subnet network match; the
dispatched handler is the same one used by per-interface
transports, so the rest of the daemon sees a consistent
``(msg, src, ifname)`` interface regardless of which socket the
packet arrived on.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from ipaddress import IPv4Address
from typing import Callable

from truenas_pynetbiosns.protocol.constants import (
    DGRAM_PORT,
    NBNS_MAX_PACKET_SIZE,
    NBNS_PORT,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage

from .subnet import NbnsSubnet

logger = logging.getLogger(__name__)

# Handler signature: (message, source_addr, interface_name)
MessageHandler = Callable[[NBNSMessage, tuple[str, int], str], None]
RawHandler = Callable[[bytes, tuple[str, int], str], None]


class NBNSGlobalReceiver:
    """Global receive-only UDP listeners on ports 137 and 138.

    One ``(0.0.0.0, port)`` socket per port, shared across all
    interfaces.  Matches Samba 4.23's ``ClientNMB`` / ``ClientDGRAM``
    in ``source3/nmbd/nmbd.c:735-744``.
    """

    def __init__(
        self,
        subnets: list[NbnsSubnet],
        handler: MessageHandler,
        dgram_handler: RawHandler | None = None,
    ) -> None:
        self._subnets = subnets
        self._handler = handler
        self._dgram_handler = dgram_handler
        self._sock_nmb: socket.socket | None = None
        self._sock_dgram: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(
        self, loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Open both global sockets and register them with *loop*."""
        self._loop = loop

        try:
            self._sock_nmb = self._create_global_socket(NBNS_PORT)
            loop.add_reader(
                self._sock_nmb.fileno(), self._on_readable_nmb,
            )
            logger.info(
                "NBNS global receiver up on 0.0.0.0:%d", NBNS_PORT,
            )
        except OSError as e:
            logger.error(
                "Failed to open NBNS global socket: %s", e,
            )
            if self._sock_nmb:
                self._sock_nmb.close()
                self._sock_nmb = None

        if self._dgram_handler is not None:
            try:
                self._sock_dgram = self._create_global_socket(DGRAM_PORT)
                loop.add_reader(
                    self._sock_dgram.fileno(),
                    self._on_readable_dgram,
                )
                logger.info(
                    "DGRAM global receiver up on 0.0.0.0:%d",
                    DGRAM_PORT,
                )
            except OSError as e:
                logger.error(
                    "Failed to open DGRAM global socket: %s", e,
                )
                if self._sock_dgram:
                    self._sock_dgram.close()
                    self._sock_dgram = None

    async def stop(self) -> None:
        """Unregister readers and close both sockets."""
        if self._loop is None:
            return
        for sock in (self._sock_nmb, self._sock_dgram):
            if sock is not None:
                try:
                    self._loop.remove_reader(sock.fileno())
                except Exception:
                    pass
                sock.close()
        self._sock_nmb = None
        self._sock_dgram = None

    def update_subnets(self, subnets: list[NbnsSubnet]) -> None:
        """Refresh the subnet list used for source-IP dispatch
        (called after SIGHUP reload)."""
        self._subnets = subnets

    # -- Receive callbacks --------------------------------------------------

    def _on_readable_nmb(self) -> None:
        """Port 137 (name service) read callback."""
        if self._sock_nmb is None:
            return
        try:
            data, addr = self._sock_nmb.recvfrom(NBNS_MAX_PACKET_SIZE)
        except OSError:
            return

        ifname = self._ifname_for_source(addr[0])
        if ifname is None:
            return

        # Skip echoes of our own broadcasts.  Our daemon sends
        # from (my_ip, NBNS_PORT); matching both IP and port
        # identifies a loopback echo without also dropping
        # packets from co-located clients (e.g. ``nbt-status``
        # on the same host uses an ephemeral source port).
        if self._is_own_echo(addr[0], addr[1], NBNS_PORT):
            return

        try:
            msg = NBNSMessage.from_wire(data)
        except (ValueError, IndexError):
            return

        self._handler(msg, addr, ifname)

    def _on_readable_dgram(self) -> None:
        """Port 138 (datagram / browse) read callback."""
        if self._sock_dgram is None or self._dgram_handler is None:
            return
        try:
            data, addr = self._sock_dgram.recvfrom(NBNS_MAX_PACKET_SIZE)
        except OSError:
            return

        ifname = self._ifname_for_source(addr[0])
        if ifname is None:
            return
        if self._is_own_echo(addr[0], addr[1], DGRAM_PORT):
            return

        self._dgram_handler(data, addr, ifname)

    # -- Source-IP dispatch -------------------------------------------------

    def _ifname_for_source(self, src_ip_str: str) -> str | None:
        """Match a source IP to a configured subnet's interface name.

        Linear scan of ``self._subnets`` — N is small (typically
        1-4 interfaces).  Cache a flattened mapping later if this
        ever shows up in a profile; for now, clarity wins.
        """
        try:
            src_ip = IPv4Address(src_ip_str)
        except ValueError:
            return None
        for subnet in self._subnets:
            if src_ip in subnet.network:
                return subnet.interface_name
        return None

    def _is_own_echo(
        self, src_ip_str: str, src_port: int, listen_port: int,
    ) -> bool:
        """True if ``(src_ip, src_port)`` matches any interface's
        ``(my_ip, listen_port)`` — i.e. the packet is a loopback
        echo of something our own daemon sent."""
        if src_port != listen_port:
            return False
        try:
            src_ip = IPv4Address(src_ip_str)
        except ValueError:
            return False
        return any(
            subnet.my_ip == src_ip for subnet in self._subnets
        )

    # -- Socket creation ----------------------------------------------------

    def _create_global_socket(self, port: int) -> socket.socket:
        """Create an INADDR_ANY UDP socket for catchall receive.

        Mirrors Samba 4.23 ``source3/lib/util_sock.c:244-300``
        (``open_socket_in_protocol``): ``SO_REUSEADDR`` and
        ``SO_REUSEPORT`` only.  We additionally set
        ``SO_BROADCAST`` because ``nmbd.c:756`` does
        ``set_socket_options(ClientNMB, "SO_BROADCAST")`` and
        the semantic equivalent in 4.23 is still the same flag.
        """
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEPORT, 1,
                )
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setblocking(False)
            sock.bind(("", port))
            return sock
        except BaseException:
            sock.close()
            raise
