"""Asyncio NetBIOS Name Service transport using UDP broadcast.

Creates per-interface sockets for port 137 (RFC 1002 name service)
and optionally port 138 (RFC 1002 datagram/browse service).  Uses
``loop.add_reader()`` for async receive, direct ``sendto()`` for send.

Mirrors Samba 4.23's per-subnet socket layout in
``source3/nmbd/nmbd_subnetdb.c:make_subnet()`` (lines 83-162).
With the default ``nmbd bind explicit broadcast = yes``
(``source3/param/loadparm.c:646``), Samba opens two sockets per
port per interface:

- ``nmb_sock`` bound to the interface's specific unicast IP
  (``(myip, port)``).  Our ``_sock_nmb_unicast`` / ``_sock_dgram_unicast``.
- ``nmb_bcast`` bound to the interface's specific broadcast IP
  (``(bcast_ip, port)``).  Our ``_sock_nmb_bcast`` / ``_sock_dgram_bcast``.

Per-interface isolation comes from the kernel's destination-
address matching at bind time — no device filter needed.  A third
``(0.0.0.0, port)`` catchall is provided at the daemon level by
``NBNSGlobalReceiver`` (mirrors Samba's ``ClientNMB`` /
``ClientDGRAM`` in ``source3/nmbd/nmbd.c``).
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Callable

from truenas_pynetbiosns.protocol.constants import DGRAM_PORT, NBNS_MAX_PACKET_SIZE, NBNS_PORT
from truenas_pynetbiosns.protocol.message import NBNSMessage

logger = logging.getLogger(__name__)

# Handler signature: (message, source_addr, interface_name)
MessageHandler = Callable[[NBNSMessage, tuple[str, int], str], None]

# Raw packet handler for port 138 datagrams (not parsed as NBNS)
RawHandler = Callable[[bytes, tuple[str, int], str], None]


class NBNSTransport:
    """Manages NetBIOS UDP sockets for a single network interface.

    Opens port 137 for name service (query/register/release/defend)
    and port 138 for datagram service (browse announcements).  Per
    Samba 4.23's ``make_subnet`` pattern, each port has a unicast
    socket (bound to the interface IP) and a subnet-broadcast
    socket (bound to the subnet broadcast IP).
    """

    def __init__(
        self,
        interface_name: str,
        interface_addr: str,
        broadcast_addr: str,
        *,
        enable_dgram: bool = True,
    ) -> None:
        self._ifname = interface_name
        self._ifaddr = interface_addr
        self._bcast = broadcast_addr
        self._enable_dgram = enable_dgram
        # Port 137 sockets
        self._sock_nmb_unicast: socket.socket | None = None
        self._sock_nmb_bcast: socket.socket | None = None
        # Port 138 sockets
        self._sock_dgram_unicast: socket.socket | None = None
        self._sock_dgram_bcast: socket.socket | None = None
        self._handler: MessageHandler | None = None
        self._dgram_handler: RawHandler | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(
        self,
        loop: asyncio.AbstractEventLoop,
        handler: MessageHandler,
        dgram_handler: RawHandler | None = None,
    ) -> None:
        """Open sockets and begin receiving."""
        self._loop = loop
        self._handler = handler
        self._dgram_handler = dgram_handler

        # Port 137 — Name Service (unicast + subnet-bcast sockets)
        self._sock_nmb_unicast = self._open_or_log(
            self._ifaddr, NBNS_PORT, "NBNS unicast",
        )
        if self._sock_nmb_unicast is not None:
            loop.add_reader(
                self._sock_nmb_unicast.fileno(),
                self._on_readable_nmb_unicast,
            )
        self._sock_nmb_bcast = self._open_or_log(
            self._bcast, NBNS_PORT, "NBNS subnet-bcast",
        )
        if self._sock_nmb_bcast is not None:
            loop.add_reader(
                self._sock_nmb_bcast.fileno(),
                self._on_readable_nmb_bcast,
            )
        if self._sock_nmb_unicast is not None:
            logger.info(
                "NBNS transport up on %s (unicast %s, bcast %s)",
                self._ifname, self._ifaddr, self._bcast,
            )

        # Port 138 — Datagram Service (unicast + subnet-bcast)
        if self._enable_dgram:
            self._sock_dgram_unicast = self._open_or_log(
                self._ifaddr, DGRAM_PORT, "DGRAM unicast",
            )
            if self._sock_dgram_unicast is not None:
                loop.add_reader(
                    self._sock_dgram_unicast.fileno(),
                    self._on_readable_dgram_unicast,
                )
            self._sock_dgram_bcast = self._open_or_log(
                self._bcast, DGRAM_PORT, "DGRAM subnet-bcast",
            )
            if self._sock_dgram_bcast is not None:
                loop.add_reader(
                    self._sock_dgram_bcast.fileno(),
                    self._on_readable_dgram_bcast,
                )
            if self._sock_dgram_unicast is not None:
                logger.info(
                    "DGRAM transport up on %s", self._ifname,
                )

    async def stop(self) -> None:
        """Close all sockets."""
        if self._loop is None:
            return

        for sock in (
            self._sock_nmb_unicast, self._sock_nmb_bcast,
            self._sock_dgram_unicast, self._sock_dgram_bcast,
        ):
            if sock is not None:
                try:
                    self._loop.remove_reader(sock.fileno())
                except Exception:
                    pass
                sock.close()

        self._sock_nmb_unicast = None
        self._sock_nmb_bcast = None
        self._sock_dgram_unicast = None
        self._sock_dgram_bcast = None

    @property
    def is_active(self) -> bool:
        """True if the name service unicast socket is open."""
        return self._sock_nmb_unicast is not None

    # -- Send ---------------------------------------------------------------
    #
    # All sends go through the unicast socket — its bound source IP
    # matches the interface's address, which is what we want for both
    # unicast replies and subnet-broadcast emissions.  Mirrors Samba
    # 4.23 where ``nmb_sock`` (the unicast socket) is used as the
    # ``send_fd`` for every subnet; see
    # ``source3/nmbd/nmbd_packets.c:send_netbios_packet``.

    def send_broadcast(self, message: NBNSMessage) -> None:
        """Send a name service message to the subnet broadcast address."""
        if self._sock_nmb_unicast is None:
            return
        wire = message.to_wire()
        try:
            self._sock_nmb_unicast.sendto(wire, (self._bcast, NBNS_PORT))
        except OSError as e:
            logger.debug(
                "Broadcast sendto failed on %s: %s", self._ifname, e,
            )

    def send_unicast(
        self, message: NBNSMessage, addr: tuple[str, int],
    ) -> None:
        """Send a name service message to a specific address."""
        if self._sock_nmb_unicast is None:
            return
        wire = message.to_wire()
        try:
            self._sock_nmb_unicast.sendto(wire, addr)
        except OSError as e:
            logger.debug(
                "Unicast sendto failed on %s: %s", self._ifname, e,
            )

    def send_dgram_broadcast(self, data: bytes) -> None:
        """Send raw datagram data to broadcast on port 138."""
        if self._sock_dgram_unicast is None:
            return
        try:
            self._sock_dgram_unicast.sendto(
                data, (self._bcast, DGRAM_PORT),
            )
        except OSError as e:
            logger.debug(
                "DGRAM broadcast failed on %s: %s", self._ifname, e,
            )

    # -- Receive callbacks --------------------------------------------------
    #
    # All four callbacks share the same parse-and-dispatch shape; the
    # split is purely by which socket saw the packet.  On multi-homed
    # hosts where two interfaces happen to share a subnet, both
    # transports' bcast sockets receive a clone of each subnet
    # broadcast — Linux delivers broadcasts to every socket matching
    # the destination address regardless of ``SO_REUSEPORT`` (only
    # unicast is load-balanced).  Each transport correctly processes
    # its copy; the nmbd state machines are idempotent.

    def _on_readable_nmb_unicast(self) -> None:
        self._recv_and_dispatch_nmb(self._sock_nmb_unicast)

    def _on_readable_nmb_bcast(self) -> None:
        self._recv_and_dispatch_nmb(self._sock_nmb_bcast)

    def _on_readable_dgram_unicast(self) -> None:
        self._recv_and_dispatch_dgram(self._sock_dgram_unicast)

    def _on_readable_dgram_bcast(self) -> None:
        self._recv_and_dispatch_dgram(self._sock_dgram_bcast)

    def _recv_and_dispatch_nmb(
        self, sock: socket.socket | None,
    ) -> None:
        if sock is None or self._handler is None:
            return
        try:
            data, addr = sock.recvfrom(NBNS_MAX_PACKET_SIZE)
        except OSError:
            return

        # Skip echoes of our own broadcasts.  Our sends leave port
        # NBNS_PORT with source = our interface IP; a (src_ip,
        # src_port) match against that tuple identifies a
        # loopback echo.  An IP-only check would also drop
        # legitimate queries from co-located clients (e.g.
        # ``nbt-status`` on the same host uses an ephemeral
        # source port).
        if addr[0] == self._ifaddr and addr[1] == NBNS_PORT:
            return

        try:
            msg = NBNSMessage.from_wire(data)
        except (ValueError, IndexError):
            return

        self._handler(msg, addr, self._ifname)

    def _recv_and_dispatch_dgram(
        self, sock: socket.socket | None,
    ) -> None:
        if sock is None or self._dgram_handler is None:
            return
        try:
            data, addr = sock.recvfrom(NBNS_MAX_PACKET_SIZE)
        except OSError:
            return

        # Same (src_ip, src_port) echo check as the NBNS path — see
        # ``_recv_and_dispatch_nmb`` for rationale.
        if addr[0] == self._ifaddr and addr[1] == DGRAM_PORT:
            return

        self._dgram_handler(data, addr, self._ifname)

    # -- Socket creation ----------------------------------------------------

    def _open_or_log(
        self, bind_ip: str, port: int, label: str,
    ) -> socket.socket | None:
        """Open an interface-specific socket, logging failures rather
        than raising — matches Samba 4.23's ``make_subnet`` behaviour
        where a failed bind logs ``DBG_ERR`` and the subnet proceeds
        with whichever sockets opened successfully
        (``source3/nmbd/nmbd_subnetdb.c:110-162``)."""
        try:
            return self._create_specific_socket(bind_ip, port)
        except OSError as e:
            logger.error(
                "Failed to open %s socket on %s (%s:%d): %s",
                label, self._ifname, bind_ip, port, e,
            )
            return None

    def _create_specific_socket(
        self, bind_ip: str, port: int,
    ) -> socket.socket:
        """Create a UDP socket bound to a specific (IP, port) pair.

        Mirrors Samba 4.23 ``open_socket_in_protocol``
        (``source3/lib/util_sock.c:244-300``): ``SO_REUSEADDR`` +
        ``SO_REUSEPORT`` let this coexist with the global
        INADDR_ANY receiver; ``SO_BROADCAST`` lets the unicast
        socket emit subnet-broadcast sends.
        """
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setblocking(False)
            sock.bind((bind_ip, port))
            return sock
        except BaseException:
            sock.close()
            raise
