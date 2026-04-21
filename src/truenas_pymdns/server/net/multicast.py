"""Multicast UDP socket creation and group management."""
from __future__ import annotations

import socket
import struct

from truenas_pymdns.protocol.constants import (
    MDNS_IPV4_GROUP,
    MDNS_IPV6_GROUP,
    MDNS_PORT,
    MDNS_TTL,
)

# IP_RECVTTL is not always exposed by Python's socket module
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)


def create_v4_socket(
    interface_name: str,
    interface_addr: str,
) -> socket.socket:
    """Create an IPv4 multicast UDP socket for mDNS.

    Binds to 0.0.0.0:5353 on the given interface.  Sets socket options
    needed for mDNS: multicast TTL 255, loopback enabled, receive-TTL
    for ancillary data validation, and interface binding.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass

        # RFC 6762 s11: multicast TTL must be 255
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MDNS_TTL)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, MDNS_TTL)
        # Need loopback to detect our own probes for conflict detection
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        # Set outgoing multicast interface
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(interface_addr),
        )
        # Receive TTL in ancillary data for validation
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
        # Receive packet info (which interface packet arrived on)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)  # type: ignore[attr-defined]
        # Bind to specific interface
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            interface_name.encode() + b"\0",
        )

        sock.setblocking(False)
        sock.bind(("", MDNS_PORT))
        return sock
    except BaseException:
        sock.close()
        raise


def create_v6_socket(
    interface_index: int,
    interface_name: str,
) -> socket.socket:
    """Create an IPv6 multicast UDP socket for mDNS.

    Binds to [::]:5353 on the given interface.
    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass

        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        # RFC 6762 s11: multicast hop limit must be 255
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, MDNS_TTL)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, MDNS_TTL)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
        # Set outgoing multicast interface by index.  ``@I`` = native-
        # endian unsigned int: Linux's ``IPV6_MULTICAST_IF`` takes a
        # host-byte-order ``int``.  Using ``!I`` (network byte order)
        # would byte-swap the ifindex on little-endian hosts and the
        # kernel would reject the socket option with ENODEV.
        sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_MULTICAST_IF,
            struct.pack("@I", interface_index),
        )
        # Receive hop limit in ancillary data
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
        # Receive packet info
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        # Bind to specific interface
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            interface_name.encode() + b"\0",
        )

        sock.setblocking(False)
        sock.bind(("", MDNS_PORT))
        return sock
    except BaseException:
        sock.close()
        raise


def join_multicast_v4(
    sock: socket.socket, interface_addr: str,
    group: str = MDNS_IPV4_GROUP,
) -> None:
    """Join an IPv4 multicast group on a specific interface."""
    mreq = socket.inet_aton(group) + socket.inet_aton(interface_addr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def leave_multicast_v4(
    sock: socket.socket, interface_addr: str,
    group: str = MDNS_IPV4_GROUP,
) -> None:
    """Leave an IPv4 multicast group."""
    mreq = socket.inet_aton(group) + socket.inet_aton(interface_addr)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)


def join_multicast_v6(
    sock: socket.socket, interface_index: int,
    group: str = MDNS_IPV6_GROUP,
) -> None:
    """Join an IPv6 multicast group on a specific interface.

    ``@I`` packs the ifindex in native byte order — the
    ``ipv6_mreq::ipv6mr_ifindex`` field is a host-byte-order ``int``.
    Using ``!I`` (network byte order) here silently fails with
    ENODEV on little-endian hosts.
    """
    group_bin = socket.inet_pton(socket.AF_INET6, group)
    mreq = group_bin + struct.pack("@I", interface_index)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)


def leave_multicast_v6(
    sock: socket.socket, interface_index: int,
    group: str = MDNS_IPV6_GROUP,
) -> None:
    """Leave an IPv6 multicast group.  See ``join_multicast_v6`` for
    the byte-order rationale on the ifindex."""
    group_bin = socket.inet_pton(socket.AF_INET6, group)
    mreq = group_bin + struct.pack("@I", interface_index)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq)
