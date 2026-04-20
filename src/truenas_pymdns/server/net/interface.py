"""Resolve interface names to OS indexes and all addresses.

Uses socket.if_nametoindex() for index, SIOCGIFADDR ioctl for the
primary IPv4 address, /proc/net/if_inet6 for all IPv6 addresses.
Called at startup and on SIGHUP — no live monitoring.
"""
from __future__ import annotations

import fcntl
import logging
import socket
import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

logger = logging.getLogger(__name__)

# ioctl constants (Linux)
SIOCGIFADDR = 0x8915


@dataclass(slots=True)
class InterfaceInfo:
    """Resolved interface: name, OS index, and all discovered addresses."""
    name: str
    index: int
    addrs_v4: list[IPv4Address] = field(default_factory=list)
    addrs_v6: list[IPv6Address] = field(default_factory=list)


def resolve_interface(name: str) -> InterfaceInfo | None:
    """Resolve an interface name to its index and all addresses.

    Returns None if the interface doesn't exist.
    """
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        logger.warning("Interface not found: %s", name)
        return None

    info = InterfaceInfo(
        name=name,
        index=index,
        addrs_v4=_get_v4_addresses(name),
        addrs_v6=_get_v6_addresses(name),
    )
    logger.info(
        "Resolved %s: index=%d, v4=%s, v6=%s",
        name, index,
        [str(a) for a in info.addrs_v4],
        [str(a) for a in info.addrs_v6],
    )
    return info


def _get_v4_addresses(name: str) -> list[IPv4Address]:
    """Get the primary IPv4 address for an interface via SIOCGIFADDR."""
    addrs: list[IPv4Address] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # ifreq: 16-byte name + 16-byte sockaddr
            ifreq = struct.pack("256s", name.encode("utf-8")[:15])
            result = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
            # sockaddr_in starts at offset 16: family(2) + port(2) + addr(4)
            addr = IPv4Address(result[20:24])
            if not addr.is_unspecified:
                addrs.append(addr)
        finally:
            s.close()
    except OSError as e:
        logger.debug("SIOCGIFADDR failed for %s: %s", name, e)
    return addrs


def _get_v6_addresses(name: str) -> list[IPv6Address]:
    """Get all IPv6 addresses for an interface from /proc/net/if_inet6."""
    proc_path = Path("/proc/net/if_inet6")
    if not proc_path.exists():
        return []
    try:
        text = proc_path.read_text()
    except OSError:
        return []

    addrs: list[IPv6Address] = []
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        if parts[5] != name:
            continue
        try:
            addr = IPv6Address(bytes.fromhex(parts[0]))
            if addr not in addrs:
                addrs.append(addr)
        except (ValueError, IndexError):
            continue
    return addrs
