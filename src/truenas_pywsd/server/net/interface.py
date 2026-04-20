"""Resolve interface names to OS indexes and addresses.

Reuses the mDNS pattern but includes both IPv4 and IPv6 addresses
since WSD supports both address families.
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

SIOCGIFADDR = 0x8915


@dataclass(slots=True)
class InterfaceInfo:
    """Resolved interface: name, OS index, and all discovered addresses."""
    name: str
    index: int
    addrs_v4: list[IPv4Address] = field(default_factory=list)
    addrs_v6: list[IPv6Address] = field(default_factory=list)


def resolve_interface(name: str) -> InterfaceInfo | None:
    """Resolve an interface name to its index and all addresses."""
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
    addrs: list[IPv4Address] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ifreq = struct.pack("256s", name.encode("utf-8")[:15])
            result = fcntl.ioctl(s.fileno(), SIOCGIFADDR, ifreq)
            addr = IPv4Address(result[20:24])
            if not addr.is_unspecified:
                addrs.append(addr)
        finally:
            s.close()
    except OSError:
        pass
    return addrs


def _get_v6_addresses(name: str) -> list[IPv6Address]:
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
            if addr.is_link_local and addr not in addrs:
                addrs.append(addr)
        except (ValueError, IndexError):
            continue
    return addrs
