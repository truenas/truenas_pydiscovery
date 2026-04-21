"""Resolve interface names to OS indexes and all addresses.

Delegates address enumeration to
``truenas_pydiscovery_utils.netlink_addr.enumerate_addresses``.
``InterfaceInfo`` exposes bare ``IPv4Address`` / ``IPv6Address``
lists — mDNS consumers (A/AAAA record registration,
``IP_MULTICAST_IF`` binding, status JSON) need only the host
address, not the prefix.
"""
from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from truenas_pydiscovery_utils.netlink_addr import enumerate_addresses

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class InterfaceInfo:
    """Resolved interface: name, OS index, and all discovered addresses."""
    name: str
    index: int
    addrs_v4: list[IPv4Address] = field(default_factory=list)
    addrs_v6: list[IPv6Address] = field(default_factory=list)


def resolve_interface(name: str) -> InterfaceInfo | None:
    """Resolve an interface name to its index and all addresses.

    Returns ``None`` if the interface doesn't exist.
    """
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        logger.warning("Interface not found: %s", name)
        return None

    addrs = enumerate_addresses(index)
    info = InterfaceInfo(
        name=name,
        index=index,
        addrs_v4=[a.ip for a in addrs.v4],
        addrs_v6=[a.ip for a in addrs.v6],
    )
    logger.info(
        "Resolved %s: index=%d, v4=%s, v6=%s",
        name, index,
        [str(a) for a in info.addrs_v4],
        [str(a) for a in info.addrs_v6],
    )
    return info
