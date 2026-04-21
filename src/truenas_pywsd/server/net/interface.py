"""Resolve interface names to OS indexes and addresses.

Enumerates every IPv4 and IPv6 address on a named interface via
``truenas_pydiscovery_utils.netlink_addr.enumerate_addresses``.
Each address is paired with its network prefix in a single
``IPv4Interface`` / ``IPv6Interface`` object, so the on-link
source filter in ``core/responder.py`` and the ``XAddrs`` URL
builder in ``server.py`` always see the full list of reachable
subnets on each interface.

The filter drops Probe/Resolve datagrams whose claimed source IP
isn't reachable on the receive interface.  The purpose is to
remove this daemon from the pool of UDP reflectors usable for
cross-subnet amplification attacks: without the filter, a spoofed
Probe with ``src = victim`` from off-link would elicit
``UNICAST_UDP_REPEAT`` replies aimed at the victim.  Spec hooks:
WS-Discovery 1.1 §3.1.1 (link-local multicast scope) and §8.1
(Target Service MAY decline Probes from a different administrative
domain).
"""
from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv6Interface

from truenas_pydiscovery_utils.netlink_addr import enumerate_addresses

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class InterfaceInfo:
    """Resolved interface: name, OS index, and all reachable addresses."""
    name: str
    index: int
    addrs_v4: list[IPv4Interface] = field(default_factory=list)
    addrs_v6: list[IPv6Interface] = field(default_factory=list)


def resolve_interface(name: str) -> InterfaceInfo | None:
    """Resolve an interface name to its index + full address list."""
    try:
        index = socket.if_nametoindex(name)
    except OSError:
        logger.warning("Interface not found: %s", name)
        return None

    addrs = enumerate_addresses(index)
    info = InterfaceInfo(
        name=name,
        index=index,
        addrs_v4=addrs.v4,
        addrs_v6=addrs.v6,
    )
    logger.info(
        "Resolved %s: index=%d, v4=%s, v6=%s",
        name, index,
        [a.with_prefixlen for a in info.addrs_v4],
        [a.with_prefixlen for a in info.addrs_v6],
    )
    return info
