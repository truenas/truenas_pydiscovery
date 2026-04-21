"""Resolve ``[netbiosns] interfaces = `` tokens to NetBIOS subnet entries.

NetBIOS name service is subnet-directed broadcast: a name registered on
one subnet is only reachable by hosts that share that broadcast domain.
A single interface with IPs in two subnets is two broadcast domains.
``NbnsSubnet`` captures one such domain; Samba's ``subnet_record``
(``source3/nmbd/nmbd_subnetdb.c``) is the reference shape.

Accepted token forms (mirroring Samba's ``interpret_interface``):

- Interface name (``eth0``): every local IPv4 address on that interface
  yields one ``NbnsSubnet`` entry.
- Bare IPv4 (``10.0.0.5``): the one local address matching this IP.
- CIDR (``192.168.1.0/24``): every local IPv4 address inside this
  network; user-supplied netmask overrides the kernel's for the entry.

Unresolvable tokens raise ``ValueError``.

Broadcast-address limitation: broadcast is derived from the
address prefix (``IPv4Network.broadcast_address``), which matches
the kernel default for every standard deployment.  Custom
broadcasts configured via ``ip addr add .../24 broadcast <custom>``
are not preserved — the standard all-ones broadcast is used.
"""
from __future__ import annotations

import logging
import socket
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from truenas_pydiscovery_utils.netlink_addr import enumerate_all_addresses

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class NbnsSubnet:
    """One (interface, source IP, netmask, broadcast) broadcast domain."""
    interface_name: str
    interface_index: int
    my_ip: IPv4Address
    netmask: IPv4Address
    broadcast: IPv4Address

    @property
    def network(self) -> IPv4Network:
        return IPv4Network(f"{self.my_ip}/{self.netmask}", strict=False)


@dataclass(slots=True, frozen=True)
class _ProbedAddr:
    ifname: str
    ifindex: int
    ip: IPv4Address
    netmask: IPv4Address
    broadcast: IPv4Address


def probe_addresses() -> list[_ProbedAddr]:
    """Enumerate local IPv4 addresses with their netmask and broadcast.

    Broadcast is derived from the address prefix — see the module
    docstring for the limitation on custom broadcasts.
    """
    probed: list[_ProbedAddr] = []
    for ifindex, addrs in enumerate_all_addresses().items():
        try:
            ifname = socket.if_indextoname(ifindex)
        except OSError:
            continue
        for iface in addrs.v4:
            probed.append(_ProbedAddr(
                ifname=ifname,
                ifindex=ifindex,
                ip=iface.ip,
                netmask=IPv4Address(int(iface.network.netmask)),
                broadcast=iface.network.broadcast_address,
            ))
    return probed


def _classify_token(tok: str) -> tuple[str, str | IPv4Address | IPv4Network]:
    """Return (``"name"|"ip"|"cidr"``, parsed-value) for one token."""
    tok = tok.strip()
    if not tok:
        raise ValueError("empty token")
    if "/" in tok:
        return ("cidr", IPv4Network(tok, strict=False))
    try:
        return ("ip", IPv4Address(tok))
    except ValueError:
        return ("name", tok)


def resolve_subnets(
    tokens: list[str],
    probed: list[_ProbedAddr] | None = None,
) -> list[NbnsSubnet]:
    """Expand config tokens to the full list of ``NbnsSubnet`` entries.

    *probed* is only for injection in tests; production callers leave it
    unset so we query the kernel via ioctl.
    """
    if probed is None:
        probed = probe_addresses()

    resolved: list[NbnsSubnet] = []
    seen: set[tuple[str, IPv4Address]] = set()

    def _add(p: _ProbedAddr, netmask: IPv4Address | None = None) -> None:
        mask = netmask if netmask is not None else p.netmask
        if netmask is not None:
            bcast = IPv4Address(
                int(IPv4Network(f"{p.ip}/{mask}", strict=False)
                    .broadcast_address)
            )
        else:
            bcast = p.broadcast
        key = (p.ifname, p.ip)
        if key in seen:
            return
        seen.add(key)
        resolved.append(NbnsSubnet(
            interface_name=p.ifname,
            interface_index=p.ifindex,
            my_ip=p.ip,
            netmask=mask,
            broadcast=bcast,
        ))

    for tok in tokens:
        kind, value = _classify_token(tok)

        if kind == "name":
            assert isinstance(value, str)
            matches = [p for p in probed if p.ifname == value]
            if not matches:
                raise ValueError(f"interface not found: {value}")
            for p in matches:
                _add(p)

        elif kind == "ip":
            assert isinstance(value, IPv4Address)
            matches = [p for p in probed if p.ip == value]
            if not matches:
                raise ValueError(
                    f"no local interface owns address {value}"
                )
            for p in matches:
                _add(p)

        else:
            assert isinstance(value, IPv4Network)
            matches = [p for p in probed if p.ip in value]
            if not matches:
                raise ValueError(
                    f"no local interface has an address in {value}"
                )
            user_mask = IPv4Address(int(value.netmask))
            for p in matches:
                _add(p, netmask=user_mask)

    return resolved
