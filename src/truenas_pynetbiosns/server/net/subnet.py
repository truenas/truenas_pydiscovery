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
"""
from __future__ import annotations

import array
import fcntl
import logging
import socket
import struct
import sys
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

logger = logging.getLogger(__name__)

SIOCGIFCONF = 0x8912
SIOCGIFNETMASK = 0x891B
SIOCGIFBRDADDR = 0x8919

# Linux struct ifreq: 16-byte ifr_name + ifr_ifru union.  Union size is
# dominated by struct ifmap on 64-bit (24 bytes); 16 bytes on 32-bit.
_IFREQ_SIZE = 40 if sys.maxsize > 2**32 else 32


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


def _siocgifconf() -> list[tuple[str, IPv4Address]]:
    """Return every (ifname, IPv4 address) pair the kernel exposes.

    Secondary addresses added via ``ip addr add`` show up as additional
    entries with the same ifname.  IPv4 only — NetBIOS NS has no IPv6.
    """
    max_bytes = 16384
    addr_buf = array.array("B", b"\0" * max_bytes)
    buf_addr, _ = addr_buf.buffer_info()
    ifconf = struct.pack("iL", max_bytes, buf_addr)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        result = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifconf)
    finally:
        s.close()

    used_bytes = struct.unpack("iL", result)[0]
    raw = addr_buf.tobytes()[:used_bytes]

    out: list[tuple[str, IPv4Address]] = []
    for offset in range(0, used_bytes, _IFREQ_SIZE):
        chunk = raw[offset:offset + _IFREQ_SIZE]
        if len(chunk) < 24:
            break
        name = chunk[:16].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        family = struct.unpack("<H", chunk[16:18])[0]
        if family != socket.AF_INET:
            continue
        out.append((name, IPv4Address(chunk[20:24])))
    return out


def _ioctl_ipv4(
    sock: socket.socket, ifname: str, op: int,
) -> IPv4Address | None:
    """Extract the IPv4 address returned by an ifname-keyed ioctl."""
    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
    try:
        result = fcntl.ioctl(sock.fileno(), op, ifreq)
    except OSError:
        return None
    return IPv4Address(result[20:24])


def probe_addresses() -> list[_ProbedAddr]:
    """Enumerate local IPv4 addresses with their netmask and broadcast."""
    pairs = _siocgifconf()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probed: list[_ProbedAddr] = []
        for name, ip in pairs:
            try:
                idx = socket.if_nametoindex(name)
            except OSError:
                continue
            mask = _ioctl_ipv4(s, name, SIOCGIFNETMASK)
            bcast = _ioctl_ipv4(s, name, SIOCGIFBRDADDR)
            if mask is None or bcast is None:
                continue
            probed.append(_ProbedAddr(
                ifname=name, ifindex=idx, ip=ip,
                netmask=mask, broadcast=bcast,
            ))
    finally:
        s.close()
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
