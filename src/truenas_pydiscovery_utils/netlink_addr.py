"""Linux netlink address enumeration.

Dumps every IPv4 / IPv6 address the kernel has bound to an
interface by sending one ``RTM_GETADDR`` request with
``NLM_F_REQUEST | NLM_F_DUMP`` and parsing the resulting
``RTM_NEWADDR`` replies.  Tentative, DAD-failed, and deprecated
addresses are excluded — those aren't reachable for a client.

References:
    - ``linux/netlink.h`` — ``nlmsghdr``, ``NLM_F_*``, ``NLMSG_*``.
    - ``linux/rtnetlink.h`` — ``RTM_*``.
    - ``linux/if_addr.h`` — ``ifaddrmsg`` and ``IFA_*``.
    - RFC 3549 (Linux Netlink as IP Services Protocol) §2.
"""
from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv6Interface

logger = logging.getLogger(__name__)

# -- netlink protocol constants (from Linux uapi headers) --------------

# netlink header flags (linux/netlink.h)
NLM_F_REQUEST = 0x01
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH   # 0x300

# netlink message types (linux/netlink.h)
NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3

# rtnetlink message types (linux/rtnetlink.h)
RTM_NEWADDR = 20
RTM_GETADDR = 22

# IFA address flags (linux/if_addr.h) — addresses in these states
# are not reachable, so callers must not bind services to them or
# accept traffic claiming to be from them.
IFA_F_TENTATIVE = 0x40
IFA_F_DADFAILED = 0x08
IFA_F_DEPRECATED = 0x20

# IFA attribute types (linux/if_addr.h)
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_FLAGS = 8

# -- struct layouts ---------------------------------------------------

# struct nlmsghdr: len (u32), type (u16), flags (u16), seq (u32), pid (u32)
_NLMSGHDR = struct.Struct("=IHHII")
# struct ifaddrmsg: family (u8), prefixlen (u8), flags (u8), scope (u8), index (u32)
_IFADDRMSG = struct.Struct("=BBBBI")
# struct rtattr: len (u16), type (u16)
_RTATTR = struct.Struct("=HH")

# Netlink and rtattr payloads are 4-byte aligned.
_ALIGN = 4

# -- module-local tunables ---------------------------------------------

# Address-family byte lengths (packed form, as emitted inside rtattrs).
_IPV4_ADDR_LEN = 4
_IPV6_ADDR_LEN = 16

# Seconds the ``recv`` loop will wait for the kernel to finish the
# dump.  A healthy kernel completes ``RTM_GETADDR`` in milliseconds;
# the generous bound exists so a broken kernel / exotic net-ns
# doesn't hang startup indefinitely.
_NETLINK_DUMP_TIMEOUT_S = 2.0

# Per-``recv`` buffer size.  Netlink messages max out well under this;
# the dump may still span multiple datagrams on very busy hosts, which
# ``_drain_until_done`` handles by concatenating.
_RECV_BUF_SIZE = 65536

# Netlink address ``(portid=0, groups=0)`` — serves both uses on
# this short-lived dump socket:
#   * ``sendto``: portid 0 names the kernel as the destination peer.
#   * ``bind``:   portid 0 asks the kernel to auto-assign our local
#                 portid (``netlink(7)``: "If set to 0, kernel takes
#                 care of assigning it when calling bind(2)").  A
#                 specific portid would collide with any other
#                 netlink socket in this process bound to the same
#                 value (notably ``link_monitor.LinkMonitor``, which
#                 subscribes to ``RTMGRP_LINK``).
# Groups 0 means no multicast subscriptions — we only want the
# one-shot dump, not live ``RTM_NEWADDR`` / ``RTM_DELADDR`` events.
_ANY_ADDR = (0, 0)

# Sequence number stamped on our single request.  Any integer works;
# the kernel echoes it back on each reply so a caller can correlate
# request/response — we don't rely on that here.
_REQUEST_SEQ = 1


def _align(n: int) -> int:
    return (n + _ALIGN - 1) & ~(_ALIGN - 1)


@dataclass(slots=True)
class InterfaceAddresses:
    """All kernel-known addresses on one ifindex, family-split.

    Each element pairs an address with its network prefix via the
    stdlib ``IPv4Interface`` / ``IPv6Interface`` types — one object
    carries both, so there is no possibility of parallel-list drift.

    Emptiness is meaningful: if the netlink dump fails or the
    interface has no usable addresses, both lists are empty.
    Callers should treat that as "no clients reachable on this
    interface" (fail-safe) rather than "respond to everyone".
    """
    v4: list[IPv4Interface] = field(default_factory=list)
    v6: list[IPv6Interface] = field(default_factory=list)


def enumerate_all_addresses() -> dict[int, InterfaceAddresses]:
    """Dump every IPv4/IPv6 address on every interface via netlink.

    Opens a short-lived ``AF_NETLINK / NETLINK_ROUTE`` socket, sends
    one ``RTM_GETADDR`` with ``ifa_family = AF_UNSPEC`` (so both
    families come back in one round-trip), drains responses until
    ``NLMSG_DONE`` or ``NLMSG_ERROR``, and parses each
    ``RTM_NEWADDR``.  The returned dict is keyed by ``ifa_index``.

    Tentative / DAD-failed / deprecated addresses are excluded.

    Any netlink-level failure logs at ERROR and returns an empty
    dict.
    """
    try:
        sock = socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE,
        )
    except OSError as e:
        logger.error("netlink socket open failed: %s", e)
        return {}
    try:
        sock.settimeout(_NETLINK_DUMP_TIMEOUT_S)
        sock.bind(_ANY_ADDR)
        _send_getaddr(sock)
        buf = _drain_until_done(sock)
    except OSError as e:
        logger.error("netlink dump failed: %s", e)
        sock.close()
        return {}
    sock.close()
    return parse_dump_all(buf)


def enumerate_addresses(ifindex: int) -> InterfaceAddresses:
    """Dump every IPv4/IPv6 address bound to *ifindex*.

    Convenience wrapper over ``enumerate_all_addresses`` — issues the
    same system-wide dump and returns the entry for *ifindex*, or an
    empty ``InterfaceAddresses`` if the interface has no reachable
    addresses (or the dump failed).
    """
    return enumerate_all_addresses().get(ifindex, InterfaceAddresses())


def _send_getaddr(sock: socket.socket) -> None:
    """Send one ``RTM_GETADDR`` dump request (both families)."""
    body = _IFADDRMSG.pack(socket.AF_UNSPEC, 0, 0, 0, 0)
    hdr = _NLMSGHDR.pack(
        _NLMSGHDR.size + len(body),
        RTM_GETADDR,
        NLM_F_REQUEST | NLM_F_DUMP,
        _REQUEST_SEQ,
        0,               # nlmsg_pid: 0 ⇒ kernel fills in on reply
    )
    sock.sendto(hdr + body, _ANY_ADDR)


def _drain_until_done(sock: socket.socket) -> bytes:
    """Read netlink replies until ``NLMSG_DONE`` or ``NLMSG_ERROR``.

    The kernel may split the dump across several ``recv`` datagrams;
    we concatenate them and let ``parse_dump`` walk the stream.
    Malformed buffers are tolerated — the walker stops cleanly.
    """
    chunks: list[bytes] = []
    while True:
        data = sock.recv(_RECV_BUF_SIZE)
        chunks.append(data)
        if _terminates(data):
            break
    return b"".join(chunks)


def _terminates(buf: bytes) -> bool:
    """True if *buf* contains ``NLMSG_DONE`` or ``NLMSG_ERROR``."""
    offset = 0
    while offset + _NLMSGHDR.size <= len(buf):
        msg_len, msg_type, _, _, _ = _NLMSGHDR.unpack_from(buf, offset)
        if msg_type in (NLMSG_DONE, NLMSG_ERROR):
            return True
        if msg_len < _NLMSGHDR.size:
            return True   # malformed — don't loop forever
        offset += _align(msg_len)
    return False


def parse_dump_all(buf: bytes) -> dict[int, InterfaceAddresses]:
    """Parse a concatenated ``RTM_NEWADDR`` stream keyed by ifindex.

    For IPv4 prefer ``IFA_LOCAL`` (the local side of a point-to-point
    link); otherwise fall back to ``IFA_ADDRESS``.  For IPv6,
    ``IFA_ADDRESS`` is always the local address.  When ``IFA_FLAGS``
    is present it overrides the 8-bit ``ifa_flags`` with the 32-bit
    variant — needed to test ``IFA_F_DEPRECATED`` reliably on
    kernels ≥ 3.14.

    Exposed as a module-level function so tests can feed it synthetic
    netlink buffers without opening a real socket.
    """
    result: dict[int, InterfaceAddresses] = {}
    offset = 0
    while offset + _NLMSGHDR.size <= len(buf):
        msg_len, msg_type, _, _, _ = _NLMSGHDR.unpack_from(buf, offset)
        if msg_len < _NLMSGHDR.size or offset + msg_len > len(buf):
            return result
        body_start = offset + _NLMSGHDR.size
        body_end = offset + msg_len

        if msg_type == NLMSG_DONE:
            return result
        if msg_type != RTM_NEWADDR:
            offset += _align(msg_len)
            continue
        if body_start + _IFADDRMSG.size > body_end:
            offset += _align(msg_len)
            continue

        fam, prefixlen, flags, _scope, idx = _IFADDRMSG.unpack_from(
            buf, body_start,
        )
        if fam not in (socket.AF_INET, socket.AF_INET6):
            offset += _align(msg_len)
            continue

        addr_bytes, flags32 = _scan_attrs(
            buf, body_start + _IFADDRMSG.size, body_end, fam,
        )
        if flags32 is not None:
            flags = flags32

        if flags & (
            IFA_F_TENTATIVE | IFA_F_DADFAILED | IFA_F_DEPRECATED
        ):
            offset += _align(msg_len)
            continue

        if addr_bytes is not None:
            bucket = result.setdefault(idx, InterfaceAddresses())
            _record(bucket, fam, addr_bytes, prefixlen)

        offset += _align(msg_len)
    return result


def parse_dump(
    buf: bytes, ifindex: int, out: InterfaceAddresses,
) -> None:
    """Parse *buf* and accumulate addresses for *ifindex* into *out*.

    Thin wrapper around ``parse_dump_all`` kept for the per-interface
    consumer (WSD) and for the existing test surface that feeds
    ``parse_dump`` synthetic buffers.  Addresses for other ifindexes
    are silently discarded.
    """
    matched = parse_dump_all(buf).get(ifindex)
    if matched is None:
        return
    out.v4.extend(matched.v4)
    out.v6.extend(matched.v6)


def _scan_attrs(
    buf: bytes, start: int, end: int, family: int,
) -> tuple[bytes | None, int | None]:
    """Walk the ``rtattr`` list after an ``ifaddrmsg``.

    Returns ``(addr_bytes, flags32_or_None)``.  ``addr_bytes`` is the
    chosen address payload — ``IFA_LOCAL`` for IPv4 (preferred),
    ``IFA_ADDRESS`` otherwise.
    """
    expect_len = (
        _IPV4_ADDR_LEN if family == socket.AF_INET else _IPV6_ADDR_LEN
    )
    addr: bytes | None = None
    local: bytes | None = None
    flags32: int | None = None
    i = start
    while i + _RTATTR.size <= end:
        attr_len, attr_type = _RTATTR.unpack_from(buf, i)
        if attr_len < _RTATTR.size or i + attr_len > end:
            break
        payload = buf[i + _RTATTR.size:i + attr_len]
        if attr_type == IFA_LOCAL and family == socket.AF_INET:
            if len(payload) >= _IPV4_ADDR_LEN:
                local = payload[:_IPV4_ADDR_LEN]
        elif attr_type == IFA_ADDRESS and len(payload) >= expect_len:
            addr = payload[:expect_len]
        elif attr_type == IFA_FLAGS and len(payload) >= 4:
            flags32 = struct.unpack_from("=I", payload)[0]
        i += _align(attr_len)
    if family == socket.AF_INET:
        return (local or addr), flags32
    return addr, flags32


def _record(
    out: InterfaceAddresses,
    family: int,
    addr_bytes: bytes,
    prefixlen: int,
) -> None:
    """Append a parsed address (with prefix) to *out*."""
    try:
        if family == socket.AF_INET:
            iface4 = IPv4Interface((addr_bytes, prefixlen))
            if iface4.ip.is_unspecified:
                return
            out.v4.append(iface4)
        else:
            iface6 = IPv6Interface((addr_bytes, prefixlen))
            if iface6.ip.is_unspecified:
                return
            out.v6.append(iface6)
    except ValueError:
        pass
