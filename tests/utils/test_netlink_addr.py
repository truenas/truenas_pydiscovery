"""Netlink address enumeration: parser unit tests + loopback round-trip.

The parser tests (``TestParseDump``) feed ``parse_dump`` synthetic
netlink bytes so we don't need ``AF_NETLINK`` privileges or a
specific kernel state.  The live test (``TestEnumerateLoopback``)
runs the real ``enumerate_addresses`` against the ``lo`` interface
— every Linux host has 127.0.0.1/8 and ::1/128 bound there, so it
doubles as a smoke test that our netlink framing matches the kernel.
"""
from __future__ import annotations

import socket
import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

from truenas_pydiscovery_utils.netlink_addr import (
    IFA_ADDRESS,
    IFA_FLAGS,
    IFA_F_DADFAILED,
    IFA_F_DEPRECATED,
    IFA_F_TENTATIVE,
    IFA_LOCAL,
    InterfaceAddresses,
    NLMSG_DONE,
    RTM_NEWADDR,
    enumerate_addresses,
    enumerate_all_addresses,
    parse_dump,
    parse_dump_all,
)


# -- Synthetic-message helpers -----------------------------------------

_NLMSG_ALIGN = 4


def _align(n: int) -> int:
    return (n + _NLMSG_ALIGN - 1) & ~(_NLMSG_ALIGN - 1)


def _pack_rtattr(attr_type: int, payload: bytes) -> bytes:
    attr_len = 4 + len(payload)
    rta = struct.pack("=HH", attr_len, attr_type) + payload
    return rta + b"\0" * (_align(attr_len) - attr_len)


def _pack_newaddr(
    family: int,
    prefixlen: int,
    ifindex: int,
    addr_bytes: bytes,
    *,
    flags8: int = 0,
    flags32: int | None = None,
    use_local_attr: bool = False,
) -> bytes:
    """One ``RTM_NEWADDR`` message: nlmsghdr + ifaddrmsg + rtattrs."""
    body = struct.pack(
        "=BBBBI", family, prefixlen, flags8, 0, ifindex,
    )
    attr_type = IFA_LOCAL if use_local_attr else IFA_ADDRESS
    body += _pack_rtattr(attr_type, addr_bytes)
    if flags32 is not None:
        body += _pack_rtattr(IFA_FLAGS, struct.pack("=I", flags32))
    total_len = 16 + len(body)
    hdr = struct.pack("=IHHII", total_len, RTM_NEWADDR, 2, 0, 0)
    out = hdr + body
    return out + b"\0" * (_align(total_len) - total_len)


def _pack_done() -> bytes:
    return struct.pack("=IHHII", 16, NLMSG_DONE, 2, 0, 0)


# -- Pure parser tests -------------------------------------------------


class TestParseDump:
    def test_empty_buffer_produces_no_addresses(self):
        out = InterfaceAddresses()
        parse_dump(b"", ifindex=1, out=out)
        assert out.v4 == [] and out.v6 == []

    def test_single_ipv4_address(self):
        buf = _pack_newaddr(
            family=socket.AF_INET,
            prefixlen=24,
            ifindex=7,
            addr_bytes=IPv4Address("10.0.0.1").packed,
            use_local_attr=True,
        ) + _pack_done()
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert len(out.v4) == 1
        assert out.v4[0].ip == IPv4Address("10.0.0.1")
        assert out.v4[0].network.prefixlen == 24

    def test_single_ipv6_address(self):
        buf = _pack_newaddr(
            family=socket.AF_INET6,
            prefixlen=64,
            ifindex=7,
            addr_bytes=IPv6Address("2001:db8::1").packed,
        ) + _pack_done()
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert len(out.v6) == 1
        assert out.v6[0].ip == IPv6Address("2001:db8::1")
        assert out.v6[0].network.prefixlen == 64

    def test_wrong_ifindex_is_skipped(self):
        buf = _pack_newaddr(
            family=socket.AF_INET,
            prefixlen=24,
            ifindex=99,
            addr_bytes=IPv4Address("10.0.0.1").packed,
            use_local_attr=True,
        ) + _pack_done()
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert out.v4 == []

    @pytest.mark.parametrize(
        "flag",
        [IFA_F_TENTATIVE, IFA_F_DADFAILED, IFA_F_DEPRECATED],
    )
    def test_tentative_failed_or_deprecated_is_skipped(self, flag):
        buf = _pack_newaddr(
            family=socket.AF_INET,
            prefixlen=24,
            ifindex=7,
            addr_bytes=IPv4Address("10.0.0.1").packed,
            use_local_attr=True,
            flags32=flag,
        ) + _pack_done()
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert out.v4 == []

    def test_ifa_flags_32bit_overrides_8bit(self):
        """``IFA_FLAGS`` attribute replaces the 8-bit ``ifa_flags``
        so kernels ≥ 3.14 can expose flags above 0xff."""
        # 8-bit says "fine", 32-bit says "deprecated" — should skip.
        buf = _pack_newaddr(
            family=socket.AF_INET,
            prefixlen=24,
            ifindex=7,
            addr_bytes=IPv4Address("10.0.0.1").packed,
            use_local_attr=True,
            flags8=0,
            flags32=IFA_F_DEPRECATED,
        ) + _pack_done()
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert out.v4 == []

    def test_multiple_addresses_same_interface(self):
        buf = (
            _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=7,
                addr_bytes=IPv4Address("10.0.0.1").packed,
                use_local_attr=True,
            )
            + _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=7,
                addr_bytes=IPv4Address("192.168.1.1").packed,
                use_local_attr=True,
            )
            + _pack_done()
        )
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert [str(a.ip) for a in out.v4] == [
            "10.0.0.1", "192.168.1.1",
        ]

    def test_nlmsg_done_terminates_early(self):
        """Anything after ``NLMSG_DONE`` must be ignored."""
        buf = (
            _pack_done()
            + _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=7,
                addr_bytes=IPv4Address("10.0.0.1").packed,
                use_local_attr=True,
            )
        )
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert out.v4 == []

    def test_mixed_families(self):
        buf = (
            _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=7,
                addr_bytes=IPv4Address("10.0.0.1").packed,
                use_local_attr=True,
            )
            + _pack_newaddr(
                family=socket.AF_INET6, prefixlen=64, ifindex=7,
                addr_bytes=IPv6Address("2001:db8::1").packed,
            )
            + _pack_done()
        )
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert len(out.v4) == 1 and len(out.v6) == 1

    def test_ipv4_prefers_ifa_local_over_ifa_address(self):
        """On point-to-point links ``IFA_ADDRESS`` is the peer and
        ``IFA_LOCAL`` is the local address; we want the local one."""
        body = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, 7)
        body += _pack_rtattr(
            IFA_ADDRESS, IPv4Address("203.0.113.2").packed,
        )
        body += _pack_rtattr(
            IFA_LOCAL, IPv4Address("10.0.0.1").packed,
        )
        total_len = 16 + len(body)
        hdr = struct.pack(
            "=IHHII", total_len, RTM_NEWADDR, 2, 0, 0,
        )
        buf = hdr + body + _pack_done()
        out = InterfaceAddresses()
        parse_dump(buf, ifindex=7, out=out)
        assert out.v4[0].ip == IPv4Address("10.0.0.1")


# -- Live loopback smoke test ------------------------------------------


class TestEnumerateLoopback:
    def test_loopback_has_127_0_0_1_and_optionally_ipv6(self):
        """``lo`` always exists with 127.0.0.1/8; IPv6 ``::1/128`` is
        present on any host where IPv6 is enabled (the norm).  We
        assert the IPv4 invariant unconditionally and treat IPv6 as
        "if present, must be correct"."""
        try:
            lo_index = socket.if_nametoindex("lo")
        except OSError:
            pytest.skip("no loopback interface (exotic net-ns)")
        addrs = enumerate_addresses(lo_index)
        v4_strs = [str(a.ip) for a in addrs.v4]
        assert "127.0.0.1" in v4_strs
        for iface in addrs.v4:
            if iface.ip == IPv4Address("127.0.0.1"):
                assert iface.network.prefixlen == 8
        if addrs.v6:
            assert any(str(a.ip) == "::1" for a in addrs.v6)


# -- parse_dump_all: system-wide parser --------------------------------


class TestParseDumpAll:
    def test_empty_buffer_produces_empty_dict(self):
        assert parse_dump_all(b"") == {}

    def test_single_interface(self):
        buf = _pack_newaddr(
            family=socket.AF_INET, prefixlen=24, ifindex=7,
            addr_bytes=IPv4Address("10.0.0.1").packed,
            use_local_attr=True,
        ) + _pack_done()
        result = parse_dump_all(buf)
        assert set(result.keys()) == {7}
        assert result[7].v4[0].ip == IPv4Address("10.0.0.1")

    def test_two_interfaces_bucketed_separately(self):
        """One dump containing addresses on two ifindexes must return
        a two-entry dict with addresses routed to the right bucket."""
        buf = (
            _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=2,
                addr_bytes=IPv4Address("10.0.0.1").packed,
                use_local_attr=True,
            )
            + _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=3,
                addr_bytes=IPv4Address("192.168.1.1").packed,
                use_local_attr=True,
            )
            + _pack_newaddr(
                family=socket.AF_INET6, prefixlen=64, ifindex=2,
                addr_bytes=IPv6Address("2001:db8::1").packed,
            )
            + _pack_done()
        )
        result = parse_dump_all(buf)
        assert set(result.keys()) == {2, 3}
        assert [str(a.ip) for a in result[2].v4] == ["10.0.0.1"]
        assert [str(a.ip) for a in result[2].v6] == ["2001:db8::1"]
        assert [str(a.ip) for a in result[3].v4] == ["192.168.1.1"]

    def test_tentative_addresses_skipped_across_all_interfaces(self):
        buf = (
            _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=2,
                addr_bytes=IPv4Address("10.0.0.1").packed,
                use_local_attr=True,
                flags32=IFA_F_TENTATIVE,
            )
            + _pack_newaddr(
                family=socket.AF_INET, prefixlen=24, ifindex=3,
                addr_bytes=IPv4Address("192.168.1.1").packed,
                use_local_attr=True,
            )
            + _pack_done()
        )
        result = parse_dump_all(buf)
        assert set(result.keys()) == {3}


# -- Live enumerate_all_addresses smoke test ---------------------------


class TestEnumerateAllAddresses:
    def test_loopback_visible_in_system_dump(self):
        """``enumerate_all_addresses`` must surface ``lo``'s
        ``127.0.0.1/8`` alongside any other interfaces present on the
        host — one netlink round trip covering everything."""
        try:
            lo_index = socket.if_nametoindex("lo")
        except OSError:
            pytest.skip("no loopback interface (exotic net-ns)")
        everything = enumerate_all_addresses()
        assert lo_index in everything
        lo = everything[lo_index]
        assert any(str(a.ip) == "127.0.0.1" for a in lo.v4)
