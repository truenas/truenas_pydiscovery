"""Tests for ``[netbiosns] interfaces = `` token resolution."""
from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from truenas_pynetbiosns.server.net.subnet import (
    NbnsSubnet,
    _ProbedAddr,
    resolve_subnets,
)


def _p(
    ifname: str, ip: str, netmask: str = "255.255.255.0",
    broadcast: str | None = None, ifindex: int = 1,
) -> _ProbedAddr:
    if broadcast is None:
        # Derive a plausible default broadcast from ip + mask
        net_int = int(IPv4Address(ip)) & int(IPv4Address(netmask))
        host_int = (~int(IPv4Address(netmask))) & 0xFFFFFFFF
        broadcast = str(IPv4Address(net_int | host_int))
    return _ProbedAddr(
        ifname=ifname, ifindex=ifindex,
        ip=IPv4Address(ip),
        netmask=IPv4Address(netmask),
        broadcast=IPv4Address(broadcast),
    )


class TestInterfaceName:
    def test_single_address(self):
        probed = [_p("eth0", "10.0.0.5")]
        subnets = resolve_subnets(["eth0"], probed)
        assert len(subnets) == 1
        assert subnets[0].interface_name == "eth0"
        assert subnets[0].my_ip == IPv4Address("10.0.0.5")
        assert subnets[0].broadcast == IPv4Address("10.0.0.255")

    def test_multiple_addresses_expands_to_multiple_subnets(self):
        probed = [
            _p("eth0", "10.0.0.5", "255.255.255.0"),
            _p("eth0", "192.168.1.5", "255.255.255.0"),
        ]
        subnets = resolve_subnets(["eth0"], probed)
        assert len(subnets) == 2
        ips = {str(s.my_ip) for s in subnets}
        assert ips == {"10.0.0.5", "192.168.1.5"}

    def test_unknown_name_raises(self):
        probed = [_p("eth0", "10.0.0.5")]
        with pytest.raises(ValueError, match="interface not found"):
            resolve_subnets(["eth9"], probed)


class TestBareIP:
    def test_match_by_address(self):
        probed = [
            _p("eth0", "10.0.0.5"),
            _p("eth1", "192.168.1.5"),
        ]
        subnets = resolve_subnets(["10.0.0.5"], probed)
        assert len(subnets) == 1
        assert subnets[0].interface_name == "eth0"

    def test_unowned_ip_raises(self):
        probed = [_p("eth0", "10.0.0.5")]
        with pytest.raises(
            ValueError, match="no local interface owns"
        ):
            resolve_subnets(["10.99.99.99"], probed)


class TestCIDR:
    def test_match_expands_all_addrs_in_range(self):
        probed = [
            _p("eth0", "10.0.0.5", "255.255.255.0"),
            _p("eth0", "10.0.0.6", "255.255.255.0"),
            _p("eth1", "192.168.1.5", "255.255.255.0"),
        ]
        subnets = resolve_subnets(["10.0.0.0/24"], probed)
        assert len(subnets) == 2
        assert all(s.interface_name == "eth0" for s in subnets)

    def test_user_supplied_netmask_wins(self):
        # kernel says /24; user config says /16 → we honour the user.
        probed = [_p("eth0", "10.0.0.5", "255.255.255.0")]
        subnets = resolve_subnets(["10.0.0.0/16"], probed)
        assert len(subnets) == 1
        assert subnets[0].netmask == IPv4Address("255.255.0.0")
        assert subnets[0].broadcast == IPv4Address("10.0.255.255")

    def test_cidr_with_no_local_match_raises(self):
        probed = [_p("eth0", "10.0.0.5")]
        with pytest.raises(
            ValueError, match="no local interface has an address in"
        ):
            resolve_subnets(["192.168.99.0/24"], probed)


class TestMixedAndDedup:
    def test_mixed_tokens(self):
        probed = [
            _p("eth0", "10.0.0.5"),
            _p("eth1", "192.168.1.5"),
        ]
        subnets = resolve_subnets(
            ["eth0", "192.168.1.5"], probed,
        )
        assert len(subnets) == 2
        ips = {str(s.my_ip) for s in subnets}
        assert ips == {"10.0.0.5", "192.168.1.5"}

    def test_duplicate_tokens_collapse(self):
        probed = [_p("eth0", "10.0.0.5")]
        # name, then bare IP on the same entry, then CIDR covering it.
        subnets = resolve_subnets(
            ["eth0", "10.0.0.5", "10.0.0.0/24"], probed,
        )
        assert len(subnets) == 1

    def test_empty_token_raises(self):
        probed = [_p("eth0", "10.0.0.5")]
        with pytest.raises(ValueError, match="empty token"):
            resolve_subnets([""], probed)


class TestSubnetShape:
    def test_network_property(self):
        s = NbnsSubnet(
            interface_name="eth0", interface_index=1,
            my_ip=IPv4Address("10.0.0.5"),
            netmask=IPv4Address("255.255.255.0"),
            broadcast=IPv4Address("10.0.0.255"),
        )
        assert str(s.network) == "10.0.0.0/24"
