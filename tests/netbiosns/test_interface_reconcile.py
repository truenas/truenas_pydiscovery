"""NBNSServer._reconcile_interfaces: subnets changing under a running
server, handled per interface as nmbd's ``reload_interfaces`` does.

The subnets live on loopback (all of 127.0.0.0/8 is local on Linux) and
on a dummy interface the test creates, so binding ports 137/138 and
creating the interface need root.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
from ipaddress import IPv4Address
from pathlib import Path
from typing import Awaitable, Callable, Iterator

import pytest

from truenas_pynetbiosns.protocol.constants import DGRAM_PORT, NameType
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.config import DaemonConfig, ServerConfig
from truenas_pynetbiosns.server.net.subnet import NbnsSubnet
from truenas_pynetbiosns.server.server import NBNSServer

_NETMASK = IPv4Address("255.255.255.0")
_SERVER_NAME = NetBIOSName("NAS01", NameType.SERVER)


def _subnet(interface: str, my_ip: str, broadcast: str) -> NbnsSubnet:
    return NbnsSubnet(
        interface_name=interface,
        interface_index=socket.if_nametoindex(interface),
        my_ip=IPv4Address(my_ip),
        netmask=_NETMASK,
        broadcast=IPv4Address(broadcast),
    )


def _can_bind_datagram_port() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", DGRAM_PORT))
    except OSError:
        return False
    finally:
        sock.close()
    return True


needs_root = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("ip") is None
    or not _can_bind_datagram_port(),
    reason="binding ports 137/138 and creating a dummy link need root",
)


@pytest.fixture
def dummy_link() -> Iterator[str]:
    name = f"pdnb{os.getpid() % 10000}"
    for args in (
        ["link", "add", name, "type", "dummy"],
        ["addr", "add", "203.0.113.1/24", "brd", "+", "dev", name],
        ["link", "set", name, "up"],
    ):
        subprocess.run(["ip", *args], check=True)
    try:
        yield name
    finally:
        subprocess.run(["ip", "link", "del", name], capture_output=True)


def _registered(state) -> bool:
    entry = state.name_table.lookup(_SERVER_NAME)
    return entry is not None and entry.registered


Scenario = Callable[[NBNSServer, asyncio.AbstractEventLoop], Awaitable[None]]


def _run(tmp_path: Path, initial: list[NbnsSubnet],
         scenario: Scenario) -> None:
    server = NBNSServer(DaemonConfig(
        server=ServerConfig(netbios_name="NAS01", workgroup="WG"),
        rundir=tmp_path,
    ))

    async def main() -> None:
        loop = asyncio.get_running_loop()
        try:
            await server._apply_subnets(initial, loop)
            await scenario(server, loop)
        finally:
            await server._stop()

    asyncio.run(asyncio.wait_for(main(), timeout=30))


def _states(server: NBNSServer) -> dict[IPv4Address, object]:
    return {state.subnet.my_ip: state for state in server._subnets}


def test_unchanged_subnets_are_left_alone(tmp_path):
    """Nothing is torn down or set up when the resolution is the same."""
    a = _subnet("lo", "127.0.1.2", "127.0.1.255")
    server = NBNSServer(DaemonConfig(
        server=ServerConfig(netbios_name="NAS01", workgroup="WG"),
        rundir=tmp_path,
    ))
    server._resolved_subnets = [a]

    async def scenario() -> None:
        await server._apply_subnets([a], asyncio.get_running_loop())

    asyncio.run(scenario())
    assert server._resolved_subnets == [a]
    assert server._subnets == []


@needs_root
class TestApplySubnets:
    def test_subnet_on_another_interface_leaves_the_rest_alone(
        self, tmp_path, dummy_link,
    ):
        d = _subnet(dummy_link, "203.0.113.1", "203.0.113.255")
        a = _subnet("lo", "127.0.1.2", "127.0.1.255")

        async def scenario(server, loop):
            before = _states(server)[d.my_ip]
            await server._apply_subnets([d, a], loop)
            states = _states(server)
            assert states[d.my_ip] is before
            assert _registered(states[a.my_ip])
            assert set(server._transports) == {dummy_link, "lo"}

        _run(tmp_path, [d], scenario)

    def test_subnet_whose_address_is_gone_is_closed(
        self, tmp_path, dummy_link,
    ):
        d = _subnet(dummy_link, "203.0.113.1", "203.0.113.255")
        a = _subnet("lo", "127.0.1.2", "127.0.1.255")

        async def scenario(server, loop):
            kept = _states(server)[d.my_ip]
            await server._apply_subnets([d], loop)
            assert _states(server) == {d.my_ip: kept}
            assert set(server._transports) == {dummy_link}
            assert server._resolved_subnets == [d]

        _run(tmp_path, [d, a], scenario)

    def test_new_subnet_on_the_same_interface_leaves_the_others(
        self, tmp_path,
    ):
        """As nmbd's ``reload_interfaces`` makes a subnet for a new
        address only: the existing subnet keeps its state, transport
        and names, and only the new one claims."""
        a = _subnet("lo", "127.0.1.2", "127.0.1.255")
        b = _subnet("lo", "127.0.2.2", "127.0.2.255")

        async def scenario(server, loop):
            old = _states(server)[a.my_ip]
            transport = server._transports["lo"]
            await server._apply_subnets([a, b], loop)
            states = _states(server)
            assert states[a.my_ip] is old
            assert _registered(states[a.my_ip])
            assert _registered(states[b.my_ip])
            assert server._transports == {"lo": transport}

        _run(tmp_path, [a], scenario)

    def test_vanished_subnet_on_the_same_interface_leaves_the_others(
        self, tmp_path,
    ):
        """The remaining subnet keeps answering for its names: they are
        not claimed again."""
        a = _subnet("lo", "127.0.1.2", "127.0.1.255")
        b = _subnet("lo", "127.0.2.2", "127.0.2.255")

        async def scenario(server, loop):
            kept = _states(server)[a.my_ip]
            transport = server._transports["lo"]
            await server._apply_subnets([a], loop)
            assert _states(server) == {a.my_ip: kept}
            assert _registered(kept)
            assert server._transports == {"lo": transport}

        _run(tmp_path, [a, b], scenario)

    def test_losing_the_bound_address_sets_the_interface_up_afresh(
        self, tmp_path,
    ):
        """The interface's transport is bound to its first subnet's
        address; when that goes, the remaining subnets are set up on a
        new transport and claim their names again."""
        a = _subnet("lo", "127.0.1.2", "127.0.1.255")
        b = _subnet("lo", "127.0.2.2", "127.0.2.255")

        async def scenario(server, loop):
            old = _states(server)[b.my_ip]
            assert server._transports["lo"].interface_addr == str(a.my_ip)
            await server._apply_subnets([b], loop)
            states = _states(server)
            assert set(states) == {b.my_ip}
            assert states[b.my_ip] is not old
            assert _registered(states[b.my_ip])
            assert server._transports["lo"].interface_addr == str(b.my_ip)

        _run(tmp_path, [a, b], scenario)


@needs_root
class TestReloadKeepsSubnets:
    def test_reload_that_adds_an_address_leaves_the_served_subnet(
        self, tmp_path, dummy_link,
    ):
        """A reload that changes ``interfaces`` keeps serving the
        subnets it still resolves to, as nmbd's SIGHUP runs
        ``reload_interfaces``: their state and names stay, and only
        the new subnet claims."""
        subprocess.run(
            ["ip", "addr", "add", "198.51.100.1/24", "brd", "+",
             "dev", dummy_link],
            check=True,
        )

        def config(*interfaces: str) -> DaemonConfig:
            return DaemonConfig(
                server=ServerConfig(
                    netbios_name="NAS01", workgroup="WG",
                    interfaces=list(interfaces),
                ),
                rundir=tmp_path,
            )

        server = NBNSServer(config("203.0.113.1"))

        async def main() -> None:
            try:
                await server._reload()
                (kept,) = server._subnets
                transport = server._transports[dummy_link]
                server.apply_config(config("203.0.113.1", "198.51.100.1"))
                await server._reload()
                states = _states(server)
                assert states[kept.subnet.my_ip] is kept
                assert _registered(kept)
                assert _registered(states[IPv4Address("198.51.100.1")])
                assert server._transports == {dummy_link: transport}
            finally:
                await server._stop()

        asyncio.run(asyncio.wait_for(main(), timeout=30))
