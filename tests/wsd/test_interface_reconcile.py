"""WSDServer._reconcile_interfaces: interfaces and addresses changing
under a running server.

The server runs on loopback with real sockets.  All of 127.0.0.0/8 is
local on Linux, so an ``InterfaceInfo`` can carry a second loopback
address without one being configured, and the metadata listener the
server opens on it accepts connections.  The transport sends with
``IP_MULTICAST_LOOP`` off, so the Hello itself is checked from a peer
namespace by the functional tests.
"""
from __future__ import annotations

import asyncio
import socket
from ipaddress import IPv4Interface
from pathlib import Path
from typing import Awaitable, Callable

import pytest

from truenas_pywsd.protocol.constants import WSD_HTTP_PORT
from truenas_pywsd.server.config import DaemonConfig, ServerConfig
from truenas_pywsd.server.net.interface import InterfaceInfo
from truenas_pywsd.server.server import WSDServer

LO = socket.if_nametoindex("lo")
FIRST = IPv4Interface("127.0.0.1/8")
SECOND = IPv4Interface("127.0.0.2/8")


def _lo(*addresses: IPv4Interface) -> dict[int, InterfaceInfo]:
    return {LO: InterfaceInfo(name="lo", index=LO, addrs_v4=list(addresses))}


def _accepts(address: IPv4Interface) -> bool:
    """True if the metadata port on *address* accepts a connection."""
    try:
        with socket.create_connection(
            (str(address.ip), WSD_HTTP_PORT), timeout=1,
        ):
            return True
    except OSError:
        return False


Scenario = Callable[[WSDServer, asyncio.AbstractEventLoop], Awaitable[None]]


def _run(tmp_path: Path, initial: dict[int, InterfaceInfo],
         scenario: Scenario) -> None:
    server = WSDServer(DaemonConfig(
        server=ServerConfig(hostname="nas", interfaces=["lo"]),
        rundir=tmp_path,
    ))

    async def main() -> None:
        loop = asyncio.get_running_loop()
        try:
            await server._apply_interfaces(initial, loop)
            if LO not in server._interfaces:
                pytest.skip("cannot open WSD sockets on loopback")
            await scenario(server, loop)
        finally:
            await server._stop()

    asyncio.run(asyncio.wait_for(main(), timeout=30))


class TestReconcileInterfaces:
    def test_unchanged_addresses_leave_the_interface_alone(self, tmp_path):
        async def scenario(server, loop):
            ifstate = server._interfaces[LO]
            await server._apply_interfaces(_lo(FIRST), loop)
            assert server._interfaces[LO] is ifstate

        _run(tmp_path, _lo(FIRST), scenario)

    def test_added_address_is_served_and_advertised(self, tmp_path):
        """The interface is set up afresh: a metadata listener on the
        new address, and an XAddr for it in what the responder
        sends."""
        async def scenario(server, loop):
            old = server._interfaces[LO]
            assert not await loop.run_in_executor(None, _accepts, SECOND)
            await server._apply_interfaces(_lo(FIRST, SECOND), loop)
            new = server._interfaces[LO]
            assert new is not old
            assert old.transport is not None and not old.transport.is_active
            assert await loop.run_in_executor(None, _accepts, SECOND)
            assert f"http://{SECOND.ip}:{WSD_HTTP_PORT}/" in (
                server._build_xaddrs(new.iface)
            )

        _run(tmp_path, _lo(FIRST), scenario)

    def test_vanished_interface_is_torn_down(self, tmp_path):
        async def scenario(server, loop):
            assert await loop.run_in_executor(None, _accepts, FIRST)
            await server._apply_interfaces({}, loop)
            assert server._interfaces == {}
            assert not await loop.run_in_executor(None, _accepts, FIRST)

        _run(tmp_path, _lo(FIRST), scenario)
