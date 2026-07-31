"""Shared real-dependency fixtures for the mDNS server tests.

Server-level tests need ``PerInterfaceState`` objects whose transports
are genuinely open: ``_register_host_addresses`` gates on
``has_ipv4`` / ``has_ipv6``, and those are true only once the sockets
exist.  Loopback is the one interface a test can rely on being able to
join the mDNS groups on, so the transport binds there while the
``InterfaceInfo`` carries the index and addresses under test.

That split is honest rather than a stand-in, because nothing under
test reads both halves: the transport is consulted only for its
address-family predicates, and ``iface`` only for the index and
addresses that end up in the records.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import replace
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from truenas_pymdns.server.config import DaemonConfig, ServerConfig
from truenas_pymdns.server.net.interface import InterfaceInfo
from truenas_pymdns.server.server import MDNSServer, PerInterfaceState


@pytest.fixture
def make_server():
    """Factory for an ``MDNSServer`` with real service and run dirs."""
    def _make(tmp_path: Path, hostname: str = "nas") -> MDNSServer:
        service_dir = tmp_path / "services.d"
        service_dir.mkdir(exist_ok=True)
        rundir = tmp_path / "rundir"
        rundir.mkdir(exist_ok=True)
        return MDNSServer(DaemonConfig(
            server=ServerConfig(host_name=hostname),
            service_dir=service_dir,
            rundir=rundir,
        ))
    return _make


@pytest.fixture
def started_state():
    """Factory for a ``PerInterfaceState`` with an open transport."""
    def _make(
        loop: asyncio.AbstractEventLoop,
        config: DaemonConfig,
        iface: InterfaceInfo,
    ) -> PerInterfaceState:
        # Bind shared, whatever the config under test says: every
        # fixture transport lands on the one loopback device, and
        # two exclusive (``disallow-other-stacks``) binds on the
        # SAME device conflict.  Production interfaces are distinct
        # devices, where exclusive binds coexist; exclusivity itself
        # is covered by test_multicast_sockets.py.
        shared = replace(
            config,
            server=replace(
                config.server, disallow_other_stacks=False,
            ),
        )
        state = PerInterfaceState(
            InterfaceInfo(
                name="lo",
                index=socket.if_nametoindex("lo"),
                addrs_v4=[IPv4Address("127.0.0.1")],
            ),
            shared,
        )
        loop.run_until_complete(
            state.transport.start(loop, lambda *a, **kw: None),
        )
        state.iface = iface
        return state
    return _make
