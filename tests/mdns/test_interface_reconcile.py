"""MDNSServer._reconcile_interfaces: interfaces and addresses changing
under a running server.

The server runs on loopback with real transports, and a socket joined
to the mDNS group on loopback sees what it multicasts.  All of
127.0.0.0/8 is local on Linux, so an ``InterfaceInfo`` can carry a
second loopback address without one being configured.
"""
from __future__ import annotations

import asyncio
import socket
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Awaitable, Callable

import pytest

from truenas_pymdns.protocol.constants import EntryGroupState, QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    AAAARecordData,
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    SRVRecordData,
)
from truenas_pymdns.server.config import DaemonConfig, ServerConfig
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.net.interface import InterfaceInfo
from truenas_pymdns.server.server import MDNSServer

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
LO = socket.if_nametoindex("lo")
FIRST = IPv4Address("127.0.0.1")
SECOND = IPv4Address("127.0.0.2")
LINK_LOCAL = IPv6Address("fe80::10")
ROUTABLE = IPv6Address("2001:db8::10")
HOST = "nas.local"


def _lo(*addresses: IPv4Address,
        v6: tuple[IPv6Address, ...] = ()) -> dict[int, InterfaceInfo]:
    return {LO: InterfaceInfo(
        name="lo", index=LO, addrs_v4=list(addresses), addrs_v6=list(v6),
    )}


def _server(tmp_path: Path) -> MDNSServer:
    service_dir = tmp_path / "services.d"
    service_dir.mkdir()
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    # Shared bind, so the listener below can sit on 5353 beside it.
    return MDNSServer(DaemonConfig(
        server=ServerConfig(
            host_name="nas", interfaces=["lo"], disallow_other_stacks=False,
        ),
        service_dir=service_dir,
        rundir=rundir,
    ))


class _Listener:
    """A socket joined to the mDNS group on loopback."""

    def __init__(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", MDNS_PORT))
        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(MDNS_GROUP) + socket.inet_aton(str(FIRST)),
        )
        sock.setblocking(False)
        self._sock = sock

    def drain(self) -> list[MDNSMessage]:
        """Every message received since the last call."""
        messages = []
        while True:
            try:
                data = self._sock.recv(9000)
            except BlockingIOError:
                return messages
            messages.append(MDNSMessage.from_wire(data))

    def close(self) -> None:
        self._sock.close()


def _answers(messages: list[MDNSMessage]) -> list[MDNSRecord]:
    return [rr for message in messages if message.is_response
            for rr in message.answers]


def _host_addresses(server: MDNSServer) -> set[IPv4Address]:
    return {
        record.data.address
        for group in server._host_groups
        for record in group.records
        if isinstance(record.data, ARecordData)
    }


Scenario = Callable[[MDNSServer, _Listener, asyncio.AbstractEventLoop],
                    Awaitable[None]]


def _run(tmp_path: Path, initial: dict[int, InterfaceInfo],
         scenario: Scenario) -> None:
    """Start the server on *initial*, then run *scenario* against it."""
    server = _server(tmp_path)
    listener = _Listener()

    async def main() -> None:
        loop = asyncio.get_running_loop()
        try:
            await server._apply_interfaces(initial, loop)
            if initial and LO not in server._interfaces:
                pytest.skip("cannot open mDNS sockets on loopback")
            await scenario(server, listener, loop)
        finally:
            await server._stop()

    try:
        asyncio.run(asyncio.wait_for(main(), timeout=30))
    finally:
        listener.close()


class TestReconcileInterfaces:
    def test_interface_that_appears_is_set_up_and_announced(self, tmp_path):
        async def scenario(server, listener, loop):
            await server._apply_interfaces(_lo(FIRST), loop)
            if LO not in server._interfaces:
                pytest.skip("cannot open mDNS sockets on loopback")
            (host,) = server._host_groups
            assert host.state == EntryGroupState.ESTABLISHED
            assert _host_addresses(server) == {FIRST}
            await asyncio.sleep(0.3)
            assert any(
                rr.key.name == HOST and rr.data == ARecordData(FIRST)
                and rr.ttl > 0
                for rr in _answers(listener.drain())
            )

        _run(tmp_path, {}, scenario)

    def test_unchanged_addresses_leave_the_interface_alone(self, tmp_path):
        async def scenario(server, listener, loop):
            ifstate = server._interfaces[LO]
            (host,) = server._host_groups
            await server._apply_interfaces(_lo(FIRST), loop)
            assert server._interfaces[LO] is ifstate
            assert server._host_groups == [host]

        _run(tmp_path, _lo(FIRST), scenario)

    def test_added_address_is_published_on_a_new_transport(self, tmp_path):
        async def scenario(server, listener, loop):
            old = server._interfaces[LO]
            listener.drain()
            await server._apply_interfaces(_lo(FIRST, SECOND), loop)
            assert server._interfaces[LO] is not old
            assert _host_addresses(server) == {FIRST, SECOND}
            await asyncio.sleep(0.3)
            assert any(
                rr.key.name == HOST and rr.data == ARecordData(SECOND)
                and rr.ttl > 0
                for rr in _answers(listener.drain())
            )

        _run(tmp_path, _lo(FIRST), scenario)

    def test_lost_address_is_withdrawn_with_a_goodbye(self, tmp_path):
        """RFC 6762 §10.1: the A record and the reverse PTR of the
        address that went away are sent with TTL 0; the address that
        stays is not."""
        async def scenario(server, listener, loop):
            await asyncio.sleep(0.3)
            listener.drain()
            await server._apply_interfaces(_lo(FIRST), loop)
            goodbyes = [
                rr for rr in _answers(listener.drain()) if rr.ttl == 0
            ]
            assert {(rr.key.name, rr.key.rtype) for rr in goodbyes} == {
                (HOST, QType.A),
                (SECOND.reverse_pointer, QType.PTR),
            }
            assert all(
                rr.data == ARecordData(SECOND)
                for rr in goodbyes if rr.key.rtype == QType.A
            )
            assert _host_addresses(server) == {FIRST}

        _run(tmp_path, _lo(FIRST, SECOND), scenario)

    def test_vanished_interface_is_torn_down(self, tmp_path):
        async def scenario(server, listener, loop):
            await server._apply_interfaces({}, loop)
            assert server._interfaces == {}
            assert server._host_groups == []
            assert server._registry.get_all_records(LO) == []

        _run(tmp_path, _lo(FIRST), scenario)

    def test_service_on_a_changed_interface_is_announced_again(
        self, tmp_path,
    ):
        """As when a link comes up, every group published on the
        interface is probed and announced again."""
        srv = MDNSRecord(
            key=MDNSRecordKey("NAS._smb._tcp.local", QType.SRV),
            ttl=120,
            data=SRVRecordData(0, 0, 445, HOST),
            cache_flush=True,
        )

        async def scenario(server, listener, loop):
            service = EntryGroup()
            service.add_record(srv)
            server._entry_groups.append(service)
            await server._probe_and_announce(service)
            assert service.state == EntryGroupState.ESTABLISHED
            await asyncio.sleep(0.3)
            listener.drain()
            await server._apply_interfaces(_lo(FIRST, SECOND), loop)
            assert service.state == EntryGroupState.ESTABLISHED
            await asyncio.sleep(0.3)
            assert any(
                rr.key == srv.key and rr.ttl > 0
                for rr in _answers(listener.drain())
            )

        _run(tmp_path, _lo(FIRST), scenario)

    def test_link_local_is_withdrawn_when_a_routable_address_arrives(
        self, tmp_path,
    ):
        """The link-local address stays on the interface but is no
        longer published (avahi's relevance rule), so it is withdrawn
        with a goodbye, as avahi does, rather than left to expire."""
        async def scenario(server, listener, loop):
            if not server._interfaces[LO].transport.has_ipv6:
                pytest.skip("no IPv6 mDNS on loopback here")
            await asyncio.sleep(0.3)
            listener.drain()
            await server._apply_interfaces(
                _lo(FIRST, v6=(LINK_LOCAL, ROUTABLE)), loop,
            )
            goodbyes = [
                rr for rr in _answers(listener.drain()) if rr.ttl == 0
            ]
            assert {(rr.key.name, rr.key.rtype) for rr in goodbyes} == {
                (HOST, QType.AAAA),
                (LINK_LOCAL.reverse_pointer, QType.PTR),
            }
            assert all(
                rr.data == AAAARecordData(LINK_LOCAL)
                for rr in goodbyes if rr.key.rtype == QType.AAAA
            )
            published = {
                record.data.address
                for group in server._host_groups
                for record in group.records
                if isinstance(record.data, AAAARecordData)
            }
            assert published == {ROUTABLE}

        _run(tmp_path, _lo(FIRST, v6=(LINK_LOCAL,)), scenario)

    def test_link_up_waits_for_a_running_reconcile(self, tmp_path):
        """A link coming up and the address changes it brings reach
        ``_on_link_up`` and ``_reconcile_interfaces`` separately; both
        re-probe the groups on the interface, under one lock, so the two
        never probe a group at the same time."""
        async def scenario(server, listener, loop):
            (host,) = server._host_groups
            async with server._get_rebuild_lock():
                link_up = asyncio.create_task(server._on_link_up(LO))
                await asyncio.sleep(0.8)
                assert host.state == EntryGroupState.ESTABLISHED
                assert server._registry.get_all_records(LO)
            await link_up
            assert host.state == EntryGroupState.ESTABLISHED
            assert server._registry.get_all_records(LO)

        _run(tmp_path, _lo(FIRST), scenario)
