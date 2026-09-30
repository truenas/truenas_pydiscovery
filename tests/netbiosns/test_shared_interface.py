"""Two subnets on one interface share its transport.

Each subnet's host announcements must still reach that subnet's own
broadcast address, as Samba nmbd's ``send_mailslot`` sends to the
subnet's ``bcast_ip``.  The subnets live in 127.0.0.0/8, which Linux
treats as local in full, so the sockets bind without configuring an
address; binding ports 137/138 needs root or CAP_NET_BIND_SERVICE.
"""
from __future__ import annotations

import asyncio
import socket
from ipaddress import IPv4Address

import pytest

from truenas_pynetbiosns.protocol.constants import DGRAM_PORT, NameType
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.config import DaemonConfig, ServerConfig
from truenas_pynetbiosns.server.net.subnet import NbnsSubnet
from truenas_pynetbiosns.server.server import NBNSServer

from .conftest import decode_mailslot

_NETMASK = IPv4Address("255.255.255.0")


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


def _loopback_subnet(my_ip: str, broadcast: str) -> NbnsSubnet:
    return NbnsSubnet(
        interface_name="lo",
        interface_index=socket.if_nametoindex("lo"),
        my_ip=IPv4Address(my_ip),
        netmask=_NETMASK,
        broadcast=IPv4Address(broadcast),
    )


@pytest.mark.skipif(
    not _can_bind_datagram_port(),
    reason="binding UDP ports 137/138 needs root or CAP_NET_BIND_SERVICE",
)
class TestSubnetsSharingAnInterface:
    def test_second_subnet_announces_to_its_own_broadcast(self, tmp_path):
        first = _loopback_subnet("127.0.1.2", "127.0.1.255")
        second = _loopback_subnet("127.0.2.2", "127.0.2.255")
        server = NBNSServer(DaemonConfig(
            server=ServerConfig(netbios_name="NAS01", workgroup="WG"),
            rundir=tmp_path,
        ))
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver.bind((str(second.broadcast), DGRAM_PORT))
        receiver.setblocking(False)

        async def scenario() -> bytes:
            loop = asyncio.get_running_loop()
            try:
                await server._setup_subnet(first, loop)
                await server._setup_subnet(second, loop)
                assert len(server._transports) == 1
                assert len(server._subnets) == 2
                # Each announcer sends its first announcement as soon
                # as it starts.
                return await asyncio.wait_for(
                    loop.sock_recv(receiver, 4096), timeout=2,
                )
            finally:
                await server._stop()

        try:
            datagram = asyncio.run(scenario())
        finally:
            receiver.close()
        announcement = decode_mailslot(datagram)
        assert announcement["source_ip"] == second.my_ip
        assert announcement["source"] == NetBIOSName(
            "NAS01", NameType.WORKSTATION,
        )
        assert announcement["dest"] == NetBIOSName(
            "WG", NameType.LOCAL_MASTER,
        )
