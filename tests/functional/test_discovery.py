"""Discovery as a host on the network sees it.

Each query goes out from a client network namespace through a veth
link, with the client tools the package installs, and the answers are
checked against the address the daemon holds on that link.
"""
from __future__ import annotations

import ipaddress
import struct
import subprocess
import sys

import pytest

from truenas_pynetbiosns.protocol.constants import (
    DGRAM_PORT,
    NBNS_PORT,
    DatagramType,
    NameType,
    Opcode,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName

from ..netbiosns.conftest import decode_mailslot
from .conftest import (
    HOST_NAME,
    NETBIOS_NAME,
    WORKGROUP,
    Discoveryd,
    Link,
    LinkFactory,
    mdns_addresses,
    netbios_addresses,
    wait_for,
    wsd_xaddrs,
)

pytestmark = pytest.mark.functional

SERVER_IP = "203.0.113.1"
CLIENT_IP = "203.0.113.2"
SUBNET_BROADCAST = "203.0.113.255"

# Run in the client namespace: print the destination address and the
# hex bytes of the first datagram that reaches UDP 138.
_RECEIVE_ONE_DATAGRAM = f"""
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
sock.bind(("", {DGRAM_PORT}))
sock.settimeout(float(sys.argv[1]))
print("listening", flush=True)
data, ancillary, _flags, _source = sock.recvmsg(4096, 256)
for level, kind, value in ancillary:
    if level == socket.IPPROTO_IP and kind == socket.IP_PKTINFO:
        print(socket.inet_ntoa(value[8:12]))
print(data.hex())
"""


# Run in the client namespace: collect what reaches UDP 137 and 138
# until stdin closes, then print "<port> <hex bytes>" per datagram.
_COLLECT_DATAGRAMS = f"""
import selectors, socket, sys
selector = selectors.DefaultSelector()
for port in ({NBNS_PORT}, {DGRAM_PORT}):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", port))
    selector.register(sock, selectors.EVENT_READ, port)
selector.register(sys.stdin, selectors.EVENT_READ, None)
print("listening", flush=True)
received = []
while True:
    for key, _events in selector.select():
        if key.data is None:
            for port, data in received:
                print(port, data.hex())
            sys.exit(0)
        received.append((key.data, key.fileobj.recv(4096)))
"""


@pytest.fixture
def link(links: LinkFactory) -> Link:
    link = links(0)
    link.add_ipv4(f"{SERVER_IP}/24", f"{CLIENT_IP}/24")
    return link


@pytest.fixture
def serving(link: Link, discoveryd: Discoveryd) -> Discoveryd:
    discoveryd.configure([link.server])
    discoveryd.restart()
    wait_for(
        lambda: netbios_addresses(link, CLIENT_IP) == {SERVER_IP},
        f"{NETBIOS_NAME} to be answered",
    )
    return discoveryd


class TestQueries:
    def test_netbios_name_is_answered(self, link: Link, serving: Discoveryd):
        assert netbios_addresses(link, CLIENT_IP) == {SERVER_IP}

    def test_mdns_host_name_is_answered(self, link: Link,
                                        serving: Discoveryd):
        wait_for(
            lambda: SERVER_IP in mdns_addresses(link, CLIENT_IP),
            f"{HOST_NAME}.local to be answered",
        )

    def test_wsd_probe_is_answered(self, link: Link, serving: Discoveryd):
        wait_for(
            lambda: any(
                url.startswith(f"http://{SERVER_IP}:")
                for url in wsd_xaddrs(link, CLIENT_IP)
            ),
            "a ProbeMatch with an XAddr on the link",
        )


class TestBrowseAnnouncement:
    def test_host_announcement_reaches_the_subnet_broadcast(
        self, link: Link, discoveryd: Discoveryd,
    ):
        """The first HostAnnouncement goes out as soon as the subnet is
        set up: a DIRECT_GROUP mailslot datagram from NAS01<00> to
        WG<1D> on \\MAILSLOT\\BROWSE, sent to the subnet's broadcast
        address (MS-BRWS §3.2.5.2)."""
        listener = subprocess.Popen(
            ["ip", "netns", "exec", link.netns, sys.executable, "-c",
             _RECEIVE_ONE_DATAGRAM, "30"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            assert listener.stdout is not None
            assert listener.stdout.readline().strip() == "listening"
            discoveryd.configure([link.server])
            discoveryd.restart()
            out, err = listener.communicate(timeout=40)
        finally:
            if listener.poll() is None:
                listener.kill()
                listener.wait()
        assert listener.returncode == 0, err
        destination, datagram_hex = out.split()
        assert destination == SUBNET_BROADCAST
        announcement = decode_mailslot(bytes.fromhex(datagram_hex))
        assert announcement["msg_type"] == DatagramType.DIRECT_GROUP
        assert announcement["source_ip"] == ipaddress.IPv4Address(SERVER_IP)
        assert announcement["source"] == NetBIOSName(
            NETBIOS_NAME, NameType.WORKSTATION,
        )
        assert announcement["dest"] == NetBIOSName(
            WORKGROUP, NameType.LOCAL_MASTER,
        )
        assert announcement["mailslot"] == "\\MAILSLOT\\BROWSE"
        server_name = announcement["data"][6:22].split(b"\0", 1)[0]
        assert server_name == NETBIOS_NAME.encode()

    def test_stop_announces_the_server_removed_and_releases_no_name(
        self, link: Link, serving: Discoveryd,
    ):
        """On stop, as nmbd's ``terminate`` does: a HostAnnouncement
        with server type 0 and Periodicity 0
        (``announce_my_servers_removed``), and no NAME RELEASE for a
        broadcast-registered name."""
        collector = subprocess.Popen(
            ["ip", "netns", "exec", link.netns, sys.executable, "-c",
             _COLLECT_DATAGRAMS],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            assert collector.stdout is not None
            assert collector.stdout.readline().strip() == "listening"
            result = serving.stop()
            assert result.returncode == 0, result.stderr
            out, err = collector.communicate(input="", timeout=30)
        finally:
            if collector.poll() is None:
                collector.kill()
                collector.wait()
        assert collector.returncode == 0, err
        received = [
            (int(port), bytes.fromhex(data))
            for port, data in (line.split() for line in out.splitlines())
        ]
        opcodes = [
            NBNSMessage.from_wire(data).opcode
            for port, data in received if port == NBNS_PORT
        ]
        assert Opcode.RELEASE not in opcodes
        announcements = [
            decode_mailslot(data)["data"]
            for port, data in received if port == DGRAM_PORT
        ]
        removed = [
            payload for payload in announcements
            if payload[6:22].split(b"\0", 1)[0] == NETBIOS_NAME.encode()
        ]
        assert removed, f"no HostAnnouncement from {NETBIOS_NAME}"
        periodicity_ms, = struct.unpack("<I", removed[-1][2:6])
        server_type, = struct.unpack("<I", removed[-1][24:28])
        assert (periodicity_ms, server_type) == (0, 0)
