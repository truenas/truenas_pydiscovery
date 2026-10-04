"""Discovery as a host on the network sees it.

Each query goes out from a client network namespace through a veth
link, with the client tools the package installs, and the answers are
checked against the address the daemon holds on that link.
"""
from __future__ import annotations

import ipaddress
import subprocess
import sys

import pytest

from truenas_pynetbiosns.protocol.constants import (
    DGRAM_PORT,
    DatagramType,
    NameType,
)
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
