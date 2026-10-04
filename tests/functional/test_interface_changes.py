"""Interfaces and addresses changing under the running daemon.

The daemon picks the changes up by itself, through its netlink
interface monitor, once they have settled: no reload is sent in any of
these tests, and each checks the journal for that.
"""
from __future__ import annotations

import re
import subprocess
import sys
import time

import pytest

from .conftest import (
    NETBIOS_NAME,
    Discoveryd,
    Link,
    LinkFactory,
    mdns_addresses,
    netbios_addresses,
    wait_for,
    wsd_xaddrs,
)

pytestmark = pytest.mark.functional

FIRST_SERVER = "203.0.113.1"
FIRST_CLIENT = "203.0.113.2"
SECOND_SERVER = "198.51.100.1"
SECOND_CLIENT = "198.51.100.2"

WSD_GROUP = "239.255.255.250"
WSD_PORT = 3702

# Run in a client namespace: join the WSD group on the given interface
# and print the XAddrs of the first Hello that arrives.
_RECEIVE_HELLO = f"""
import re, socket, struct, sys
ifindex = socket.if_nametoindex(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", {WSD_PORT}))
sock.setsockopt(
    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
    socket.inet_aton("{WSD_GROUP}") + socket.inet_aton("0.0.0.0")
    + struct.pack("=i", ifindex),
)
sock.settimeout(float(sys.argv[2]))
print("listening", flush=True)
while True:
    data = sock.recv(65536).decode()
    if "/Hello<" in data:
        match = re.search(r"<[^>]*XAddrs>([^<]*)<", data)
        print(match.group(1) if match else "")
        break
"""


@pytest.fixture
def first_link(links: LinkFactory) -> Link:
    link = links(0)
    link.add_ipv4(f"{FIRST_SERVER}/24", f"{FIRST_CLIENT}/24")
    return link


def _start(discoveryd: Discoveryd, link: Link,
           interfaces: list[str]) -> float:
    """Start the daemon on *interfaces*; return when it answers on
    *link*, with the time it was started."""
    discoveryd.configure(interfaces)
    since = time.time()
    discoveryd.restart()
    wait_for(
        lambda: netbios_addresses(link, FIRST_CLIENT) == {FIRST_SERVER},
        f"{NETBIOS_NAME} to be answered on {link.server}",
    )
    return since


def _assert_no_reload(discoveryd: Discoveryd, since: float) -> None:
    journal = discoveryd.journal_since(since)
    assert "Received SIGHUP" not in journal
    assert "Interfaces or addresses changed; updating" in journal


class TestAddressChanges:
    def test_address_added_after_start_is_served(
        self, first_link: Link, links: LinkFactory, discoveryd: Discoveryd,
    ):
        """The field report: an interface listed in the configuration
        but without an IPv4 address when the daemon starts is served
        once it gets one."""
        second = links(1)
        since = _start(discoveryd, first_link,
                       [first_link.server, second.server])
        assert netbios_addresses(second, SECOND_CLIENT) == set()

        second.add_ipv4(f"{SECOND_SERVER}/24", f"{SECOND_CLIENT}/24")
        wait_for(
            lambda: netbios_addresses(second, SECOND_CLIENT)
            == {SECOND_SERVER},
            "NetBIOS on the new address",
        )
        wait_for(
            lambda: SECOND_SERVER in mdns_addresses(second, SECOND_CLIENT),
            "mDNS on the new address",
        )
        wait_for(
            lambda: any(
                url.startswith(f"http://{SECOND_SERVER}:")
                for url in wsd_xaddrs(second, SECOND_CLIENT)
            ),
            "a ProbeMatch XAddr on the new address",
        )
        assert netbios_addresses(first_link, FIRST_CLIENT) == {FIRST_SERVER}
        _assert_no_reload(discoveryd, since)

    def test_removed_address_is_no_longer_served(
        self, first_link: Link, discoveryd: Discoveryd,
    ):
        first_link.add_ipv4(f"{SECOND_SERVER}/24", f"{SECOND_CLIENT}/24")
        since = _start(discoveryd, first_link, [first_link.server])
        wait_for(
            lambda: netbios_addresses(first_link, SECOND_CLIENT)
            == {SECOND_SERVER},
            "NetBIOS on the second subnet",
        )
        wait_for(
            lambda: SECOND_SERVER in mdns_addresses(first_link, FIRST_CLIENT),
            "mDNS to publish the second address",
        )

        first_link.remove_ipv4(f"{SECOND_SERVER}/24")
        wait_for(
            lambda: SECOND_SERVER not in mdns_addresses(
                first_link, FIRST_CLIENT,
            ),
            "mDNS to drop the removed address",
        )
        assert netbios_addresses(first_link, SECOND_CLIENT) == set()
        assert netbios_addresses(first_link, FIRST_CLIENT) == {FIRST_SERVER}
        _assert_no_reload(discoveryd, since)

    def test_interface_created_after_start_is_served(
        self, first_link: Link, links: LinkFactory, discoveryd: Discoveryd,
    ):
        """An interface listed in the configuration that does not exist
        yet when the daemon starts (a VLAN or bridge created later) is
        served once it exists and has an address."""
        since = _start(discoveryd, first_link,
                       [first_link.server, "pdsrv1"])
        second = links(1)
        second.add_ipv4(f"{SECOND_SERVER}/24", f"{SECOND_CLIENT}/24")
        wait_for(
            lambda: netbios_addresses(second, SECOND_CLIENT)
            == {SECOND_SERVER},
            "NetBIOS on the new interface",
        )
        wait_for(
            lambda: SECOND_SERVER in mdns_addresses(second, SECOND_CLIENT),
            "mDNS on the new interface",
        )
        _assert_no_reload(discoveryd, since)

    def test_hello_announces_the_new_address(
        self, first_link: Link, links: LinkFactory, discoveryd: Discoveryd,
    ):
        """WS-Discovery 1.1 §4.1.1: a Target Service sends a Hello when
        it becomes available through an additional transport address."""
        second = links(1)
        _start(discoveryd, first_link, [first_link.server, second.server])
        listener = subprocess.Popen(
            ["ip", "netns", "exec", second.netns, sys.executable, "-c",
             _RECEIVE_HELLO, second.client, "60"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            assert listener.stdout is not None
            assert listener.stdout.readline().strip() == "listening"
            second.add_ipv4(f"{SECOND_SERVER}/24", f"{SECOND_CLIENT}/24")
            out, err = listener.communicate(timeout=70)
        finally:
            if listener.poll() is None:
                listener.kill()
                listener.wait()
        assert listener.returncode == 0, err
        assert re.search(
            rf"http://{re.escape(SECOND_SERVER)}:\d+/", out,
        ), out
