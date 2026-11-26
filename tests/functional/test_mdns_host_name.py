"""Who keeps the mDNS host name.

RFC 6762 §8 and §9: the daemon probes for its host name and keeps it
unless another host already answers for it.  These run the installed
daemon on links shaped like the field reports and check the name it
ends up with: in its status, in the journal, and as a host on the link
resolves it.
"""
from __future__ import annotations

import subprocess
import sys
import time
from typing import Iterator

import pytest

from .conftest import (
    HOST_NAME,
    Discoveryd,
    Link,
    LinkFactory,
    Segment,
    mdns_addresses,
    mdns_host_name,
    wait_for,
)

pytestmark = pytest.mark.functional

HOST_FQDN = f"{HOST_NAME}.local"
RENAMED_FQDN = f"{HOST_NAME}-2.local"

# What the daemon logs when it counts a conflict, on any path.
CONFLICT_LINES = (
    "Probe conflict, will retry with alternative name",
    "Host name conflict",
    "peer rdata conflict",
)

# How long the daemon goes on announcing after probing (RFC 6762 §8.3:
# three announcements, the second a second after the first and the
# third two seconds after that), with margin.
ANNOUNCING = 8.0

# Run in a client namespace: a host that already uses a name.  It
# defends the name the way RFC 6762 §8.1 has a host defend it against
# a probe -- answering every query that asks about it -- with an A
# record for its own address.
_ANSWER_FOR_NAME = """
import socket, sys
from ipaddress import IPv4Address
from truenas_pymdns.protocol.constants import MDNS_IPV4_GROUP, MDNS_PORT, QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData, MDNSRecord, MDNSRecordKey,
)

name, address = sys.argv[1].lower(), sys.argv[2]
answer = MDNSMessage.build_response([MDNSRecord(
    key=MDNSRecordKey(name, QType.A), ttl=120,
    data=ARecordData(IPv4Address(address)), cache_flush=True,
)]).to_wire()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", MDNS_PORT))
sock.setsockopt(
    socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
    socket.inet_aton(MDNS_IPV4_GROUP) + socket.inet_aton(address),
)
sock.setsockopt(
    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address),
)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
print("listening", flush=True)
while True:
    data, _source = sock.recvfrom(9000)
    try:
        query = MDNSMessage.from_wire(data)
    except (ValueError, IndexError):
        continue
    if query.is_query and any(q.name.lower() == name for q in query.questions):
        sock.sendto(answer, (MDNS_IPV4_GROUP, MDNS_PORT))
"""


def _assert_no_conflict(journal: str) -> None:
    for line in CONFLICT_LINES:
        assert line not in journal, journal


class TestTwoPortsOnOneLan:
    """RFC 6762 §14: "If the two networks are bridged together, then
    packets the host sends on one interface will arrive on the other
    interface a few milliseconds later, and care must be taken to
    ensure that this bridging does not cause problems."

    The field report: a NAS with two ports cabled to one LAN renamed
    itself every fifteen seconds, nas -> nas-2 -> ... -> nas-21, then
    gave up.  Its ports probe one after the other; the first
    answered the second's probe with its own addresses and the second
    took that answer for another host's.  Linux drops the IPv4 copy of
    one port's traffic arriving on the other, its source being a local
    address, but delivers the IPv6 copy, so the ports hear each other
    over IPv6 only -- which is enough.
    """

    FIRST = "203.0.113.1"
    SECOND = "203.0.113.3"
    CLIENT = "203.0.113.2"

    def test_host_name_is_kept(self, segment: Segment,
                               discoveryd: Discoveryd):
        first = segment.add_port(0, f"{self.FIRST}/24")
        second = segment.add_port(1, f"{self.SECOND}/24")
        segment.add_client(f"{self.CLIENT}/24")
        discoveryd.configure([first, second])
        since = time.time()
        discoveryd.restart()

        # Each port answers with its own address (RFC 6762 §6.2), so
        # both answer only once both have probed for the name and
        # kept it.
        both = {self.FIRST, self.SECOND}
        wait_for(
            lambda: both <= mdns_addresses(segment, self.CLIENT),
            f"both ports to answer for {HOST_FQDN}",
        )
        # Each port also hears the other's announcements, which carry
        # the other port's addresses with the cache-flush bit set.
        time.sleep(ANNOUNCING)

        # A renamed host never gets the name back, so seeing it here
        # means it was kept throughout.
        wait_for(
            lambda: mdns_host_name() == HOST_FQDN,
            f"the daemon to report {HOST_FQDN}",
        )
        assert both <= mdns_addresses(segment, self.CLIENT)
        _assert_no_conflict(discoveryd.journal_since(since))


class TestNameInUse:
    """RFC 6762 §8.1: "if any conflicting Multicast DNS response is
    received, then the probing host MUST defer to the existing host"."""

    SERVER = "203.0.113.10"
    CLIENT = "203.0.113.2"

    @pytest.fixture
    def owner(self, links: LinkFactory) -> Iterator[Link]:
        """A link on which the client host already uses the daemon's
        host name, answering for it with the client address."""
        link = links(0)
        link.add_ipv4(f"{self.SERVER}/24", f"{self.CLIENT}/24")
        answering = subprocess.Popen(
            ["ip", "netns", "exec", link.netns, sys.executable, "-c",
             _ANSWER_FOR_NAME, HOST_FQDN, self.CLIENT],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            assert answering.stdout is not None
            assert answering.stdout.readline().strip() == "listening", (
                answering.stderr.read() if answering.stderr else ""
            )
            yield link
        finally:
            answering.kill()
            answering.wait()

    def test_host_answering_for_the_name_keeps_it(
        self, owner: Link, discoveryd: Discoveryd,
    ):
        """The owner's address sorts before the daemon's, so the §8.2
        tiebreak -- which settles two hosts probing at once, not a
        host probing against one that answers -- would hand the
        daemon the name.  The owner keeps it; the daemon moves to the
        next name, once."""
        discoveryd.configure([owner.server])
        since = time.time()
        discoveryd.restart()

        wait_for(
            lambda: mdns_host_name() == RENAMED_FQDN,
            f"the daemon to move to {RENAMED_FQDN}",
        )
        wait_for(
            lambda: self.SERVER in mdns_addresses(
                owner, self.CLIENT, host=RENAMED_FQDN,
            ),
            f"{RENAMED_FQDN} to be answered",
        )
        journal = discoveryd.journal_since(since)
        assert f"Host name conflict: {HOST_FQDN} -> {RENAMED_FQDN}" in (
            journal
        ), journal
        assert f"Host name conflict: {RENAMED_FQDN}" not in journal, journal
