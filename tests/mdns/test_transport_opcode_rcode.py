"""RFC 6762 §18.3 / §18.11 OPCODE / RCODE gating in the transport.

Multicast DNS carries only standard queries and responses with a zero
Response Code; a datagram whose OPCODE or RCODE is non-zero is not a
multicast DNS message and is ignored on reception (RFC 6762 §18.3,
§18.11).  avahi applies the same gate in
``avahi_dns_packet_check_valid_multicast`` (avahi-core/dns.c:325).

These tests use a real loopback UDP socket and drive the real
``MDNSTransport._recv_from_sock`` receive path (no mocks): the message
handler sees a datagram only when its header is a conformant mDNS
header.  Every case is a query (QR=0) so the gate is isolated from the
response-only source-port and TTL checks that follow it.
"""
from __future__ import annotations

import socket

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.server.net.transport import MDNSTransport

# OPCODE occupies bits 11-14 of the header flags; Update is OPCODE 5
# (RFC 1035 / RFC 2136).  RCODE is the low four bits; 3 is NXDomain.
_OPCODE_UPDATE = 5 << 11
_RCODE_NXDOMAIN = 3


def _delivered(flags: int) -> bool:
    """Send one query datagram with header *flags* over loopback through
    the real transport receive path; return True if the handler got it."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rx.settimeout(2.0)
        rx.bind(("127.0.0.1", 0))

        transport = MDNSTransport(interface_index=1, interface_name="lo")
        transport._sock_v4 = rx
        received: list[MDNSMessage] = []
        transport._handler = (
            lambda msg, addr, ifindex: received.append(msg)
        )

        query = MDNSMessage(
            flags=flags,
            questions=[MDNSQuestion("host1.local", QType.A)],
        )
        tx.sendto(query.to_wire(), rx.getsockname())
        transport._recv_from_sock(rx, socket.AF_INET)
        return bool(received)
    finally:
        rx.close()
        tx.close()


class TestOpcodeRcodeGate:
    def test_standard_query_delivered(self):
        # OPCODE 0, RCODE 0 — a conformant mDNS query reaches the handler.
        assert _delivered(0) is True

    def test_nonzero_opcode_ignored(self):
        # An OPCODE=Update datagram is not a multicast DNS message.
        assert _delivered(_OPCODE_UPDATE) is False

    def test_nonzero_rcode_ignored(self):
        # A non-zero Response Code is likewise outside the protocol.
        assert _delivered(_RCODE_NXDOMAIN) is False
