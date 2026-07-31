"""RFC 6762 §11 received-TTL extraction in the transport layer.

Linux delivers the *received* IP TTL in an IP_TTL (2) ancillary
message, not IP_RECVTTL (12) — the latter is only the setsockopt
enable option.  These tests use a real loopback UDP socket pair (no
mocks) to prove ``_extract_ttl`` reads the value the kernel actually
delivers; before the fix the IPv4 branch matched IP_RECVTTL and
returned ``None`` for every datagram.
"""
from __future__ import annotations

import socket

# IP_RECVTTL is not exposed by every Python build's socket module, so
# the transport (and this test) use the same numeric fallback.
from truenas_pymdns.server.net.multicast import IP_RECVTTL
from truenas_pymdns.server.net.transport import MDNSTransport


def _recv_ttl(send_ttl: int) -> int | None:
    """Send one datagram over loopback with *send_ttl* and return the
    TTL ``_extract_ttl`` recovers from the receiver's ancillary data."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rx.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
        rx.settimeout(2.0)
        rx.bind(("127.0.0.1", 0))
        tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, send_ttl)
        tx.sendto(b"x", rx.getsockname())
        _data, ancdata, _flags, _addr = rx.recvmsg(64, 1024)
        return MDNSTransport._extract_ttl(ancdata, socket.AF_INET)
    finally:
        rx.close()
        tx.close()


class TestExtractTTLv4:
    def test_reads_ttl_255(self):
        # 255 is the value a compliant mDNS responder sends; the
        # responder must recover it (and thus NOT drop the packet).
        assert _recv_ttl(255) == 255

    def test_reads_decremented_ttl(self):
        # A packet that crossed a router arrives with a lower TTL;
        # _extract_ttl must surface it (non-None) so the responder can
        # drop the off-link response per RFC 6762 §11.
        assert _recv_ttl(1) == 1
