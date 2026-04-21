"""Guard against the ``!I`` vs ``@I`` ifindex byte-order regression.

Linux's ``IPV6_MULTICAST_IF`` and the ``ipv6_mreq::ipv6mr_ifindex``
field are host-byte-order ``int``s.  Packing the ifindex as ``!I``
(network byte order) byte-swaps it on little-endian hosts and the
kernel rejects with ``ENODEV`` — which is exactly what happened
for the first ``truenas-discoveryd`` deployment ("Failed to start
IPv6 on eno4: [Errno 19] No such device").

These tests open a real IPv6 UDP socket and issue the two syscalls
end-to-end against the loopback interface, confirming the
``@I``-packed ifindex is accepted.  If someone re-introduces
``!I`` in either path, these tests will fail with ``OSError(19)``
on any little-endian host.
"""
from __future__ import annotations

import socket
import struct

import pytest


def _loopback_ipv6_ok() -> int | None:
    """Return ``lo``'s ifindex if IPv6 loopback is usable, else None."""
    if not socket.has_ipv6:
        return None
    try:
        idx = socket.if_nametoindex("lo")
    except OSError:
        return None
    # Creating an AF_INET6 datagram socket here doesn't need root;
    # skipping the rest of the test if the kernel rejects is safer
    # than asserting a Linux-only environment.
    try:
        s = socket.socket(
            socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        s.close()
        return idx
    except OSError:
        return None


LO_IFINDEX = _loopback_ipv6_ok()


@pytest.mark.skipif(
    LO_IFINDEX is None,
    reason="IPv6 loopback not usable in this environment",
)
class TestIpv6IfindexBindings:
    """Each test opens an independent socket — setsockopt failures
    do not leak across cases."""

    def _v6_sock(self) -> socket.socket:
        return socket.socket(
            socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )

    def test_multicast_if_native_endian_accepted(self):
        """``@I`` must be accepted by ``IPV6_MULTICAST_IF`` for the
        loopback ifindex."""
        s = self._v6_sock()
        try:
            s.setsockopt(
                socket.IPPROTO_IPV6,
                socket.IPV6_MULTICAST_IF,
                struct.pack("@I", LO_IFINDEX),
            )
        finally:
            s.close()

    def test_multicast_if_network_endian_rejected_on_le(self):
        """``!I`` must be rejected on little-endian hosts because the
        kernel reads a byte-swapped ifindex.  We only assert
        rejection when the native byte order differs from network —
        on big-endian hosts both orderings coincide and the test
        becomes a no-op.
        """
        import sys
        if sys.byteorder != "little":
            pytest.skip("byte orders coincide on this host")
        s = self._v6_sock()
        try:
            with pytest.raises(OSError) as exc_info:
                s.setsockopt(
                    socket.IPPROTO_IPV6,
                    socket.IPV6_MULTICAST_IF,
                    struct.pack("!I", LO_IFINDEX),
                )
            # ENODEV (19) is what we observed in production.
            assert exc_info.value.errno == 19, (
                f"expected ENODEV (19), got {exc_info.value.errno}"
            )
        finally:
            s.close()

    def test_join_group_native_endian_accepted(self):
        """``@I`` in ``ipv6_mreq`` must be accepted by
        ``IPV6_JOIN_GROUP`` (for a well-known link-local all-nodes
        group on loopback)."""
        s = self._v6_sock()
        try:
            # ff02::1 = all-nodes link-local — always joinable on
            # loopback without needing the mDNS or WSD groups.
            group = socket.inet_pton(socket.AF_INET6, "ff02::1")
            mreq = group + struct.pack("@I", LO_IFINDEX)
            s.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq,
            )
        finally:
            s.close()
