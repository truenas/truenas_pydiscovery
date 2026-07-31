"""Bind policy of the mDNS socket factories: the avahi
``disallow-other-stacks`` equivalent, enabled by default.

Avahi implements the option by *omitting* SO_REUSEADDR/SO_REUSEPORT
(``avahi_open_socket_ipv4`` in avahi-core/socket.c:311 sets them only
when other stacks are allowed).  These tests pin our factories to
the same mechanism with real sockets on loopback: an exclusive bind
keeps a cooperating stack's reuse-bind off UDP 5353, a shared bind
admits it, and two exclusive binds on the same device conflict —
the reason the server-level fixtures in conftest.py bind shared.
"""
from __future__ import annotations

import errno
import socket

import pytest

from truenas_pymdns.protocol.constants import MDNS_PORT
from truenas_pymdns.server.net.multicast import (
    create_v4_socket,
    create_v6_socket,
)


def _rival_socket(family: int) -> socket.socket:
    """What a cooperating mDNS stack does before binding 5353:
    SO_REUSEADDR plus best-effort SO_REUSEPORT (avahi, mDNSResponder
    and systemd-resolved all bind this way)."""
    sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    return sock


class TestDisallowOtherStacks:
    def test_default_v4_bind_is_exclusive(self):
        ours = create_v4_socket("lo", "127.0.0.1")
        rival = _rival_socket(socket.AF_INET)
        try:
            with pytest.raises(OSError) as exc:
                rival.bind(("", MDNS_PORT))
            assert exc.value.errno == errno.EADDRINUSE
        finally:
            rival.close()
            ours.close()

    def test_default_v6_bind_is_exclusive(self):
        ours = create_v6_socket(socket.if_nametoindex("lo"), "lo")
        rival = _rival_socket(socket.AF_INET6)
        try:
            with pytest.raises(OSError) as exc:
                rival.bind(("", MDNS_PORT))
            assert exc.value.errno == errno.EADDRINUSE
        finally:
            rival.close()
            ours.close()

    def test_shared_v4_bind_admits_other_stacks(self):
        """disallow-other-stacks = no restores avahi's default:
        another stack's reuse-bind coexists on 5353."""
        ours = create_v4_socket(
            "lo", "127.0.0.1", disallow_other_stacks=False,
        )
        rival = _rival_socket(socket.AF_INET)
        try:
            rival.bind(("", MDNS_PORT))
        finally:
            rival.close()
            ours.close()

    def test_exclusive_binds_conflict_on_the_same_device(self):
        """Two exclusive sockets on one device cannot share the
        port.  Production never does this — the daemon binds one
        socket per family per interface, and the kernel's UDP
        bind-conflict check (``udp_lib_lport_inuse``,
        net/ipv4/udp.c) exempts sockets SO_BINDTODEVICE-bound to
        *different* devices — but tests stacking transports on
        loopback hit it, which is why conftest binds them shared."""
        first = create_v4_socket("lo", "127.0.0.1")
        try:
            with pytest.raises(OSError) as exc:
                second = create_v4_socket("lo", "127.0.0.1")
                second.close()
            assert exc.value.errno == errno.EADDRINUSE
        finally:
            first.close()

    def test_v4_and_v6_exclusive_binds_coexist(self):
        """Different address families never conflict on the port:
        the v6 socket is IPV6_V6ONLY, so exclusive v4 + v6 binds on
        one interface — exactly what one daemon transport does —
        both succeed."""
        v4 = create_v4_socket("lo", "127.0.0.1")
        try:
            v6 = create_v6_socket(socket.if_nametoindex("lo"), "lo")
            v6.close()
        finally:
            v4.close()
