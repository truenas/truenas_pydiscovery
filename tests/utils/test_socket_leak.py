"""L4 regression: protocol socket creators must close the fresh fd
if any ``setsockopt`` or ``bind`` raises during setup.

The deleted ``test_socket_creation_leak.py`` used ``patch`` to force
``setsockopt`` to raise — which violates the project's no-mocks rule.
This replacement forces a *real* kernel error by passing a bogus
interface name; on Linux ``SO_BINDTODEVICE`` fails with ``ENODEV``
(unprivileged runs get ``EPERM`` first, which is equally valid — in
both cases the exception propagates through the same ``except
BaseException: sock.close(); raise`` cleanup path).

Leakage is measured by counting entries in ``/proc/self/fd``
immediately before and after the failed call.  The test is skipped
on platforms that don't expose that directory (macOS/BSD).
"""
from __future__ import annotations

import os

import pytest

_BOGUS_IF = "zzfake0-nonexistent"


def _fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


@pytest.fixture(autouse=True)
def _require_proc_self_fd() -> None:
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("test requires /proc/self/fd (Linux)")


def _assert_no_leak(call) -> None:
    """Invoke *call*, expect an ``OSError``, and prove no fd was leaked."""
    before = _fd_count()
    with pytest.raises(OSError):
        call()
    after = _fd_count()
    assert after == before, f"fd leak: before={before} after={after}"


class TestMDNSSocketLeak:
    def test_v4_closes_on_bindtodevice_failure(self):
        from truenas_pymdns.server.net.multicast import create_v4_socket
        _assert_no_leak(lambda: create_v4_socket(_BOGUS_IF, "127.0.0.1"))

    def test_v6_closes_on_bindtodevice_failure(self):
        from truenas_pymdns.server.net.multicast import create_v6_socket
        # A valid-looking but non-existent interface index lets the
        # IPV6_MULTICAST_IF setsockopt succeed on some kernels; the
        # SO_BINDTODEVICE step below fails on the bogus name.
        _assert_no_leak(lambda: create_v6_socket(999999, _BOGUS_IF))


class TestNBNSSocketLeak:
    def test_specific_socket_closes_on_bind_failure(self):
        """``NBNSTransport._create_specific_socket`` binds to a
        specific (IP, port) pair; failure is induced by binding
        to an unowned local IP so ``bind()`` raises
        ``EADDRNOTAVAIL`` and the ``except BaseException:
        sock.close(); raise`` path is exercised."""
        from truenas_pynetbiosns.protocol.constants import NBNS_PORT
        from truenas_pynetbiosns.server.net.transport import NBNSTransport
        t = NBNSTransport(
            interface_name="lo",
            interface_addr="127.0.0.1",
            broadcast_addr="127.255.255.255",
        )
        # 192.0.2.254 is RFC 5737 TEST-NET-1 and isn't configured on
        # any real interface here → bind fails with EADDRNOTAVAIL.
        _assert_no_leak(
            lambda: t._create_specific_socket(
                "192.0.2.254", NBNS_PORT,
            ),
        )


class TestWSDSocketLeak:
    def test_v4_socket_closes_on_bindtodevice_failure(self):
        from truenas_pywsd.server.net.transport import WSDTransport
        t = WSDTransport(
            interface_index=999999,
            interface_name=_BOGUS_IF,
            interface_addr_v4="127.0.0.1",
        )
        _assert_no_leak(t._create_v4_socket)

    def test_v6_socket_closes_on_bindtodevice_failure(self):
        from truenas_pywsd.server.net.transport import WSDTransport
        t = WSDTransport(
            interface_index=999999,
            interface_name=_BOGUS_IF,
            interface_addr_v4=None,
            use_ipv4=False,
        )
        _assert_no_leak(t._create_v6_socket)
