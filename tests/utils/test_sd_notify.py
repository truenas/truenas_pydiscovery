"""systemd notifications (sd_notify(3)) sent over a real datagram socket."""
from __future__ import annotations

import os
import socket
import time

from truenas_pydiscovery_utils.sd_notify import (
    notify,
    notify_ready,
    notify_reloading,
)


def _monotonic_usec() -> int:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000


class TestNotify:
    def test_ready(self, notify_socket):
        assert notify_ready() is True
        assert notify_socket.recv(4096) == b"READY=1"

    def test_reloading_carries_current_monotonic_usec(self, notify_socket):
        """Type=notify-reload pairs RELOADING=1 with MONOTONIC_USEC, the
        CLOCK_MONOTONIC time in microseconds (systemd.service(5))."""
        before = _monotonic_usec()
        assert notify_reloading() is True
        after = _monotonic_usec()

        reloading, monotonic = notify_socket.recv(4096).decode().split("\n")
        assert reloading == "RELOADING=1"
        key, _, value = monotonic.partition("=")
        assert key == "MONOTONIC_USEC"
        assert before <= int(value) <= after

    def test_abstract_namespace_address(self, monkeypatch):
        """A leading "@" names an abstract-namespace socket."""
        name = f"pydiscovery-sdnotify-{os.getpid()}"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind("\0" + name)
        sock.settimeout(2.0)
        monkeypatch.setenv("NOTIFY_SOCKET", "@" + name)
        try:
            assert notify("STATUS=abstract") is True
            assert sock.recv(4096) == b"STATUS=abstract"
        finally:
            sock.close()

    def test_unset_socket_is_a_noop(self, monkeypatch):
        monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
        assert notify_ready() is False

    def test_unsupported_address_is_a_noop(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_SOCKET", "vsock:2:1234")
        assert notify_ready() is False

    def test_send_failure_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent-dir/notify")
        assert notify_ready() is False
