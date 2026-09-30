"""Shared fixtures for the daemon-lifecycle tests."""
from __future__ import annotations

import os
import socket
import tempfile

import pytest


@pytest.fixture
def notify_socket(monkeypatch):
    """A bound AF_UNIX datagram socket published as ``$NOTIFY_SOCKET``.

    It stands where systemd's notification socket would: whatever the
    code under test sends through ``sd_notify`` arrives here, and child
    processes inherit the variable.  The directory comes from
    ``tempfile.mkdtemp`` rather than ``tmp_path`` because ``sun_path``
    holds at most 107 bytes.
    """
    directory = tempfile.mkdtemp(prefix="sdnotify")
    path = os.path.join(directory, "notify")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(path)
    sock.settimeout(2.0)
    monkeypatch.setenv("NOTIFY_SOCKET", path)
    try:
        yield sock
    finally:
        sock.close()
        os.unlink(path)
        os.rmdir(directory)
