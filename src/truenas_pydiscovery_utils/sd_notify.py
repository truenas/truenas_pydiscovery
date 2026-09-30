"""systemd service notification (sd_notify(3)) without libsystemd.

A ``Type=notify-reload`` unit learns that the daemon has finished
starting, has begun a reload, and has finished it from datagrams the
daemon sends to the socket named by ``$NOTIFY_SOCKET``.  Each datagram
carries newline-separated ``KEY=VALUE`` fields.  systemd documents the
protocol as stable and meant to be reimplemented by services without
libsystemd (systemd.service(5), "Services that notify systemd about
their initialization").

Outside systemd (``$NOTIFY_SOCKET`` unset) every call is a no-op.
"""
from __future__ import annotations

import logging
import os
import socket
import time

logger = logging.getLogger(__name__)

NOTIFY_SOCKET_ENV = "NOTIFY_SOCKET"


def notify(*fields: str) -> bool:
    """Send *fields* to systemd as one notification datagram.

    Returns True if the datagram was sent.  Returns False when
    ``$NOTIFY_SOCKET`` is unset or names something other than an
    AF_UNIX path or abstract socket, or when the send fails.
    """
    address = os.environ.get(NOTIFY_SOCKET_ENV)
    if not address:
        return False
    if address.startswith("@"):
        # Abstract-namespace socket: "@" stands for the leading NUL.
        address = "\0" + address[1:]
    elif not address.startswith("/"):
        logger.debug("Unsupported %s address %r", NOTIFY_SOCKET_ENV, address)
        return False
    payload = "\n".join(fields).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, address)
    except OSError as e:
        logger.warning("systemd notification %r failed: %s", fields, e)
        return False
    return True


def notify_ready() -> bool:
    """Report that startup, or a reload, has completed (``READY=1``)."""
    return notify("READY=1")


def notify_reloading() -> bool:
    """Report that a reload has begun.

    ``Type=notify-reload`` requires ``RELOADING=1`` together with
    ``MONOTONIC_USEC=``, the current CLOCK_MONOTONIC time in
    microseconds (systemd.service(5)).
    """
    usec = time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000
    return notify("RELOADING=1", f"MONOTONIC_USEC={usec}")
