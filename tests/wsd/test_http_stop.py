"""WSDHttpServer.stop() must not block on in-flight connections.

Regression test for the slow-shutdown bug.  On CPython 3.13
``asyncio.Server.close()`` leaves already-open connections running
and ``wait_closed()`` blocks until each one drains on its own — for
the metadata handler that is up to ``HTTP_REQUEST_TIMEOUT_S`` (its
read deadline).  Because the WSD daemon binds one listener per
address and tears them down in turn, a few peers holding idle
connections at shutdown could stall the daemon's stop for tens of
seconds.  ``stop()`` must abort live connections so teardown stays
prompt regardless of what clients are connected.

Real dependencies only: a real ``WSDHttpServer`` on the loopback and
real TCP client sockets that connect and then stay silent, parking
the server-side handler in its first ``readline()``.
"""
from __future__ import annotations

import asyncio
import socket
import time

from truenas_pywsd.protocol.constants import HTTP_REQUEST_TIMEOUT_S
from truenas_pywsd.server.net.http import WSDHttpServer


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _never_called(_body: bytes) -> bytes:
    # No-op sink: the clients send nothing, so the metadata handler
    # never reaches this — its job is only to satisfy the signature.
    return b""


def _drive_stop_with_idle_conns(n_conns: int) -> float:
    """Open *n_conns* idle client connections, then time ``stop()``."""
    port = _free_port()
    server = WSDHttpServer("127.0.0.1", port, _never_called)

    async def drive() -> float:
        await server.start()
        conns: list[tuple] = []
        for _ in range(n_conns):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            conns.append((reader, writer))
        # Let every server-side handler task attach to the server and
        # park in its readline() before we tear the server down.
        await asyncio.sleep(0.1)

        t0 = time.monotonic()
        await server.stop()
        elapsed = time.monotonic() - t0

        for _reader, writer in conns:
            writer.close()
        return elapsed

    loop = asyncio.new_event_loop()
    try:
        # Outer cap: if the bug regressed, stop() would block ~10s
        # (the handler read deadline); fail loudly rather than hang.
        return loop.run_until_complete(
            asyncio.wait_for(drive(), timeout=HTTP_REQUEST_TIMEOUT_S - 1.0)
        )
    finally:
        loop.close()


def test_stop_does_not_block_on_a_single_idle_connection():
    elapsed = _drive_stop_with_idle_conns(1)
    assert elapsed < 1.0, (
        f"stop() took {elapsed:.2f}s — it blocked on the idle "
        f"connection's read deadline instead of aborting it"
    )


def test_stop_stays_prompt_regardless_of_connection_count():
    # The old close()+wait_closed() waited for every connection to
    # drain; teardown time must not grow with how many are open.
    elapsed = _drive_stop_with_idle_conns(5)
    assert elapsed < 1.0, (
        f"stop() took {elapsed:.2f}s with 5 idle connections — "
        f"teardown is still waiting on connections to drain"
    )
