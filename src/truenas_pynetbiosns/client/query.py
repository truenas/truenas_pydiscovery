"""Direct NetBIOS Name Service query engine.

Sends name queries and node status requests via UDP broadcast
on an ephemeral port.  No daemon required.
"""
from __future__ import annotations

import asyncio
import socket

from truenas_pynetbiosns.protocol.constants import (
    NBNS_MAX_PACKET_SIZE,
    NBNS_PORT,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage

BROADCAST_ADDR = "255.255.255.255"


def create_query_socket(interface_addr: str | None = None) -> socket.socket:
    """Create a UDP broadcast socket for NetBIOS queries.

    Binds to an ephemeral port.  Responses come back as unicast
    to this socket.
    """
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if interface_addr is not None:
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            b"",  # clear; use IP_MULTICAST_IF-like binding below
        )
        sock.bind((interface_addr, 0))
    else:
        sock.bind(("", 0))
    sock.setblocking(False)
    return sock


def send_query(
    sock: socket.socket,
    message: NBNSMessage,
    dest: str = BROADCAST_ADDR,
) -> None:
    """Send a NetBIOS name service message."""
    wire = message.to_wire()
    sock.sendto(wire, (dest, NBNS_PORT))


async def collect_responses(
    sock: socket.socket,
    timeout: float,
    results: list[NBNSMessage],
) -> None:
    """Receive responses and append parsed messages to *results*."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, NBNS_MAX_PACKET_SIZE),
                timeout=remaining,
            )
        except TimeoutError:
            break
        try:
            msg = NBNSMessage.from_wire(data)
        except (ValueError, IndexError):
            continue
        if msg.is_response:
            results.append(msg)


async def one_shot_query(
    message: NBNSMessage,
    timeout: float = 2.0,
    dest: str = BROADCAST_ADDR,
    interface_addr: str | None = None,
) -> list[NBNSMessage]:
    """Send a query and return all responses within *timeout*."""
    sock = create_query_socket(interface_addr)
    try:
        send_query(sock, message, dest)
        results: list[NBNSMessage] = []
        await collect_responses(sock, timeout, results)
        return results
    finally:
        sock.close()
