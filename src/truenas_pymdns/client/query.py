"""Direct mDNS multicast query engine.

Sends mDNS queries directly on the network using QU (unicast-response)
questions on an ephemeral port (RFC 6762 s5.4).  No daemon or elevated
privileges required -- responders send unicast replies back to the
querier's source address and port.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

from truenas_pymdns.protocol.constants import (
    MDNS_IPV4_GROUP,
    MDNS_MAX_PACKET_SIZE,
    MDNS_PORT,
    MDNS_RECV_BUFSIZE,
    MDNS_TTL,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    AAAARecordData,
    MDNSRecord,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)

MDNS_MCAST_ADDR = (MDNS_IPV4_GROUP, MDNS_PORT)


def create_query_socket(interface_addr: str | None = None) -> socket.socket:
    """Create a UDP socket for sending mDNS QU queries.

    Binds to an ephemeral port.  Queries should set the QU bit
    (``unicast_response=True``) so responders reply via unicast
    directly to this socket.

    If *interface_addr* is given (dotted IPv4), outgoing multicast
    is sent via that interface.
    """
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # RFC 6762 s11: multicast TTL must be 255
    sock.setsockopt(
        socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MDNS_TTL,
    )
    if interface_addr is not None:
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(interface_addr),
        )
    sock.setblocking(False)
    sock.bind(("", 0))
    return sock


def send_query(
    sock: socket.socket,
    questions: list[MDNSQuestion],
) -> None:
    """Build and send an mDNS query packet."""
    msg = MDNSMessage.build_query(questions)
    wire = msg.to_wire(max_size=MDNS_MAX_PACKET_SIZE)
    sock.sendto(wire, MDNS_MCAST_ADDR)


async def collect_responses(
    sock: socket.socket,
    timeout: float,
    records: list[MDNSRecord],
) -> None:
    """Receive mDNS response packets and append records to *records*.

    Collects answers and additional records from all responses
    received within *timeout* seconds.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, MDNS_RECV_BUFSIZE),
                timeout=remaining,
            )
        except TimeoutError:
            break
        try:
            msg = MDNSMessage.from_wire(data)
        except (ValueError, IndexError):
            continue
        if not msg.is_response:
            continue
        records.extend(msg.answers)
        records.extend(msg.additionals)


async def one_shot_query(
    questions: list[MDNSQuestion],
    timeout: float = 3.0,
    interface_addr: str | None = None,
) -> list[MDNSRecord]:
    """Send a one-shot mDNS QU query and return collected records.

    Creates a socket, sends the query, waits up to *timeout* seconds
    for responses, then closes the socket and returns all records
    (answers + additionals) from all responses received.
    """
    sock = create_query_socket(interface_addr)
    try:
        send_query(sock, questions)
        records: list[MDNSRecord] = []
        await collect_responses(sock, timeout, records)
        return records
    finally:
        sock.close()


def qu_question(name: str, qtype: QType) -> MDNSQuestion:
    """Build a question with the QU (unicast-response) bit set."""
    return MDNSQuestion(name=name, qtype=qtype, unicast_response=True)


# ---------------------------------------------------------------------------
# Result extraction helpers
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ServiceInfo:
    """Resolved service instance information.

    ``txt`` keys are normalised to lowercase so callers can look up
    values without worrying about the case the advertising peer
    chose — "Path=/mnt", "PATH=/mnt", and "path=/mnt" all land at
    ``info.txt["path"]`` (RFC 6763 §6.6: "Case is ignored when
    interpreting a key").
    """
    name: str
    service_type: str
    domain: str
    host: str = ""
    port: int = 0
    addresses: list[str] = field(default_factory=list)
    txt: dict[str, str] = field(default_factory=dict)


def extract_ptr_targets(
    records: list[MDNSRecord], name: str,
) -> list[str]:
    """Return PTR target names for a given owner name."""
    name_lower = name.lower()
    targets: list[str] = []
    for rr in records:
        if (rr.key.name == name_lower
                and rr.key.rtype == QType.PTR
                and isinstance(rr.data, PTRRecordData)):
            targets.append(rr.data.target)
    return targets


def extract_service_info(
    records: list[MDNSRecord],
    instance_name: str,
    service_type: str,
    domain: str,
) -> ServiceInfo:
    """Extract SRV, TXT, and address records for a service instance."""
    fqdn = f"{instance_name}.{service_type}.{domain}".lower()
    info = ServiceInfo(
        name=instance_name, service_type=service_type, domain=domain,
    )

    for rr in records:
        if rr.key.name == fqdn:
            if (rr.key.rtype == QType.SRV
                    and isinstance(rr.data, SRVRecordData)):
                info.host = rr.data.target
                info.port = rr.data.port
            elif (rr.key.rtype == QType.TXT
                    and isinstance(rr.data, TXTRecordData)):
                for entry in rr.data.entries:
                    text = entry.decode("utf-8", errors="replace")
                    # RFC 6763 §6.6: TXT keys are case-insensitive.
                    # Normalise to lowercase so later lookups work
                    # regardless of the case the peer sent.
                    if "=" in text:
                        k, v = text.split("=", 1)
                        info.txt[k.lower()] = v
                    elif text:
                        info.txt[text.lower()] = ""

    # Collect addresses for the target hostname
    if info.host:
        host_lower = info.host.lower()
        for rr in records:
            if rr.key.name == host_lower:
                if (rr.key.rtype == QType.A
                        and isinstance(rr.data, ARecordData)):
                    info.addresses.append(str(rr.data.address))
                elif (rr.key.rtype == QType.AAAA
                        and isinstance(rr.data, AAAARecordData)):
                    info.addresses.append(str(rr.data.address))

    return info


def extract_addresses(
    records: list[MDNSRecord], hostname: str,
) -> list[str]:
    """Return A and AAAA addresses for a hostname."""
    hostname_lower = hostname.lower()
    addrs: list[str] = []
    for rr in records:
        if rr.key.name == hostname_lower:
            if (rr.key.rtype == QType.A
                    and isinstance(rr.data, ARecordData)):
                addrs.append(str(rr.data.address))
            elif (rr.key.rtype == QType.AAAA
                    and isinstance(rr.data, AAAARecordData)):
                addrs.append(str(rr.data.address))
    return addrs
