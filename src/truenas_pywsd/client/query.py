"""Direct WSD query engine.

Sends WS-Discovery Probe via UDP multicast on an ephemeral port.
ProbeMatch responses are unicast back to us.  Also provides HTTP
metadata fetching for Get/GetResponse exchange.
"""
from __future__ import annotations

import asyncio
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import defusedxml.ElementTree as SafeET  # type: ignore[import-untyped]

from truenas_pywsd.protocol.constants import (
    Action,
    DeviceType,
    Element,
    Prefix,
    WSD_MAX_LEN,
    WSD_MCAST_V4,
    WSD_UDP_PORT,
)
from truenas_pywsd.protocol.namespaces import qname
from truenas_pywsd.protocol.soap import SOAPEnvelope, build_envelope, parse_envelope


def create_wsd_socket(interface_addr: str | None = None) -> socket.socket:
    """Create a UDP socket for sending WSD Probe queries.

    Binds to an ephemeral port.  ProbeMatch responses are
    unicast back to this socket.
    """
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    if interface_addr is not None:
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(interface_addr),
        )
    sock.setblocking(False)
    sock.bind(("", 0))
    return sock


def build_probe() -> bytes:
    """Build a WSD Probe message for wsdp:Device."""
    probe = ET.Element(qname(Prefix.WSD, Element.PROBE))
    ET.SubElement(
        probe, qname(Prefix.WSD, Element.TYPES),
    ).text = DeviceType.DEVICE
    return build_envelope(Action.PROBE, probe)


def send_probe(sock: socket.socket) -> None:
    """Send a WSD Probe to the multicast group."""
    data = build_probe()
    sock.sendto(data, (WSD_MCAST_V4, WSD_UDP_PORT))


async def collect_responses(
    sock: socket.socket,
    timeout: float,
    results: list[SOAPEnvelope],
) -> None:
    """Receive WSD responses and append parsed envelopes to *results*."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock, WSD_MAX_LEN),
                timeout=remaining,
            )
        except TimeoutError:
            break
        try:
            env = parse_envelope(data)
        except (ValueError, Exception):
            continue
        if env.action in (
            Action.PROBE_MATCHES,
            Action.RESOLVE_MATCHES,
            Action.HELLO,
        ):
            results.append(env)


async def discover_devices(
    timeout: float = 4.0,
    interface_addr: str | None = None,
) -> list[SOAPEnvelope]:
    """Send a Probe and return all ProbeMatch/ResolveMatch responses."""
    sock = create_wsd_socket(interface_addr)
    try:
        send_probe(sock)
        results: list[SOAPEnvelope] = []
        await collect_responses(sock, timeout, results)
        return results
    finally:
        sock.close()


def extract_endpoint(env: SOAPEnvelope) -> str:
    """Extract the endpoint address from a ProbeMatch/ResolveMatch body."""
    if env.body is None:
        return ""
    for tag in (Element.PROBE_MATCHES, Element.RESOLVE_MATCHES):
        container = env.body.find(qname(Prefix.WSD, tag))
        if container is None:
            continue
        match_tag = (
            Element.PROBE_MATCH if tag == Element.PROBE_MATCHES
            else Element.RESOLVE_MATCH
        )
        match = container.find(qname(Prefix.WSD, match_tag))
        if match is None:
            continue
        epr = match.find(qname(Prefix.WSA, Element.ENDPOINT_REFERENCE))
        if epr is None:
            continue
        addr = epr.find(qname(Prefix.WSA, Element.ADDRESS))
        if addr is not None and addr.text:
            return addr.text
    return ""


def extract_xaddrs(env: SOAPEnvelope) -> str:
    """Extract XAddrs from a ProbeMatch/ResolveMatch body."""
    if env.body is None:
        return ""
    for tag in (Element.PROBE_MATCHES, Element.RESOLVE_MATCHES):
        container = env.body.find(qname(Prefix.WSD, tag))
        if container is None:
            continue
        match_tag = (
            Element.PROBE_MATCH if tag == Element.PROBE_MATCHES
            else Element.RESOLVE_MATCH
        )
        match = container.find(qname(Prefix.WSD, match_tag))
        if match is None:
            continue
        xaddrs = match.find(qname(Prefix.WSD, Element.XADDRS))
        if xaddrs is not None and xaddrs.text:
            return xaddrs.text
    return ""


async def fetch_metadata(url: str, timeout: float = 5.0) -> dict:
    """HTTP POST a Get request to a WSD metadata endpoint.

    Returns a dict with device info fields.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 5357

    get_body = build_envelope(Action.GET, to=url)

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )
    try:
        request = (
            f"POST {parsed.path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/soap+xml; charset=utf-8\r\n"
            f"Content-Length: {len(get_body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + get_body
        writer.write(request)
        await writer.drain()

        response = await asyncio.wait_for(
            reader.read(WSD_MAX_LEN), timeout=timeout,
        )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    # Skip HTTP headers
    body_start = response.find(b"\r\n\r\n")
    if body_start < 0:
        return {}
    soap_body = response[body_start + 4:]

    try:
        root = SafeET.fromstring(soap_body)
    except ET.ParseError:
        return {}

    info: dict[str, str] = {}

    # Extract metadata fields
    for el in root.iter():
        local = el.tag.split("}")[-1] if "}" in el.tag else el.tag
        if local == Element.FRIENDLY_NAME and el.text:
            info["friendly_name"] = el.text
        elif local == Element.MANUFACTURER and el.text:
            info["manufacturer"] = el.text
        elif local == Element.MODEL_NAME and el.text:
            info["model_name"] = el.text
        elif local == Element.COMPUTER and el.text:
            info["computer"] = el.text

    return info
