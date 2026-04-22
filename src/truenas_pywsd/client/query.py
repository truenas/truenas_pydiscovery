"""Direct WSD query engine.

Sends WS-Discovery Probe via UDP multicast on an ephemeral port.
ProbeMatch responses are unicast back to us.  Also provides HTTP
metadata fetching for Get/GetResponse exchange.
"""
from __future__ import annotations

import asyncio
import re
import socket
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import defusedxml.ElementTree as SafeET  # type: ignore[import-untyped]

from truenas_pywsd.protocol.constants import (
    Action,
    DeviceType,
    Element,
    Prefix,
    WellKnownURI,
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


def build_resolve(endpoint_uuid: str) -> bytes:
    """Build a WSD Resolve message targeting *endpoint_uuid*.

    Per WS-Discovery 1.1 §6.1, Resolve carries the target's endpoint
    reference; the owning device replies via unicast
    ResolveMatches containing XAddrs.  Clients need this fallback
    because Windows hosts (by default) omit XAddrs from their
    ProbeMatches for privacy — see Samba ``wsdd.py`` comment at
    ``source3/script/wsdd.py:744``."""
    resolve = ET.Element(qname(Prefix.WSD, Element.RESOLVE))
    epr = ET.SubElement(
        resolve, qname(Prefix.WSA, Element.ENDPOINT_REFERENCE),
    )
    ET.SubElement(
        epr, qname(Prefix.WSA, Element.ADDRESS),
    ).text = endpoint_uuid
    return build_envelope(Action.RESOLVE, resolve)


def send_resolve(sock: socket.socket, endpoint_uuid: str) -> None:
    """Send a WSD Resolve for *endpoint_uuid* to the multicast group."""
    data = build_resolve(endpoint_uuid)
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


async def resolve_endpoint(
    endpoint_uuid: str,
    timeout: float = 2.0,
    interface_addr: str | None = None,
) -> str:
    """Send a Resolve for *endpoint_uuid* and return its XAddrs.

    Returns the first non-empty XAddrs string from a ResolveMatches
    whose endpoint address matches *endpoint_uuid*; returns an empty
    string if nothing matches within *timeout*.  Used by the
    discovery CLI to extract transport URLs from Windows hosts,
    which omit XAddrs from ProbeMatches by default."""
    sock = create_wsd_socket(interface_addr)
    try:
        send_resolve(sock, endpoint_uuid)
        results: list[SOAPEnvelope] = []
        await collect_responses(sock, timeout, results)
        for env in results:
            if extract_endpoint(env) != endpoint_uuid:
                continue
            xaddrs = extract_xaddrs(env)
            if xaddrs:
                return xaddrs
        return ""
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


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def endpoint_urn_from_xaddrs(url: str) -> str:
    """Derive the ``wsa:To`` value for a WS-Transfer Get from an
    XAddrs URL.

    DPWS devices publish ``http://HOST:PORT/UUID`` where *UUID*
    matches the endpoint's ``urn:uuid:UUID`` identity (DPWS §4.3).
    Windows WSDAPI dispatches incoming Get requests on the
    ``wsa:To`` header and rejects the HTTP URL form with a SOAP
    ``wsa:DestinationUnreachable`` fault; wsdd and our own server
    are permissive and accept either.

    Returns the URN when the final path segment looks like a UUID;
    otherwise returns the original URL.  Non-DPWS WSD services
    (e.g. HP printers advertising ``/WebServices/Device``) fall
    into the second bucket — their servers are permissive enough
    to accept the URL unchanged."""
    parsed = urlparse(url)
    tail = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    if _UUID_RE.match(tail):
        return f"urn:uuid:{tail}"
    return url


async def fetch_metadata(
    url: str,
    timeout: float = 5.0,
    endpoint: str | None = None,
) -> dict:
    """HTTP POST a Get request to a WSD metadata endpoint.

    *endpoint* is the ``wsa:To`` value to put on the Get envelope.
    When ``None`` (the default), it's derived from *url* via
    :func:`endpoint_urn_from_xaddrs` so Windows accepts the
    request.  Callers that already know the endpoint URN (e.g.
    ``wsd-discover`` after a Resolve exchange) should pass it
    explicitly — it's authoritative.

    Returns a dict with device info fields.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 5357

    wsa_to = endpoint if endpoint else endpoint_urn_from_xaddrs(url)
    # WSDAPI rejects Get requests without <wsa:ReplyTo> — observed
    # directly on the wire: a peer that sent anonymous ReplyTo got
    # a GetResponse with metadata, ours (without it) got
    # ``wsa:EndpointUnavailable``.  WS-Addressing 1.0 §3.1 says
    # ReplyTo "SHOULD" be present and that anonymous is the default
    # when absent; Windows enforces the SHOULD as MUST.
    get_body = build_envelope(
        Action.GET, to=wsa_to,
        reply_to=WellKnownURI.WSA_ANONYMOUS,
    )

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

        # Read headers, then exactly Content-Length body bytes.
        # ``reader.read(n)`` with a positive ``n`` returns *up to*
        # n bytes as soon as any data arrives rather than waiting
        # for the full response — a server that writes headers
        # and body in separate TCP segments (observed against our
        # own daemon) leaves the body in the socket if we stop
        # after the first read.  ``reader.read()`` with no arg
        # waits for EOF but is unbounded — a hostile peer could
        # stream indefinitely.  The safe path is to parse headers
        # and Content-Length, then ``readexactly`` the body up to
        # the DPWS §3.4 MAX_ENVELOPE_SIZE cap (WSD_MAX_LEN).
        try:
            header_bytes = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=timeout,
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return {}

        content_length = 0
        for line in header_bytes.split(b"\r\n"):
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"content-length":
                try:
                    content_length = int(value.strip())
                except ValueError:
                    content_length = 0
                break
        if content_length <= 0 or content_length > WSD_MAX_LEN:
            return {}

        try:
            soap_body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=timeout,
            )
        except asyncio.IncompleteReadError:
            return {}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    try:
        env = parse_envelope(soap_body)
    except (ET.ParseError, ValueError):
        return {}

    try:
        root = SafeET.fromstring(soap_body)
    except ET.ParseError:
        return {}

    # WSDAPI (and any other WS-Addressing peer) returns a Fault
    # envelope instead of metadata when it rejects the Get — e.g.
    # ``wsa:DestinationUnreachable`` when ``wsa:To`` doesn't map
    # to a registered endpoint.  Surface the Code and Reason so
    # callers see *why* metadata wasn't returned rather than an
    # empty dict that looks like success.
    is_fault = env.action == Action.FAULT

    info: dict[str, str] = {}
    # SOAP 1.2 Fault nests Code/Value (category like soap:Sender)
    # and Code/Subcode/Value (specific fault like
    # wsa:DestinationUnreachable).  Document-order iteration
    # visits the category first and the subcode last; the
    # subcode is the more useful diagnostic, so we keep the
    # deepest value by overwriting as we walk.
    fault_values: list[str] = []
    for el in root.iter():
        local = el.tag.split("}")[-1] if "}" in el.tag else el.tag
        if is_fault:
            if local == Element.VALUE and el.text and el.text.strip():
                fault_values.append(el.text.strip())
            elif (
                local == Element.TEXT and el.text
                and "fault_reason" not in info
            ):
                info["fault_reason"] = el.text.strip()
        else:
            if local == Element.FRIENDLY_NAME and el.text:
                info["friendly_name"] = el.text
            elif local == Element.MANUFACTURER and el.text:
                info["manufacturer"] = el.text
            elif local == Element.MODEL_NAME and el.text:
                info["model_name"] = el.text
            elif local == Element.COMPUTER and el.text:
                info["computer"] = el.text

    if is_fault and fault_values:
        info["fault"] = fault_values[-1]

    return info
