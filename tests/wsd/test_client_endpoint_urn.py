"""``wsa:To`` derivation for WS-Transfer Get requests.

Windows WSDAPI dispatches incoming Get on the ``wsa:To`` header
and returns ``wsa:DestinationUnreachable`` when that value isn't a
URN it has registered.  Other implementations (wsdd, our own
server) are permissive and accept the HTTP URL form.  The client
therefore derives an endpoint URN from the XAddrs URL — strict
enough for Windows, unchanged for devices that use non-UUID paths.
"""
from __future__ import annotations

import asyncio
import socket

from truenas_pywsd.protocol.constants import Action
from truenas_pywsd.protocol.messages import build_get_response
from truenas_pywsd.protocol.soap import parse_envelope
from truenas_pywsd.client.query import (
    endpoint_urn_from_xaddrs,
    fetch_metadata,
)
from truenas_pywsd.server.net.http import WSDHttpServer


# Documentation-range addresses (RFC 5737) and fixed placeholder
# UUIDs so the test never names real endpoints from debug captures.
_DOC_UUID_LOWER = "00000000-0000-0000-0000-000000000001"
_DOC_UUID_UPPER = "00000000-0000-0000-0000-000000000001".upper()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestEndpointUrnFromXAddrs:
    def test_uuid_path_with_trailing_slash(self):
        # Some servers publish XAddrs with a trailing slash.
        # The derived wsa:To is the endpoint's urn:uuid:UUID —
        # exactly what WSDAPI expects.
        assert endpoint_urn_from_xaddrs(
            f"http://192.0.2.10:5357/{_DOC_UUID_LOWER}/"
        ) == f"urn:uuid:{_DOC_UUID_LOWER}"

    def test_uuid_path_without_trailing_slash(self):
        # Others publish without a trailing slash; both are valid.
        assert endpoint_urn_from_xaddrs(
            f"http://192.0.2.11:5357/{_DOC_UUID_LOWER}"
        ) == f"urn:uuid:{_DOC_UUID_LOWER}"

    def test_non_uuid_path_returns_url_unchanged(self):
        # Some non-DPWS WSD services (HP printers etc.) advertise
        # XAddrs with a free-form path.  We can't derive a URN so
        # we fall back to the URL; the device's own server is
        # permissive and accepts it.
        url = "http://192.0.2.20:80/WebServices/Device"
        assert endpoint_urn_from_xaddrs(url) == url

    def test_uuid_case_preserved(self):
        # RFC 4122 UUIDs are case-insensitive on the wire, but the
        # output preserves the input case because the recipient
        # may dispatch by exact string match against its own
        # registered urn:uuid: identity.
        assert endpoint_urn_from_xaddrs(
            f"http://192.0.2.12:5357/{_DOC_UUID_UPPER}"
        ) == f"urn:uuid:{_DOC_UUID_UPPER}"

    def test_empty_path_returns_url_unchanged(self):
        # Degenerate URL with no path component — nothing to
        # derive from.
        url = "http://192.0.2.13:5357/"
        assert endpoint_urn_from_xaddrs(url) == url


class TestFetchMetadataSendsDerivedURN:
    """End-to-end over loopback: ``fetch_metadata`` must put the
    endpoint URN (not the HTTP URL) into ``<wsa:To>`` so the Get
    actually dispatches on a WSDAPI-style server."""

    def test_get_carries_anonymous_reply_to(self):
        # Windows WSDAPI rejects Get requests without <wsa:ReplyTo>
        # with ``wsa:EndpointUnavailable`` — observed directly on
        # the wire against Windows 11.  WS-Addressing 1.0 §3.1
        # declares anonymous as the implicit default, but WSDAPI
        # enforces the SHOULD as a MUST.  ReplyTo=anonymous is
        # spec-compliant and the minimum for interop.
        captured: list[bytes] = []

        def handler(body: bytes) -> bytes:
            captured.append(body)
            env = parse_envelope(body)
            return build_get_response(
                endpoint_uuid=_DOC_UUID_LOWER,
                hostname="host1",
                workgroup_or_domain="WG",
                is_domain=False,
                relates_to=env.message_id,
            )

        port = _free_port()
        server = WSDHttpServer("127.0.0.1", port, handler)
        url = f"http://127.0.0.1:{port}/{_DOC_UUID_LOWER}"

        async def drive() -> None:
            await server.start()
            try:
                await fetch_metadata(url, timeout=3.0)
            finally:
                await server.stop()

        asyncio.new_event_loop().run_until_complete(drive())
        assert captured
        body = captured[0]
        assert b"<wsa:ReplyTo>" in body
        assert (
            b"http://schemas.xmlsoap.org/ws/2004/08/addressing"
            b"/role/anonymous"
        ) in body

    def test_wsa_to_is_endpoint_urn_when_no_explicit_endpoint(self):
        captured: list[bytes] = []

        def handler(body: bytes) -> bytes:
            captured.append(body)
            # Reply with a minimal valid GetResponse so
            # fetch_metadata doesn't abort with a parse error.
            env = parse_envelope(body)
            return build_get_response(
                endpoint_uuid=_DOC_UUID_LOWER,
                hostname="host1",
                workgroup_or_domain="WG",
                is_domain=False,
                relates_to=env.message_id,
            )

        port = _free_port()
        server = WSDHttpServer("127.0.0.1", port, handler)
        url = f"http://127.0.0.1:{port}/{_DOC_UUID_LOWER}"

        async def drive() -> None:
            await server.start()
            try:
                await fetch_metadata(url, timeout=3.0)
            finally:
                await server.stop()

        asyncio.new_event_loop().run_until_complete(drive())

        assert captured, "handler saw no request"
        env = parse_envelope(captured[0])
        assert env.action == Action.GET
        assert env.to == f"urn:uuid:{_DOC_UUID_LOWER}"

    def test_soap_fault_surfaces_subcode_and_reason(self):
        # When the server returns a SOAP fault (WSDAPI does this
        # with wsa:DestinationUnreachable if wsa:To doesn't match
        # a registered endpoint), ``fetch_metadata`` must surface
        # the fault's deepest Code/Subcode/Value and the Reason
        # text instead of silently returning an empty dict that
        # looks like success.
        import xml.etree.ElementTree as ET

        from truenas_pywsd.protocol.constants import (
            Action, Element, Prefix,
        )
        from truenas_pywsd.protocol.namespaces import qname
        from truenas_pywsd.protocol.soap import build_envelope

        def _build_fault_body() -> ET.Element:
            fault = ET.Element(qname(Prefix.SOAP, Element.FAULT))
            code = ET.SubElement(fault, qname(Prefix.SOAP, Element.CODE))
            ET.SubElement(
                code, qname(Prefix.SOAP, Element.VALUE),
            ).text = "soap:Sender"
            subcode = ET.SubElement(
                code, qname(Prefix.SOAP, Element.SUBCODE),
            )
            ET.SubElement(
                subcode, qname(Prefix.SOAP, Element.VALUE),
            ).text = "wsa:DestinationUnreachable"
            reason = ET.SubElement(
                fault, qname(Prefix.SOAP, Element.REASON),
            )
            ET.SubElement(
                reason, qname(Prefix.SOAP, Element.TEXT),
            ).text = (
                "No route can be determined to reach "
                "the destination role defined by the "
                "WS-Addressing To."
            )
            return fault

        def handler(body: bytes) -> bytes:
            return build_envelope(
                Action.FAULT,
                _build_fault_body(),
                relates_to="urn:uuid:probe",
            )

        port = _free_port()
        server = WSDHttpServer("127.0.0.1", port, handler)
        url = f"http://127.0.0.1:{port}/{_DOC_UUID_LOWER}"

        async def drive() -> dict:
            await server.start()
            try:
                return await fetch_metadata(url, timeout=3.0)
            finally:
                await server.stop()

        info = asyncio.new_event_loop().run_until_complete(drive())

        # The deepest <soap:Value> is the useful diagnostic.
        assert info["fault"] == "wsa:DestinationUnreachable"
        assert "destination" in info["fault_reason"].lower()
        # No metadata was sent, so the content fields are absent —
        # prevents the caller from mistaking a fault for a success.
        assert "friendly_name" not in info
        assert "computer" not in info

    def test_handles_response_split_across_tcp_segments(self):
        # Servers routinely flush HTTP headers before the body
        # (observed on the wire: 111-byte headers segment, then a
        # 2 KB body segment).  ``asyncio.StreamReader.read(n)`` with
        # positive n returns *up to* n bytes as soon as data is
        # available, so a naive single read would catch only the
        # headers and treat the body as empty.  The fix reads the
        # headers with ``readuntil``, parses Content-Length, then
        # ``readexactly(n)`` for the body.
        metadata_body = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<soap:Envelope '
            b'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            b'xmlns:wsa='
            b'"http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            b'xmlns:wsdp='
            b'"http://schemas.xmlsoap.org/ws/2006/02/devprof">'
            b'<soap:Header>'
            b'<wsa:To>'
            b'http://schemas.xmlsoap.org/ws/2004/08/addressing'
            b'/role/anonymous</wsa:To>'
            b'<wsa:Action>'
            b'http://schemas.xmlsoap.org/ws/2004/09/transfer'
            b'/GetResponse</wsa:Action>'
            b'<wsa:MessageID>urn:uuid:resp-1</wsa:MessageID>'
            b'</soap:Header>'
            b'<soap:Body>'
            b'<wsdp:FriendlyName>test-host</wsdp:FriendlyName>'
            b'</soap:Body>'
            b'</soap:Envelope>'
        )
        headers = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/soap+xml\r\n"
            + f"Content-Length: {len(metadata_body)}\r\n".encode()
            + b"Connection: close\r\n"
            b"\r\n"
        )

        async def handle_client(reader, writer):
            # Drain the POST request first.
            try:
                await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=2.0,
                )
            except asyncio.IncompleteReadError:
                writer.close()
                return
            # Write headers, flush, pause, then write body.  The
            # drain + sleep guarantees the reader sees headers
            # alone before the body arrives — the condition that
            # triggered the original bug.
            writer.write(headers)
            await writer.drain()
            await asyncio.sleep(0.05)
            writer.write(metadata_body)
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        port = _free_port()

        async def drive() -> dict:
            server = await asyncio.start_server(
                handle_client, "127.0.0.1", port,
            )
            try:
                return await fetch_metadata(
                    f"http://127.0.0.1:{port}/{_DOC_UUID_LOWER}",
                    timeout=3.0,
                )
            finally:
                server.close()
                await server.wait_closed()

        info = asyncio.new_event_loop().run_until_complete(drive())
        assert info.get("friendly_name") == "test-host"

    def test_explicit_endpoint_overrides_url_derived_value(self):
        # Callers that learned the URN from a prior Resolve
        # exchange (e.g. wsd-discover -r) pass it through so
        # fetch_metadata doesn't re-derive.  The explicit value
        # wins even when the URL would derive something else.
        captured: list[bytes] = []
        explicit = "urn:uuid:deadbeef-dead-beef-dead-beefdeadbeef"

        def handler(body: bytes) -> bytes:
            captured.append(body)
            env = parse_envelope(body)
            return build_get_response(
                endpoint_uuid=explicit,
                hostname="host1",
                workgroup_or_domain="WG",
                is_domain=False,
                relates_to=env.message_id,
            )

        port = _free_port()
        server = WSDHttpServer("127.0.0.1", port, handler)
        # URL carries a different UUID; the explicit endpoint
        # argument should take precedence.
        url = f"http://127.0.0.1:{port}/{_DOC_UUID_LOWER}"

        async def drive() -> None:
            await server.start()
            try:
                await fetch_metadata(
                    url, timeout=3.0, endpoint=explicit,
                )
            finally:
                await server.stop()

        asyncio.new_event_loop().run_until_complete(drive())

        env = parse_envelope(captured[0])
        assert env.to == explicit
