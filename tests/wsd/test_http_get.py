"""WSD HTTP metadata endpoint (DPWS §4, WS-Transfer Get).

The integration test ``test_fetches_metadata`` was intermittently
flaky because it round-trips via the CLI and depends on daemon
startup timing.  This unit test binds the HTTP server on an
ephemeral port, drives a real HTTP POST with a SOAP Get request,
and asserts the response structure deterministically.
"""
from __future__ import annotations

import asyncio
import socket

from truenas_pywsd.protocol.constants import (
    Action,
    Namespace,
    WellKnownURI,
)
from truenas_pywsd.protocol.soap import build_envelope, parse_envelope
from truenas_pywsd.server.net.http import WSDHttpServer


def _run(coro, timeout: float = 5.0) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
    finally:
        loop.close()


def _free_port() -> int:
    """Grab an ephemeral port by binding & closing a socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_post(
    host: str, port: int, body: bytes,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    """Minimal stdlib-only HTTP/1.1 POST client.

    Returns (status_code, headers_bytes, body_bytes).
    """
    req = [
        b"POST / HTTP/1.1",
        f"Host: {host}:{port}".encode("ascii"),
        f"Content-Length: {len(body)}".encode("ascii"),
        b"Content-Type: application/soap+xml; charset=utf-8",
        b"Connection: close",
    ]
    for k, v in (headers or {}).items():
        req.append(f"{k}: {v}".encode("ascii"))
    req.append(b"")
    req.append(body)
    wire = b"\r\n".join(req)

    sock = socket.create_connection((host, port), timeout=3.0)
    try:
        sock.sendall(wire)
        chunks: list[bytes] = []
        while True:
            c = sock.recv(65536)
            if not c:
                break
            chunks.append(c)
    finally:
        sock.close()
    data = b"".join(chunks)
    header_end = data.find(b"\r\n\r\n")
    assert header_end >= 0, f"no header/body split in {data!r}"
    headers_part = data[:header_end]
    body_part = data[header_end + 4:]
    status_line = headers_part.split(b"\r\n", 1)[0]
    status_code = int(status_line.split()[1])
    return status_code, headers_part, body_part


def _http_send_raw(
    host: str, port: int, wire: bytes,
) -> tuple[int, bytes]:
    sock = socket.create_connection((host, port), timeout=3.0)
    try:
        sock.sendall(wire)
        chunks: list[bytes] = []
        while True:
            c = sock.recv(65536)
            if not c:
                break
            chunks.append(c)
    finally:
        sock.close()
    data = b"".join(chunks)
    status_line = data.split(b"\r\n", 1)[0]
    status_code = int(status_line.split()[1])
    return status_code, data


class TestHTTPServerDispatch:
    def _echo_handler(self, body: bytes) -> bytes:
        """Handler returns a trivial GetResponse with relates_to set
        to the caller's MessageID — proves the handler actually ran."""
        env = parse_envelope(body)
        return build_envelope(
            Action.GET_RESPONSE,
            body_element=None,
            relates_to=env.message_id,
        )

    def test_post_request_returns_200_and_invokes_handler(self):
        port = _free_port()
        server = WSDHttpServer(
            "127.0.0.1", port, self._echo_handler,
        )
        req = build_envelope(
            Action.GET, to=WellKnownURI.WSA_ANONYMOUS,
            message_id="urn:uuid:req-abc",
        )

        async def drive() -> tuple[int, bytes]:
            await server.start()
            try:
                loop = asyncio.get_running_loop()
                status, _hdrs, body = await loop.run_in_executor(
                    None, _http_post, "127.0.0.1", port, req,
                )
                return status, body
            finally:
                await server.stop()

        status, body = _run(drive())
        assert status == 200
        env = parse_envelope(body)
        assert env.action == Action.GET_RESPONSE
        assert env.relates_to == "urn:uuid:req-abc"

    def test_get_request_rejected_as_method_not_allowed(self):
        port = _free_port()
        server = WSDHttpServer(
            "127.0.0.1", port, self._echo_handler,
        )

        async def drive() -> int:
            await server.start()
            try:
                wire = (
                    b"GET / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Connection: close\r\n\r\n"
                )
                loop = asyncio.get_running_loop()
                status, _ = await loop.run_in_executor(
                    None, _http_send_raw, "127.0.0.1", port, wire,
                )
                return status
            finally:
                await server.stop()

        assert _run(drive()) == 405

    def test_oversize_body_rejected(self):
        port = _free_port()
        server = WSDHttpServer(
            "127.0.0.1", port, self._echo_handler,
        )

        async def drive() -> int:
            await server.start()
            try:
                wire = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 999999999\r\n"
                    b"Connection: close\r\n\r\n"
                )
                loop = asyncio.get_running_loop()
                status, _ = await loop.run_in_executor(
                    None, _http_send_raw, "127.0.0.1", port, wire,
                )
                return status
            finally:
                await server.stop()

        assert _run(drive()) == 413

    def test_handler_exception_returns_500(self):
        def raising_handler(_body: bytes) -> bytes:
            raise RuntimeError("boom")

        port = _free_port()
        server = WSDHttpServer("127.0.0.1", port, raising_handler)
        req = build_envelope(Action.GET, message_id="urn:uuid:x")

        async def drive() -> int:
            await server.start()
            try:
                loop = asyncio.get_running_loop()
                status, _, _ = await loop.run_in_executor(
                    None, _http_post, "127.0.0.1", port, req,
                )
                return status
            finally:
                await server.stop()

        assert _run(drive()) == 500


class TestHandlerIntegration:
    def test_response_has_soap_envelope_content_type(self):
        port = _free_port()

        def handler(body: bytes) -> bytes:
            return build_envelope(
                Action.GET_RESPONSE,
                relates_to=parse_envelope(body).message_id,
            )

        server = WSDHttpServer("127.0.0.1", port, handler)
        req = build_envelope(Action.GET, message_id="urn:uuid:y")

        async def drive() -> bytes:
            await server.start()
            try:
                loop = asyncio.get_running_loop()
                _, hdrs, _ = await loop.run_in_executor(
                    None, _http_post, "127.0.0.1", port, req,
                )
                return hdrs
            finally:
                await server.stop()

        hdrs = _run(drive())
        assert b"application/soap+xml" in hdrs
        # Sanity: the SOAP namespace URI doesn't leak into headers.
        assert Namespace.SOAP.encode("ascii") not in hdrs
