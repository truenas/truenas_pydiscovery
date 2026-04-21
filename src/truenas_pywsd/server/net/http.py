"""Async HTTP server for WS-MetadataExchange (port 5357).

Handles SOAP POST requests for Get/GetResponse metadata exchange.
Minimal HTTP parsing — just enough for WSD metadata retrieval.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable

from truenas_pywsd.protocol.constants import (
    HTTP_REQUEST_TIMEOUT_S,
    WSD_MAX_LEN,
)

logger = logging.getLogger(__name__)

# Handler: (request_body: bytes) -> response_body: bytes
MetadataHandler = Callable[[bytes], bytes]

CONTENT_TYPE = "application/soap+xml; charset=utf-8"


class WSDHttpServer:
    """Async HTTP server for WSD metadata exchange."""

    def __init__(
        self,
        bind_addr: str,
        port: int,
        handler: MetadataHandler,
    ) -> None:
        self._bind_addr = bind_addr
        self._port = port
        self._handler = handler
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start listening for HTTP connections."""
        self._server = await asyncio.start_server(
            self._handle_connection, self._bind_addr, self._port,
        )
        logger.info(
            "WSD HTTP server listening on %s:%d",
            self._bind_addr, self._port,
        )

    async def stop(self) -> None:
        """Stop the HTTP server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            # Read HTTP request line + headers
            request_line = await asyncio.wait_for(
                reader.readline(), timeout=HTTP_REQUEST_TIMEOUT_S,
            )
            if not request_line:
                return

            # Read headers until blank line
            content_length = 0
            while True:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=HTTP_REQUEST_TIMEOUT_S,
                )
                if line in (b"\r\n", b"\n", b""):
                    break
                header = line.decode("utf-8", errors="replace").strip()
                if header.lower().startswith("content-length:"):
                    try:
                        content_length = int(header.split(":", 1)[1].strip())
                    except ValueError:
                        self._send_response(writer, 400, b"Bad Request")
                        return

            # Only handle POST
            method = request_line.split(b" ")[0] if request_line else b""
            if method != b"POST" or content_length <= 0:
                self._send_response(writer, 405, b"Method Not Allowed")
                return

            if content_length > WSD_MAX_LEN:
                self._send_response(writer, 413, b"Content Too Large")
                return

            # Read body
            body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=HTTP_REQUEST_TIMEOUT_S,
            )

            # Process SOAP request
            try:
                response_body = self._handler(body)
            except Exception as e:
                logger.error("Metadata handler error: %s", e)
                self._send_response(
                    writer, 500, b"Internal Server Error",
                )
                return

            # Send HTTP response
            response_headers = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: {CONTENT_TYPE}\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            writer.write(response_headers.encode("utf-8"))
            writer.write(response_body)
            await writer.drain()

        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
    ) -> None:
        reason = {
            200: "OK", 400: "Bad Request", 405: "Method Not Allowed",
            413: "Content Too Large", 500: "Internal Server Error",
        }
        response = (
            f"HTTP/1.1 {status} {reason.get(status, 'Error')}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        writer.write(response.encode("utf-8") + body)
