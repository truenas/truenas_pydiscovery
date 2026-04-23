"""WSDServer._handle_message parse-error classification.

A remote peer sending malformed SOAP/XML must not kill the
receive loop nor spam the ERROR log — the handler catches the
ValueError that ``parse_envelope`` surfaces, logs at debug, and
increments a ``parse_errors`` counter so operators can tell
"network full of broken clients" from "we've never seen a packet"
by reading status.json instead of tailing logs.
"""
from __future__ import annotations

from pathlib import Path

from truenas_pywsd.server.config import DaemonConfig, ServerConfig
from truenas_pywsd.server.net.interface import InterfaceInfo
from truenas_pywsd.server.server import PerInterfaceState, WSDServer


def _make_server(tmp_path: Path) -> WSDServer:
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    return WSDServer(DaemonConfig(
        server=ServerConfig(hostname="host", workgroup="WG"),
        rundir=rundir,
    ))


def _seed_interface(server: WSDServer, ifname: str = "lo") -> None:
    iface = InterfaceInfo(name=ifname, index=1)
    server._interfaces[iface.index] = PerInterfaceState(iface)


class TestParseErrorsCounted:
    def test_malformed_xml_increments_parse_errors(self, tmp_path):
        server = _make_server(tmp_path)
        _seed_interface(server)
        assert server._status._counters.get("parse_errors", 0) == 0

        server._handle_message(
            b"<not xml at all", ("127.0.0.1", 3702), "lo",
        )

        assert server._status._counters["parse_errors"] == 1

    def test_wrong_root_element_increments_parse_errors(
        self, tmp_path,
    ):
        server = _make_server(tmp_path)
        _seed_interface(server)

        # Valid XML, wrong root — parse_envelope raises ValueError.
        server._handle_message(
            b"<?xml version='1.0'?><not-an-envelope/>",
            ("127.0.0.1", 3702), "lo",
        )

        assert server._status._counters["parse_errors"] == 1

    def test_unknown_interface_does_not_increment(self, tmp_path):
        # Early return path (no matching ifstate) must not touch
        # the counter — that's not a parse error, it's a routing
        # miss.
        server = _make_server(tmp_path)
        # No interface seeded; no PerInterfaceState matches.

        server._handle_message(
            b"garbage", ("127.0.0.1", 3702), "lo",
        )

        assert "parse_errors" not in server._status._counters
