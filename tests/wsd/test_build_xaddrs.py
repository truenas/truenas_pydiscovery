"""WSDServer._build_xaddrs multi-URL emission.

WS-Discovery 1.1 §5.3 allows ``wsd:XAddrs`` to carry multiple
whitespace-separated URLs.  When an interface has more than one
IPv4 address (one per subnet), we advertise one URL per address
so a client on any of those subnets gets a reachable metadata
endpoint.  A single-URL advertisement leaves secondary-subnet
clients with an unreachable XAddr.
"""
from __future__ import annotations

import tempfile
from ipaddress import IPv4Interface
from pathlib import Path

from truenas_pywsd.protocol.constants import WSD_HTTP_PORT
from truenas_pywsd.server.config import DaemonConfig, ServerConfig
from truenas_pywsd.server.net.interface import InterfaceInfo
from truenas_pywsd.server.server import WSDServer


def _make_server() -> WSDServer:
    with tempfile.TemporaryDirectory() as tmp:
        config = DaemonConfig(
            server=ServerConfig(
                hostname="testhost",
                workgroup="TESTGROUP",
                interfaces=["eth0"],
            ),
            rundir=Path(tmp),
        )
        return WSDServer(config)


def _iface(addrs: list[IPv4Interface]) -> InterfaceInfo:
    return InterfaceInfo(name="eth0", index=2, addrs_v4=addrs)


class TestBuildXaddrs:
    def test_single_address_emits_one_url(self):
        server = _make_server()
        iface = _iface([IPv4Interface("10.0.0.1/24")])
        xaddrs = server._build_xaddrs(iface)
        assert xaddrs == (
            f"http://10.0.0.1:{WSD_HTTP_PORT}/{server._endpoint_uuid}"
        )

    def test_multiple_addresses_emit_space_separated_urls(self):
        server = _make_server()
        iface = _iface([
            IPv4Interface("10.0.0.1/24"),
            IPv4Interface("192.168.1.1/24"),
        ])
        xaddrs = server._build_xaddrs(iface)
        parts = xaddrs.split(" ")
        assert parts == [
            f"http://10.0.0.1:{WSD_HTTP_PORT}/{server._endpoint_uuid}",
            f"http://192.168.1.1:{WSD_HTTP_PORT}/{server._endpoint_uuid}",
        ]

    def test_no_addresses_yields_empty_string(self):
        server = _make_server()
        iface = _iface([])
        assert server._build_xaddrs(iface) == ""

    def test_url_uses_address_only_not_prefix(self):
        """Regression: ``str(IPv4Interface)`` returns ``'10.0.0.1/24'``
        — we must use ``.ip`` so the URL host is bare."""
        server = _make_server()
        iface = _iface([IPv4Interface("10.0.0.1/24")])
        xaddrs = server._build_xaddrs(iface)
        assert "/24" not in xaddrs
