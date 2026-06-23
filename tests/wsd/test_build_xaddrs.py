"""WSDServer._build_xaddrs multi-URL emission.

WS-Discovery 1.1 §5.3 allows ``wsd:XAddrs`` to carry multiple
whitespace-separated URLs.  We advertise one URL per reachable
metadata endpoint: every IPv4 address (one per subnet) and every
link-local IPv6 address (bracketed per RFC 3986, zone-less).  A
single-URL advertisement would leave secondary-subnet — or
IPv6-only — clients with an unreachable XAddr.
"""
from __future__ import annotations

import tempfile
from ipaddress import IPv4Interface, IPv6Interface
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


def _iface(
    addrs_v4: list[IPv4Interface] | None = None,
    addrs_v6: list[IPv6Interface] | None = None,
) -> InterfaceInfo:
    return InterfaceInfo(
        name="eth0", index=2,
        addrs_v4=addrs_v4 or [],
        addrs_v6=addrs_v6 or [],
    )


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


class TestBuildXaddrsIPv6:
    def test_link_local_v6_emits_bracketed_url_after_v4(self):
        server = _make_server()
        iface = _iface(
            [IPv4Interface("10.0.0.1/24")],
            [IPv6Interface("fe80::1/64")],
        )
        parts = server._build_xaddrs(iface).split(" ")
        assert parts == [
            f"http://10.0.0.1:{WSD_HTTP_PORT}/{server._endpoint_uuid}",
            f"http://[fe80::1]:{WSD_HTTP_PORT}/{server._endpoint_uuid}",
        ]

    def test_global_v6_is_not_advertised(self):
        """WSD is link-scoped (ff02::c); like wsdd / wsdd-native we
        serve metadata only over link-local v6, never global/ULA."""
        server = _make_server()
        iface = _iface(
            [],
            [IPv6Interface("2001:db8::5/64"), IPv6Interface("fe80::2/64")],
        )
        xaddrs = server._build_xaddrs(iface)
        assert "2001:db8" not in xaddrs
        assert f"http://[fe80::2]:{WSD_HTTP_PORT}/{server._endpoint_uuid}" \
            == xaddrs

    def test_ipv6_only_interface_still_advertises(self):
        """Regression for the v4-only XAddrs gap: a link-local-v6-only
        interface must still hand clients a metadata endpoint instead
        of an empty XAddrs."""
        server = _make_server()
        iface = _iface([], [IPv6Interface("fe80::3/64")])
        assert server._build_xaddrs(iface) == (
            f"http://[fe80::3]:{WSD_HTTP_PORT}/{server._endpoint_uuid}"
        )

    def test_link_local_v6_url_carries_no_zone_index(self):
        """The advertised URL is zone-less — the peer supplies its own
        zone from the receiving interface (matching wsdd /
        wsdd-native, which zero the scope id before formatting)."""
        server = _make_server()
        iface = _iface([], [IPv6Interface("fe80::4/64")])
        assert "%" not in server._build_xaddrs(iface)
