"""WSD responder on-link source filter.

Verifies that ``WSDResponder.handle_message`` drops Probe/Resolve
datagrams whose source IP isn't reachable on any of the interface
addresses it was constructed with, and accepts those that are.
See ``WSDResponder`` docstring for the reflector-attack rationale
and the known §5.2.2 directed-Probe limitation.
"""
from __future__ import annotations

import asyncio
import uuid
import xml.etree.ElementTree as ET
from ipaddress import IPv4Interface, IPv6Interface

from truenas_pywsd.protocol.constants import (
    Action,
    Namespace,
    UDP_UPPER_DELAY,
    WSD_DEVICE_TYPES,
    urn_uuid,
)
from truenas_pywsd.protocol.soap import SOAPEnvelope
from truenas_pywsd.server.core.dedup import MessageDedup
from truenas_pywsd.server.core.responder import WSDResponder


def _probe_envelope() -> SOAPEnvelope:
    body = ET.Element(f"{{{Namespace.SOAP}}}Body")
    probe = ET.SubElement(body, f"{{{Namespace.WSD}}}Probe")
    ET.SubElement(probe, f"{{{Namespace.WSD}}}Types").text = (
        WSD_DEVICE_TYPES
    )
    env = SOAPEnvelope()
    env.action = Action.PROBE
    env.message_id = f"urn:uuid:{uuid.uuid4()}"
    env.body = body
    return env


def _resolve_envelope(endpoint: str) -> SOAPEnvelope:
    body = ET.Element(f"{{{Namespace.SOAP}}}Body")
    resolve = ET.SubElement(body, f"{{{Namespace.WSD}}}Resolve")
    epr = ET.SubElement(resolve, f"{{{Namespace.WSA}}}EndpointReference")
    ET.SubElement(epr, f"{{{Namespace.WSA}}}Address").text = endpoint
    env = SOAPEnvelope()
    env.action = Action.RESOLVE
    env.message_id = f"urn:uuid:{uuid.uuid4()}"
    env.body = body
    return env


def _make_responder(
    addrs_v4: list[IPv4Interface] | None = None,
    addrs_v6: list[IPv6Interface] | None = None,
) -> tuple[WSDResponder, list[tuple]]:
    cap: list[tuple] = []
    endpoint_uuid = str(uuid.uuid4())
    resp = WSDResponder(
        lambda d, a: cap.append((d, a)),
        endpoint_uuid,
        "http://x",
        MessageDedup(),
        addrs_v4=addrs_v4 or [],
        addrs_v6=addrs_v6 or [],
    )
    return resp, cap


class TestIsOnLinkPure:
    def test_ipv4_in_subnet_passes(self):
        resp, _ = _make_responder(
            addrs_v4=[IPv4Interface("10.0.0.1/24")],
        )
        assert resp._is_on_link(("10.0.0.9", 3702)) is True

    def test_ipv4_outside_subnet_rejected(self):
        resp, _ = _make_responder(
            addrs_v4=[IPv4Interface("10.0.0.1/24")],
        )
        assert resp._is_on_link(("10.0.1.9", 3702)) is False

    def test_ipv4_no_addresses_rejects_everything(self):
        """Fail-safe: an interface with no configured addresses
        answers nothing."""
        resp, _ = _make_responder()
        assert resp._is_on_link(("10.0.0.9", 3702)) is False

    def test_ipv4_multiple_subnets(self):
        """Secondary aliases on the same interface are admitted so
        long as the source falls inside any of them."""
        resp, _ = _make_responder(
            addrs_v4=[
                IPv4Interface("10.0.0.1/24"),
                IPv4Interface("192.168.1.1/24"),
            ],
        )
        assert resp._is_on_link(("10.0.0.9", 3702)) is True
        assert resp._is_on_link(("192.168.1.50", 3702)) is True
        assert resp._is_on_link(("172.16.0.1", 3702)) is False

    def test_ipv6_link_local_always_passes(self):
        """``fe80::/10`` is per-interface; our receive socket is
        already scoped to one interface via ``SO_BINDTODEVICE``."""
        resp, _ = _make_responder()
        assert resp._is_on_link(
            ("fe80::1234", 3702, 0, 2),
        ) is True

    def test_ipv6_global_in_subnet_passes(self):
        resp, _ = _make_responder(
            addrs_v6=[IPv6Interface("2001:db8::1/64")],
        )
        assert resp._is_on_link(
            ("2001:db8::42", 3702, 0, 0),
        ) is True

    def test_ipv6_global_outside_subnet_rejected(self):
        resp, _ = _make_responder(
            addrs_v6=[IPv6Interface("2001:db8::1/64")],
        )
        assert resp._is_on_link(
            ("2001:db8:1::1", 3702, 0, 0),
        ) is False

    def test_malformed_source_rejected(self):
        resp, _ = _make_responder(
            addrs_v4=[IPv4Interface("10.0.0.1/24")],
        )
        assert resp._is_on_link(("not-an-ip", 3702)) is False
        assert resp._is_on_link(()) is False


class TestHandleMessageFilter:
    def test_off_link_probe_elicits_no_reply(self):
        resp, cap = _make_responder(
            addrs_v4=[IPv4Interface("10.0.0.1/24")],
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            resp.handle_message(_probe_envelope(), ("203.0.113.5", 3702))
            await asyncio.sleep(UDP_UPPER_DELAY * 3 + 0.3)

        asyncio.run(drive())
        assert cap == [], (
            "off-link Probe must not elicit a ProbeMatch"
        )

    def test_on_link_probe_elicits_reply(self):
        resp, cap = _make_responder(
            addrs_v4=[IPv4Interface("10.0.0.1/24")],
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            resp.handle_message(_probe_envelope(), ("10.0.0.9", 3702))
            await asyncio.sleep(UDP_UPPER_DELAY * 3 + 0.3)

        asyncio.run(drive())
        assert cap, "on-link Probe must elicit a ProbeMatch"

    def test_off_link_resolve_elicits_no_reply(self):
        endpoint_uuid = str(uuid.uuid4())
        cap: list[tuple] = []
        resp = WSDResponder(
            lambda d, a: cap.append((d, a)),
            endpoint_uuid,
            "http://x",
            MessageDedup(),
            addrs_v4=[IPv4Interface("10.0.0.1/24")],
            addrs_v6=[],
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            resp.handle_message(
                _resolve_envelope(urn_uuid(endpoint_uuid)),
                ("203.0.113.5", 3702),
            )
            await asyncio.sleep(UDP_UPPER_DELAY * 3 + 0.3)

        asyncio.run(drive())
        assert cap == []

    def test_secondary_subnet_probe_elicits_reply(self):
        """Regression for the multi-address interface fix — a Probe
        from a secondary subnet must be answered now that
        ``enumerate_addresses`` returns all IPv4 addresses."""
        resp, cap = _make_responder(
            addrs_v4=[
                IPv4Interface("10.0.0.1/24"),
                IPv4Interface("192.168.1.1/24"),
            ],
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            resp.handle_message(
                _probe_envelope(), ("192.168.1.50", 3702),
            )
            await asyncio.sleep(UDP_UPPER_DELAY * 3 + 0.3)

        asyncio.run(drive())
        assert cap, (
            "secondary-subnet Probe must elicit a ProbeMatch"
        )
