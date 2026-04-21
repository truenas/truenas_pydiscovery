"""Tests for WSD message builders and parsers."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from truenas_pywsd.protocol.constants import (
    Action,
    DeviceType,
    Element,
    Prefix,
    urn_uuid,
)
from truenas_pywsd.protocol.messages import (
    build_bye,
    build_get_response,
    build_hello,
    build_probe_match,
    build_resolve_match,
    parse_probe_types,
    parse_resolve_endpoint,
)
from truenas_pywsd.protocol.namespaces import qname
from truenas_pywsd.protocol.soap import parse_envelope

TEST_UUID = "12345678-1234-1234-1234-123456789abc"
TEST_XADDRS = f"http://192.168.1.100:5357/{TEST_UUID}"


class TestHello:
    def test_build_hello(self):
        data = build_hello(TEST_UUID, TEST_XADDRS)
        env = parse_envelope(data)
        assert env.action == Action.HELLO
        assert b"urn:uuid:" + TEST_UUID.encode() in data
        assert TEST_XADDRS.encode() in data

    def test_hello_has_types(self):
        data = build_hello(TEST_UUID, TEST_XADDRS)
        assert b"wsdp:Device" in data
        assert b"pub:Computer" in data

    def test_hello_metadata_version(self):
        data = build_hello(TEST_UUID, TEST_XADDRS, metadata_version=2)
        assert b">2<" in data


class TestBye:
    def test_build_bye(self):
        data = build_bye(TEST_UUID)
        env = parse_envelope(data)
        assert env.action == Action.BYE
        assert b"urn:uuid:" + TEST_UUID.encode() in data

    def test_bye_no_xaddrs(self):
        data = build_bye(TEST_UUID)
        assert b"XAddrs" not in data


class TestProbeMatch:
    def test_build_probe_match(self):
        data = build_probe_match(
            TEST_UUID, relates_to="urn:uuid:probe-123",
        )
        env = parse_envelope(data)
        assert env.action == Action.PROBE_MATCHES
        assert env.relates_to == "urn:uuid:probe-123"
        assert b"wsdp:Device" in data

    def test_probe_match_no_xaddrs(self):
        """ProbeMatch should not include XAddrs (client must Resolve)."""
        data = build_probe_match(TEST_UUID, relates_to="urn:uuid:x")
        assert b"XAddrs" not in data


class TestResolveMatch:
    def test_build_resolve_match(self):
        data = build_resolve_match(
            TEST_UUID, TEST_XADDRS, relates_to="urn:uuid:resolve-456",
        )
        env = parse_envelope(data)
        assert env.action == Action.RESOLVE_MATCHES
        assert env.relates_to == "urn:uuid:resolve-456"
        assert TEST_XADDRS.encode() in data


class TestGetResponse:
    def test_workgroup_mode(self):
        data = build_get_response(
            TEST_UUID, "TRUENAS", "WORKGROUP",
        )
        env = parse_envelope(data)
        assert env.action == Action.GET_RESPONSE
        assert b"TRUENAS/Workgroup:WORKGROUP" in data
        assert b"FriendlyName" in data
        assert b"TrueNAS" in data

    def test_domain_mode(self):
        data = build_get_response(
            TEST_UUID, "TRUENAS", "CORP.COM", is_domain=True,
        )
        assert b"TRUENAS/Domain:CORP.COM" in data

    def test_metadata_sections(self):
        data = build_get_response(TEST_UUID, "HOST", "WG")
        assert b"ThisDevice" in data
        assert b"ThisModel" in data
        assert b"Relationship" in data
        assert b"Computers" in data


class TestParseProbe:
    def test_parse_probe_types(self):
        """Build a Probe body element and parse its types."""
        probe = ET.Element(qname(Prefix.WSD, Element.PROBE))
        ET.SubElement(
            probe, qname(Prefix.WSD, Element.TYPES),
        ).text = DeviceType.DEVICE
        body = ET.Element(qname(Prefix.SOAP, Element.BODY))
        body.append(probe)
        types = parse_probe_types(body)
        assert DeviceType.DEVICE in types

    def test_parse_empty_probe(self):
        types = parse_probe_types(None)
        assert types == []


class TestParseResolve:
    def test_parse_resolve_endpoint(self):
        resolve = ET.Element(qname(Prefix.WSD, Element.RESOLVE))
        epr = ET.SubElement(
            resolve, qname(Prefix.WSA, Element.ENDPOINT_REFERENCE),
        )
        ET.SubElement(
            epr, qname(Prefix.WSA, Element.ADDRESS),
        ).text = urn_uuid(TEST_UUID)
        body = ET.Element(qname(Prefix.SOAP, Element.BODY))
        body.append(resolve)
        endpoint = parse_resolve_endpoint(body)
        assert endpoint == urn_uuid(TEST_UUID)

    def test_parse_empty_resolve(self):
        assert parse_resolve_endpoint(None) == ""
