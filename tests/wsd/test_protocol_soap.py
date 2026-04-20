"""Tests for WSD SOAP envelope building and parsing."""
from __future__ import annotations

import pytest

from truenas_pywsd.protocol.constants import Action
from truenas_pywsd.protocol.soap import build_envelope, parse_envelope


class TestBuildEnvelope:
    def test_basic_envelope(self):
        data = build_envelope(Action.HELLO)
        assert b"soap:Envelope" in data
        assert Action.HELLO.encode() in data

    def test_message_id_generated(self):
        data = build_envelope(Action.HELLO)
        assert b"urn:uuid:" in data

    def test_relates_to(self):
        data = build_envelope(
            Action.HELLO, relates_to="urn:uuid:test-123",
        )
        assert b"urn:uuid:test-123" in data

    def test_app_sequence(self):
        data = build_envelope(Action.HELLO, app_sequence=42)
        assert b"AppSequence" in data
        assert b'InstanceId="42"' in data


class TestParseEnvelope:
    def test_round_trip(self):
        data = build_envelope(Action.HELLO, message_id="urn:uuid:abc")
        env = parse_envelope(data)
        assert env.action == Action.HELLO
        assert env.message_id == "urn:uuid:abc"

    def test_to_field(self):
        data = build_envelope(Action.PROBE, to="urn:custom:target")
        env = parse_envelope(data)
        assert env.to == "urn:custom:target"

    def test_relates_to_round_trip(self):
        data = build_envelope(
            Action.HELLO, relates_to="urn:uuid:original",
        )
        env = parse_envelope(data)
        assert env.relates_to == "urn:uuid:original"

    def test_body_present(self):
        data = build_envelope(Action.HELLO)
        env = parse_envelope(data)
        assert env.body is not None

    def test_malformed_xml(self):
        with pytest.raises(ValueError, match="XML parse error"):
            parse_envelope(b"not xml at all")

    def test_wrong_root_element(self):
        with pytest.raises(ValueError, match="Expected SOAP Envelope"):
            parse_envelope(b"<notsoap/>")


class TestDefusedXml:
    def test_xxe_blocked(self):
        """defusedxml should block XML entity expansion attacks."""
        xxe_payload = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE foo ['
            b'<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            b']>'
            b'<soap:Envelope xmlns:soap='
            b'"http://www.w3.org/2003/05/soap-envelope">'
            b'<soap:Header/><soap:Body>&xxe;</soap:Body>'
            b'</soap:Envelope>'
        )
        with pytest.raises((ValueError, Exception)):
            parse_envelope(xxe_payload)
