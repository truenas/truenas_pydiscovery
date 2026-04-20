"""WS-Discovery §5.1 URI-scope matching on Probe.

Verifies the pure ``scope_matches`` helper (RFC 3986 prefix rule)
and the integration at the responder level: a scoped Probe triggers
a ProbeMatch only when every probe scope is a canonical prefix of
at least one configured target scope.
"""
from __future__ import annotations

import asyncio
import time
import uuid
import xml.etree.ElementTree as ET

import pytest

from truenas_pywsd.protocol.constants import (
    Action,
    Namespace,
    UDP_UPPER_DELAY,
    WSD_DEVICE_TYPES,
)
from truenas_pywsd.protocol.messages import (
    parse_probe_scopes,
    scope_matches,
)
from truenas_pywsd.protocol.soap import SOAPEnvelope
from truenas_pywsd.server.core.dedup import MessageDedup
from truenas_pywsd.server.core.responder import WSDResponder


class TestScopeMatchesPure:
    def test_empty_probe_scopes_match_anything(self):
        assert scope_matches([], []) is True
        assert scope_matches([], ["http://example.com/a"]) is True

    def test_exact_prefix_match(self):
        targets = ["http://example.com/floor1"]
        assert scope_matches(
            ["http://example.com/floor1"], targets,
        ) is True

    def test_target_strictly_longer_matches(self):
        targets = ["http://example.com/floor1/rack3"]
        assert scope_matches(
            ["http://example.com/floor1"], targets,
        ) is True

    def test_probe_strictly_longer_does_not_match(self):
        targets = ["http://example.com/floor1"]
        assert scope_matches(
            ["http://example.com/floor1/rack3"], targets,
        ) is False

    def test_scheme_and_authority_case_insensitive(self):
        """RFC 3986: scheme and authority are case-insensitive; the
        path is case-sensitive."""
        targets = ["http://Example.Com/Path"]
        assert scope_matches(
            ["HTTP://example.com/Path"], targets,
        ) is True
        # Path remains case-sensitive.
        assert scope_matches(
            ["HTTP://example.com/path"], targets,
        ) is False

    def test_all_probe_scopes_must_match(self):
        targets = ["http://a.com/x", "http://b.com/y"]
        assert scope_matches(
            ["http://a.com/x", "http://b.com/y"], targets,
        ) is True
        assert scope_matches(
            ["http://a.com/x", "http://c.com/z"], targets,
        ) is False

    def test_urn_scheme_canonicalised_to_lowercase(self):
        assert scope_matches(
            ["URN:TestScope"], ["urn:TestScope"],
        ) is True

    def test_trailing_slash_ignored(self):
        targets = ["http://example.com/floor1/"]
        assert scope_matches(
            ["http://example.com/floor1"], targets,
        ) is True


class TestParseProbeScopes:
    def _probe_with_scopes(self, scopes_text: str | None) -> ET.Element:
        body = ET.Element(f"{{{Namespace.SOAP}}}Body")
        probe = ET.SubElement(body, f"{{{Namespace.WSD}}}Probe")
        ET.SubElement(probe, f"{{{Namespace.WSD}}}Types").text = (
            WSD_DEVICE_TYPES
        )
        if scopes_text is not None:
            ET.SubElement(
                probe, f"{{{Namespace.WSD}}}Scopes",
            ).text = scopes_text
        return body

    def test_returns_empty_when_no_scopes_element(self):
        body = self._probe_with_scopes(None)
        assert parse_probe_scopes(body) == []

    def test_splits_whitespace_separated_uris(self):
        body = self._probe_with_scopes(
            "http://a.com/x http://b.com/y",
        )
        assert parse_probe_scopes(body) == [
            "http://a.com/x", "http://b.com/y",
        ]


class TestResponderScopeFiltering:
    def _probe_envelope(
        self, scopes: list[str] | None = None,
    ) -> SOAPEnvelope:
        body = ET.Element(f"{{{Namespace.SOAP}}}Body")
        probe = ET.SubElement(body, f"{{{Namespace.WSD}}}Probe")
        ET.SubElement(
            probe, f"{{{Namespace.WSD}}}Types",
        ).text = WSD_DEVICE_TYPES
        if scopes:
            ET.SubElement(
                probe, f"{{{Namespace.WSD}}}Scopes",
            ).text = " ".join(scopes)
        env = SOAPEnvelope()
        env.action = Action.PROBE
        env.message_id = f"urn:uuid:{uuid.uuid4()}"
        env.body = body
        return env

    @pytest.fixture
    def responder_with_scopes(self):
        cap: list[tuple[bytes, tuple]] = []

        def send(data: bytes, addr: tuple) -> None:
            cap.append((data, addr))

        resp = WSDResponder(
            send, str(uuid.uuid4()), "http://x", MessageDedup(),
            scopes=["http://example.com/floor1"],
        )
        return resp, cap

    def test_matching_scope_triggers_probe_match(
        self, responder_with_scopes,
    ):
        resp, cap = responder_with_scopes

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            env = self._probe_envelope(
                scopes=["http://example.com/floor1"],
            )
            resp.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(UDP_UPPER_DELAY * 3 + 0.3)

        asyncio.run(drive())
        assert cap, "matching scope must produce a ProbeMatch"

    def test_non_matching_scope_suppresses_response(
        self, responder_with_scopes,
    ):
        resp, cap = responder_with_scopes

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            env = self._probe_envelope(
                scopes=["http://example.com/floor99"],
            )
            resp.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(UDP_UPPER_DELAY + 0.2)

        asyncio.run(drive())
        assert cap == []

    def test_no_scopes_in_probe_matches_any_responder(self):
        """An unscoped Probe (no Scopes element) must be answered
        even if the responder has scopes configured."""
        cap: list[tuple[bytes, tuple]] = []
        resp = WSDResponder(
            lambda d, a: cap.append((d, a)),
            str(uuid.uuid4()), "http://x", MessageDedup(),
            scopes=["http://example.com/floor1"],
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            resp._loop = loop
            env = self._probe_envelope(scopes=None)
            resp.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(UDP_UPPER_DELAY * 3 + 0.3)

        asyncio.run(drive())
        assert cap


_ = time  # kept for readability of imports in similar tests
