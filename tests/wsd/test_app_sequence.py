"""WS-Discovery §7 AppSequence invariants.

The AppSequence header carries three fields:
  * ``InstanceId`` — fixed per daemon lifetime
  * ``SequenceId`` — per-group; each group gets a stable URN
  * ``MessageNumber`` — monotonically increasing across messages

This test exercises the invariants at the builder level so we don't
regress if someone tweaks the soap.py layout.
"""
from __future__ import annotations

import re

from truenas_pywsd.protocol.constants import Action
from truenas_pywsd.protocol.messages import (
    build_bye,
    build_hello,
    build_probe_match,
    build_resolve_match,
)
from truenas_pywsd.protocol.soap import build_envelope


_APPSEQ_RE = re.compile(
    rb'<wsd:AppSequence\s+[^/]*InstanceId="(?P<inst>\d+)"\s+'
    rb'SequenceId="(?P<seq>urn:uuid:[^"]+)"\s+'
    rb'MessageNumber="(?P<msgnum>\d+)"',
)


def _extract_appseq(data: bytes) -> dict[str, object] | None:
    m = _APPSEQ_RE.search(data)
    if m is None:
        return None
    return {
        "instance_id": int(m.group("inst")),
        "sequence_id": m.group("seq").decode("ascii"),
        "message_number": int(m.group("msgnum")),
    }


class TestHelloAndByeAppSequence:
    def test_both_include_appsequence(self):
        hello = build_hello("uuid-a", "http://x", app_sequence=7,
                            message_number=1)
        bye = build_bye("uuid-a", app_sequence=7, message_number=2)
        h = _extract_appseq(hello)
        b = _extract_appseq(bye)
        assert h is not None
        assert b is not None

    def test_instance_id_stable_across_messages(self):
        hello = build_hello("uuid-a", "http://x", app_sequence=42,
                            message_number=1)
        bye = build_bye("uuid-a", app_sequence=42, message_number=2)
        assert _extract_appseq(hello)["instance_id"] == 42
        assert _extract_appseq(bye)["instance_id"] == 42

    def test_message_number_monotonic_across_announcements(self):
        hello = build_hello("uuid-a", "http://x", app_sequence=1,
                            message_number=1)
        bye = build_bye("uuid-a", app_sequence=1, message_number=5)
        assert (
            _extract_appseq(hello)["message_number"]
            < _extract_appseq(bye)["message_number"]
        )


class TestProbeAndResolveOmitAppSequence:
    """RFC / WS-Discovery §7: AppSequence is required on Hello/Bye
    (announcements) but MUST NOT appear on request/response messages
    that are not announcements — Probe, Resolve, ProbeMatches,
    ResolveMatches.  Our builders call ``build_envelope`` without
    an ``app_sequence`` argument for those paths."""

    def test_probe_match_has_no_appsequence(self):
        data = build_probe_match("uuid-a", relates_to="urn:uuid:orig")
        assert _extract_appseq(data) is None
        assert b"AppSequence" not in data

    def test_resolve_match_has_no_appsequence(self):
        data = build_resolve_match(
            "uuid-a", xaddrs="http://x",
            relates_to="urn:uuid:orig",
        )
        assert _extract_appseq(data) is None
        assert b"AppSequence" not in data

    def test_envelope_without_app_sequence_omits_header(self):
        """If build_envelope is called without an app_sequence
        argument at all, the AppSequence header must be absent."""
        data = build_envelope(Action.PROBE)
        assert b"AppSequence" not in data


class TestSequenceIdUniqueness:
    def test_sequence_id_differs_per_announcement(self):
        """Each AppSequence gets a fresh SequenceId (URN).  Two
        consecutive Hello builds with the same InstanceId and
        MessageNumber must still produce different SequenceIds."""
        a = build_hello("uuid-a", "http://x", app_sequence=1,
                        message_number=1)
        b = build_hello("uuid-a", "http://x", app_sequence=1,
                        message_number=1)
        seq_a = _extract_appseq(a)["sequence_id"]
        seq_b = _extract_appseq(b)["sequence_id"]
        assert seq_a != seq_b

    def test_sequence_id_is_urn_uuid_format(self):
        data = build_hello("uuid-a", "http://x", app_sequence=1)
        seq = _extract_appseq(data)["sequence_id"]
        assert seq.startswith("urn:uuid:")
        # UUID portion after the prefix should match UUID shape.
        uuid_part = seq[len("urn:uuid:"):]
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$",
            uuid_part,
        ), f"bad UUID format: {uuid_part}"
