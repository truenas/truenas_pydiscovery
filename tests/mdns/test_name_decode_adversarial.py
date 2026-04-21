"""Adversarial DNS name decoding: protects against compression-loop
crashes, runaway pointer chains, and truncated labels — classic
attack surface for DNS parsers.
"""
from __future__ import annotations

import pytest

from truenas_pymdns.protocol.name import _MAX_POINTER_DEPTH, decode_name


class TestPointerLoops:
    def test_self_pointer_rejected(self):
        """A pointer that targets its own offset must be rejected,
        not followed into infinite recursion."""
        # 0xC0 0x00 = pointer to offset 0 (its own position).
        data = bytes([0xC0, 0x00])
        with pytest.raises(ValueError, match="pointer loop"):
            decode_name(data, 0)

    def test_two_pointer_loop_rejected(self):
        """A → B → A must be rejected via the ``visited`` set."""
        # Offset 0: pointer to 2.  Offset 2: pointer to 0.
        data = bytes([0xC0, 0x02, 0xC0, 0x00])
        with pytest.raises(ValueError, match="pointer loop"):
            decode_name(data, 0)


class TestPointerBounds:
    def test_pointer_past_end_of_message_rejected(self):
        # Pointer to offset 99 in a 2-byte buffer.
        data = bytes([0xC0, 0x63])
        with pytest.raises(ValueError, match="truncated"):
            decode_name(data, 0)

    def test_truncated_pointer_second_byte_rejected(self):
        """A pointer starts with a 0b11 prefix but the second byte is
        missing — must raise rather than index past the buffer."""
        data = bytes([0xC0])
        with pytest.raises(ValueError, match="truncated"):
            decode_name(data, 0)


class TestTruncatedLabels:
    def test_label_length_exceeds_remaining_buffer(self):
        """A length byte declares more octets than are left in the
        buffer — must raise 'label truncated'."""
        # length=5 but only 2 bytes of label follow, no terminator.
        data = bytes([0x05, 0x61, 0x62])
        with pytest.raises(ValueError, match="truncated"):
            decode_name(data, 0)

    def test_buffer_ends_before_terminator(self):
        """Valid label but no 0x00 terminator before buffer end."""
        data = bytes([0x03, 0x61, 0x62, 0x63])
        with pytest.raises(ValueError, match="truncated"):
            decode_name(data, 0)


class TestCompressionDepthLimit:
    def test_pointer_chain_beyond_max_depth_rejected(self):
        """Even without forming a cycle, a long pointer chain must
        not cause unbounded recursion.  Build a chain that visits
        ``_MAX_POINTER_DEPTH + 5`` unique offsets."""
        # Chain: offset 0 → 2 → 4 → ... → (depth*2) → terminator.
        chain_entries = _MAX_POINTER_DEPTH + 5
        buf = bytearray()
        for i in range(chain_entries):
            next_offset = (i + 1) * 2
            buf.append(0xC0 | (next_offset >> 8))
            buf.append(next_offset & 0xFF)
        # Final destination: a zero terminator.
        buf.append(0x00)

        with pytest.raises(ValueError, match="pointer loop"):
            decode_name(bytes(buf), 0)


class TestNormalDecodeBoundary:
    def test_max_legal_label_length_63_decodes(self):
        """A 63-byte label is the largest legal label (RFC 1035 s2.3.4);
        decoding must succeed."""
        label = b"a" * 63
        data = bytes([63]) + label + bytes([0])
        name, offset = decode_name(data, 0)
        assert name == "a" * 63
        assert offset == 65
