"""Tests for NetBIOS name encoding/decoding.

Test patterns informed by Samba source4/torture/nbt/wins.c which tests
names with various types, scopes (including 237/238 byte boundary),
case sensitivity, and special characters.
"""
from __future__ import annotations

import pytest

from truenas_pynetbiosns.protocol.name import (
    NetBIOSName,
    decode_netbios_name,
    encode_netbios_name,
)


class TestNetBIOSName:
    def test_str_representation(self):
        n = NetBIOSName("TRUENAS", 0x20)
        assert str(n) == "TRUENAS<20>"

    def test_str_with_scope(self):
        n = NetBIOSName("HOST", 0x00, "example.com")
        assert str(n) == "HOST<00>.example.com"

    def test_case_insensitive_equality(self):
        a = NetBIOSName("TRUENAS", 0x20)
        b = NetBIOSName("truenas", 0x20)
        assert a == b

    def test_case_insensitive_hash(self):
        a = NetBIOSName("TRUENAS", 0x20)
        b = NetBIOSName("truenas", 0x20)
        assert hash(a) == hash(b)

    def test_different_type_not_equal(self):
        a = NetBIOSName("HOST", 0x00)
        b = NetBIOSName("HOST", 0x20)
        assert a != b

    def test_scope_case_insensitive(self):
        a = NetBIOSName("HOST", 0x00, "Example.Com")
        b = NetBIOSName("HOST", 0x00, "example.com")
        assert a == b
        assert hash(a) == hash(b)


class TestEncodeName:
    def test_simple_name(self):
        wire = encode_netbios_name("TRUENAS", 0x20)
        # Length prefix = 0x20 (32), then 32 encoded bytes, then 0x00
        assert wire[0] == 0x20
        assert len(wire) == 1 + 32 + 1  # prefix + encoded + null

    def test_name_padded_with_spaces(self):
        wire = encode_netbios_name("A", 0x00)
        # Decode back to verify padding
        name, _ = decode_netbios_name(wire)
        assert name.name == "A"
        assert name.name_type == 0x00

    def test_name_uppercased(self):
        wire1 = encode_netbios_name("host", 0x20)
        wire2 = encode_netbios_name("HOST", 0x20)
        assert wire1 == wire2

    def test_type_byte_preserved(self):
        for name_type in (0x00, 0x03, 0x20, 0x1B, 0x1D, 0x1E):
            wire = encode_netbios_name("TEST", name_type)
            name, _ = decode_netbios_name(wire)
            assert name.name_type == name_type

    def test_half_ascii_encoding(self):
        # 'T' = 0x54 → 0x46 ('F'), 0x45 ('E')
        wire = encode_netbios_name("T", 0x00)
        assert wire[1] == 0x46  # 0x54 >> 4 + 0x41 = 0x46
        assert wire[2] == 0x45  # 0x54 & 0x0F + 0x41 = 0x45

    def test_with_scope(self):
        wire = encode_netbios_name("HOST", 0x20, "example.com")
        name, _ = decode_netbios_name(wire)
        assert name.name == "HOST"
        assert name.name_type == 0x20
        assert name.scope == "example.com"

    def test_scope_label_too_long(self):
        long_label = "a" * 64
        with pytest.raises(ValueError, match="Scope label too long"):
            encode_netbios_name("HOST", 0x20, long_label)

    def test_max_name_length_truncated(self):
        wire = encode_netbios_name("ABCDEFGHIJKLMNOP", 0x20)  # 16 chars
        name, _ = decode_netbios_name(wire)
        assert len(name.name) <= 15

    def test_empty_name(self):
        wire = encode_netbios_name("", 0x00)
        name, _ = decode_netbios_name(wire)
        assert name.name == ""
        assert name.name_type == 0x00

    def test_wildcard_name(self):
        """Wildcard name '*' used for node status queries."""
        wire = encode_netbios_name("*", 0x00)
        name, _ = decode_netbios_name(wire)
        assert name.name == "*"


class TestDecodeName:
    def test_round_trip(self):
        for test_name in ("TRUENAS", "A", "MY-HOST", "HOST.NAME"):
            for name_type in (0x00, 0x03, 0x20):
                wire = encode_netbios_name(test_name, name_type)
                name, offset = decode_netbios_name(wire)
                assert name.name == test_name.upper()[:15]
                assert name.name_type == name_type
                assert offset == len(wire)

    def test_round_trip_with_scope(self):
        wire = encode_netbios_name("HOST", 0x20, "foo.example.com")
        name, _ = decode_netbios_name(wire)
        assert name.scope == "foo.example.com"

    def test_decode_at_offset(self):
        prefix = b"\x00\x00\x00"
        wire = prefix + encode_netbios_name("TEST", 0x20)
        name, _ = decode_netbios_name(wire, offset=3)
        assert name.name == "TEST"
        assert name.name_type == 0x20

    def test_truncated_raises(self):
        wire = encode_netbios_name("HOST", 0x20)
        with pytest.raises(ValueError):
            decode_netbios_name(wire[:5])

    def test_wrong_label_length_raises(self):
        wire = bytearray(encode_netbios_name("HOST", 0x20))
        wire[0] = 0x10  # wrong length prefix
        with pytest.raises(ValueError, match="Expected label length"):
            decode_netbios_name(bytes(wire))

    def test_names_with_special_chars(self):
        """Samba wins.c tests names with dots and hyphens."""
        for test_name in ("hyphen-dot.0", "HAS-DASH", "A.B"):
            wire = encode_netbios_name(test_name, 0x00)
            name, _ = decode_netbios_name(wire)
            assert name.name == test_name.upper()[:15]
