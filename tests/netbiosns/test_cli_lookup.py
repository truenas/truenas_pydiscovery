"""Tests for the ``nbt-lookup`` CLI argument parser."""
from __future__ import annotations

import argparse

import pytest

from truenas_pynetbiosns.client.cli.lookup import _parse_name_type
from truenas_pynetbiosns.protocol.constants import NameType


class TestParseNameType:
    def test_enum_name_exact(self):
        assert _parse_name_type("WORKSTATION") == NameType.WORKSTATION.value
        assert _parse_name_type("SERVER") == NameType.SERVER.value
        assert _parse_name_type("MESSENGER") == NameType.MESSENGER.value

    def test_enum_name_case_insensitive(self):
        assert _parse_name_type("workstation") == 0x00
        assert _parse_name_type("Server") == 0x20
        assert _parse_name_type("mAsTeR_bRoWsEr") == 0x01

    def test_enum_name_surrounding_whitespace(self):
        assert _parse_name_type("  SERVER  ") == 0x20

    def test_hex_literal(self):
        # Unusual name types not in the enum must still be addressable.
        assert _parse_name_type("0x41") == 0x41
        assert _parse_name_type("0X20") == 0x20

    def test_decimal_literal(self):
        assert _parse_name_type("32") == 32

    def test_octal_literal(self):
        assert _parse_name_type("0o40") == 0x20

    def test_invalid_raises_argument_type_error(self):
        with pytest.raises(argparse.ArgumentTypeError) as excinfo:
            _parse_name_type("not-a-type")
        # Error message lists the enum names so the user knows what's valid.
        msg = str(excinfo.value)
        assert "WORKSTATION" in msg
        assert "SERVER" in msg
        assert "integer literal" in msg

    def test_empty_string_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            _parse_name_type("")

    def test_every_enum_member_parses(self):
        # Regression guard: if someone adds a NameType, this catches
        # any lookup path that accidentally skips it.
        for member in NameType:
            assert _parse_name_type(member.name) == member.value
