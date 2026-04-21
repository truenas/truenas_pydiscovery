"""Tests for NetBIOS NS daemon configuration and name validation.

Validation rules match middlewared/utils/netbios.py.
"""
from __future__ import annotations

import pytest

from truenas_pynetbiosns.server.config import (
    ServerConfig,
    validate_netbios_domain,
    validate_netbios_name,
)


class TestValidateNetbiosName:
    def test_valid_simple(self):
        validate_netbios_name("TRUENAS")

    def test_valid_with_special_chars(self):
        validate_netbios_name("MY-NAS_01")
        validate_netbios_name("NAS!@#")
        validate_netbios_name("host-name")

    def test_valid_hyphen_underscore(self):
        validate_netbios_name("A-B_C")

    def test_max_length(self):
        validate_netbios_name("A" * 15)

    def test_too_long(self):
        with pytest.raises(ValueError, match="1-15 characters"):
            validate_netbios_name("A" * 16)

    def test_empty(self):
        with pytest.raises(ValueError, match="1-15 characters"):
            validate_netbios_name("")

    def test_all_digits_rejected(self):
        with pytest.raises(ValueError, match="not all digits"):
            validate_netbios_name("12345")

    def test_dot_rejected_in_name(self):
        with pytest.raises(ValueError, match="1-15 characters"):
            validate_netbios_name("HOST.NAME")

    def test_illegal_chars(self):
        for char in r'\/:*?"<>|':
            with pytest.raises(ValueError):
                validate_netbios_name(f"HOST{char}NAME")

    def test_reserved_word_anonymous(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_netbios_name("ANONYMOUS")

    def test_reserved_word_case_insensitive(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_netbios_name("gateway")

    def test_reserved_word_world(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_netbios_name("WORLD")


class TestValidateNetbiosDomain:
    def test_valid_simple(self):
        validate_netbios_domain("WORKGROUP")

    def test_dot_allowed_in_domain(self):
        validate_netbios_domain("MY.DOMAIN")

    def test_reserved_word_rejected(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_netbios_domain("NETWORK")

    def test_too_long(self):
        with pytest.raises(ValueError):
            validate_netbios_domain("A" * 16)


class TestServerConfigValidation:
    def test_valid_config(self):
        ServerConfig(
            netbios_name="TRUENAS",
            workgroup="WORKGROUP",
        )

    def test_empty_name_allowed(self):
        """Empty name means 'use system hostname'."""
        ServerConfig(netbios_name="")

    def test_invalid_name_rejected(self):
        with pytest.raises(ValueError):
            ServerConfig(netbios_name="HOST.BAD")

    def test_invalid_alias_rejected(self):
        with pytest.raises(ValueError):
            ServerConfig(netbios_aliases=["GOOD", "BAD:NAME"])

    def test_invalid_workgroup_rejected(self):
        with pytest.raises(ValueError):
            ServerConfig(workgroup="BAD\\GROUP")

    def test_reserved_name_rejected(self):
        with pytest.raises(ValueError, match="reserved"):
            ServerConfig(netbios_name="ANONYMOUS")
