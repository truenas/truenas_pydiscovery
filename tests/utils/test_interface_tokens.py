"""Interface-token classifier and names-only validator.

Used by each protocol's ``ServerConfig.__post_init__`` and by the
unified loader's ``[discovery] interfaces`` validation.  The
classifier was consolidated from NBNS's private ``_classify_token``
in ``subnet.py``; the names-only validator is new and enforces the
layering rule that shared-section interface lists must be portable
across all protocols.
"""
from __future__ import annotations

import pytest

from truenas_pydiscovery_utils.interface_tokens import (
    TokenKind,
    classify_token,
    require_names_only,
)


class TestClassifyToken:
    def test_plain_name(self):
        assert classify_token("eth0") is TokenKind.NAME

    def test_systemd_style_name(self):
        assert classify_token("enp3s0") is TokenKind.NAME

    def test_bare_ipv4_address(self):
        assert classify_token("192.168.1.5") is TokenKind.IPV4

    def test_cidr_network(self):
        assert classify_token("192.168.1.0/24") is TokenKind.CIDR

    def test_cidr_with_host_bits_accepted(self):
        # ``IPv4Network(..., strict=False)`` tolerates host bits set;
        # NBNS's legacy resolver does the same.  Consolidating here
        # preserves that behaviour.
        assert classify_token("192.168.1.5/24") is TokenKind.CIDR

    def test_whitespace_stripped(self):
        assert classify_token("  eth0  ") is TokenKind.NAME
        assert classify_token(" 10.0.0.1 ") is TokenKind.IPV4

    def test_empty_token_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            classify_token("")

    def test_whitespace_only_token_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            classify_token("   ")

    def test_malformed_cidr_rejects(self):
        with pytest.raises(ValueError):
            classify_token("192.168.1.0/99")


class TestRequireNamesOnly:
    def test_all_names_returns_unchanged(self):
        tokens = ["eth0", "enp3s0", "wlan0"]
        assert require_names_only(tokens) == tokens

    def test_empty_list_ok(self):
        assert require_names_only([]) == []

    def test_single_ipv4_rejected(self):
        with pytest.raises(ValueError, match="ipv4"):
            require_names_only(["eth0", "192.168.1.5"])

    def test_single_cidr_rejected(self):
        with pytest.raises(ValueError, match="cidr"):
            require_names_only(["10.0.0.0/8"])

    def test_error_names_the_offender(self):
        # Error message must identify which token failed so the
        # operator knows which line to fix — not just "something
        # in your config is wrong."
        with pytest.raises(ValueError, match="10.0.0.5"):
            require_names_only(["eth0", "10.0.0.5", "eth1"])

    def test_error_mentions_nbns_alternative(self):
        # Pointed directive: the error tells the operator where to
        # put the rejected token so they can fix without reading
        # the project docs.
        with pytest.raises(
            ValueError, match="\\[netbiosns\\] interfaces",
        ):
            require_names_only(["10.0.0.5"])
