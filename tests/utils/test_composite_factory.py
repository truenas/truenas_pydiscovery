"""Tests for the config → composite factory wiring."""
from __future__ import annotations

from pathlib import Path

import pytest

from truenas_pydiscovery.composite import build_composite_daemon
from truenas_pydiscovery.config import load_unified_config


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "u.conf"
    p.write_text(body)
    return p


def test_all_three_enabled_gives_three_children(tmp_path):
    cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]

[netbiosns]
workgroup = WG

[wsd]
"""))
    composite = build_composite_daemon(cfg)
    names = [n for n, _ in composite.children]
    assert names == ["mdns", "netbiosns", "wsd"]


def test_one_disabled_gives_two_children(tmp_path):
    cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]

[netbiosns]
enabled = false
workgroup = WG

[wsd]
"""))
    composite = build_composite_daemon(cfg)
    names = [n for n, _ in composite.children]
    assert names == ["mdns", "wsd"]


def test_only_mdns(tmp_path):
    cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
"""))
    composite = build_composite_daemon(cfg)
    names = [n for n, _ in composite.children]
    assert names == ["mdns"]


def test_factory_refuses_empty():
    """Guardrail — build_composite_daemon should never be handed a
    config with no enabled protocols, because load_unified_config
    errors first.  Make sure the error surfaces."""
    # load_unified_config raises on empty; factory would never see it.
    # This test asserts that call-chain contract.
    from truenas_pydiscovery.config import UnifiedConfig
    cfg = UnifiedConfig()  # all None
    with pytest.raises(ValueError, match="at least one"):
        build_composite_daemon(cfg)
