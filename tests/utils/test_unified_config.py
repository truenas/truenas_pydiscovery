"""Tests for the unified truenas-pydiscoveryd config loader."""
from __future__ import annotations

from pathlib import Path

import pytest

from truenas_pydiscovery.config import (
    NoProtocolsEnabledError,
    load_unified_config,
)


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "unified.conf"
    p.write_text(body)
    return p


class TestEnabledFlag:
    def test_all_three_enabled_by_default(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]

[netbiosns]
workgroup = WG

[wsd]
"""))
        assert cfg.mdns is not None
        assert cfg.netbiosns is not None
        assert cfg.wsd is not None

    def test_explicit_disable(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
enabled = false

[netbiosns]
workgroup = WG

[wsd]
enabled = no
"""))
        assert cfg.mdns is None
        assert cfg.netbiosns is not None
        assert cfg.wsd is None

    def test_missing_section_disables(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
"""))
        assert cfg.mdns is not None
        assert cfg.netbiosns is None
        assert cfg.wsd is None

    def test_all_disabled_errors(self, tmp_path):
        with pytest.raises(NoProtocolsEnabledError, match="No protocols enabled"):
            load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
enabled = false

[netbiosns]
enabled = false

[wsd]
enabled = false
"""))

    def test_missing_file_errors(self, tmp_path):
        with pytest.raises(NoProtocolsEnabledError, match="No protocols enabled"):
            load_unified_config(tmp_path / "does-not-exist.conf")

    def test_no_protocols_enabled_is_value_error_subclass(self):
        # Kept as a ValueError subclass so any pre-existing callers
        # that catch ValueError still work.
        assert issubclass(NoProtocolsEnabledError, ValueError)


class TestSharedFields:
    def test_discovery_interfaces_used_as_fallback(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0, eth1

[mdns]

[netbiosns]
workgroup = WG

[wsd]
"""))
        assert cfg.mdns.server.interfaces == ["eth0", "eth1"]
        assert cfg.netbiosns.server.interfaces == ["eth0", "eth1"]
        assert cfg.wsd.server.interfaces == ["eth0", "eth1"]

    def test_per_protocol_override(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
interfaces = eth1, eth2

[netbiosns]
workgroup = WG
"""))
        assert cfg.mdns.server.interfaces == ["eth1", "eth2"]
        assert cfg.netbiosns.server.interfaces == ["eth0"]

    def test_shared_hostname_and_workgroup(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0
hostname = TRUENAS
workgroup = MYWG

[mdns]

[netbiosns]

[wsd]
"""))
        assert cfg.mdns.server.host_name == "TRUENAS"
        assert cfg.netbiosns.server.netbios_name == "TRUENAS"
        assert cfg.netbiosns.server.workgroup == "MYWG"
        assert cfg.wsd.server.hostname == "TRUENAS"
        assert cfg.wsd.server.workgroup == "MYWG"


class TestProtocolSpecifics:
    def test_mdns_fields(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]
use-ipv4 = no
use-ipv6 = yes
domain-name = alt
cache-entries-max = 2048
enable-reflector = yes
"""))
        assert cfg.mdns is not None
        assert cfg.mdns.server.use_ipv4 is False
        assert cfg.mdns.server.use_ipv6 is True
        assert cfg.mdns.server.domain_name == "alt"
        assert cfg.mdns.server.cache_entries_max == 2048
        assert cfg.mdns.reflector.enable_reflector is True

    def test_netbiosns_fields(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[netbiosns]
workgroup = MYWG
server-string = Test TrueNAS
netbios-aliases = ALIAS1, ALIAS2
"""))
        assert cfg.netbiosns is not None
        assert cfg.netbiosns.server.workgroup == "MYWG"
        assert cfg.netbiosns.server.server_string == "Test TrueNAS"
        assert cfg.netbiosns.server.netbios_aliases == ["ALIAS1", "ALIAS2"]

    def test_wsd_fields(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[wsd]
use-ipv4 = no
use-ipv6 = yes
domain = corp.example
"""))
        assert cfg.wsd is not None
        assert cfg.wsd.server.use_ipv4 is False
        assert cfg.wsd.server.use_ipv6 is True
        assert cfg.wsd.server.domain == "corp.example"


class TestRundir:
    def test_default_rundir_per_protocol(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, """
[discovery]
interfaces = eth0

[mdns]

[netbiosns]
workgroup = WG

[wsd]
"""))
        assert str(cfg.mdns.rundir).endswith("/truenas-pydiscovery/mdns")
        assert str(cfg.netbiosns.rundir).endswith(
            "/truenas-pydiscovery/netbiosns",
        )
        assert str(cfg.wsd.rundir).endswith("/truenas-pydiscovery/wsd")

    def test_custom_rundir_base(self, tmp_path):
        cfg = load_unified_config(_write(tmp_path, f"""
[discovery]
interfaces = eth0
rundir = {tmp_path}/rundir

[mdns]
"""))
        assert cfg.mdns.rundir == tmp_path / "rundir" / "mdns"
