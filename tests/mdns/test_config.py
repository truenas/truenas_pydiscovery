"""Tests for config generation, parsing, and service file loading."""
import pytest
from pathlib import Path
from textwrap import dedent

from truenas_pymdns.server.config import (
    DaemonConfig,
    ReflectorConfig,
    ServerConfig,
    ServiceConfig,
    generate_daemon_config,
    generate_service_config,
    get_hostname,
    load_daemon_config,
    load_service_config,
)
from truenas_pymdns.server.service.file_loader import (
    load_service_directory,
    service_to_entry_group,
)
from truenas_pymdns.protocol.constants import QType


class TestLoadDaemonConfig:
    def test_defaults(self, tmp_path):
        cfg = load_daemon_config(tmp_path / "nonexistent.conf")
        assert cfg.server.domain_name == "local"
        assert cfg.server.use_ipv4 is True
        assert cfg.server.use_ipv6 is True
        assert cfg.server.cache_entries_max == 4096
        assert cfg.server.interfaces == []
        assert cfg.reflector.enable_reflector is False

    def test_full_config(self, tmp_path):
        conf = tmp_path / "test.conf"
        conf.write_text(dedent("""\
            [server]
            host-name = truenas
            domain-name = local
            interfaces = eth0, eth1
            use-ipv4 = yes
            use-ipv6 = no
            cache-entries-max = 2048
            ratelimit-interval-usec = 500000
            ratelimit-burst = 500

            [reflector]
            enable-reflector = no

            [paths]
            service-dir = /custom/services
            rundir = /custom/run
        """))
        cfg = load_daemon_config(conf)
        assert cfg.server.host_name == "truenas"
        assert cfg.server.use_ipv6 is False
        assert cfg.server.interfaces == ["eth0", "eth1"]
        assert cfg.server.cache_entries_max == 2048
        assert cfg.service_dir == Path("/custom/services")
        assert cfg.rundir == Path("/custom/run")

    def test_partial_config(self, tmp_path):
        conf = tmp_path / "partial.conf"
        conf.write_text("[server]\nhost-name = myhost\n")
        cfg = load_daemon_config(conf)
        assert cfg.server.host_name == "myhost"
        assert cfg.server.use_ipv4 is True

    def test_get_hostname_configured(self):
        assert get_hostname(ServerConfig(host_name="custom")) == "custom"

    def test_get_hostname_system(self):
        hostname = get_hostname(ServerConfig())
        assert len(hostname) > 0
        assert "." not in hostname


class TestGenerateDaemonConfig:
    def test_round_trip(self, tmp_path):
        original = DaemonConfig(
            server=ServerConfig(
                host_name="truenas",
                interfaces=["eth0", "eth1"],
                use_ipv6=False,
                cache_entries_max=2048,
            ),
            reflector=ReflectorConfig(enable_reflector=True),
        )
        data = generate_daemon_config(original)
        assert isinstance(data, bytes)

        conf = tmp_path / "generated.conf"
        conf.write_bytes(data)
        loaded = load_daemon_config(conf)

        assert loaded.server.host_name == "truenas"
        assert loaded.server.interfaces == ["eth0", "eth1"]
        assert loaded.server.use_ipv6 is False
        assert loaded.server.cache_entries_max == 2048
        assert loaded.reflector.enable_reflector is True

    def test_defaults_round_trip(self, tmp_path):
        data = generate_daemon_config(DaemonConfig())
        conf = tmp_path / "defaults.conf"
        conf.write_bytes(data)
        loaded = load_daemon_config(conf)
        assert loaded.server.domain_name == "local"
        assert loaded.server.use_ipv4 is True


class TestServiceConfig:
    def test_validation_missing_type(self):
        with pytest.raises(ValueError, match="service_type is required"):
            ServiceConfig(service_type="", port=80)

    def test_validation_bad_type_prefix(self):
        with pytest.raises(ValueError, match="underscore"):
            ServiceConfig(service_type="http._tcp", port=80)

    def test_validation_bad_port(self):
        with pytest.raises(ValueError, match="port"):
            ServiceConfig(service_type="_http._tcp", port=99999)

    def test_valid(self):
        svc = ServiceConfig(
            service_type="_smb._tcp",
            port=445,
            interfaces=["eth0"],
            txt={"model": "MacPro7,1"},
        )
        assert svc.port == 445
        assert svc.instance_name == "%h"


class TestGenerateServiceConfig:
    def test_round_trip(self, tmp_path):
        original = ServiceConfig(
            service_type="_smb._tcp",
            port=445,
            instance_name="My NAS",
            interfaces=["eth0", "eth1"],
            txt={"model": "MacPro7,1@ECOLOR=226,226,224"},
        )
        data = generate_service_config(original)
        assert isinstance(data, bytes)
        assert b"_smb._tcp" in data

        conf = tmp_path / "SMB.conf"
        conf.write_bytes(data)
        loaded = load_service_config(conf)

        assert loaded is not None
        assert loaded.service_type == "_smb._tcp"
        assert loaded.port == 445
        assert loaded.instance_name == "My NAS"
        assert loaded.interfaces == ["eth0", "eth1"]
        assert loaded.txt["model"] == "MacPro7,1@ECOLOR=226,226,224"

    def test_minimal_round_trip(self, tmp_path):
        original = ServiceConfig(service_type="_http._tcp", port=80)
        data = generate_service_config(original)
        conf = tmp_path / "HTTP.conf"
        conf.write_bytes(data)
        loaded = load_service_config(conf)
        assert loaded is not None
        assert loaded.service_type == "_http._tcp"
        assert loaded.port == 80
        assert loaded.instance_name == "%h"

    def test_adisk_complex_txt(self, tmp_path):
        original = ServiceConfig(
            service_type="_adisk._tcp",
            port=9,
            txt={
                "sys": "waMa=0,adVF=0x100",
                "dk0": "adVN=TimeMachine,adVF=0x82,adVU=aabb",
            },
        )
        data = generate_service_config(original)
        conf = tmp_path / "ADISK.conf"
        conf.write_bytes(data)
        loaded = load_service_config(conf)
        assert loaded is not None
        assert loaded.txt["sys"] == "waMa=0,adVF=0x100"
        assert "adVN=TimeMachine" in loaded.txt["dk0"]


class TestLoadServiceFile:
    def test_load_from_file(self, tmp_path):
        f = tmp_path / "SMB.conf"
        f.write_text(dedent("""\
            [service]
            type = _smb._tcp
            port = 445
            interfaces = eth0, eth1
        """))
        svc = load_service_config(f)
        assert svc is not None
        assert svc.service_type == "_smb._tcp"
        assert svc.interfaces == ["eth0", "eth1"]

    def test_missing_type(self, tmp_path):
        f = tmp_path / "bad.conf"
        f.write_text("[service]\nport = 80\n")
        assert load_service_config(f) is None

    def test_missing_section(self, tmp_path):
        f = tmp_path / "bad2.conf"
        f.write_text("[txt]\nfoo = bar\n")
        assert load_service_config(f) is None

    def test_load_directory(self, tmp_path):
        (tmp_path / "A.conf").write_text(
            "[service]\ntype = _smb._tcp\nport = 445\n"
        )
        (tmp_path / "B.conf").write_text(
            "[service]\ntype = _http._tcp\nport = 80\n"
        )
        (tmp_path / "ignored.txt").write_text("not a conf file")
        services = load_service_directory(tmp_path)
        assert len(services) == 2

    def test_load_nonexistent_directory(self, tmp_path):
        assert load_service_directory(tmp_path / "nope") == []


class TestServiceToEntryGroup:
    def test_basic(self):
        svc = ServiceConfig(service_type="_smb._tcp", port=445)
        group = service_to_entry_group(svc, "truenas", "truenas.local")
        records = group.records
        assert len(records) == 4

        srv = [r for r in records if r.key.rtype == QType.SRV][0]
        assert srv.data.port == 445
        assert srv.data.target == "truenas.local"

    def test_with_txt(self):
        svc = ServiceConfig(
            service_type="_device-info._tcp",
            port=9,
            instance_name="My NAS",
            txt={"model": "MacPro7,1"},
        )
        group = service_to_entry_group(svc, "truenas", "truenas.local")
        txt_records = [
            r for r in group.records if r.key.rtype == QType.TXT
        ]
        assert len(txt_records) == 1
        assert b"model=MacPro7,1" in txt_records[0].data.entries

    def test_interface_binding(self):
        svc = ServiceConfig(service_type="_http._tcp", port=443)
        group = service_to_entry_group(
            svc, "nas", "nas.local", interface_indexes=[1, 3]
        )
        assert group.interfaces == [1, 3]
