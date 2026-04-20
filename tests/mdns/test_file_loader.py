"""Service file loading and EntryGroup conversion.

Covers the on-disk .conf parser (load_service_directory) and the
service-to-record factory (service_to_entry_group), including the
``%h`` hostname substitution and interface-index propagation.
"""
from __future__ import annotations

from pathlib import Path

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.server.config import ServiceConfig
from truenas_pymdns.server.service.file_loader import (
    load_service_directory,
    service_to_entry_group,
)


class TestLoadServiceDirectory:
    def test_missing_directory_returns_empty_list(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist"
        assert load_service_directory(missing) == []

    def test_empty_directory_returns_empty_list(self, tmp_path: Path):
        assert load_service_directory(tmp_path) == []

    def test_deterministic_sort_by_filename(self, tmp_path: Path):
        (tmp_path / "c.conf").write_text(_conf("_http._tcp", 80))
        (tmp_path / "a.conf").write_text(_conf("_ssh._tcp", 22))
        (tmp_path / "b.conf").write_text(_conf("_smb._tcp", 445))

        services = load_service_directory(tmp_path)
        types = [s.service_type for s in services]
        # sorted(glob) → a.conf, b.conf, c.conf → ssh, smb, http
        assert types == ["_ssh._tcp", "_smb._tcp", "_http._tcp"]

    def test_malformed_conf_skipped_siblings_still_loaded(
        self, tmp_path: Path,
    ):
        """A single unparseable file must not poison the whole dir."""
        (tmp_path / "good.conf").write_text(_conf("_good._tcp", 1))
        (tmp_path / "broken.conf").write_text("not a valid [ini section\n")
        services = load_service_directory(tmp_path)
        assert len(services) == 1
        assert services[0].service_type == "_good._tcp"

    def test_conf_without_service_section_skipped(self, tmp_path: Path):
        (tmp_path / "empty.conf").write_text("[txt]\nfoo=bar\n")
        assert load_service_directory(tmp_path) == []

    def test_conf_without_type_skipped(self, tmp_path: Path):
        (tmp_path / "no-type.conf").write_text(
            "[service]\nport=80\n",
        )
        assert load_service_directory(tmp_path) == []


def _conf(svc_type: str, port: int) -> str:
    return f"[service]\ntype={svc_type}\nport={port}\n"


class TestServiceToEntryGroup:
    def test_percent_h_replaced_with_hostname(self):
        svc = ServiceConfig(
            service_type="_smb._tcp",
            port=445,
            instance_name="%h-server",
        )
        grp = service_to_entry_group(svc, "myhost", "myhost.local")

        srv_names = {
            r.key.name for r in grp.records
            if r.key.rtype == QType.SRV
        }
        assert srv_names == {"myhost-server._smb._tcp.local"}

    def test_interface_indexes_propagate(self):
        svc = ServiceConfig(
            service_type="_smb._tcp",
            port=445,
        )
        grp = service_to_entry_group(
            svc, "host", "host.local", interface_indexes=[2, 3],
        )
        assert grp.interfaces == [2, 3]

    def test_no_interfaces_means_all(self):
        """``interface_indexes=None`` leaves ``group.interfaces``
        as None, meaning 'register on every interface'."""
        svc = ServiceConfig(
            service_type="_smb._tcp",
            port=445,
        )
        grp = service_to_entry_group(svc, "host", "host.local")
        assert grp.interfaces is None

    def test_srv_target_uses_host_override_when_set(self):
        svc = ServiceConfig(
            service_type="_http._tcp",
            port=80,
            host="web.local",
        )
        grp = service_to_entry_group(svc, "myhost", "myhost.local")

        srv = next(
            r for r in grp.records if r.key.rtype == QType.SRV
        )
        assert srv.data.target == "web.local"

    def test_srv_target_falls_back_to_fqdn(self):
        svc = ServiceConfig(
            service_type="_http._tcp",
            port=80,
            host=None,
        )
        grp = service_to_entry_group(svc, "myhost", "myhost.local")

        srv = next(
            r for r in grp.records if r.key.rtype == QType.SRV
        )
        assert srv.data.target == "myhost.local"
