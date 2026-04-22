"""SIGHUP service-delta reload: adding, removing, and editing
services.d files without tearing the whole registry down.

The delta path is what keeps a middleware SMB-share edit from
taking every advertised service offline and re-announcing it —
which is the whole reason the reload coordinator picks it for
"services-only" changes.  These tests verify the identity of kept
services survives the delta, that added/removed services get
reflected in the registry, and that the fallback to full rebuild
kicks in when anything outside services.d changed.

Tests drive ``MDNSServer`` with ``interfaces=[]`` so the
per-interface transports / probers never come up; we exercise the
diff logic, ``_service_groups`` index bookkeeping, and registry
state directly.  Wire-level goodbye timing stays in the integration
suite where a real loopback transport is available.
"""
from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from truenas_pymdns.server.config import (
    DaemonConfig,
    ServerConfig,
    ServiceConfig,
    generate_service_config,
)
from truenas_pymdns.server.server import MDNSServer
from truenas_pymdns.server.service.file_loader import ServiceKey


def _write_svc(
    service_dir: Path,
    filename: str,
    service_type: str,
    port: int,
    instance_name: str = "host",
    txt: dict[str, str] | None = None,
) -> None:
    svc = ServiceConfig(
        service_type=service_type,
        port=port,
        instance_name=instance_name,
        txt=txt or {},
    )
    (service_dir / filename).write_bytes(generate_service_config(svc))


def _make_server(
    tmp_path: Path,
    *,
    hostname: str = "host",
    interfaces: list[str] | None = None,
) -> MDNSServer:
    service_dir = tmp_path / "services.d"
    service_dir.mkdir()
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    return MDNSServer(DaemonConfig(
        server=ServerConfig(
            host_name=hostname,
            interfaces=interfaces or [],
        ),
        service_dir=service_dir,
        rundir=rundir,
    ))


class TestServiceKey:
    """Identity of a service for diff purposes."""

    def test_equal_for_byte_identical_configs(self):
        svc1 = ServiceConfig(
            service_type="_smb._tcp", port=445, instance_name="h",
        )
        svc2 = ServiceConfig(
            service_type="_smb._tcp", port=445, instance_name="h",
        )
        assert (
            ServiceKey.from_config(svc1, "h", "h.local")
            == ServiceKey.from_config(svc2, "h", "h.local")
        )

    def test_differs_on_txt_change(self):
        # RFC 6763 §6: TXT rdata is part of the service's published
        # data, so a TXT-only edit must trigger re-publish.
        s1 = ServiceConfig(
            service_type="_smb._tcp", port=445, txt={"model": "Mac"},
        )
        s2 = ServiceConfig(
            service_type="_smb._tcp", port=445, txt={"model": "NAS"},
        )
        assert (
            ServiceKey.from_config(s1, "h", "h.local")
            != ServiceKey.from_config(s2, "h", "h.local")
        )

    def test_differs_on_subtype_change(self):
        s1 = ServiceConfig(
            service_type="_smb._tcp", port=445, subtypes=["_print"],
        )
        s2 = ServiceConfig(
            service_type="_smb._tcp", port=445, subtypes=["_backup"],
        )
        assert (
            ServiceKey.from_config(s1, "h", "h.local")
            != ServiceKey.from_config(s2, "h", "h.local")
        )

    def test_txt_order_normalised(self):
        # Dict iteration order shouldn't affect identity — tuple
        # is sorted at key construction time.
        s1 = ServiceConfig(
            service_type="_smb._tcp", port=445,
            txt={"a": "1", "b": "2"},
        )
        s2 = ServiceConfig(
            service_type="_smb._tcp", port=445,
            txt={"b": "2", "a": "1"},
        )
        assert (
            ServiceKey.from_config(s1, "h", "h.local")
            == ServiceKey.from_config(s2, "h", "h.local")
        )

    def test_percent_h_substituted_against_hostname(self):
        # Two different hosts registering "%h.srv" produce different
        # instance FQDNs and therefore different keys.
        svc = ServiceConfig(
            service_type="_smb._tcp", port=445, instance_name="%h",
        )
        k1 = ServiceKey.from_config(svc, "host1", "host1.local")
        k2 = ServiceKey.from_config(svc, "host2", "host2.local")
        assert k1.instance_name == "host1"
        assert k2.instance_name == "host2"
        assert k1 != k2


class TestReloadDispatch:
    """Which reload path fires for each kind of config change."""

    def test_first_reload_is_full_rebuild(self, tmp_path):
        # ``_prev_config`` starts as None in ``__init__``; the
        # dispatcher must fall through to full rebuild.
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "smb.conf", "_smb._tcp", 445)

        assert server._prev_config is None

        asyncio.run(server._reload())

        assert len(server._service_groups) == 1

    def test_services_only_reload_preserves_untouched_group_identity(
        self, tmp_path,
    ):
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "smb.conf", "_smb._tcp", 445)
        asyncio.run(server._reload())

        smb_key = next(iter(server._service_groups))
        smb_group_before = server._service_groups[smb_key]

        # Add a second service with the same config shape.
        _write_svc(server._config.service_dir, "ssh.conf", "_ssh._tcp", 22)
        # apply_config with the same config object stashes _prev_config
        # so the dispatcher can tell nothing in the config sections
        # changed — the only candidate reload is services.d.
        server.apply_config(server._config)
        asyncio.run(server._reload())

        assert len(server._service_groups) == 2
        # The SMB group object is the same instance: the delta path
        # did not re-register it.
        assert server._service_groups[smb_key] is smb_group_before

    def test_services_only_reload_removes_deleted_service(self, tmp_path):
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "smb.conf", "_smb._tcp", 445)
        _write_svc(server._config.service_dir, "ssh.conf", "_ssh._tcp", 22)
        asyncio.run(server._reload())

        smb_key = next(
            k for k in server._service_groups
            if k.service_type == "_smb._tcp"
        )
        ssh_key = next(
            k for k in server._service_groups
            if k.service_type == "_ssh._tcp"
        )
        smb_group = server._service_groups[smb_key]
        ssh_group = server._service_groups[ssh_key]

        (server._config.service_dir / "ssh.conf").unlink()
        server.apply_config(server._config)
        asyncio.run(server._reload())

        assert list(server._service_groups) == [smb_key]
        assert server._service_groups[smb_key] is smb_group
        # The removed group was also dropped from _entry_groups so
        # status output and iterations don't see it.
        assert ssh_group not in server._entry_groups

    def test_txt_edit_replaces_group(self, tmp_path):
        server = _make_server(tmp_path)
        _write_svc(
            server._config.service_dir, "smb.conf",
            "_smb._tcp", 445, txt={"model": "Mac"},
        )
        asyncio.run(server._reload())

        old_key = next(iter(server._service_groups))
        old_group = server._service_groups[old_key]

        _write_svc(
            server._config.service_dir, "smb.conf",
            "_smb._tcp", 445, txt={"model": "NAS"},
        )
        server.apply_config(server._config)
        asyncio.run(server._reload())

        # TXT changed, so the key changed, so the delta saw
        # (to_remove={old_key}, to_add={new_key}) and produced a
        # fresh group.
        assert old_key not in server._service_groups
        assert len(server._service_groups) == 1
        new_group = next(iter(server._service_groups.values()))
        assert new_group is not old_group

    def test_unchanged_services_produce_noop_reload(self, tmp_path):
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "smb.conf", "_smb._tcp", 445)
        asyncio.run(server._reload())

        group_before = next(iter(server._service_groups.values()))

        server.apply_config(server._config)
        asyncio.run(server._reload())

        # Same object: nothing was removed and re-added.
        assert next(iter(server._service_groups.values())) is group_before

    def test_missing_services_dir_retires_everything(self, tmp_path):
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "smb.conf", "_smb._tcp", 445)
        asyncio.run(server._reload())
        assert len(server._service_groups) == 1

        shutil.rmtree(server._config.service_dir)
        server.apply_config(server._config)
        asyncio.run(server._reload())

        assert server._service_groups == {}

    def test_interface_change_forces_full_rebuild(self, tmp_path):
        # Interface list change: sockets must rebind.  Delta path
        # would be a bug here — verify the dispatcher falls through
        # to full rebuild by checking that the service group object
        # gets replaced even though services.d is unchanged.
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "smb.conf", "_smb._tcp", 445)
        asyncio.run(server._reload())

        old_group = next(iter(server._service_groups.values()))

        new_cfg = DaemonConfig(
            server=ServerConfig(
                host_name="host",
                interfaces=["nonexistent-iface"],
            ),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        new_group = next(iter(server._service_groups.values()))
        assert new_group is not old_group

    def test_record_still_asserted_across_groups(self, tmp_path):
        # RFC 6763 §9: two services of the same type share the
        # meta-PTR ``_services._dns-sd._udp.<domain>`` →
        # ``<type>.<domain>``.  The asserted-check must spot that
        # identity so the service-delta path can skip goodbye for
        # it when the other service is still advertising.
        server = _make_server(tmp_path)
        _write_svc(
            server._config.service_dir, "smb-a.conf",
            "_smb._tcp", 445, instance_name="a",
        )
        _write_svc(
            server._config.service_dir, "smb-b.conf",
            "_smb._tcp", 445, instance_name="b",
        )
        asyncio.run(server._reload())
        assert len(server._service_groups) == 2

        # Grab the meta-PTR record from one group.
        from truenas_pymdns.protocol.constants import QType
        key_a = next(
            k for k in server._service_groups
            if k.instance_name == "a"
        )
        group_a = server._service_groups[key_a]
        meta_ptr = next(
            r for r in group_a.records
            if r.key.name.startswith("_services._dns-sd._udp")
            and r.key.rtype == QType.PTR
        )
        # With both groups registered, the meta-PTR is asserted by
        # every group — we'd find one in the other group too.
        assert server._record_still_asserted(meta_ptr) is True

        # Simulate removing group A: drop from _entry_groups first
        # (mirrors the order _service_delta_reload uses).
        server._entry_groups.remove(group_a)
        # B still asserts the meta-PTR, so the kept-group check
        # returns True and the service-delta path will skip the
        # meta-PTR goodbye.
        assert server._record_still_asserted(meta_ptr) is True

        # Remove B too (find it in the remaining _entry_groups
        # rather than via _service_groups, which still has both
        # keys in this test setup).
        server._entry_groups.clear()
        assert server._record_still_asserted(meta_ptr) is False

    def test_removing_one_of_two_same_type_keeps_meta_ptr(self, tmp_path):
        # Integration-ish check on the delta path itself: after
        # removing one of two SMB services, the kept service's
        # meta-PTR remains in the registry for the responder to
        # serve.  Per RFC 6763 §9, the _services._dns-sd._udp PTR
        # must stay authoritative as long as any service of that
        # type is advertised.
        server = _make_server(tmp_path)
        _write_svc(
            server._config.service_dir, "smb-a.conf",
            "_smb._tcp", 445, instance_name="a",
        )
        _write_svc(
            server._config.service_dir, "smb-b.conf",
            "_smb._tcp", 445, instance_name="b",
        )
        asyncio.run(server._reload())

        # Remove A's .conf; B stays.
        (server._config.service_dir / "smb-a.conf").unlink()
        server.apply_config(server._config)
        asyncio.run(server._reload())

        # B's group remains and still owns the meta-PTR.
        assert len(server._service_groups) == 1
        kept = next(iter(server._service_groups.values()))
        from truenas_pymdns.protocol.constants import QType
        meta_ptrs = [
            r for r in kept.records
            if r.key.name.startswith("_services._dns-sd._udp")
            and r.key.rtype == QType.PTR
        ]
        assert len(meta_ptrs) == 1

    def test_duplicate_services_deduplicated_on_load(self, tmp_path):
        # Two .conf files with identical content should register
        # only one service, and the delta-reload index must stay
        # consistent with what's in _entry_groups.
        server = _make_server(tmp_path)
        _write_svc(server._config.service_dir, "a.conf", "_smb._tcp", 445)
        _write_svc(server._config.service_dir, "b.conf", "_smb._tcp", 445)
        asyncio.run(server._reload())

        assert len(server._service_groups) == 1
        # Every service group in the index is present in
        # _entry_groups (minus any host-address group, which has no
        # ServiceKey).
        for group in server._service_groups.values():
            assert group in server._entry_groups
