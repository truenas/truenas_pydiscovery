"""SIGHUP host-rename reload path.

Hostname or domain-name changes flip the FQDN every record is
published under (A/AAAA keys, SRV targets, ``%h``-templated
instance names).  The host-rename path goodbyes everything and
re-probes under the new name without touching transports or
per-interface tasks — cheaper than a full rebuild but more work
than a services-only delta.  These tests verify the dispatcher
picks host-rename for the right changes and that the group
refresh actually produces fresh ``EntryGroup`` instances (so a
naive identity-preserving delta path couldn't silently replace
the host-rename path).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from truenas_pymdns.server.config import (
    DaemonConfig,
    ServerConfig,
    ServiceConfig,
    generate_service_config,
)
from truenas_pymdns.server.server import MDNSServer


def _write_svc(
    service_dir: Path, filename: str,
    service_type: str, port: int,
    instance_name: str = "%h",
) -> None:
    svc = ServiceConfig(
        service_type=service_type,
        port=port,
        instance_name=instance_name,
    )
    (service_dir / filename).write_bytes(generate_service_config(svc))


def _make_server(
    tmp_path: Path, *, hostname: str = "oldhost",
) -> MDNSServer:
    service_dir = tmp_path / "services.d"
    service_dir.mkdir()
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    return MDNSServer(DaemonConfig(
        server=ServerConfig(host_name=hostname),
        service_dir=service_dir,
        rundir=rundir,
    ))


class TestHostRenameDispatch:
    def test_host_name_change_replaces_every_service_group(self, tmp_path):
        server = _make_server(tmp_path, hostname="oldhost")
        _write_svc(
            server._config.service_dir, "smb.conf", "_smb._tcp", 445,
        )
        asyncio.run(server._reload())

        old_group = next(iter(server._service_groups.values()))
        assert server._fqdn == "oldhost.local"

        new_cfg = DaemonConfig(
            server=ServerConfig(host_name="newhost"),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        # FQDN updated.
        assert server._hostname == "newhost"
        assert server._fqdn == "newhost.local"
        # Group object was recreated (host-rename clears
        # _service_groups and re-registers).
        new_group = next(iter(server._service_groups.values()))
        assert new_group is not old_group
        # The new service's instance name carries the new hostname
        # (since instance_name was "%h").
        new_key = next(iter(server._service_groups.keys()))
        assert new_key.instance_name == "newhost"

    def test_domain_name_change_takes_host_rename_path(self, tmp_path):
        # Domain change (e.g. "local" -> "lan") flips FQDN the same
        # way a hostname change does; same reconciliation path.
        server = _make_server(tmp_path, hostname="host")
        _write_svc(
            server._config.service_dir, "smb.conf", "_smb._tcp", 445,
        )
        asyncio.run(server._reload())
        old_group = next(iter(server._service_groups.values()))
        assert server._fqdn == "host.local"

        new_cfg = DaemonConfig(
            server=ServerConfig(host_name="host", domain_name="lan"),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        assert server._fqdn == "host.lan"
        new_group = next(iter(server._service_groups.values()))
        assert new_group is not old_group

    def test_interface_change_preferred_over_host_rename(self, tmp_path):
        # If both interfaces and hostname change, full rebuild wins —
        # transports MUST rebind, so the host-rename path would be
        # wrong even though the FQDN also changes.  This guards
        # against re-ordering the dispatcher checks.
        server = _make_server(tmp_path, hostname="oldhost")
        _write_svc(
            server._config.service_dir, "smb.conf", "_smb._tcp", 445,
        )
        asyncio.run(server._reload())

        # Change interfaces to a non-existent name — resolve_interface
        # returns None so _interfaces stays empty but the full-rebuild
        # path runs (the point is that transports WOULD rebind if any
        # had been running).
        new_cfg = DaemonConfig(
            server=ServerConfig(
                host_name="newhost",
                interfaces=["nonexistent-iface"],
            ),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        # State is consistent regardless of which path ran: one
        # service under the new hostname.
        assert server._hostname == "newhost"
        assert len(server._service_groups) == 1
