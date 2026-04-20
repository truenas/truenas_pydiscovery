"""SIGHUP-driven reload: adding and removing service files while
the daemon is running.
"""
from __future__ import annotations

import json
import signal
import time

import pytest

from truenas_pymdns.server.config import (
    ServiceConfig,
    generate_service_config,
)

from .conftest import run_tool

pytestmark = pytest.mark.integration


def _browse_targets(iface_addr: str, svc_type: str) -> set[str]:
    result = run_tool([
        "mdns-browse", svc_type, "-t", "3", "--json",
        "-i", iface_addr,
    ])
    if result.returncode != 0:
        return set()
    return {
        json.loads(line)["target"]
        for line in result.stdout.strip().splitlines()
        if line.strip()
    }


def _write_service(service_dir, name: str, svc_type: str, port: int) -> None:
    svc = ServiceConfig(
        service_type=svc_type,
        port=port,
        instance_name="%h",
    )
    (service_dir / f"{name}.conf").write_bytes(
        generate_service_config(svc),
    )


class TestSIGHUPAddsService:
    def test_new_conf_file_becomes_discoverable_after_sighup(
        self, mdns_daemon,
    ):
        """Drop a fresh .conf into the service dir, send SIGHUP,
        and verify the new service is reachable via mdns-browse."""
        # Before reload: only the fixture's _test._tcp is present.
        before = _browse_targets(mdns_daemon.interface_addr, "_http._tcp")
        assert not any(
            t.startswith(f"{mdns_daemon.hostname}.")
            for t in before
        )

        _write_service(
            mdns_daemon.service_dir, "HTTP", "_http._tcp", 8080,
        )
        mdns_daemon.proc.send_signal(signal.SIGHUP)
        # Reload re-runs probe + announce; give it time.
        time.sleep(4.0)

        after = _browse_targets(mdns_daemon.interface_addr, "_http._tcp")
        assert any(
            t.startswith(f"{mdns_daemon.hostname}.")
            and t.endswith("._http._tcp.local")
            for t in after
        ), f"HTTP service not found after SIGHUP; got {after}"


class TestSIGHUPRemovesService:
    def test_deleted_conf_stops_being_advertised(self, mdns_daemon):
        """Remove the service .conf, SIGHUP, and verify the original
        service is no longer in browse output (pre-existing cache
        entries elsewhere would have been invalidated by the
        goodbye that ``_reload`` emits before reload)."""
        before = _browse_targets(mdns_daemon.interface_addr, "_test._tcp")
        # Pre-condition: our fixture's service is visible.
        assert any(
            t.startswith(f"{mdns_daemon.hostname}.")
            and t.endswith("._test._tcp.local")
            for t in before
        ), f"fixture service missing before reload: {before}"

        # Delete the .conf and reload.
        conf_path = mdns_daemon.service_dir / "TEST.conf"
        assert conf_path.exists()
        conf_path.unlink()
        mdns_daemon.proc.send_signal(signal.SIGHUP)
        time.sleep(3.0)

        after = _browse_targets(mdns_daemon.interface_addr, "_test._tcp")
        assert not any(
            t.startswith(f"{mdns_daemon.hostname}.")
            and t.endswith("._test._tcp.local")
            for t in after
        ), f"service still advertised after conf removed: {after}"
