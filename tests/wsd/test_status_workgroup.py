"""Status dump includes workgroup and domain.

The daemon's metadata carries ``pub:Computer`` with a
``<Relationship>`` that names the host's workgroup — or domain, if
configured — per MS-PBSD.  Surfacing those two strings in the
SIGUSR1 status dump lets external observers verify that a config
update landed in the running process without fetching and parsing
the full HTTP metadata XML on port 5357."""
from __future__ import annotations

import json
from pathlib import Path

from truenas_pywsd.server.config import DaemonConfig, ServerConfig
from truenas_pywsd.server.server import WSDServer


def _make_server(tmp_path: Path, workgroup: str, domain: str = "") -> WSDServer:
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    return WSDServer(DaemonConfig(
        server=ServerConfig(
            hostname="host",
            workgroup=workgroup,
            domain=domain,
            interfaces=[],
        ),
        rundir=rundir,
    ))


def _read_status(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "rundir" / "status.json").read_text())


class TestStatusWorkgroup:
    def test_workgroup_surfaced_in_status(self, tmp_path):
        server = _make_server(tmp_path, workgroup="SALES")

        server._write_status()

        status = _read_status(tmp_path)
        assert status["workgroup"] == "SALES"
        assert status["domain"] == ""

    def test_domain_surfaced_alongside_workgroup(self, tmp_path):
        # When ``domain`` is set the daemon advertises as a domain
        # member in its metadata, but the status dump still reports
        # the raw config values so observers can tell which mode the
        # daemon is running in.
        server = _make_server(
            tmp_path, workgroup="WORKGROUP", domain="example.com",
        )

        server._write_status()

        status = _read_status(tmp_path)
        assert status["workgroup"] == "WORKGROUP"
        assert status["domain"] == "example.com"

    def test_config_reload_changes_status_workgroup(self, tmp_path):
        # A fresh config (as produced by SIGHUP reload) must be
        # reflected on the next status write — this guards the
        # ``_write_status`` reading through ``self._config.server``
        # rather than caching the workgroup at ``__init__`` time.
        server = _make_server(tmp_path, workgroup="OLDWG")
        server._write_status()
        assert _read_status(tmp_path)["workgroup"] == "OLDWG"

        server._config = DaemonConfig(
            server=ServerConfig(
                hostname="host",
                workgroup="NEWWG",
                interfaces=[],
            ),
            rundir=tmp_path / "rundir",
        )
        server._write_status()

        assert _read_status(tmp_path)["workgroup"] == "NEWWG"
