"""Tests for the shared StatusWriter."""
from __future__ import annotations

import json
import logging

from truenas_pydiscovery_utils.status import StatusWriter


class TestStatusWriter:
    def test_write_creates_json(self, tmp_path):
        log = logging.getLogger("test.status")
        sw = StatusWriter(tmp_path, log)
        sw.write({"state": "running"})

        path = tmp_path / "status.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["state"] == "running"
        assert "uptime_seconds" in data

    def test_counters(self, tmp_path):
        log = logging.getLogger("test.status")
        sw = StatusWriter(tmp_path, log)
        sw.inc("queries")
        sw.inc("queries")
        sw.inc("responses", 5)
        sw.write({})

        data = json.loads((tmp_path / "status.json").read_text())
        assert data["queries"] == 2
        assert data["responses"] == 5

    def test_atomic_overwrite(self, tmp_path):
        log = logging.getLogger("test.status")
        sw = StatusWriter(tmp_path, log)
        sw.write({"version": 1})
        sw.write({"version": 2})

        data = json.loads((tmp_path / "status.json").read_text())
        assert data["version"] == 2

    def test_creates_rundir(self, tmp_path):
        rundir = tmp_path / "nested" / "dir"
        log = logging.getLogger("test.status")
        sw = StatusWriter(rundir, log)
        sw.write({"ok": True})

        assert (rundir / "status.json").exists()
