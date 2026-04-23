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

    def test_write_returns_true_on_success(self, tmp_path):
        log = logging.getLogger("test.status")
        sw = StatusWriter(tmp_path, log)
        assert sw.write({"state": "running"}) is True

    def test_write_returns_false_on_json_encoding_error(
        self, tmp_path, caplog,
    ):
        # ``default=str`` in the json.dump call covers most oddballs,
        # but a value that raises inside its own ``__str__`` still
        # bubbles out as a JSON encoding failure.  The write must
        # return False (caller-observable) and log an error, rather
        # than claim success and leave an empty status.
        log = logging.getLogger("test.status")
        sw = StatusWriter(tmp_path, log)

        class _BadRepr:
            def __str__(self):
                raise RuntimeError("explode in __str__")

        with caplog.at_level(logging.ERROR, logger="test.status"):
            assert sw.write({"bad": _BadRepr()}) is False
        # Error was surfaced in the log too.
        assert any(
            "Failed to write status" in r.message
            for r in caplog.records
        )
