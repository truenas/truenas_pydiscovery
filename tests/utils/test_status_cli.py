"""Tests for the ``truenas-discovery-status`` CLI."""
from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

import pytest

from truenas_pydiscovery.cli import status as cli


def _age_file(path: Path, seconds: float) -> None:
    """Set *path*'s mtime/atime to *seconds* in the past.

    Needed because ``touch()`` sets mtime to "now", and a file just
    created by the test is already at "now" — polling for a later
    mtime would race with the filesystem's timestamp resolution."""
    now = time.time()
    old = now - seconds
    os.utime(path, (old, old))


class TestReadPid:
    def test_missing_pidfile_returns_none_and_logs(self, tmp_path, capsys):
        assert cli._read_pid(tmp_path / "nope.pid") is None
        assert "daemon not running" in capsys.readouterr().err

    def test_valid_pid(self, tmp_path):
        pidfile = tmp_path / "daemon.pid"
        pidfile.write_text("12345\n")
        assert cli._read_pid(pidfile) == 12345

    def test_invalid_pid_logs_and_returns_none(self, tmp_path, capsys):
        pidfile = tmp_path / "daemon.pid"
        pidfile.write_text("not-a-pid")
        assert cli._read_pid(pidfile) is None
        assert "invalid pid" in capsys.readouterr().err


@pytest.fixture
def refresh_on_sigusr1():
    """Install a SIGUSR1 handler set by the test body.

    Yields a callable the test uses to set the actual handler
    function; unconditionally restores the previous handler on
    teardown so other tests aren't affected by the handoff."""
    prev = signal.getsignal(signal.SIGUSR1)
    installed: list[signal.Handlers | object] = [None]

    def _install(handler):
        signal.signal(signal.SIGUSR1, handler)
        installed[0] = handler

    try:
        yield _install
    finally:
        signal.signal(signal.SIGUSR1, prev)


def _populate_rundir(tmp_path: Path, child_names=cli.CHILD_NAMES) -> list[Path]:
    pidfile = tmp_path / cli.PIDFILE_NAME
    pidfile.write_text(f"{os.getpid()}\n")
    paths = []
    for name in child_names:
        sub = tmp_path / name
        sub.mkdir()
        p = sub / "status.json"
        p.write_text(json.dumps({"state": "running", "proto": name}))
        _age_file(p, 10.0)
        paths.append(p)
    return paths


class TestRun:
    def test_missing_pidfile_returns_1(self, tmp_path):
        args = cli.parse_args([
            "--rundir", str(tmp_path), "--timeout", "0",
        ])
        assert cli._run(args) == 1

    def test_end_to_end_refreshes_and_merges(
        self, tmp_path, capsys, refresh_on_sigusr1,
    ):
        paths = _populate_rundir(tmp_path)

        def _handler(signum, frame):
            for p in paths:
                p.touch()

        refresh_on_sigusr1(_handler)

        args = cli.parse_args([
            "--rundir", str(tmp_path), "--timeout", "2",
        ])
        rc = cli._run(args)
        assert rc == 0

        data = json.loads(capsys.readouterr().out)
        assert data["pid"] == os.getpid()
        assert set(data["children"].keys()) == set(cli.CHILD_NAMES)
        assert data["children"]["mdns"]["proto"] == "mdns"
        assert data["children"]["wsd"]["state"] == "running"

    def test_missing_child_is_absent_from_output(
        self, tmp_path, capsys, refresh_on_sigusr1,
    ):
        # Populate only mdns.
        paths = _populate_rundir(tmp_path, child_names=("mdns",))

        def _handler(signum, frame):
            for p in paths:
                p.touch()

        refresh_on_sigusr1(_handler)

        args = cli.parse_args([
            "--rundir", str(tmp_path), "--timeout", "1",
        ])
        assert cli._run(args) == 0
        data = json.loads(capsys.readouterr().out)
        assert list(data["children"].keys()) == ["mdns"]

    def test_timeout_zero_skips_waiting(
        self, tmp_path, capsys, refresh_on_sigusr1,
    ):
        _populate_rundir(tmp_path, child_names=("mdns",))
        refresh_on_sigusr1(lambda s, f: None)

        args = cli.parse_args([
            "--rundir", str(tmp_path), "--timeout", "0",
        ])
        start = time.monotonic()
        assert cli._run(args) == 0
        elapsed = time.monotonic() - start
        # Without polling, this should finish fast.  Loose upper
        # bound handles CI noise.
        assert elapsed < 1.0
        data = json.loads(capsys.readouterr().out)
        assert data["children"]["mdns"]["proto"] == "mdns"

    def test_pretty_flag_indents_output(
        self, tmp_path, capsys, refresh_on_sigusr1,
    ):
        pidfile = tmp_path / cli.PIDFILE_NAME
        pidfile.write_text(f"{os.getpid()}\n")
        refresh_on_sigusr1(lambda s, f: None)

        args = cli.parse_args([
            "--rundir", str(tmp_path),
            "--timeout", "0",
            "--pretty",
        ])
        assert cli._run(args) == 0
        out = capsys.readouterr().out
        # Indentation produces newline-indent pairs.
        assert "\n  " in out

    def test_timeout_warning_when_daemon_does_not_refresh(
        self, tmp_path, capsys, refresh_on_sigusr1,
    ):
        _populate_rundir(tmp_path, child_names=("mdns",))
        # Handler that does nothing — simulates a hung daemon.
        refresh_on_sigusr1(lambda s, f: None)

        args = cli.parse_args([
            "--rundir", str(tmp_path), "--timeout", "0.2",
        ])
        assert cli._run(args) == 0
        err = capsys.readouterr().err
        assert "timed out" in err
