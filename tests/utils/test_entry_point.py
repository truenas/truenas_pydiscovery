"""Tests for the shared entry point helper."""
from __future__ import annotations

from pathlib import Path

from truenas_pydiscovery_utils.entry_point import run_daemon


class _InstantServer:
    """Minimal server_class: records its config, exits immediately."""

    def __init__(self, config) -> None:
        _InstantServer.seen.append(config)

    async def run(self) -> None:
        return None

    # Class-level list captures instances across constructions so the
    # test can inspect what config values arrived.  Reset in each test.
    seen: list = []


class TestRunDaemon:
    def test_parses_args_and_runs(self, monkeypatch):
        _InstantServer.seen = []
        captured_paths: list[Path] = []

        def capture_loader(path: Path) -> str:
            captured_paths.append(path)
            return "fake-config"

        monkeypatch.setattr(
            "sys.argv",
            ["test-daemon", "-c", "/tmp/test.conf", "-vv"],
        )
        run_daemon(
            "test-daemon", "Test daemon",
            capture_loader, _InstantServer, Path("/etc/default.conf"),
        )

        assert captured_paths == [Path("/tmp/test.conf")]
        assert _InstantServer.seen == ["fake-config"]

    def test_uses_default_config(self, monkeypatch):
        _InstantServer.seen = []
        captured_paths: list[Path] = []

        def capture_loader(path: Path) -> str:
            captured_paths.append(path)
            return "cfg"

        default = Path("/etc/test/daemon.conf")
        monkeypatch.setattr("sys.argv", ["test-daemon"])
        run_daemon(
            "test-daemon", "Test",
            capture_loader, _InstantServer, default,
        )

        assert captured_paths == [default]
        assert _InstantServer.seen == ["cfg"]
