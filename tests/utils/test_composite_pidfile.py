"""Tests for CompositeDaemon pidfile lifecycle."""
from __future__ import annotations

import asyncio
import logging
import os

from truenas_pydiscovery_utils.composite import CompositeDaemon
from truenas_pydiscovery_utils.daemon import BaseDaemon


class _StubChild(BaseDaemon):
    def __init__(self, name: str) -> None:
        super().__init__(logging.getLogger(f"test.{name}"))
        self.name = name

    async def _start(self, loop):
        return None

    async def _stop(self):
        return None


class TestPidfileLifecycle:
    def test_no_pidfile_when_unset(self):
        composite = CompositeDaemon(
            logging.getLogger("test.composite"),
            [("a", _StubChild("a"))],
        )

        async def _run():
            await composite._start(asyncio.get_running_loop())
            await composite._stop()

        asyncio.run(_run())

    def test_pidfile_written_on_start_and_removed_on_stop(self, tmp_path):
        pidfile = tmp_path / "daemon.pid"
        composite = CompositeDaemon(
            logging.getLogger("test.composite"),
            [("a", _StubChild("a"))],
            pidfile=pidfile,
        )

        async def _run():
            await composite._start(asyncio.get_running_loop())
            assert pidfile.exists()
            assert int(pidfile.read_text().strip()) == os.getpid()
            await composite._stop()
            assert not pidfile.exists()

        asyncio.run(_run())

    def test_pidfile_parent_directory_is_created(self, tmp_path):
        pidfile = tmp_path / "nested" / "run" / "daemon.pid"
        composite = CompositeDaemon(
            logging.getLogger("test.composite"),
            [("a", _StubChild("a"))],
            pidfile=pidfile,
        )

        async def _run():
            await composite._start(asyncio.get_running_loop())
            assert pidfile.exists()
            await composite._stop()

        asyncio.run(_run())

    def test_stop_tolerates_missing_pidfile(self, tmp_path):
        pidfile = tmp_path / "daemon.pid"
        composite = CompositeDaemon(
            logging.getLogger("test.composite"),
            [("a", _StubChild("a"))],
            pidfile=pidfile,
        )

        async def _run():
            await composite._start(asyncio.get_running_loop())
            # Simulate external removal (operator cleaning up, tmpfs
            # restart, etc.) — _stop() must not raise.
            pidfile.unlink()
            await composite._stop()

        asyncio.run(_run())

    def test_write_failure_is_logged_not_raised(self, tmp_path, caplog):
        # Use a path whose parent is a regular file — mkdir will fail.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        pidfile = blocker / "daemon.pid"
        composite = CompositeDaemon(
            logging.getLogger("test.composite.pidfile"),
            [("a", _StubChild("a"))],
            pidfile=pidfile,
        )

        async def _run():
            await composite._start(asyncio.get_running_loop())
            await composite._stop()

        with caplog.at_level(
            logging.ERROR, logger="test.composite.pidfile",
        ):
            asyncio.run(_run())
        assert any(
            "Failed to write pidfile" in r.message for r in caplog.records
        )
