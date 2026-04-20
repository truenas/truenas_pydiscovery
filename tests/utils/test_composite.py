"""Tests for CompositeDaemon fan-out and failure isolation."""
from __future__ import annotations

import asyncio
import logging

import pytest

from truenas_pydiscovery_utils.composite import CompositeDaemon
from truenas_pydiscovery_utils.daemon import BaseDaemon


class StubChild(BaseDaemon):
    """Minimal BaseDaemon that records every lifecycle call."""

    def __init__(self, name: str, *, fail: str | None = None):
        super().__init__(logging.getLogger(f"test.{name}"))
        self.name = name
        self.started = False
        self.stopped = False
        self.reloaded = False
        self.status_written = False
        # *fail* is the name of the method that should raise, or None.
        self.fail = fail

    async def _start(self, loop):
        if self.fail == "start":
            raise RuntimeError(f"{self.name} start boom")
        self.started = True

    async def _stop(self):
        if self.fail == "stop":
            raise RuntimeError(f"{self.name} stop boom")
        self.stopped = True

    async def _reload(self):
        if self.fail == "reload":
            raise RuntimeError(f"{self.name} reload boom")
        self.reloaded = True

    def _write_status(self):
        if self.fail == "status":
            raise RuntimeError(f"{self.name} status boom")
        self.status_written = True


def _composite(*children):
    return CompositeDaemon(
        logging.getLogger("test.composite"),
        [(c.name, c) for c in children],
    )


class TestConstruction:
    def test_rejects_empty_children(self):
        with pytest.raises(ValueError, match="at least one"):
            CompositeDaemon(logging.getLogger("x"), [])

    def test_children_property_is_readonly_copy(self):
        a = StubChild("a")
        b = StubChild("b")
        c = _composite(a, b)
        view = c.children
        view.clear()
        # Underlying list is unaffected.
        assert len(c.children) == 2


class TestStartFanOut:
    def test_start_fans_out_to_all_children(self):
        a = StubChild("a")
        b = StubChild("b")
        composite = _composite(a, b)

        async def _run() -> None:
            await composite._start(asyncio.get_running_loop())

        asyncio.run(_run())
        assert a.started and b.started

    def test_one_child_start_failure_does_not_stop_others(self, caplog):
        a = StubChild("a", fail="start")
        b = StubChild("b")
        composite = _composite(a, b)

        async def _run() -> None:
            await composite._start(asyncio.get_running_loop())

        with caplog.at_level(logging.ERROR, logger="test.composite"):
            asyncio.run(_run())
        assert not a.started
        assert b.started
        assert any("a failed to start" in r.message for r in caplog.records)


class TestStopFanOut:
    def test_stop_fans_out_to_all_children(self):
        a = StubChild("a")
        b = StubChild("b")
        asyncio.run(_composite(a, b)._stop())
        assert a.stopped and b.stopped

    def test_one_child_stop_failure_is_logged_not_raised(self, caplog):
        a = StubChild("a", fail="stop")
        b = StubChild("b")
        with caplog.at_level(logging.ERROR, logger="test.composite"):
            asyncio.run(_composite(a, b)._stop())
        assert b.stopped
        assert any("a failed to stop" in r.message for r in caplog.records)


class TestReloadFanOut:
    def test_reload_fans_out_to_all_children(self):
        a = StubChild("a")
        b = StubChild("b")
        asyncio.run(_composite(a, b)._reload())
        assert a.reloaded and b.reloaded

    def test_one_child_reload_failure_does_not_stop_others(self, caplog):
        a = StubChild("a", fail="reload")
        b = StubChild("b")
        with caplog.at_level(logging.ERROR, logger="test.composite"):
            asyncio.run(_composite(a, b)._reload())
        assert b.reloaded


class TestStatusFanOut:
    def test_status_writes_every_child(self):
        a = StubChild("a")
        b = StubChild("b")
        _composite(a, b)._write_status()
        assert a.status_written and b.status_written

    def test_one_child_status_failure_does_not_stop_others(self, caplog):
        a = StubChild("a", fail="status")
        b = StubChild("b")
        with caplog.at_level(logging.ERROR, logger="test.composite"):
            _composite(a, b)._write_status()
        assert b.status_written


class TestFullLifecycle:
    def test_run_end_to_end(self):
        a = StubChild("a")
        b = StubChild("b")
        composite = _composite(a, b)
        composite._shutdown_event.set()  # immediate shutdown
        asyncio.run(composite.run())
        assert a.started and a.stopped
        assert b.started and b.stopped
