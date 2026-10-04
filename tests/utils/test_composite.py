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
        self.reconciled = False
        self.links_up: list[int] = []
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

    async def _reconcile_interfaces(self):
        if self.fail == "reconcile":
            raise RuntimeError(f"{self.name} reconcile boom")
        self.reconciled = True

    async def _on_link_up(self, ifindex):
        if self.fail == "link_up":
            raise RuntimeError(f"{self.name} link-up boom")
        self.links_up.append(ifindex)


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


class GatedChild(StubChild):
    """StubChild whose ``_start`` stays in progress until ``gate`` opens."""

    def __init__(self, name: str):
        super().__init__(name)
        self.gate = asyncio.Event()
        self.starting = False
        self.reloads = 0

    async def _start(self, loop):
        self.starting = True
        await self.gate.wait()
        await super()._start(loop)

    async def _reload(self):
        self.reloads += 1
        await super()._reload()


class TestStartupConfigPass:
    """systemd folds a reload requested before READY=1 into the start
    job, so startup itself ends with a reload pass against the
    configuration on disk."""

    def test_start_with_reloader_ends_with_one_reload(self):
        a, b = StubChild("a"), StubChild("b")
        dispatched: list = []
        comp = CompositeDaemon(
            logging.getLogger("test.composite"),
            [(a.name, a), (b.name, b)],
            config_reloader=lambda: "config-on-disk",
            config_dispatch=lambda children, cfg: dispatched.append(cfg),
        )

        async def _run():
            await comp._start(asyncio.get_running_loop())

        asyncio.run(_run())
        assert a.started and b.started
        assert a.reloaded and b.reloaded
        assert dispatched == ["config-on-disk"]

    def test_start_without_reloader_does_not_reload(self):
        a = StubChild("a")

        async def _run():
            await _composite(a)._start(asyncio.get_running_loop())

        asyncio.run(_run())
        assert a.started
        assert not a.reloaded

    @pytest.mark.parametrize("failing_step", ["reader", "dispatch"])
    def test_failed_reread_leaves_children_as_started(self, failing_step):
        """Without a fresh config there is nothing to apply, and a
        child reload would only rebuild what startup just built."""
        a = StubChild("a")

        def fail(*args):
            raise RuntimeError(f"{failing_step} boom")

        comp = CompositeDaemon(
            logging.getLogger("test.composite"),
            [(a.name, a)],
            config_reloader=(
                fail if failing_step == "reader" else lambda: "cfg"
            ),
            config_dispatch=(
                fail if failing_step == "dispatch"
                else lambda children, cfg: None
            ),
        )

        async def _run():
            await comp._start(asyncio.get_running_loop())

        asyncio.run(_run())
        assert a.started
        assert not a.reloaded
        assert comp.reload_failure_counts[failing_step] == 1

    def test_sighup_held_during_startup_replaces_the_pass(
        self, notify_socket,
    ):
        """The reload that serves a SIGHUP held during startup reads
        the file itself, so the startup pass is skipped rather than
        run as well."""
        child = GatedChild("a")
        reads: list[str] = []
        comp = CompositeDaemon(
            logging.getLogger("test.composite"),
            [(child.name, child)],
            config_reloader=lambda: reads.append("read") or "cfg",
            config_dispatch=lambda children, cfg: None,
        )

        async def scenario() -> None:
            runner = asyncio.create_task(comp.run())
            while not child.starting:
                await asyncio.sleep(0.01)
            comp._signal_reload()
            child.gate.set()
            while comp._work_task is None:
                await asyncio.sleep(0.01)
            await comp._work_task
            comp._signal_shutdown()
            await runner

        asyncio.run(asyncio.wait_for(scenario(), timeout=5))
        assert reads == ["read"]
        assert child.reloads == 1
        assert notify_socket.recv(4096) == b"READY=1"
        assert notify_socket.recv(4096).startswith(b"RELOADING=1\n")
        assert notify_socket.recv(4096) == b"READY=1"


class TestInterfaceChanges:
    """The composite owns the one InterfaceMonitor and fans its events
    out to every child."""

    def test_reconcile_reaches_every_child(self):
        a, b = StubChild("a"), StubChild("b")
        asyncio.run(_composite(a, b)._reconcile_interfaces())
        assert a.reconciled and b.reconciled

    def test_a_failing_reconcile_does_not_stop_the_others(self, caplog):
        a, b = StubChild("a", fail="reconcile"), StubChild("b")
        with caplog.at_level(logging.ERROR, logger="test.composite"):
            asyncio.run(_composite(a, b)._reconcile_interfaces())
        assert b.reconciled
        assert any("a failed to update" in r.message for r in caplog.records)

    def test_link_up_reaches_every_child(self):
        a, b = StubChild("a", fail="link_up"), StubChild("b")
        asyncio.run(_composite(a, b)._on_link_up(4))
        assert b.links_up == [4]

    def test_monitor_listens_while_the_composite_runs(self):
        comp = _composite(StubChild("a"))

        async def lifecycle() -> tuple[bool, bool]:
            await comp._start(asyncio.get_running_loop())
            listening = comp._monitor._sock is not None
            await comp._stop()
            return listening, comp._monitor._sock is None

        assert asyncio.run(lifecycle()) == (True, True)

    def test_settled_change_requests_a_reconcile(self):
        """The monitor's ``on_change`` is the composite's
        ``request_reconcile``: a settled change runs one reconcile pass
        across the children."""
        a = StubChild("a")
        comp = _composite(a)

        async def scenario() -> None:
            runner = asyncio.create_task(comp.run())
            while not comp._started:
                await asyncio.sleep(0.01)
            comp._monitor._on_change()
            while not a.reconciled:
                await asyncio.sleep(0.01)
            comp._signal_shutdown()
            await runner

        asyncio.run(asyncio.wait_for(scenario(), timeout=5))
        assert a.reconciled
