"""Tests for the shared BaseDaemon lifecycle."""
from __future__ import annotations

import asyncio
import logging
import signal
import subprocess
import sys

from truenas_pydiscovery_utils.daemon import BaseDaemon


class _RecordingLoop:
    """Records add_signal_handler calls without touching real OS signals."""

    def __init__(self) -> None:
        self.handlers: list[tuple] = []

    def add_signal_handler(self, signum, callback, *args) -> None:
        self.handlers.append((signum, callback, args))


class StubDaemon(BaseDaemon):
    """Minimal concrete daemon for testing."""

    def __init__(self):
        super().__init__(logging.getLogger("test.daemon"))
        self.started = False
        self.stopped = False
        self.reloaded = False
        self.status_written = False

    async def _start(self, loop):
        self.started = True

    async def _stop(self):
        self.stopped = True

    async def _reload(self):
        self.reloaded = True

    def _write_status(self):
        self.status_written = True


class TestBaseDaemon:
    def test_signal_shutdown_sets_event(self):
        d = StubDaemon()
        d._signal_shutdown()
        assert d._shutdown_event.is_set()

    def test_setup_signals_registers_all(self):
        d = StubDaemon()
        loop = _RecordingLoop()
        d._setup_signals(loop)
        signals = [h[0] for h in loop.handlers]
        assert signal.SIGTERM in signals
        assert signal.SIGINT in signals
        assert signal.SIGHUP in signals
        assert signal.SIGUSR1 in signals

    def test_run_calls_start_and_stop(self):
        d = StubDaemon()
        # Trigger immediate shutdown
        d._shutdown_event.set()
        asyncio.run(d.run())
        assert d.started
        assert d.stopped

    def test_signal_status_schedules_write(self):
        d = StubDaemon()
        loop = asyncio.new_event_loop()
        try:
            # _signal_status uses run_in_executor, needs a running loop
            loop.call_soon(d._signal_status)
            loop.call_soon(loop.stop)
            loop.run_forever()
            # Let executor task complete
            loop.run_until_complete(asyncio.sleep(0.05))
        finally:
            loop.close()
        assert d.status_written


class GatedDaemon(BaseDaemon):
    """Daemon whose ``_start`` and ``_reload`` stay in progress until
    their gates open, recording each lifecycle step in ``events``."""

    def __init__(self):
        super().__init__(logging.getLogger("test.daemon.gated"))
        self.start_gate = asyncio.Event()
        self.reload_gate = asyncio.Event()
        self.reload_gate.set()
        self.fail_next_reload = False
        self.events: list[str] = []
        self.reloads = 0

    async def _start(self, loop):
        self.events.append("start-begin")
        try:
            await self.start_gate.wait()
        except asyncio.CancelledError:
            self.events.append("start-cancelled")
            raise
        self.events.append("start-end")

    async def _stop(self):
        self.events.append("stop")

    async def _reload(self):
        self.reloads += 1
        self.events.append("reload-begin")
        try:
            await self.reload_gate.wait()
        except asyncio.CancelledError:
            self.events.append("reload-cancelled")
            raise
        if self.fail_next_reload:
            self.fail_next_reload = False
            raise RuntimeError("reload boom")
        self.events.append("reload-end")


async def _until(condition) -> None:
    while not condition():
        await asyncio.sleep(0.01)


def _queued(notify_socket) -> list[bytes]:
    """Every notification already on *notify_socket*, without waiting."""
    timeout = notify_socket.gettimeout()
    notify_socket.setblocking(False)
    messages = []
    try:
        while True:
            messages.append(notify_socket.recv(4096))
    except BlockingIOError:
        return messages
    finally:
        notify_socket.settimeout(timeout)


def _kinds(messages: list[bytes]) -> list[str]:
    """``READY`` / ``RELOADING`` for each notification."""
    return [m.split(b"=", 1)[0].decode() for m in messages]


def _run(scenario) -> None:
    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


# Run in a child process so a real SIGHUP can be delivered while
# ``_start`` is in progress.
_SLOW_START_DAEMON = """
import asyncio
import logging

from truenas_pydiscovery_utils.daemon import BaseDaemon


class SlowStart(BaseDaemon):
    async def _start(self, loop):
        print("start-begin", flush=True)
        await asyncio.sleep(0.5)
        print("start-end", flush=True)

    async def _stop(self):
        print("stopped", flush=True)

    async def _reload(self):
        print("reloaded", flush=True)


asyncio.run(SlowStart(logging.getLogger("slow-start")).run())
"""


class TestStartupGatingAndNotify:
    """Readiness is reported as soon as the signal handlers are in
    place, before ``_start`` runs, and each reload is reported with the
    Type=notify-reload protocol.  A SIGHUP that arrives while ``_start``
    is running is held and served once startup completes."""

    def test_ready_is_reported_before_start_completes(self, notify_socket):
        d = GatedDaemon()
        queued_during_start: list[bytes] = []

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: "start-begin" in d.events)
            queued_during_start.extend(_queued(notify_socket))
            d.start_gate.set()
            await _until(lambda: d._started)
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert queued_during_start == [b"READY=1"]
        assert _queued(notify_socket) == []

    def test_sighups_during_startup_run_one_reload_after_start(
        self, notify_socket,
    ):
        d = GatedDaemon()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: "start-begin" in d.events)
            d._signal_reload()
            d._signal_reload()
            await asyncio.sleep(0.05)
            assert d.reloads == 0
            d.start_gate.set()
            await _until(lambda: d._reload_task is not None)
            await d._reload_task
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert d.events == [
            "start-begin", "start-end", "reload-begin", "reload-end", "stop",
        ]
        messages = _queued(notify_socket)
        assert _kinds(messages) == ["READY", "RELOADING", "READY"]
        assert messages[1].split(b"\n")[1].startswith(b"MONOTONIC_USEC=")

    def test_sighup_after_startup_reloads_immediately(self, notify_socket):
        d = GatedDaemon()
        d.start_gate.set()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: d._started)
            d._signal_reload()
            await d._reload_task
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert d.reloads == 1
        assert _kinds(_queued(notify_socket)) == [
            "READY", "RELOADING", "READY",
        ]

    def test_real_sighup_during_startup_does_not_kill(self, notify_socket):
        proc = subprocess.Popen(
            [sys.executable, "-c", _SLOW_START_DAEMON],
            stdout=subprocess.PIPE, text=True,
        )
        try:
            assert proc.stdout.readline().strip() == "start-begin"
            assert _queued(notify_socket) == [b"READY=1"]
            proc.send_signal(signal.SIGHUP)
            assert proc.stdout.readline().strip() == "start-end"
            assert proc.stdout.readline().strip() == "reloaded"
            assert notify_socket.recv(4096).startswith(b"RELOADING=1\n")
            assert notify_socket.recv(4096) == b"READY=1"
            proc.send_signal(signal.SIGTERM)
            assert proc.stdout.readline().strip() == "stopped"
            assert proc.wait(timeout=5) == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


class TestStopDuringStartup:
    """A stop request abandons the rest of startup; ``_stop`` then
    tears down whatever ``_start`` had set up."""

    def test_stop_cancels_start(self, notify_socket):
        d = GatedDaemon()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: "start-begin" in d.events)
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert d.events == ["start-begin", "start-cancelled", "stop"]

    def test_sighup_held_during_startup_is_dropped(self, notify_socket):
        d = GatedDaemon()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: "start-begin" in d.events)
            d._signal_reload()
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert d.events == ["start-begin", "start-cancelled", "stop"]
        assert _queued(notify_socket) == [b"READY=1"]

    def test_sighup_after_stop_request_is_ignored(self, notify_socket):
        d = GatedDaemon()
        d.start_gate.set()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: d._started)
            d._signal_shutdown()
            d._signal_reload()
            await runner

        _run(scenario)
        assert d.reloads == 0
        assert _queued(notify_socket) == [b"READY=1"]


class TestReloadSerialisation:
    """Reloads never overlap and never outlive the daemon."""

    def test_reload_in_progress_is_cancelled_before_stop(self, notify_socket):
        d = GatedDaemon()
        d.start_gate.set()
        d.reload_gate.clear()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: d._started)
            d._signal_reload()
            await _until(lambda: "reload-begin" in d.events)
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert d.events == [
            "start-begin", "start-end",
            "reload-begin", "reload-cancelled", "stop",
        ]
        assert _kinds(_queued(notify_socket)) == [
            "READY", "RELOADING", "READY",
        ]

    def test_sighups_during_a_reload_run_one_more(self, notify_socket):
        """A systemd reload whose SIGHUP arrives during another reload
        completes only with a reload whose RELOADING=1 postdates the
        signal (systemd compares MONOTONIC_USEC), so the held SIGHUPs
        are served by one more pass rather than dropped."""
        d = GatedDaemon()
        d.start_gate.set()
        d.reload_gate.clear()

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: d._started)
            d._signal_reload()
            await _until(lambda: "reload-begin" in d.events)
            d._signal_reload()
            d._signal_reload()
            d.reload_gate.set()
            await _until(
                lambda: d.reloads == 2 and not d._reload_in_progress(),
            )
            d._signal_shutdown()
            await runner

        _run(scenario)
        assert d.reloads == 2
        messages = _queued(notify_socket)
        assert _kinds(messages) == [
            "READY", "RELOADING", "READY", "RELOADING", "READY",
        ]
        first, second = (
            int(m.split(b"MONOTONIC_USEC=")[1])
            for m in messages if m.startswith(b"RELOADING=1")
        )
        assert second > first

    def test_failed_reload_is_logged_and_the_held_one_runs(
        self, notify_socket, caplog,
    ):
        d = GatedDaemon()
        d.start_gate.set()
        d.reload_gate.clear()
        d.fail_next_reload = True

        async def scenario() -> None:
            runner = asyncio.create_task(d.run())
            await _until(lambda: d._started)
            d._signal_reload()
            await _until(lambda: "reload-begin" in d.events)
            d._signal_reload()
            d.reload_gate.set()
            await _until(
                lambda: d.reloads == 2 and not d._reload_in_progress(),
            )
            d._signal_shutdown()
            await runner

        with caplog.at_level(logging.ERROR, logger="test.daemon.gated"):
            _run(scenario)
        assert d.events == [
            "start-begin", "start-end",
            "reload-begin", "reload-begin", "reload-end", "stop",
        ]
        assert any("Reload failed" in r.message for r in caplog.records)
        assert _kinds(_queued(notify_socket)) == [
            "READY", "RELOADING", "READY", "RELOADING", "READY",
        ]
