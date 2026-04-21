"""Tests for the shared BaseDaemon lifecycle."""
from __future__ import annotations

import asyncio
import logging
import signal

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
