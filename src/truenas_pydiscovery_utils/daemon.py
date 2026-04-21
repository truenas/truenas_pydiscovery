"""Base daemon lifecycle with signal handling.

Provides ``BaseDaemon``, an async-native base class that manages:

* Graceful shutdown on SIGTERM / SIGINT
* Config reload on SIGHUP
* Status dump on SIGUSR1
* Structured start → run → stop lifecycle

Subclasses implement ``_start``, ``_stop``, and optionally
``_reload`` and ``_write_status``.
"""
from __future__ import annotations

import asyncio
import logging
import signal


class BaseDaemon:
    """Async daemon with signal-driven lifecycle.

    Subclass contract::

        async def _start(self, loop: asyncio.AbstractEventLoop) -> None:
            # Open sockets, load config, start tasks.

        async def _stop(self) -> None:
            # Cancel tasks, close sockets, write final state.

        async def _reload(self) -> None:          # optional (SIGHUP)
            ...

        def _write_status(self) -> None:           # optional (SIGUSR1)
            ...
    """

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger
        self._shutdown_event = asyncio.Event()

    async def run(self) -> None:
        """Start, run until shutdown signal, then stop."""
        loop = asyncio.get_running_loop()
        self._setup_signals(loop)
        try:
            await self._start(loop)
            await self._shutdown_event.wait()
        finally:
            await self._stop()

    # -- Hooks for subclasses -----------------------------------------------

    async def _start(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once at daemon startup.  Override in subclass."""
        raise NotImplementedError

    async def _stop(self) -> None:
        """Called once at daemon shutdown.  Override in subclass."""
        raise NotImplementedError

    async def _reload(self) -> None:
        """Called on SIGHUP.  Override to support live reload."""
        self._logger.info("SIGHUP received but reload not implemented")

    def _write_status(self) -> None:
        """Called on SIGUSR1.  Override to dump runtime status."""
        self._logger.info("SIGUSR1 received but status dump not implemented")

    # -- Signal wiring ------------------------------------------------------

    def _setup_signals(self, loop: asyncio.AbstractEventLoop) -> None:
        loop.add_signal_handler(signal.SIGTERM, self._signal_shutdown)
        loop.add_signal_handler(signal.SIGINT, self._signal_shutdown)
        loop.add_signal_handler(signal.SIGHUP, self._signal_reload)
        loop.add_signal_handler(signal.SIGUSR1, self._signal_status)

    def _signal_shutdown(self) -> None:
        self._logger.info("Received shutdown signal")
        self._shutdown_event.set()

    def _signal_reload(self) -> None:
        self._logger.info("Received SIGHUP, scheduling reload")
        asyncio.get_event_loop().create_task(self._reload())

    def _signal_status(self) -> None:
        self._logger.info("Received SIGUSR1, scheduling status write")
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, self._write_status)
