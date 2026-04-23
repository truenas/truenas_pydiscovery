"""Base daemon lifecycle with signal handling.

Provides ``BaseDaemon``, an async-native base class that manages:

* Graceful shutdown on SIGTERM / SIGINT
* Config reload on SIGHUP
* Status dump on SIGUSR1
* Structured start → run → stop lifecycle

Subclasses implement ``_start``, ``_stop``, and optionally
``apply_config``, ``_reload``, and ``_write_status``.
"""
from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any


class BaseDaemon:
    """Async daemon with signal-driven lifecycle.

    Subclass contract::

        async def _start(self, loop: asyncio.AbstractEventLoop) -> None:
            # Open sockets, load config, start tasks.

        async def _stop(self) -> None:
            # Cancel tasks, close sockets, write final state.

        def apply_config(self, new_config: Any) -> None:  # optional
            # Swap in a freshly-parsed config before _reload() runs.
            # Called by CompositeDaemon's refresh path so _reload()
            # can diff old vs new; a standalone daemon that doesn't
            # need live reload can leave the default no-op.

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

    def apply_config(self, new_config: Any) -> None:
        """Swap in a freshly-parsed config before ``_reload`` runs.

        Called by ``CompositeDaemon`` during its SIGHUP-driven
        config-refresh step so subclasses can stash the new value
        (and any cached derivations of it) before ``_reload`` fans
        out.  The default is a no-op so subclasses that don't
        support live reload — or that only need ``_reload``'s
        re-read-from-disk behaviour — can ignore the hook entirely.
        Subclasses that override should re-derive any cached fields
        here so ``_reload`` sees them ready."""
        return None

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


class ConfigDaemon(BaseDaemon):
    """``BaseDaemon`` with configuration stashing for live reload.

    The three protocol daemons (mDNS, NBNS, WSD) each implement a
    diff-based ``_reload`` that compares the previous config
    against the current one to pick a minimally disruptive
    reconciliation path.  They all need the same scaffolding: a
    ``_config`` attribute, a ``_prev_config`` slot initialised to
    ``None``, and an ``apply_config`` that stashes the outgoing
    config before overwriting.  This subclass provides that
    scaffolding once so protocol daemons only implement the
    protocol-specific bits (``_reload`` path selection and any
    cached-attribute re-derivation via ``_on_config_applied``).

    ``CompositeDaemon`` continues to extend ``BaseDaemon`` directly
    — it has no config of its own to stash; it's the orchestrator
    that dispatches fresh configs to children via each child's
    ``apply_config``.
    """

    def __init__(self, logger: logging.Logger, config: Any) -> None:
        super().__init__(logger)
        self._config = config
        # ``None`` until the first ``apply_config`` call; subclasses
        # use this to diff old vs. new on SIGHUP.  The first SIGHUP
        # always hits the ``prev is None`` full-rebuild branch.
        self._prev_config: Any = None

    def apply_config(self, new_config: Any) -> None:
        """Stash the outgoing config and swap in the new one.

        Calls ``_on_config_applied`` so subclasses can re-derive
        cached attributes (e.g. FQDN, endpoint UUID) from the
        fresh config before ``_reload`` runs against them.
        Subclasses that don't cache anything derived from config
        leave the hook as the default no-op."""
        self._prev_config = self._config
        self._config = new_config
        self._on_config_applied(new_config)

    def _on_config_applied(self, new_config: Any) -> None:
        """Hook for subclasses to re-derive cached attributes from
        the freshly-applied config.  Default is no-op; subclasses
        override when they cache anything derived from
        ``_config`` that ``_reload`` subsequently reads."""
        return None
