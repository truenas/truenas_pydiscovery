"""Base daemon lifecycle with signal handling.

Provides ``BaseDaemon``, an async-native base class that manages:

* Graceful shutdown on SIGTERM / SIGINT, including during startup
* Config reload on SIGHUP, deferred while startup or another reload
  is running
* Status dump on SIGUSR1
* Structured start → run → stop lifecycle
* systemd ``Type=notify-reload`` readiness and reload notifications

Subclasses implement ``_start``, ``_stop``, and optionally
``apply_config``, ``_reload``, and ``_write_status``.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from typing import Any

from .sd_notify import notify_ready, notify_reloading


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
        # False until ``_start`` returns.  ``_reload`` works on the
        # state ``_start`` builds, and two reloads must not interleave,
        # so a SIGHUP that arrives during startup or during a reload
        # only sets ``_reload_pending``; one reload runs once the
        # current step has finished.
        self._started = False
        self._reload_pending = False
        self._reload_task: asyncio.Task | None = None

    async def run(self) -> None:
        """Start, run until shutdown signal, then stop.

        Readiness is reported to systemd (``READY=1``, a no-op outside
        systemd) as soon as the signal handlers are installed, before
        ``_start`` runs, so systemd's start timeout does not cover the
        protocols' probing and registration.  From then on a SIGHUP is
        held until startup completes, and a stop request abandons the
        rest of startup.  A reload still running at shutdown is
        cancelled before ``_stop``.
        """
        loop = asyncio.get_running_loop()
        self._setup_signals(loop)
        notify_ready()
        try:
            if await self._start_unless_stopped(loop):
                self._started = True
                if (
                    self._reload_pending
                    and not self._shutdown_event.is_set()
                ):
                    self._reload_pending = False
                    self._schedule_reload(loop)
                await self._shutdown_event.wait()
        finally:
            await self._cancel_reload()
            await self._stop()

    async def _start_unless_stopped(
        self, loop: asyncio.AbstractEventLoop,
    ) -> bool:
        """Run ``_start``, cancelling it if a stop is requested first.

        Returns True if startup completed and False if it was
        abandoned; an exception raised by ``_start`` propagates.
        ``_stop`` then tears down whatever was set up.
        """
        start = loop.create_task(self._start(loop))
        stop_requested = loop.create_task(self._shutdown_event.wait())
        try:
            await asyncio.wait(
                {start, stop_requested},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            stop_requested.cancel()
            if not start.done():
                self._logger.info("Stop requested during startup")
                start.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await start
        if start.cancelled():
            return False
        start.result()
        return True

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
        if self._shutdown_event.is_set():
            self._logger.info("Received SIGHUP while stopping; ignored")
            return
        if not self._started or self._reload_in_progress():
            self._logger.info(
                "Received SIGHUP during %s; reloading once it completes",
                "startup" if not self._started else "a reload",
            )
            self._reload_pending = True
            return
        self._logger.info("Received SIGHUP, scheduling reload")
        self._schedule_reload(asyncio.get_running_loop())

    def _reload_in_progress(self) -> bool:
        return self._reload_task is not None and not self._reload_task.done()

    def _schedule_reload(self, loop: asyncio.AbstractEventLoop) -> None:
        self._reload_task = loop.create_task(self._run_reloads())

    async def _run_reloads(self) -> None:
        """Run ``_reload`` inside the ``Type=notify-reload`` protocol,
        and once more whenever a SIGHUP was held while it ran.

        Every pass sends ``RELOADING=1`` (with ``MONOTONIC_USEC``)
        before ``_reload`` and ``READY=1`` after it, so systemd sees a
        reload finish only once one that began after its signal has
        completed.  A failed pass is logged and does not stop the next.
        """
        while True:
            notify_reloading()
            try:
                await self._reload()
            except Exception:
                self._logger.exception("Reload failed")
            finally:
                notify_ready()
            if not self._reload_pending or self._shutdown_event.is_set():
                return
            self._reload_pending = False

    async def _cancel_reload(self) -> None:
        """Cancel a reload still running at shutdown and wait for it."""
        task = self._reload_task
        if task is None or task.done():
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

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
        # diff it against ``_config`` on reload and treat ``None`` as
        # "anything may have changed".  Under a ``CompositeDaemon``
        # with a config reloader, startup ends by applying the
        # configuration on disk, so a reload sees ``None`` only if
        # every re-read so far failed or skipped this daemon.
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
