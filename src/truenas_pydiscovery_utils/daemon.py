"""Base daemon lifecycle with signal handling.

Provides ``BaseDaemon``, an async-native base class that manages:

* Graceful shutdown on SIGTERM / SIGINT, including during startup
* Config reload on SIGHUP, and interface reconciliation when the
  system's interfaces or addresses change (``request_reconcile``),
  run one at a time and deferred while startup is running
* Status dump on SIGUSR1
* Structured start → run → stop lifecycle
* systemd ``Type=notify-reload`` readiness and reload notifications

Subclasses implement ``_start``, ``_stop``, and optionally
``apply_config``, ``_reload``, ``_reconcile_interfaces``,
``_on_link_up`` and ``_write_status``.
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

        async def _reconcile_interfaces(self) -> None:   # optional
            # Interfaces or addresses changed (``request_reconcile``).

        async def _on_link_up(self, ifindex: int) -> None:  # optional
            # Interface *ifindex* came up.

        def _write_status(self) -> None:           # optional (SIGUSR1)
            ...
    """

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger
        self._shutdown_event = asyncio.Event()
        # False until ``_start`` returns.  ``_reload`` and
        # ``_reconcile_interfaces`` work on the state ``_start`` builds
        # and must not interleave with each other, so a request that
        # arrives during startup or while one of them runs only sets
        # its pending flag; ``_run_pending`` serves it once the current
        # step has finished.
        self._started = False
        self._reload_pending = False
        self._reconcile_pending = False
        self._work_task: asyncio.Task | None = None
        # What ``_work_task`` is running, for the log.
        self._work_label = ""

    async def run(self) -> None:
        """Start, run until shutdown signal, then stop.

        Readiness is reported to systemd (``READY=1``, a no-op outside
        systemd) as soon as the signal handlers are installed, before
        ``_start`` runs, so systemd's start timeout does not cover the
        protocols' probing and registration.  From then on a SIGHUP or
        a reconcile request is held until startup completes, and a stop
        request abandons the rest of startup.  A reload or reconcile
        still running at shutdown is cancelled before ``_stop``.
        """
        loop = asyncio.get_running_loop()
        self._setup_signals(loop)
        notify_ready()
        try:
            if await self._start_unless_stopped(loop):
                self._started = True
                self._serve_pending(loop)
                await self._shutdown_event.wait()
        finally:
            await self._cancel_work()
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

    async def _reconcile_interfaces(self) -> None:
        """Called after the system's interfaces or addresses changed.

        Override to bring the live state in line with them.  Never
        runs alongside ``_start``, ``_reload`` or another reconcile."""
        return None

    async def _on_link_up(self, ifindex: int) -> None:
        """Called when interface *ifindex* comes up.  Override to
        announce on it again."""
        return None

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
        self._reload_pending = True
        if not self._started or self._work_in_progress():
            self._logger.info(
                "Received SIGHUP during %s; reloading once it completes",
                self._work_label if self._started else "startup",
            )
            return
        self._logger.info("Received SIGHUP, scheduling reload")
        self._serve_pending(asyncio.get_running_loop())

    def request_reconcile(self) -> None:
        """Have ``_reconcile_interfaces`` run: interfaces or addresses
        changed.  Held, like a SIGHUP, while startup, a reload or
        another reconcile is running."""
        if self._shutdown_event.is_set():
            return
        self._reconcile_pending = True
        if self._started and not self._work_in_progress():
            self._serve_pending(asyncio.get_running_loop())

    def _work_in_progress(self) -> bool:
        return self._work_task is not None and not self._work_task.done()

    def _serve_pending(self, loop: asyncio.AbstractEventLoop) -> None:
        if self._shutdown_event.is_set():
            return
        if self._reload_pending or self._reconcile_pending:
            self._work_task = loop.create_task(self._run_pending())

    async def _run_pending(self) -> None:
        """Run the held reloads and reconciles, one at a time, until
        none is left.

        A reload runs inside the ``Type=notify-reload`` protocol:
        ``RELOADING=1`` (with ``MONOTONIC_USEC``) before ``_reload``
        and ``READY=1`` after it, so systemd sees a reload finish only
        once one that began after its signal has completed.  A
        reconcile is not reported: systemd did not ask for it.  A held
        reload goes first.  A failed pass is logged and does not stop
        the next.
        """
        while not self._shutdown_event.is_set():
            if self._reload_pending:
                self._reload_pending = False
                self._work_label = "a reload"
                notify_reloading()
                try:
                    await self._reload()
                except Exception:
                    self._logger.exception("Reload failed")
                finally:
                    notify_ready()
            elif self._reconcile_pending:
                self._reconcile_pending = False
                self._work_label = "an interface update"
                try:
                    await self._reconcile_interfaces()
                except Exception:
                    self._logger.exception("Interface update failed")
            else:
                return

    async def _cancel_work(self) -> None:
        """Cancel a reload or reconcile still running at shutdown and
        wait for it."""
        task = self._work_task
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
