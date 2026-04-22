"""Composite daemon that hosts multiple child BaseDaemons in one process.

The discovery package runs mDNS, NetBIOS NS, and WSD.  Each is a
``BaseDaemon`` subclass with the same start/stop/reload/status
contract.  ``CompositeDaemon`` takes a list of them and fans every
lifecycle event across the list, so a single ``truenas-discoveryd``
process can host all three while keeping the per-protocol servers
completely unchanged.

Each child's failure during start, stop, or reload is caught and
logged so one protocol's problem can't take down the others.  The
composite itself is a ``BaseDaemon``, so it inherits the same signal
handling (SIGTERM/SIGINT/SIGHUP/SIGUSR1) — child daemons are driven
purely through their ``_start`` / ``_stop`` / ``_reload`` /
``_write_status`` hooks.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Sequence

from .daemon import BaseDaemon

ConfigReloader = Callable[[], Any]
ConfigDispatcher = Callable[[Sequence[tuple[str, BaseDaemon]], Any], None]


class CompositeDaemon(BaseDaemon):
    """Run several ``BaseDaemon`` instances inside a single event loop.

    The optional *config_reloader* + *config_dispatch* pair turns the
    SIGHUP fan-out into a live reload: the daemon re-reads its config
    file, pushes the fresh sub-configs into the per-protocol children,
    and only then fans SIGHUP out so each child's ``_reload()`` sees
    the new values.  Without that pair, children keep whatever config
    they captured at ``__init__`` and SIGHUP can only pick up changes
    the children read directly from disk every reload (e.g. mDNS's
    services.d directory)."""

    def __init__(
        self,
        logger: logging.Logger,
        children: Sequence[tuple[str, BaseDaemon]],
        *,
        config_reloader: ConfigReloader | None = None,
        config_dispatch: ConfigDispatcher | None = None,
    ) -> None:
        """Create a composite wrapping *children*.

        *children* is a sequence of ``(name, daemon)`` pairs; the name
        is used purely for logging so operators can tell which
        protocol is misbehaving.

        *config_reloader* is a zero-argument callable invoked on
        SIGHUP to re-read the config file; its return value is then
        passed to *config_dispatch* alongside the children list.
        ``config_dispatch`` decides how to slice the reloaded config
        into per-child sub-configs and how to push them into the
        children (typically via each child's ``apply_config``).  Both
        default to ``None``, in which case SIGHUP just fans out with
        whatever config the children already hold.
        """
        super().__init__(logger)
        if not children:
            raise ValueError("CompositeDaemon needs at least one child")
        self._children: list[tuple[str, BaseDaemon]] = list(children)
        self._config_reloader = config_reloader
        self._config_dispatch = config_dispatch

    async def _start(
        self, loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Start every child concurrently.  One failing doesn't abort others."""
        self._logger.info(
            "Starting composite daemon with children: %s",
            ", ".join(name for name, _ in self._children),
        )
        results = await asyncio.gather(
            *(child._start(loop) for _, child in self._children),
            return_exceptions=True,
        )
        for (name, _), res in zip(self._children, results):
            if isinstance(res, BaseException):
                self._logger.error(
                    "Child %s failed to start: %s", name, res,
                )

    async def _stop(self) -> None:
        """Stop every child concurrently.  Errors are logged, not re-raised."""
        results = await asyncio.gather(
            *(child._stop() for _, child in self._children),
            return_exceptions=True,
        )
        for (name, _), res in zip(self._children, results):
            if isinstance(res, BaseException):
                self._logger.error(
                    "Child %s failed to stop cleanly: %s", name, res,
                )

    async def _reload(self) -> None:
        """Re-read config (if a reloader is wired up) and fan SIGHUP
        out to every child."""
        if self._config_reloader is not None:
            await self._refresh_child_configs()
        results = await asyncio.gather(
            *(child._reload() for _, child in self._children),
            return_exceptions=True,
        )
        for (name, _), res in zip(self._children, results):
            if isinstance(res, BaseException):
                self._logger.error(
                    "Child %s failed to reload: %s", name, res,
                )

    async def _refresh_child_configs(self) -> None:
        """Invoke the config reloader + dispatcher before fan-out.

        Errors from either step are logged and swallowed — we still
        fan SIGHUP out so children can re-probe interfaces etc., just
        with whatever config they already have."""
        reloader = self._config_reloader
        if reloader is None:
            return
        loop = asyncio.get_running_loop()
        try:
            new_config = await loop.run_in_executor(None, reloader)
        except Exception:
            self._logger.exception(
                "Reload: failed to re-read config; "
                "fanning out SIGHUP with previous config",
            )
            return
        if self._config_dispatch is None:
            return
        try:
            self._config_dispatch(self._children, new_config)
        except Exception:
            self._logger.exception(
                "Reload: config dispatch raised; "
                "children may hold stale config",
            )

    def _write_status(self) -> None:
        """Fan SIGUSR1 out to every child."""
        for name, child in self._children:
            try:
                child._write_status()
            except Exception as e:
                self._logger.error(
                    "Child %s failed to write status: %s", name, e,
                )

    @property
    def children(self) -> list[tuple[str, BaseDaemon]]:
        """Read-only view of (name, daemon) children."""
        return list(self._children)
