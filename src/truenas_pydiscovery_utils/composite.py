"""Composite daemon that hosts multiple child BaseDaemons in one process.

The discovery package runs mDNS, NetBIOS NS, and WSD.  Each is a
``BaseDaemon`` subclass with the same start/stop/reload/status
contract.  ``CompositeDaemon`` takes a list of them and fans every
lifecycle event across the list, so a single ``truenas-pydiscoveryd``
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
from typing import Sequence

from .daemon import BaseDaemon


class CompositeDaemon(BaseDaemon):
    """Run several ``BaseDaemon`` instances inside a single event loop."""

    def __init__(
        self,
        logger: logging.Logger,
        children: Sequence[tuple[str, BaseDaemon]],
    ) -> None:
        """Create a composite wrapping *children*.

        *children* is a sequence of ``(name, daemon)`` pairs; the name
        is used purely for logging so operators can tell which
        protocol is misbehaving.
        """
        super().__init__(logger)
        if not children:
            raise ValueError("CompositeDaemon needs at least one child")
        self._children: list[tuple[str, BaseDaemon]] = list(children)

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
        """Fan SIGHUP out to every child."""
        results = await asyncio.gather(
            *(child._reload() for _, child in self._children),
            return_exceptions=True,
        )
        for (name, _), res in zip(self._children, results):
            if isinstance(res, BaseException):
                self._logger.error(
                    "Child %s failed to reload: %s", name, res,
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
