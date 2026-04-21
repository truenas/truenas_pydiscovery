"""Atomic JSON status writer for daemon health/metrics.

Writes a ``status.json`` file to the daemon's run directory on demand
(typically triggered by SIGUSR1).  Uses temp-file + rename for
atomic updates so readers never see partial data.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path


class StatusWriter:
    """Writes runtime status as JSON to the run directory."""

    def __init__(self, rundir: Path, logger: logging.Logger) -> None:
        self._rundir = rundir
        self._status_path = rundir / "status.json"
        self._start_time = time.monotonic()
        self._counters: dict[str, int] = {}
        self._logger = logger

    def inc(self, counter: str, n: int = 1) -> None:
        """Increment a named counter by *n*."""
        self._counters[counter] = self._counters.get(counter, 0) + n

    def write(self, server_state: dict) -> None:
        """Write status.json atomically (write to tmp + rename)."""
        self._rundir.mkdir(parents=True, exist_ok=True)

        status = {
            "uptime_seconds": int(time.monotonic() - self._start_time),
            **self._counters,
            **server_state,
        }

        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self._rundir),
                prefix=".status-",
                suffix=".json",
            )
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(status, f, indent=2, default=str)
                    f.write("\n")
                os.replace(tmp_path, str(self._status_path))
                self._logger.info(
                    "Status written to %s", self._status_path,
                )
            except Exception:
                os.unlink(tmp_path)
                raise
        except Exception as e:
            self._logger.error("Failed to write status: %s", e)
