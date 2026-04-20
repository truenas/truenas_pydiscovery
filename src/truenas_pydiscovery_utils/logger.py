"""Non-blocking syslog logging for TrueNAS discovery daemons.

Uses ``QueueHandler`` / ``QueueListener`` so log calls in the asyncio
event loop never block on socket I/O.  A bounded pending queue inside
the syslog handler buffers records when syslog-ng is temporarily
unavailable, draining automatically on the next successful send.

Pattern adapted from ``middlewared.logger``.
"""
from __future__ import annotations

import logging
import logging.handlers
import queue
import socket
from collections import deque
from pathlib import Path
from types import MappingProxyType

DEFAULT_SYSLOG_PATH = "/dev/log"
DEFAULT_LOG_FORMAT = "%(asctime)s %(name)s %(levelname)s %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_PENDING_QUEUE_LEN = 2048


class SyslogHandler(logging.handlers.SysLogHandler):
    """SysLogHandler with a pending queue for resilience.

    When the syslog socket is unreachable, records are buffered in a
    bounded ``deque`` and drained on the next successful emit.  An
    optional fallback handler (e.g. to a file) receives records that
    cannot be delivered.
    """

    def __init__(
        self,
        address: str = DEFAULT_SYSLOG_PATH,
        pending_maxlen: int = DEFAULT_PENDING_QUEUE_LEN,
    ) -> None:
        self._pending: deque[logging.LogRecord] = deque(
            maxlen=pending_maxlen,
        )
        self._fallback: logging.Handler | None = None
        socktype = socket.SOCK_DGRAM
        if not address.startswith("/"):
            socktype = socket.SOCK_DGRAM
        super().__init__(address, socktype=socktype)

    def set_fallback(self, handler: logging.Handler) -> None:
        """Set a fallback handler used when syslog is unreachable."""
        self._fallback = handler

    # -- emit / drain -------------------------------------------------------

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a record, buffering on failure."""
        if not self._drain_pending():
            self._pending.append(record)
            self._emit_fallback(record)
            return
        try:
            super().emit(record)
        except Exception:
            self._pending.append(record)
            self._emit_fallback(record)

    def handleError(self, record: logging.LogRecord) -> None:
        """Re-raise so our ``emit`` wrapper can catch and queue."""
        raise

    def close(self) -> None:
        super().close()
        if self._fallback:
            self._fallback.close()
            self._fallback = None

    # -- internals ----------------------------------------------------------

    def _drain_pending(self) -> bool:
        """Try to send all queued records.  Return True on success."""
        while self._pending:
            record = self._pending.popleft()
            try:
                super().emit(record)
            except Exception:
                self._pending.appendleft(record)
                return False
        return True

    def _emit_fallback(self, record: logging.LogRecord) -> None:
        if self._fallback is None:
            return
        try:
            self._fallback.emit(record)
        except Exception:
            pass


class SyslogFormatter(logging.Formatter):
    """Formatter that collapses multi-line messages for syslog."""

    _NL_TABLE = MappingProxyType(str.maketrans({"\n": r"\n"}))

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return msg.translate(self._NL_TABLE)


# -- Public setup helpers ---------------------------------------------------

def setup_syslog(
    name: str,
    *,
    syslog_path: str = DEFAULT_SYSLOG_PATH,
    ident: str | None = None,
    fallback_path: Path | None = None,
    level: int = logging.DEBUG,
    log_format: str = DEFAULT_LOG_FORMAT,
    date_format: str = DEFAULT_DATE_FORMAT,
    pending_maxlen: int = DEFAULT_PENDING_QUEUE_LEN,
) -> logging.Logger:
    """Configure non-blocking syslog logging for a daemon.

    Returns the root logger (or named logger if *name* is not None).
    All log calls go through a ``QueueHandler`` so the asyncio loop
    is never blocked by syslog I/O.
    """
    # Background syslog handler with pending queue
    syslog_handler = SyslogHandler(
        address=syslog_path,
        pending_maxlen=pending_maxlen,
    )
    syslog_handler.setLevel(level)
    syslog_handler.setFormatter(
        SyslogFormatter(log_format, datefmt=date_format),
    )
    if ident is None:
        ident = f"{name.upper()}: "
    syslog_handler.ident = ident

    # Optional file fallback
    if fallback_path is not None:
        fallback = logging.handlers.RotatingFileHandler(
            str(fallback_path), "a", 10_485_760, 3, "utf-8",
        )
        fallback.setLevel(level)
        fallback.setFormatter(
            logging.Formatter(log_format, datefmt=date_format),
        )
        syslog_handler.set_fallback(fallback)

    # Non-blocking queue
    log_queue: queue.Queue[logging.LogRecord] = queue.Queue()
    queue_handler = logging.handlers.QueueHandler(log_queue)

    listener = logging.handlers.QueueListener(
        log_queue, syslog_handler, respect_handler_level=True,
    )
    listener.start()

    logger = logging.getLogger(name)
    logger.addHandler(queue_handler)
    logger.setLevel(level)
    return logger


def setup_console(
    verbosity: int = 0,
    log_format: str = DEFAULT_LOG_FORMAT,
    date_format: str = DEFAULT_DATE_FORMAT,
) -> None:
    """Configure console (stderr) logging based on ``-v`` count.

    0 = WARNING, 1 = INFO, 2+ = DEBUG.
    """
    level = {0: logging.WARNING, 1: logging.INFO}.get(
        verbosity, logging.DEBUG,
    )
    logging.basicConfig(
        level=level,
        format=log_format,
        datefmt=date_format,
    )
