"""Tests for the shared logger module."""
from __future__ import annotations

import logging

from truenas_pydiscovery_utils.logger import (
    SyslogFormatter,
    SyslogHandler,
    setup_console,
)


class TestSyslogFormatter:
    def test_collapses_newlines(self):
        fmt = SyslogFormatter()
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "line1\nline2\nline3", (), None,
        )
        result = fmt.format(record)
        assert "\n" not in result
        assert r"\n" in result

    def test_single_line_unchanged(self):
        fmt = SyslogFormatter()
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "no newlines here", (), None,
        )
        result = fmt.format(record)
        assert "no newlines here" in result


class TestSyslogHandler:
    def test_pending_queue_buffers_on_failure(self):
        # Use a bogus address that will fail
        handler = SyslogHandler(
            address="/nonexistent/socket/path",
            pending_maxlen=100,
        )
        record = logging.LogRecord(
            "test", logging.INFO, "", 0, "test message", (), None,
        )
        # emit should not raise — it buffers
        handler.emit(record)
        assert len(handler._pending) == 1
        handler.close()

    def test_pending_queue_bounded(self):
        handler = SyslogHandler(
            address="/nonexistent/socket/path",
            pending_maxlen=3,
        )
        for i in range(10):
            record = logging.LogRecord(
                "test", logging.INFO, "", 0, f"msg {i}", (), None,
            )
            handler.emit(record)
        # deque maxlen=3 keeps only the last 3
        assert len(handler._pending) <= 3
        handler.close()


class TestSetupConsole:
    def _reset_root_logger(self):
        """Remove all handlers so basicConfig can re-run."""
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        root.setLevel(logging.WARNING)

    def test_verbosity_0_is_warning(self):
        self._reset_root_logger()
        setup_console(0)
        assert logging.root.level == logging.WARNING

    def test_verbosity_1_is_info(self):
        self._reset_root_logger()
        setup_console(1)
        assert logging.root.level == logging.INFO

    def test_verbosity_2_is_debug(self):
        self._reset_root_logger()
        setup_console(2)
        assert logging.root.level == logging.DEBUG
