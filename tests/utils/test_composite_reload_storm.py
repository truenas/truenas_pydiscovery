"""Overlap guard on ``CompositeDaemon._reload``.

The composite sets ``_reload_running = True`` around the reload
body and drops any SIGHUP that arrives while that flag is set.
These tests drive a real composite with a real ``MDNSServer``
child (``interfaces=[]`` so no network I/O happens) and exercise
the state transitions: initial value, flag cleared after a normal
reload, drop-and-log when the flag is set on entry, and normal
reloads in sequence once the flag clears.

Racing two reload tasks through the guard would need a child that
can park its ``_reload`` mid-flight at a test-controlled gate —
that's a hand-rolled fake per the project rule, which we avoid.
Flipping ``_reload_running`` manually gives the same observable
(the guard returns early) without a fake child.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from truenas_pydiscovery_utils.composite import CompositeDaemon
from truenas_pymdns.server.config import (
    DaemonConfig as MdnsConfig,
    ServerConfig as MdnsServerConfig,
)
from truenas_pymdns.server.server import MDNSServer


def _logger() -> logging.Logger:
    return logging.getLogger("test.composite.storm")


def _composite(tmp_path: Path) -> tuple[CompositeDaemon, MDNSServer]:
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    child = MDNSServer(MdnsConfig(
        server=MdnsServerConfig(host_name="host"),
        service_dir=tmp_path / "no-services",
        rundir=rundir,
    ))
    comp = CompositeDaemon(_logger(), [("mdns", child)])
    return comp, child


class TestOverlapGuard:
    def test_flag_clears_after_reload(self, tmp_path):
        comp, _ = _composite(tmp_path)
        asyncio.run(comp._reload())
        assert comp._reload_running is False

    def test_sighup_during_inflight_reload_is_dropped(
        self, tmp_path, caplog,
    ):
        # Flip the guard manually to simulate being inside a
        # parked reload.  The next ``_reload`` call must return
        # early and log, rather than run the body — which is
        # exactly what happens to the second SIGHUP in a real
        # overlap.
        comp, child = _composite(tmp_path)
        service_groups_before = dict(child._service_groups)
        comp._reload_running = True
        try:
            with caplog.at_level(
                logging.INFO, logger="test.composite.storm",
            ):
                asyncio.run(comp._reload())
        finally:
            comp._reload_running = False
        # The child's _reload never ran: its registry bookkeeping
        # is unchanged.
        assert child._service_groups == service_groups_before
        # The drop was logged.
        assert any(
            "dropped" in r.message.lower()
            for r in caplog.records
        )

    def test_followup_sighup_runs_normally(self, tmp_path):
        # Once the guard clears, subsequent SIGHUPs run as normal —
        # this is the expected operator flow after an overlapped
        # SIGHUP was dropped.
        comp, _ = _composite(tmp_path)
        asyncio.run(comp._reload())
        asyncio.run(comp._reload())
        assert comp._reload_running is False
