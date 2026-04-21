"""Refresher: periodic name refresh per RFC 1002 s4.2.4.

Emits one REFRESH packet per registered name on each tick of the
configured interval.  Pending / group-flag behaviour matches the
registrar's wire output.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import NBFlag, Opcode
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.core.nametable import NameTable
from truenas_pynetbiosns.server.core.refresher import Refresher


def _run(coro, timeout: float = 2.0) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
    finally:
        loop.close()


def _seed_registered(table: NameTable, name: str, *,
                     group: bool = False) -> None:
    nb = NetBIOSName(name, 0x20)
    flags = NBFlag.GROUP if group else NBFlag(0)
    table.add(nb, IPv4Address("10.0.0.1"), flags)
    table.mark_registered(nb)


class TestRefreshTick:
    def test_emits_one_refresh_per_registered_name_per_tick(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed_registered(table, "HOSTA")
        _seed_registered(table, "HOSTB")

        # interval small so we can observe one tick quickly
        refresher = Refresher(
            sent.append, table, IPv4Address("10.0.0.1"), interval=0.050,
        )

        async def drive() -> None:
            refresher.start()
            await asyncio.sleep(0.080)  # just past one tick
            refresher.cancel()

        _run(drive())
        assert len(sent) == 2
        names = {m.questions[0].name.name for m in sent}
        assert names == {"HOSTA", "HOSTB"}
        for msg in sent:
            assert msg.opcode == Opcode.REFRESH

    def test_pending_entries_not_refreshed(self):
        """Names still in registration have ``registered=False`` and
        must be skipped by the tick."""
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed_registered(table, "DONE")
        # Pending: added but not marked registered
        table.add(
            NetBIOSName("PENDING", 0x20),
            IPv4Address("10.0.0.2"), NBFlag(0),
        )

        refresher = Refresher(
            sent.append, table, IPv4Address("10.0.0.1"), interval=0.050,
        )

        async def drive() -> None:
            refresher.start()
            await asyncio.sleep(0.080)
            refresher.cancel()

        _run(drive())
        assert len(sent) == 1
        assert sent[0].questions[0].name.name == "DONE"


class TestCancel:
    def test_cancel_stops_loop_without_exception(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed_registered(table, "HOSTX")
        refresher = Refresher(
            sent.append, table, IPv4Address("10.0.0.1"), interval=10.0,
        )

        async def drive() -> None:
            refresher.start()
            await asyncio.sleep(0.010)
            refresher.cancel()
            # give the task a moment to wake up and exit cleanly
            await asyncio.sleep(0.010)

        _run(drive())
        # No refresh fired because the tick (10s) didn't elapse.
        assert sent == []
        # Task was cleared.
        assert refresher._task is None

    def test_cancel_before_start_is_safe(self):
        """Refresher created but never started — cancel must not raise."""
        refresher = Refresher(
            lambda m: None, NameTable(), IPv4Address("10.0.0.1"),
        )
        refresher.cancel()
