"""Registrar for NetBIOS name registration (RFC 1002 s4.2.2).

Sends REGISTRATION_RETRY_COUNT broadcast packets at
REGISTRATION_RETRY_INTERVAL apart; if no conflict notification
arrives before the last packet, the name transitions from pending
to registered in the local NameTable.
"""
from __future__ import annotations

import asyncio
import struct
import time
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import (
    NBFlag,
    Opcode,
    REGISTRATION_RETRY_COUNT,
    REGISTRATION_RETRY_INTERVAL,
    RRType,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.core.nametable import NameTable
from truenas_pynetbiosns.server.core.registrar import Registrar


def _run(coro, timeout: float = 3.0) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
    finally:
        loop.close()


def _new_pair() -> tuple[list[NBNSMessage], NameTable, Registrar]:
    sent: list[NBNSMessage] = []
    table = NameTable()
    reg = Registrar(sent.append, table)
    return sent, table, reg


class TestRegisterSuccessPath:
    def test_sends_retry_count_packets(self):
        sent, _, reg = _new_pair()
        assert _run(
            reg.register("HOSTA", 0x20, IPv4Address("10.0.0.1")),
        ) is True
        assert len(sent) == REGISTRATION_RETRY_COUNT

    def test_interval_between_first_two_packets(self):
        """Gap between packet 1 and 2 matches REGISTRATION_RETRY_INTERVAL."""
        stamps: list[float] = []
        table = NameTable()
        reg = Registrar(
            lambda m: stamps.append(time.monotonic()), table,
        )

        _run(reg.register("HOSTB", 0x20, IPv4Address("10.0.0.2")))
        assert len(stamps) >= 2
        gap = stamps[1] - stamps[0]
        assert (
            REGISTRATION_RETRY_INTERVAL * 0.7
            <= gap
            <= REGISTRATION_RETRY_INTERVAL * 1.5
        ), f"gap {gap:.3f}s outside tolerance"

    def test_successful_register_marks_name_registered(self):
        _, table, reg = _new_pair()
        _run(reg.register("HOSTC", 0x20, IPv4Address("10.0.0.3")))

        entry = table.lookup(NetBIOSName("HOSTC", 0x20))
        assert entry is not None
        assert entry.registered is True
        assert IPv4Address("10.0.0.3") in entry.addresses


class TestConflictAbortsRegistration:
    def test_conflict_notification_removes_name_and_returns_false(self):
        """A conflict notification received during the registration
        burst must cause ``register`` to return False and drop the
        pending entry from the table."""
        _, table, reg = _new_pair()
        target = NetBIOSName("HOSTD", 0x20)

        async def drive() -> bool:
            task = asyncio.create_task(
                reg.register("HOSTD", 0x20, IPv4Address("10.0.0.4")),
            )
            # Allow the first packet to go out, then signal a conflict
            # before the retry burst ends.
            await asyncio.sleep(0.050)
            reg.on_conflict(target)
            return await task

        result = _run(drive())
        assert result is False
        assert table.lookup(target) is None


class TestRegistrationWireFormat:
    def test_group_flag_set_in_rdata_when_group_true(self):
        sent, _, reg = _new_pair()
        _run(reg.register(
            "GROUP", 0x1e, IPv4Address("10.0.0.9"), group=True,
        ))
        assert sent

        # Round-trip through the wire to confirm the GROUP bit lands
        # in the actual rdata peers will see.
        wire = sent[0].to_wire()
        decoded = NBNSMessage.from_wire(wire)
        assert decoded.opcode == Opcode.REGISTRATION
        assert decoded.additionals
        rr = decoded.additionals[0]
        assert rr.rr_type == RRType.NB
        # NB rdata layout: 2-byte flags, 4-byte IPv4
        flags_val, = struct.unpack("!H", rr.rdata[:2])
        assert flags_val & NBFlag.GROUP

    def test_unique_name_clears_group_flag(self):
        sent, _, reg = _new_pair()
        _run(reg.register(
            "UNIQUE", 0x20, IPv4Address("10.0.0.10"), group=False,
        ))
        assert sent

        wire = sent[0].to_wire()
        decoded = NBNSMessage.from_wire(wire)
        rr = decoded.additionals[0]
        flags_val, = struct.unpack("!H", rr.rdata[:2])
        assert not (flags_val & NBFlag.GROUP)
