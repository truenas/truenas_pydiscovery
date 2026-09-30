"""Registrar for NetBIOS name registration (RFC 1002 s4.2.2).

Broadcasts one registration request up to REGISTRATION_RETRY_COUNT
times, each followed by a REGISTRATION_RETRY_INTERVAL wait (RFC 1002
s5.1.1.1); if no negative response carrying the request's NAME_TRN_ID
arrives by the end of the last wait, the name transitions from pending
to registered in the local NameTable.
"""
from __future__ import annotations

import asyncio
import struct
import time
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import (
    NBFlag,
    NameType,
    Opcode,
    REGISTRATION_RETRY_COUNT,
    REGISTRATION_RETRY_INTERVAL,
    RRType,
    Rcode,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.config import DaemonConfig, ServerConfig
from truenas_pynetbiosns.server.core.nametable import NameTable
from truenas_pynetbiosns.server.core.registrar import Registrar
from truenas_pynetbiosns.server.net.subnet import NbnsSubnet
from truenas_pynetbiosns.server.net.transport import NBNSTransport
from truenas_pynetbiosns.server.server import NBNSServer, PerSubnetState


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

    def test_every_retransmission_carries_the_same_trn_id(self):
        """RFC 1002 s5.1.1.1 retransmits one request and matches the
        response against its transaction id; nmbd resends the same
        packet (``retransmit_or_expire_response_records``)."""
        sent, _, reg = _new_pair()
        _run(reg.register("HOSTF", 0x20, IPv4Address("192.0.2.6")))
        assert len(sent) == REGISTRATION_RETRY_COUNT
        assert len({msg.trn_id for msg in sent}) == 1


class TestConflictAbortsRegistration:
    def test_conflict_notification_removes_name_and_returns_false(self):
        """A conflict notification received during the registration
        burst must cause ``register`` to return False and drop the
        pending entry from the table."""
        sent, table, reg = _new_pair()
        target = NetBIOSName("HOSTD", 0x20)

        async def drive() -> bool:
            task = asyncio.create_task(
                reg.register("HOSTD", 0x20, IPv4Address("10.0.0.4")),
            )
            # Allow the first packet to go out, then signal a conflict
            # before the retry burst ends.
            await asyncio.sleep(0.050)
            reg.on_conflict(target, sent[0].trn_id)
            return await task

        result = _run(drive())
        assert result is False
        assert table.lookup(target) is None

    def test_conflict_after_last_request_aborts_registration(self):
        """RFC 1002 s5.1.1.1 pauses BCAST_REQ_RETRY_TIMEOUT after the
        final request as well, so a negative response to that request
        still blocks the claim."""
        table = NameTable()
        target = NetBIOSName("HOSTE", 0x20)
        sent: list[NBNSMessage] = []

        def send(msg: NBNSMessage) -> None:
            sent.append(msg)
            if len(sent) == REGISTRATION_RETRY_COUNT:
                asyncio.get_running_loop().call_later(
                    REGISTRATION_RETRY_INTERVAL / 5,
                    reg.on_conflict, target, msg.trn_id,
                )

        reg = Registrar(send, table)
        result = _run(
            reg.register("HOSTE", 0x20, IPv4Address("192.0.2.5")),
        )
        assert result is False
        assert table.lookup(target) is None

    def test_negative_response_stops_retransmission(self):
        """The request is repeated "UNTIL response packet is received"
        (RFC 1002 s5.1.1.1): after a negative response to the first
        broadcast, no further request goes out."""
        sent, table, reg = _new_pair()
        target = NetBIOSName("HOSTG", 0x20)

        async def drive() -> bool:
            task = asyncio.create_task(
                reg.register("HOSTG", 0x20, IPv4Address("192.0.2.7")),
            )
            await asyncio.sleep(0.050)
            reg.on_conflict(target, sent[0].trn_id)
            return await task

        assert _run(drive()) is False
        assert len(sent) == 1
        assert table.lookup(target) is None

    def test_response_with_another_trn_id_is_ignored(self):
        """RFC 1002 s5.1.1.1: "IF NOT response tid = request tid THEN
        ignore response packet"."""
        sent, table, reg = _new_pair()
        target = NetBIOSName("HOSTH", 0x20)

        async def drive() -> bool:
            task = asyncio.create_task(
                reg.register("HOSTH", 0x20, IPv4Address("192.0.2.8")),
            )
            await asyncio.sleep(0.050)
            reg.on_conflict(target, (sent[0].trn_id + 1) & 0xFFFF)
            return await task

        assert _run(drive()) is True
        assert len(sent) == REGISTRATION_RETRY_COUNT
        entry = table.lookup(target)
        assert entry is not None and entry.registered


_MY_IP = IPv4Address("192.0.2.10")
_DEFENDER = ("192.0.2.20", 137)


def _server_with_registrar(tmp_path) -> tuple[NBNSServer, Registrar, list]:
    """An NBNSServer with one subnet whose registrar's requests are
    collected in the returned list."""
    server = NBNSServer(DaemonConfig(
        server=ServerConfig(netbios_name="NAS01", workgroup="WG"),
        rundir=tmp_path,
    ))
    subnet = NbnsSubnet(
        interface_name="eth0", interface_index=2, my_ip=_MY_IP,
        netmask=IPv4Address("255.255.255.0"),
        broadcast=IPv4Address("192.0.2.255"),
    )
    state = PerSubnetState(subnet, NBNSTransport(
        interface_name="eth0", interface_addr=str(_MY_IP),
        broadcast_addr=str(subnet.broadcast),
    ))
    sent: list[NBNSMessage] = []
    state.registrar = Registrar(sent.append, state.name_table)
    server._subnets.append(state)
    return server, state.registrar, sent


class TestNegativeResponseDispatch:
    """``NBNSServer._handle_message`` passes a negative response's
    NAME_TRN_ID to the registrar of the subnet it came from."""

    def _register_against(self, tmp_path, trn_id_of) -> tuple[bool, int]:
        server, registrar, sent = _server_with_registrar(tmp_path)

        async def drive() -> bool:
            task = asyncio.create_task(
                registrar.register("NAS01", NameType.SERVER, _MY_IP),
            )
            await asyncio.sleep(0.050)
            server._handle_message(
                NBNSMessage.build_negative_response(
                    trn_id_of(sent[0]), "NAS01", NameType.SERVER,
                    Rcode.ACT_ERR,
                ),
                _DEFENDER, "eth0",
            )
            return await task

        return bool(_run(drive())), len(sent)

    def test_defence_of_our_request_blocks_the_claim(self, tmp_path):
        claimed, requests = self._register_against(
            tmp_path, lambda request: request.trn_id,
        )
        assert claimed is False
        assert requests == 1

    def test_response_to_another_request_is_ignored(self, tmp_path):
        claimed, requests = self._register_against(
            tmp_path, lambda request: (request.trn_id + 1) & 0xFFFF,
        )
        assert claimed is True
        assert requests == REGISTRATION_RETRY_COUNT


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
