"""Responder additional-record generation (RFC 6763 s12) and the
QU / QM / legacy-unicast response paths (RFC 6762 s5.4, s6, s6.7).
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import (
    LEGACY_RESPONSE_TTL_CAP,
    MDNS_PORT,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    AAAARecordData,
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.query.responder import Responder
from truenas_pymdns.server.service.registry import ServiceRegistry


def _registry_for_service() -> ServiceRegistry:
    """_smb._tcp.local → 'nas' instance at host.local:445, with A/AAAA."""
    grp = EntryGroup()
    grp.add_record(MDNSRecord(
        key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
        ttl=4500,
        data=PTRRecordData("nas._smb._tcp.local"),
    ))
    grp.add_record(MDNSRecord(
        key=MDNSRecordKey("nas._smb._tcp.local", QType.SRV),
        ttl=1800,
        data=SRVRecordData(0, 0, 445, "host.local"),
        cache_flush=True,
    ))
    grp.add_record(MDNSRecord(
        key=MDNSRecordKey("nas._smb._tcp.local", QType.TXT),
        ttl=4500,
        data=TXTRecordData(entries=(b"path=/mnt",)),
        cache_flush=True,
    ))
    grp.add_record(MDNSRecord(
        key=MDNSRecordKey("host.local", QType.A),
        ttl=1800,
        data=ARecordData(IPv4Address("10.0.0.1")),
        cache_flush=True,
    ))
    grp.add_record(MDNSRecord(
        key=MDNSRecordKey("host.local", QType.AAAA),
        ttl=1800,
        data=AAAARecordData(IPv6Address("fe80::1")),
        cache_flush=True,
    ))
    reg = ServiceRegistry()
    reg.add_group(grp)
    return reg


def _responder_and_loop(
    reg: ServiceRegistry,
) -> tuple[Responder, list[MDNSMessage], list[tuple], asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    multi: list[MDNSMessage] = []
    unis: list[tuple] = []

    def _uni(msg: MDNSMessage, dest: tuple) -> None:
        unis.append((msg, dest))

    resp = Responder(multi.append, _uni, reg)
    resp.start(loop)
    return resp, multi, unis, loop


class TestAdditionalsForPTR:
    def test_ptr_query_attaches_srv_txt_and_a_records(self):
        """RFC 6763 s12: response to a PTR query includes the SRV, TXT,
        and A/AAAA records for the instance as additional records."""
        reg = _registry_for_service()
        resp, multi, unis, loop = _responder_and_loop(reg)
        try:
            query = MDNSMessage(questions=[
                MDNSQuestion("_smb._tcp.local", QType.PTR,
                             unicast_response=True),
            ])
            # QU query → unicast (bypass the defer).
            resp.handle_query(
                query, ("10.0.0.50", MDNS_PORT), interface_index=1,
            )
            assert len(unis) == 1
            msg, _dest = unis[0]
            assert len(msg.answers) == 1
            assert msg.answers[0].key.rtype == QType.PTR
            add_types = {rr.key.rtype for rr in msg.additionals}
            assert QType.SRV in add_types
            assert QType.TXT in add_types
            assert QType.A in add_types
            assert QType.AAAA in add_types
        finally:
            resp.cancel_all()
            loop.close()


class TestAdditionalsForSRV:
    def test_srv_query_attaches_a_and_aaaa_for_target(self):
        reg = _registry_for_service()
        resp, _multi, unis, loop = _responder_and_loop(reg)
        try:
            query = MDNSMessage(questions=[
                MDNSQuestion("nas._smb._tcp.local", QType.SRV,
                             unicast_response=True),
            ])
            resp.handle_query(
                query, ("10.0.0.50", MDNS_PORT), interface_index=1,
            )
            assert len(unis) == 1
            msg, _ = unis[0]
            assert msg.answers
            assert msg.answers[0].key.rtype == QType.SRV
            add_types = {rr.key.rtype for rr in msg.additionals}
            assert QType.A in add_types
            assert QType.AAAA in add_types
            # No unrelated additionals
            add_names = {rr.key.name for rr in msg.additionals}
            assert add_names == {"host.local"}
        finally:
            resp.cancel_all()
            loop.close()


class TestQUvsQM:
    def test_qu_bit_triggers_immediate_unicast(self):
        reg = _registry_for_service()
        resp, multi, unis, loop = _responder_and_loop(reg)
        try:
            q = MDNSMessage(questions=[
                MDNSQuestion("host.local", QType.A,
                             unicast_response=True),
            ])
            resp.handle_query(q, ("10.0.0.50", MDNS_PORT),
                              interface_index=1)
            assert len(unis) == 1
            assert multi == []
        finally:
            resp.cancel_all()
            loop.close()

    def test_qm_schedules_deferred_multicast(self):
        reg = _registry_for_service()
        resp, multi, unis, loop = _responder_and_loop(reg)
        try:
            q = MDNSMessage(questions=[
                MDNSQuestion("host.local", QType.A,
                             unicast_response=False),
            ])
            resp.handle_query(q, ("10.0.0.50", MDNS_PORT),
                              interface_index=1)
            # No immediate send (QM defers 20-120ms).
            assert multi == []
            assert unis == []
            assert resp._pending
            # Wait out the jitter to see the actual multicast.
            loop.run_until_complete(asyncio.sleep(0.200))
            assert len(multi) == 1
        finally:
            resp.cancel_all()
            loop.close()


class TestLegacyUnicast:
    def test_non_5353_source_port_echoes_transaction_id(self):
        """RFC 6762 s6.7: legacy queries arrive from a non-5353 port;
        the response echoes the query's transaction ID."""
        reg = _registry_for_service()
        resp, multi, unis, loop = _responder_and_loop(reg)
        try:
            query = MDNSMessage(
                msg_id=0x1234,
                questions=[MDNSQuestion("host.local", QType.A)],
            )
            resp.handle_query(
                query, ("10.0.0.50", 34567), interface_index=1,
            )
            assert len(unis) == 1
            response, _ = unis[0]
            assert response.msg_id == 0x1234
            # Legacy responses must not have the cache-flush bit set
            # on answers (RFC 6762 s6.7).
            assert response.answers
            assert all(not r.cache_flush for r in response.answers)
            assert multi == []
        finally:
            resp.cancel_all()
            loop.close()

    def test_legacy_ttl_is_capped(self):
        reg = _registry_for_service()
        resp, _multi, unis, loop = _responder_and_loop(reg)
        try:
            query = MDNSMessage(
                msg_id=0xbeef,
                questions=[MDNSQuestion("host.local", QType.A)],
            )
            resp.handle_query(
                query, ("10.0.0.50", 34567), interface_index=1,
            )
            assert unis
            response, _ = unis[0]
            for rr in response.answers:
                assert rr.ttl <= LEGACY_RESPONSE_TTL_CAP
        finally:
            resp.cancel_all()
            loop.close()
