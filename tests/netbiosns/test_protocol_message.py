"""Tests for NetBIOS Name Service message parse/build.

Test patterns informed by Samba source4/torture/nbt/ — registration,
query, release, refresh, node status, and defense operations.
"""
from __future__ import annotations

import pytest

from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import (
    HeaderFlags,
    NBFlag,
    NameType,
    Opcode,
    Rcode,
    RRType,
)
from truenas_pynetbiosns.protocol.message import (
    NBNSMessage,
    NBQuestion,
    NBResourceRecord,
    build_nb_rdata,
    parse_nb_rdata,
)
from truenas_pynetbiosns.protocol.name import NetBIOSName


class TestNBRdata:
    def test_build_and_parse(self):
        ip = IPv4Address("192.168.1.100")
        rdata = build_nb_rdata(ip, NBFlag(0))
        entries = parse_nb_rdata(rdata)
        assert len(entries) == 1
        assert entries[0][1] == ip

    def test_group_flag(self):
        ip = IPv4Address("10.0.0.1")
        rdata = build_nb_rdata(ip, NBFlag.GROUP)
        entries = parse_nb_rdata(rdata)
        assert entries[0][0] & NBFlag.GROUP

    def test_multiple_addresses(self):
        rdata = (
            build_nb_rdata(IPv4Address("10.0.0.1"), NBFlag(0))
            + build_nb_rdata(IPv4Address("10.0.0.2"), NBFlag(0))
        )
        entries = parse_nb_rdata(rdata)
        assert len(entries) == 2
        assert entries[0][1] == IPv4Address("10.0.0.1")
        assert entries[1][1] == IPv4Address("10.0.0.2")


class TestNBQuestion:
    def test_round_trip(self):
        q = NBQuestion(
            name=NetBIOSName("TRUENAS", NameType.SERVER),
            q_type=RRType.NB,
        )
        wire = q.to_wire()
        q2, end = NBQuestion.from_wire(wire, 0)
        assert q2.name == q.name
        assert q2.q_type == RRType.NB
        assert end == len(wire)

    def test_nbstat_question(self):
        q = NBQuestion(
            name=NetBIOSName("*", 0x00),
            q_type=RRType.NBSTAT,
        )
        wire = q.to_wire()
        q2, _ = NBQuestion.from_wire(wire, 0)
        assert q2.q_type == RRType.NBSTAT


class TestNBResourceRecord:
    def test_round_trip(self):
        ip = IPv4Address("192.168.1.100")
        rr = NBResourceRecord(
            name=NetBIOSName("HOST", NameType.SERVER),
            rr_type=RRType.NB,
            ttl=300,
            rdata=build_nb_rdata(ip),
        )
        wire = rr.to_wire()
        rr2, end = NBResourceRecord.from_wire(wire, 0)
        assert rr2.name == rr.name
        assert rr2.rr_type == RRType.NB
        assert rr2.ttl == 300
        entries = parse_nb_rdata(rr2.rdata)
        assert entries[0][1] == ip
        assert end == len(wire)


class TestNBNSMessageRegistration:
    def test_build_registration(self):
        msg = NBNSMessage.build_registration(
            "TRUENAS", NameType.SERVER,
            IPv4Address("192.168.1.100"),
        )
        assert msg.opcode == Opcode.REGISTRATION
        assert msg.flags & HeaderFlags.BROADCAST
        assert msg.flags & HeaderFlags.RD
        assert len(msg.questions) == 1
        assert len(msg.additionals) == 1
        assert msg.questions[0].name.name == "TRUENAS"
        assert msg.questions[0].name.name_type == NameType.SERVER

    def test_registration_round_trip(self):
        msg = NBNSMessage.build_registration(
            "MYHOST", NameType.WORKSTATION,
            IPv4Address("10.0.0.5"),
            ttl=300,
        )
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.opcode == Opcode.REGISTRATION
        assert msg2.trn_id == msg.trn_id
        assert len(msg2.questions) == 1
        assert msg2.questions[0].name.name == "MYHOST"
        assert msg2.questions[0].name.name_type == NameType.WORKSTATION
        assert len(msg2.additionals) == 1
        entries = parse_nb_rdata(msg2.additionals[0].rdata)
        assert entries[0][1] == IPv4Address("10.0.0.5")

    def test_group_registration(self):
        msg = NBNSMessage.build_registration(
            "WORKGROUP", NameType.WORKSTATION,
            IPv4Address("10.0.0.1"),
            group=True,
        )
        rdata = msg.additionals[0].rdata
        entries = parse_nb_rdata(rdata)
        assert entries[0][0] & NBFlag.GROUP


class TestNBNSMessageQuery:
    def test_build_name_query(self):
        msg = NBNSMessage.build_name_query(
            "TRUENAS", NameType.SERVER,
        )
        assert msg.opcode == Opcode.QUERY
        assert msg.flags & HeaderFlags.BROADCAST
        assert msg.flags & HeaderFlags.RD
        assert len(msg.questions) == 1

    def test_query_round_trip(self):
        msg = NBNSMessage.build_name_query("HOST", NameType.WORKSTATION)
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.opcode == Opcode.QUERY
        assert msg2.questions[0].name.name == "HOST"

    def test_unicast_query(self):
        msg = NBNSMessage.build_name_query(
            "HOST", NameType.SERVER, broadcast=False,
        )
        assert not (msg.flags & HeaderFlags.BROADCAST)


class TestNBNSMessageRelease:
    def test_build_release(self):
        msg = NBNSMessage.build_release(
            "HOST", NameType.SERVER,
            IPv4Address("10.0.0.1"),
        )
        assert msg.opcode == Opcode.RELEASE
        assert len(msg.questions) == 1
        assert len(msg.additionals) == 1
        assert msg.additionals[0].ttl == 0

    def test_release_round_trip(self):
        msg = NBNSMessage.build_release(
            "TRUENAS", NameType.WORKSTATION,
            IPv4Address("192.168.1.50"),
        )
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.opcode == Opcode.RELEASE
        assert msg2.additionals[0].ttl == 0
        entries = parse_nb_rdata(msg2.additionals[0].rdata)
        assert entries[0][1] == IPv4Address("192.168.1.50")


class TestNBNSMessageRefresh:
    def test_build_refresh(self):
        msg = NBNSMessage.build_refresh(
            "HOST", NameType.SERVER,
            IPv4Address("10.0.0.1"),
            ttl=900,
        )
        assert msg.opcode == Opcode.REFRESH
        assert msg.additionals[0].ttl == 900

    def test_refresh_round_trip(self):
        msg = NBNSMessage.build_refresh(
            "HOST", NameType.WORKSTATION,
            IPv4Address("10.0.0.1"),
            ttl=900,
        )
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.opcode == Opcode.REFRESH
        assert msg2.additionals[0].ttl == 900


class TestNBNSMessageResponse:
    def test_positive_response(self):
        msg = NBNSMessage.build_positive_response(
            trn_id=0x1234,
            name="TRUENAS",
            name_type=NameType.SERVER,
            ip=IPv4Address("192.168.1.100"),
        )
        assert msg.is_response
        assert msg.rcode == Rcode.OK
        assert msg.trn_id == 0x1234
        assert len(msg.answers) == 1
        entries = parse_nb_rdata(msg.answers[0].rdata)
        assert entries[0][1] == IPv4Address("192.168.1.100")

    def test_positive_response_round_trip(self):
        msg = NBNSMessage.build_positive_response(
            trn_id=0xABCD,
            name="HOST",
            name_type=NameType.WORKSTATION,
            ip=IPv4Address("10.0.0.5"),
        )
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.is_response
        assert msg2.trn_id == 0xABCD
        assert msg2.rcode == Rcode.OK

    def test_negative_response(self):
        """Defense: respond with ACT_ERR when name is ours (Samba register.c pattern)."""
        msg = NBNSMessage.build_negative_response(
            trn_id=0x5678,
            name="MYHOST",
            name_type=NameType.SERVER,
            rcode=Rcode.ACT_ERR,
        )
        assert msg.is_response
        assert msg.rcode == Rcode.ACT_ERR
        assert msg.trn_id == 0x5678

    def test_negative_response_round_trip(self):
        msg = NBNSMessage.build_negative_response(
            trn_id=0x9999,
            name="HOST",
            name_type=NameType.WORKSTATION,
            rcode=Rcode.ACT_ERR,
        )
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.rcode == Rcode.ACT_ERR
        assert msg2.opcode == Opcode.REGISTRATION


class TestNBNSMessageNodeStatus:
    def test_node_status_query(self):
        msg = NBNSMessage.build_node_status_query()
        assert msg.opcode == Opcode.QUERY
        assert msg.questions[0].q_type == RRType.NBSTAT
        assert msg.questions[0].name.name == "*"

    def test_node_status_response(self):
        names = [
            ("TRUENAS", NameType.WORKSTATION, 0x0400),
            ("TRUENAS", NameType.SERVER, 0x0400),
            ("WORKGROUP", NameType.WORKSTATION, 0x8400),
        ]
        query_name = NetBIOSName("*", 0x00)
        msg = NBNSMessage.build_node_status_response(
            trn_id=0x1111, query_name=query_name, names=names,
        )
        assert msg.is_response
        assert len(msg.answers) == 1
        assert msg.answers[0].rr_type == RRType.NBSTAT
        # First byte of rdata is name count
        assert msg.answers[0].rdata[0] == 3

    def test_node_status_round_trip(self):
        names = [
            ("HOST", NameType.WORKSTATION, 0x0400),
            ("HOST", NameType.SERVER, 0x0400),
        ]
        msg = NBNSMessage.build_node_status_response(
            trn_id=0x2222,
            query_name=NetBIOSName("*", 0x00),
            names=names,
        )
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.answers[0].rr_type == RRType.NBSTAT
        assert msg2.answers[0].rdata[0] == 2


class TestNBNSMessageTransactionID:
    def test_trn_id_preserved(self):
        msg = NBNSMessage.build_name_query("HOST", 0x20)
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert msg2.trn_id == msg.trn_id

    def test_trn_id_is_16_bit_unsigned(self):
        """RFC 1002 §4.2.1: NAME_TRN_ID is a 16-bit field."""
        for _ in range(100):
            msg = NBNSMessage.build_name_query("X", 0x20)
            assert 0 <= msg.trn_id <= 0xFFFF

    def test_trn_ids_are_unpredictable(self):
        """Defence against off-path spoofing: TRN_IDs must be drawn
        from a cryptographically secure source rather than a
        monotonic counter, so a LAN attacker who sees one broadcast
        cannot predict the next ID and race a forged response.

        Proxy check: over 64 freshly-generated IDs we expect
        high-entropy draws, so sequential consecutive pairs
        (``id_{n+1} == id_n + 1``) should be rare.  A monotonic
        counter would show 100 %.  We tolerate up to 4 such pairs
        (expected rate across 63 gaps with uniform 16-bit draws is
        ~63 / 65536 ≈ 0.001, so any realistic pass rate).
        """
        ids = [
            NBNSMessage.build_name_query("X", 0x20).trn_id
            for _ in range(64)
        ]
        sequential_pairs = sum(
            1 for a, b in zip(ids, ids[1:]) if b == (a + 1) & 0xFFFF
        )
        assert sequential_pairs <= 4, (
            f"TRN_IDs look monotonic: {sequential_pairs} sequential "
            f"pairs in 63 gaps (expected near 0)"
        )

    def test_trn_ids_collision_rate_is_low(self):
        """64 draws from a 16-bit space should yield 64 unique
        values with overwhelming probability (birthday-paradox
        collision probability ≈ 64²/2¹⁶ ≈ 3 %).  Tolerate up to 2
        collisions to avoid flakiness while still catching a
        constant or narrow-range generator."""
        ids = [
            NBNSMessage.build_name_query("X", 0x20).trn_id
            for _ in range(64)
        ]
        assert len(set(ids)) >= 62, (
            f"too many TRN_ID collisions: {64 - len(set(ids))} "
            f"duplicates in 64 draws"
        )


class TestNBNSMessageEdgeCases:
    def test_packet_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            NBNSMessage.from_wire(b"\x00" * 11)

    def test_empty_message_round_trip(self):
        msg = NBNSMessage(trn_id=0)
        wire = msg.to_wire()
        msg2 = NBNSMessage.from_wire(wire)
        assert len(msg2.questions) == 0
        assert len(msg2.answers) == 0
