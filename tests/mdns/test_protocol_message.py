"""Tests for DNS message parsing and building."""
import pytest
from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import MDNSFlags, QClass, QType
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.protocol.records import (
    ARecordData,
    AAAARecordData,
    MDNSRecord,
    PTRRecordData,
    MDNSRecordKey,
    SRVRecordData,
    TXTRecordData,
)


class TestMDNSQuestion:
    def test_round_trip(self):
        q = MDNSQuestion("_http._tcp.local", QType.PTR)
        buf = bytearray()
        q.to_wire(buf)
        q2, end = MDNSQuestion.from_wire(bytes(buf), 0)
        assert q2.name == "_http._tcp.local"
        assert q2.qtype == QType.PTR
        assert q2.qclass == QClass.IN
        assert q2.unicast_response is False
        assert end == len(buf)

    def test_qu_bit(self):
        q = MDNSQuestion("myhost.local", QType.A, unicast_response=True)
        buf = bytearray()
        q.to_wire(buf)
        q2, _ = MDNSQuestion.from_wire(bytes(buf), 0)
        assert q2.unicast_response is True
        assert q2.qclass == QClass.IN

    def test_truncated(self):
        buf = bytearray()
        MDNSQuestion("a.local", QType.A).to_wire(buf)
        with pytest.raises(ValueError):
            MDNSQuestion.from_wire(bytes(buf[:-1]), 0)


class TestMDNSMessageQuery:
    def test_build_simple_query(self):
        msg = MDNSMessage.build_query([
            MDNSQuestion("_smb._tcp.local", QType.PTR),
        ])
        assert msg.is_query
        assert not msg.is_response
        assert len(msg.questions) == 1
        assert len(msg.answers) == 0

    def test_round_trip_query(self):
        msg = MDNSMessage.build_query([
            MDNSQuestion("_http._tcp.local", QType.PTR),
            MDNSQuestion("_smb._tcp.local", QType.PTR),
        ])
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert msg2.is_query
        assert len(msg2.questions) == 2
        assert msg2.questions[0].name == "_http._tcp.local"
        assert msg2.questions[1].name == "_smb._tcp.local"

    def test_query_with_known_answers(self):
        known = MDNSRecord(
            key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
            ttl=4500,
            data=PTRRecordData("My NAS._smb._tcp.local"),
        )
        msg = MDNSMessage.build_query(
            [MDNSQuestion("_smb._tcp.local", QType.PTR)],
            known_answers=[known],
        )
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert len(msg2.questions) == 1
        assert len(msg2.answers) == 1
        assert msg2.answers[0].data.target == "My NAS._smb._tcp.local"


class TestMDNSMessageResponse:
    def test_build_response_flags(self):
        msg = MDNSMessage.build_response([
            MDNSRecord(
                key=MDNSRecordKey("myhost.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.1")),
                cache_flush=True,
            ),
        ])
        assert msg.is_response
        assert msg.flags & MDNSFlags.QR
        assert msg.flags & MDNSFlags.AA

    def test_round_trip_multi_record_response(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("My NAS._smb._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("My NAS._smb._tcp.local", QType.SRV),
                ttl=120,
                data=SRVRecordData(0, 0, 445, "truenas.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("My NAS._smb._tcp.local", QType.TXT),
                ttl=4500,
                data=TXTRecordData.from_dict({"model": "MacPro7,1"}),
            ),
            MDNSRecord(
                key=MDNSRecordKey("truenas.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.100")),
                cache_flush=True,
            ),
            MDNSRecord(
                key=MDNSRecordKey("truenas.local", QType.AAAA),
                ttl=120,
                data=AAAARecordData(IPv6Address("fe80::1")),
                cache_flush=True,
            ),
        ]
        msg = MDNSMessage.build_response(records)
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)

        assert msg2.is_response
        assert len(msg2.answers) == 5

        ptr = msg2.answers[0]
        assert ptr.key.rtype == QType.PTR
        assert ptr.data.target == "My NAS._smb._tcp.local"

        srv = msg2.answers[1]
        assert srv.key.rtype == QType.SRV
        assert srv.data.port == 445
        assert srv.data.target == "truenas.local"

        txt = msg2.answers[2]
        assert txt.key.rtype == QType.TXT
        assert b"model=MacPro7,1" in txt.data.entries

        a = msg2.answers[3]
        assert a.key.rtype == QType.A
        assert a.cache_flush is True
        assert a.data.address == IPv4Address("192.168.1.100")

        aaaa = msg2.answers[4]
        assert aaaa.key.rtype == QType.AAAA
        assert aaaa.data.address == IPv6Address("fe80::1")

    def test_response_with_additionals(self):
        answer = MDNSRecord(
            key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
            ttl=4500,
            data=PTRRecordData("My NAS._smb._tcp.local"),
        )
        additional = MDNSRecord(
            key=MDNSRecordKey("truenas.local", QType.A),
            ttl=120,
            data=ARecordData(IPv4Address("10.0.0.1")),
        )
        msg = MDNSMessage.build_response([answer], additionals=[additional])
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert len(msg2.answers) == 1
        assert len(msg2.additionals) == 1
        assert msg2.additionals[0].data.address == IPv4Address("10.0.0.1")


class TestMDNSMessageProbe:
    def test_build_probe(self):
        questions = [
            MDNSQuestion("myhost.local", QType.ANY, unicast_response=True),
        ]
        authority = [
            MDNSRecord(
                key=MDNSRecordKey("myhost.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.50")),
            ),
        ]
        msg = MDNSMessage.build_probe(questions, authority)
        assert msg.is_query
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert len(msg2.questions) == 1
        assert msg2.questions[0].unicast_response is True
        assert len(msg2.authorities) == 1
        assert msg2.authorities[0].data.address == IPv4Address("192.168.1.50")


class TestMDNSMessageGoodbye:
    def test_goodbye_sets_ttl_zero(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("myhost.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.1")),
                cache_flush=True,
            ),
            MDNSRecord(
                key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("My NAS._smb._tcp.local"),
            ),
        ]
        msg = MDNSMessage.build_goodbye(records)
        assert msg.is_response
        for rr in msg.answers:
            assert rr.ttl == 0
        # Original records should be unchanged
        assert records[0].ttl == 120
        assert records[1].ttl == 4500

    def test_goodbye_round_trip(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("truenas.local", QType.AAAA),
                ttl=120,
                data=AAAARecordData(IPv6Address("fe80::1")),
            ),
        ]
        msg = MDNSMessage.build_goodbye(records)
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert msg2.answers[0].ttl == 0
        assert msg2.answers[0].data.address == IPv6Address("fe80::1")


class TestMDNSMessageCompression:
    def test_compression_reduces_size(self):
        """Multiple records sharing name suffixes should compress."""
        records = [
            MDNSRecord(
                key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("My NAS._smb._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("_http._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("TrueNAS._http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("truenas.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.1")),
            ),
        ]
        msg = MDNSMessage.build_response(records)
        compressed = msg.to_wire()

        # Verify it parses back correctly
        msg2 = MDNSMessage.from_wire(compressed)
        assert len(msg2.answers) == 3
        assert msg2.answers[0].data.target == "My NAS._smb._tcp.local"
        assert msg2.answers[1].data.target == "TrueNAS._http._tcp.local"
        assert msg2.answers[2].data.address == IPv4Address("192.168.1.1")

    def test_ptr_rdata_does_not_corrupt_subsequent_owner_names(self):
        """PTR rdata compression offsets must not corrupt later records.

        When a PTR record's rdata target shares a suffix with a later
        record's owner name, the compression pointer for that owner name
        must point to the correct position in the packet — not to offset 0
        (the message header).

        This is the exact record order produced by add_service(): meta-PTR,
        service-PTR, SRV, TXT.  The meta-PTR rdata introduces the name
        suffix that the service-PTR owner and SRV/TXT owners reference.
        """
        records = [
            MDNSRecord(
                key=MDNSRecordKey("_services._dns-sd._udp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("_http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("_http._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("TN26NEW._http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("TN26NEW._http._tcp.local", QType.SRV),
                ttl=120,
                data=SRVRecordData(0, 0, 443, "TN26NEW.local"),
                cache_flush=True,
            ),
            MDNSRecord(
                key=MDNSRecordKey("TN26NEW._http._tcp.local", QType.TXT),
                ttl=4500,
                data=TXTRecordData(entries=()),
                cache_flush=True,
            ),
        ]
        msg = MDNSMessage.build_response(records)
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)

        assert len(msg2.answers) == 4
        assert msg2.answers[0].key.name == "_services._dns-sd._udp.local"
        assert msg2.answers[0].data.target == "_http._tcp.local"
        assert msg2.answers[1].key.name == "_http._tcp.local"
        assert msg2.answers[1].data.target == "TN26NEW._http._tcp.local"
        assert msg2.answers[2].key.name == "tn26new._http._tcp.local"
        assert msg2.answers[2].key.rtype == QType.SRV
        assert msg2.answers[2].data.port == 443
        assert msg2.answers[3].key.name == "tn26new._http._tcp.local"
        assert msg2.answers[3].key.rtype == QType.TXT

    def test_goodbye_owner_names_survive_compression(self):
        """Goodbye packets (TTL=0) must have correct owner names.

        This reproduces the full record set sent during daemon shutdown:
        service records followed by address records.  All owner names
        must round-trip correctly through build_goodbye + to_wire.
        """
        records = [
            MDNSRecord(
                key=MDNSRecordKey("_services._dns-sd._udp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("_http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("_http._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("TN26NEW._http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("TN26NEW._http._tcp.local", QType.SRV),
                ttl=120,
                data=SRVRecordData(0, 0, 443, "TN26NEW.local"),
                cache_flush=True,
            ),
            MDNSRecord(
                key=MDNSRecordKey("TN26NEW._http._tcp.local", QType.TXT),
                ttl=4500,
                data=TXTRecordData(entries=()),
                cache_flush=True,
            ),
            MDNSRecord(
                key=MDNSRecordKey("TN26NEW.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.102")),
                cache_flush=True,
            ),
            MDNSRecord(
                key=MDNSRecordKey("102.1.168.192.in-addr.arpa", QType.PTR),
                ttl=120,
                data=PTRRecordData("TN26NEW.local"),
                cache_flush=True,
            ),
        ]
        goodbye = MDNSMessage.build_goodbye(records)
        wire = goodbye.to_wire()
        msg = MDNSMessage.from_wire(wire)

        expected_names = [
            "_services._dns-sd._udp.local",
            "_http._tcp.local",
            "tn26new._http._tcp.local",
            "tn26new._http._tcp.local",
            "tn26new.local",
            "102.1.168.192.in-addr.arpa",
        ]
        assert len(msg.answers) == 6
        for rr, expected in zip(msg.answers, expected_names):
            assert rr.key.name == expected, (
                f"owner name mismatch: expected {expected!r}, got {rr.key.name!r}"
            )
            assert rr.ttl == 0


class TestMDNSMessageEdgeCases:
    def test_packet_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            MDNSMessage.from_wire(b"\x00" * 11)

    def test_empty_message(self):
        msg = MDNSMessage()
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert len(msg2.questions) == 0
        assert len(msg2.answers) == 0

    def test_id_preserved(self):
        msg = MDNSMessage(msg_id=0x1234, flags=0)
        wire = msg.to_wire()
        msg2 = MDNSMessage.from_wire(wire)
        assert msg2.msg_id == 0x1234
