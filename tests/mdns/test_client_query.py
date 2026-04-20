"""Tests for the direct mDNS query engine."""
from __future__ import annotations

import socket
from ipaddress import IPv4Address

from truenas_pymdns.client.query import (
    create_query_socket,
    extract_addresses,
    extract_ptr_targets,
    extract_service_info,
    qu_question,
)
from truenas_pymdns.protocol.constants import (
    CLASS_CACHE_FLUSH,
    MDNS_TTL,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)


class TestCreateQuerySocket:
    def test_creates_udp_socket(self):
        sock = create_query_socket()
        try:
            assert sock.type & socket.SOCK_DGRAM
            assert sock.family == socket.AF_INET
        finally:
            sock.close()

    def test_ephemeral_port(self):
        sock = create_query_socket()
        try:
            _, port = sock.getsockname()
            assert port != 0  # OS assigned a port
            assert port != 5353
        finally:
            sock.close()

    def test_multicast_ttl_255(self):
        sock = create_query_socket()
        try:
            ttl = sock.getsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
            )
            assert ttl == MDNS_TTL
        finally:
            sock.close()

    def test_nonblocking(self):
        sock = create_query_socket()
        try:
            assert sock.getblocking() is False
        finally:
            sock.close()


class TestQuQuestion:
    def test_qu_bit_set(self):
        q = qu_question("_http._tcp.local", QType.PTR)
        assert q.unicast_response is True
        assert q.name == "_http._tcp.local"
        assert q.qtype == QType.PTR

    def test_qu_bit_in_wire_format(self):
        q = qu_question("test.local", QType.A)
        buf = bytearray()
        q.to_wire(buf)
        # QU bit is the top bit of the QCLASS field (last 2 bytes)
        class_val = int.from_bytes(buf[-2:], "big")
        assert class_val & CLASS_CACHE_FLUSH


class TestExtractPtrTargets:
    def test_extracts_matching_targets(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("_http._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("mynas._http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("_http._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("other._http._tcp.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("mynas._smb._tcp.local"),
            ),
        ]
        targets = extract_ptr_targets(records, "_http._tcp.local")
        assert len(targets) == 2
        assert "mynas._http._tcp.local" in targets
        assert "other._http._tcp.local" in targets

    def test_empty_when_no_match(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("_smb._tcp.local", QType.PTR),
                ttl=4500,
                data=PTRRecordData("mynas._smb._tcp.local"),
            ),
        ]
        assert extract_ptr_targets(records, "_http._tcp.local") == []


class TestExtractServiceInfo:
    def test_full_service_info(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("mynas._http._tcp.local", QType.SRV),
                ttl=120,
                data=SRVRecordData(0, 0, 443, "mynas.local"),
            ),
            MDNSRecord(
                key=MDNSRecordKey("mynas._http._tcp.local", QType.TXT),
                ttl=4500,
                data=TXTRecordData(entries=(b"path=/ui",)),
            ),
            MDNSRecord(
                key=MDNSRecordKey("mynas.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.100")),
            ),
        ]
        info = extract_service_info(
            records, "mynas", "_http._tcp", "local",
        )
        assert info.host == "mynas.local"
        assert info.port == 443
        assert info.addresses == ["192.168.1.100"]
        assert info.txt == {"path": "/ui"}

    def test_missing_srv(self):
        info = extract_service_info([], "mynas", "_http._tcp", "local")
        assert info.host == ""
        assert info.port == 0
        assert info.addresses == []

    def test_txt_without_value(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("mynas._http._tcp.local", QType.TXT),
                ttl=4500,
                data=TXTRecordData(entries=(b"flag",)),
            ),
        ]
        info = extract_service_info(
            records, "mynas", "_http._tcp", "local",
        )
        assert info.txt == {"flag": ""}


class TestExtractAddresses:
    def test_extracts_a_records(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("mynas.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.100")),
            ),
            MDNSRecord(
                key=MDNSRecordKey("mynas.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("10.0.0.1")),
            ),
        ]
        addrs = extract_addresses(records, "mynas.local")
        assert addrs == ["192.168.1.100", "10.0.0.1"]

    def test_case_insensitive(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey("MyNAS.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.100")),
            ),
        ]
        addrs = extract_addresses(records, "mynas.local")
        assert addrs == ["192.168.1.100"]

    def test_empty_when_no_match(self):
        assert extract_addresses([], "mynas.local") == []


class TestResponseParsing:
    def test_parse_crafted_response(self):
        """Build a response, serialize, parse, and extract records."""
        records = [
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
                key=MDNSRecordKey("TN26NEW.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("192.168.1.102")),
                cache_flush=True,
            ),
        ]
        msg = MDNSMessage.build_response(records)
        wire = msg.to_wire()
        parsed = MDNSMessage.from_wire(wire)

        all_records = parsed.answers + parsed.additionals
        targets = extract_ptr_targets(all_records, "_http._tcp.local")
        assert targets == ["TN26NEW._http._tcp.local"]

        info = extract_service_info(
            all_records, "TN26NEW", "_http._tcp", "local",
        )
        assert info.host == "TN26NEW.local"
        assert info.port == 443
        assert info.addresses == ["192.168.1.102"]
