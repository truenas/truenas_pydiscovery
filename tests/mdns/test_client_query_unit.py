"""Unit coverage for the mDNS client query engine.

Integration tests in ``tests/integration/test_mdns_integration.py``
exercise this through the full daemon; these tests isolate the
socket creator, the QU-question helper, the extraction helpers,
and the asyncio collection loop — no daemon needed.
"""
from __future__ import annotations

import asyncio
import os
import socket
from ipaddress import IPv4Address, IPv6Address

import pytest

from truenas_pymdns.client.query import (
    ServiceInfo,
    collect_responses,
    create_query_socket,
    extract_addresses,
    extract_ptr_targets,
    extract_service_info,
    one_shot_query,
    qu_question,
)
from truenas_pymdns.protocol.constants import (
    MDNS_PORT,
    MDNSFlags,
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


def _a(name: str, addr: str, ttl: int = 120) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A), ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
    )


def _aaaa(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.AAAA), ttl=120,
        data=AAAARecordData(IPv6Address(addr)),
    )


def _ptr(name: str, target: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.PTR), ttl=4500,
        data=PTRRecordData(target),
    )


def _srv(name: str, port: int, host: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.SRV), ttl=1800,
        data=SRVRecordData(0, 0, port, host),
    )


def _txt(name: str, entries: list[bytes]) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.TXT), ttl=4500,
        data=TXTRecordData(entries=tuple(entries)),
    )


class TestQUQuestion:
    def test_sets_unicast_response_bit(self):
        q = qu_question("foo.local", QType.A)
        assert q.name == "foo.local"
        assert q.qtype == QType.A
        assert q.unicast_response is True


class TestCreateQuerySocket:
    def test_binds_to_ephemeral_port(self):
        s = create_query_socket()
        try:
            assert s.getsockname()[1] != 0
            assert s.getsockname()[1] != MDNS_PORT
        finally:
            s.close()

    def test_with_interface_addr_sets_multicast_if(self):
        """Pass 127.0.0.1 — must not raise; IP_MULTICAST_IF setsockopt
        succeeded.  Reading it back confirms."""
        s = create_query_socket(interface_addr="127.0.0.1")
        try:
            sel = s.getsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 4,
            )
            assert sel == IPv4Address("127.0.0.1").packed
        finally:
            s.close()

    def test_bogus_interface_addr_raises_cleanly(self):
        """A syntactically invalid IP should raise without leaking fds."""
        if not os.path.isdir("/proc/self/fd"):
            pytest.skip("test requires /proc/self/fd (Linux)")
        before = len(os.listdir("/proc/self/fd"))
        with pytest.raises(OSError):
            create_query_socket(interface_addr="not.an.address")
        after = len(os.listdir("/proc/self/fd"))
        assert after == before, (
            f"fd leak on invalid address: {before} -> {after}"
        )


class TestCollectResponses:
    def test_times_out_when_no_response_arrives(self):
        sock = create_query_socket()
        records: list[MDNSRecord] = []

        async def drive() -> None:
            await collect_responses(sock, 0.2, records)

        try:
            asyncio.run(drive())
        finally:
            sock.close()
        assert records == []

    def test_ignores_queries_that_arrive_on_the_socket(self):
        """If someone happens to send a query to our ephemeral port,
        ``collect_responses`` must drop it (``is_query``)."""
        sock = create_query_socket()
        sock_port = sock.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        records: list[MDNSRecord] = []

        async def drive() -> None:
            # Send a query-shaped packet to our receive socket.
            q = MDNSMessage(
                questions=[MDNSQuestion("noise.local", QType.A)],
            )
            sender.sendto(q.to_wire(), ("127.0.0.1", sock_port))
            await collect_responses(sock, 0.2, records)

        try:
            asyncio.run(drive())
        finally:
            sender.close()
            sock.close()
        assert records == []  # query dropped

    def test_collects_answers_and_additionals_from_response(self):
        sock = create_query_socket()
        sock_port = sock.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        records: list[MDNSRecord] = []

        async def drive() -> None:
            msg = MDNSMessage(
                flags=MDNSFlags.QR.value | MDNSFlags.AA.value,
                answers=[_a("host.local", "10.0.0.1")],
                additionals=[_aaaa("host.local", "fe80::1")],
            )
            sender.sendto(msg.to_wire(), ("127.0.0.1", sock_port))
            await collect_responses(sock, 0.3, records)

        try:
            asyncio.run(drive())
        finally:
            sender.close()
            sock.close()

        assert len(records) == 2
        rtypes = {r.key.rtype for r in records}
        assert rtypes == {QType.A, QType.AAAA}


class TestOneShotQuery:
    def test_returns_empty_list_on_timeout(self):
        records = asyncio.run(
            one_shot_query(
                [qu_question("nothing.local", QType.A)],
                timeout=0.2,
                interface_addr="127.0.0.1",
            ),
        )
        assert records == []


class TestExtractPtrTargets:
    def test_returns_targets_for_matching_name(self):
        records = [
            _ptr("_smb._tcp.local", "nas._smb._tcp.local"),
            _ptr("_smb._tcp.local", "other._smb._tcp.local"),
            _ptr("_http._tcp.local", "nope._http._tcp.local"),
        ]
        assert set(extract_ptr_targets(records, "_smb._tcp.local")) == {
            "nas._smb._tcp.local", "other._smb._tcp.local",
        }

    def test_case_insensitive_match(self):
        records = [_ptr("_smb._tcp.local", "nas._smb._tcp.local")]
        assert extract_ptr_targets(
            records, "_SMB._TCP.LOCAL",
        ) == ["nas._smb._tcp.local"]


class TestExtractServiceInfo:
    def test_combines_srv_txt_and_addresses(self):
        records = [
            _srv("nas._smb._tcp.local", 445, "host.local"),
            _txt("nas._smb._tcp.local", [b"model=FreeNAS", b"path=/mnt"]),
            _a("host.local", "10.0.0.1"),
            _aaaa("host.local", "fe80::1"),
        ]
        info = extract_service_info(records, "nas", "_smb._tcp", "local")
        assert isinstance(info, ServiceInfo)
        assert info.port == 445
        assert info.host == "host.local"
        assert info.txt == {"model": "FreeNAS", "path": "/mnt"}
        assert "10.0.0.1" in info.addresses
        assert "fe80::1" in info.addresses

    def test_missing_srv_leaves_port_and_host_empty(self):
        records = [_txt("nas._smb._tcp.local", [b"foo=bar"])]
        info = extract_service_info(records, "nas", "_smb._tcp", "local")
        assert info.port == 0
        assert info.host == ""
        assert info.addresses == []

    def test_txt_keys_normalised_to_lowercase(self):
        """RFC 6763 §6.6: TXT keys are case-insensitive.  Mixed-case
        keys from the peer must be lowercased on parse so that
        ``info.txt["path"]`` works regardless of whether the peer
        sent ``Path=``, ``PATH=``, or ``path=``."""
        records = [
            _txt("x._smb._tcp.local", [
                b"Path=/mnt", b"MODEL=FreeNAS", b"Vendor=iX",
            ]),
        ]
        info = extract_service_info(records, "x", "_smb._tcp", "local")
        assert info.txt == {
            "path": "/mnt",
            "model": "FreeNAS",
            "vendor": "iX",
        }

    def test_valueless_txt_key_also_lowercased(self):
        """RFC 6763 §6.4: a TXT string with no '=' is a boolean-true
        key.  Still case-insensitive — our dict stores the lowercase
        form with an empty string value."""
        records = [_txt("x._smb._tcp.local", [b"AutoDiscover"])]
        info = extract_service_info(records, "x", "_smb._tcp", "local")
        assert info.txt == {"autodiscover": ""}


class TestExtractAddresses:
    def test_returns_v4_and_v6_for_hostname(self):
        records = [
            _a("host.local", "10.0.0.1"),
            _aaaa("host.local", "fe80::1"),
            _a("other.local", "10.0.0.9"),
        ]
        addrs = extract_addresses(records, "host.local")
        assert set(addrs) == {"10.0.0.1", "fe80::1"}

    def test_nonmatching_hostname_returns_empty(self):
        records = [_a("host.local", "10.0.0.1")]
        assert extract_addresses(records, "missing.local") == []
