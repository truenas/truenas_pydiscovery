"""MDNSMessage edge cases: TC flag round-trips, truncated-header
rejection, and RFC 6762 s7.2 TC-on-overflow behaviour.
"""
from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from truenas_pymdns.protocol.constants import (
    DNS_HEADER_SIZE,
    MDNSFlags,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)


class TestTCFlagRoundtrip:
    def test_tc_flag_survives_to_wire_from_wire(self):
        msg = MDNSMessage(
            flags=MDNSFlags.QR.value | MDNSFlags.TC.value,
            answers=[MDNSRecord(
                key=MDNSRecordKey("h.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address("10.0.0.1")),
            )],
        )
        wire = msg.to_wire()
        decoded = MDNSMessage.from_wire(wire)
        assert decoded.is_truncated
        assert decoded.is_response


class TestHeaderTruncation:
    def test_fewer_than_header_bytes_raises(self):
        with pytest.raises(ValueError, match="too short"):
            MDNSMessage.from_wire(b"\x00" * (DNS_HEADER_SIZE - 1))

    def test_empty_buffer_raises(self):
        with pytest.raises(ValueError, match="too short"):
            MDNSMessage.from_wire(b"")

    def test_exactly_header_with_zero_counts_is_parseable(self):
        """A bare 12-byte header with all counts=0 is a legal
        (empty) mDNS message."""
        msg = MDNSMessage.from_wire(b"\x00" * DNS_HEADER_SIZE)
        assert msg.questions == []
        assert msg.answers == []


class TestPayloadTruncation:
    def test_question_beyond_buffer_raises(self):
        """Header declares 1 question but the buffer has no room."""
        # 12 bytes header, qdcount=1, then just a length byte = 2
        # but no label data or terminator.
        buf = bytearray(b"\x00" * DNS_HEADER_SIZE)
        buf[4:6] = b"\x00\x01"  # qdcount = 1
        buf.append(0x02)  # label length 2
        buf.append(0x61)  # 'a' — only 1 of 2 label bytes
        with pytest.raises(ValueError):
            MDNSMessage.from_wire(bytes(buf))


class TestMaxSizeTruncation:
    def test_oversize_answers_get_truncated_and_tc_set(self):
        """RFC 6762 s7.2: when answers don't fit, set TC and drop
        the overflow records rather than send a malformed packet."""
        records = [
            MDNSRecord(
                key=MDNSRecordKey(f"host-{i:03d}.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address(f"10.0.0.{i + 1}")),
            )
            for i in range(100)
        ]
        msg = MDNSMessage.build_response(records)
        # Cap size so most records fall off.
        wire = msg.to_wire(max_size=200)
        assert len(wire) <= 200

        decoded = MDNSMessage.from_wire(wire)
        assert decoded.is_truncated
        assert len(decoded.answers) < len(records)

    def test_zero_max_size_disables_truncation(self):
        records = [
            MDNSRecord(
                key=MDNSRecordKey(f"r{i}.local", QType.A),
                ttl=120,
                data=ARecordData(IPv4Address(f"10.0.0.{i + 1}")),
            )
            for i in range(10)
        ]
        msg = MDNSMessage.build_response(records)
        wire = msg.to_wire(max_size=0)
        decoded = MDNSMessage.from_wire(wire)
        assert not decoded.is_truncated
        assert len(decoded.answers) == 10
