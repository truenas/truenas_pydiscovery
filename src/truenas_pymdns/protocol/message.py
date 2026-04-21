"""mDNS message (packet) parsing and building.

Wire format (RFC 1035 s4.1, adapted for mDNS by RFC 6762):

 +---------------------+
 |       Header        |  12 bytes (see constants.py for layout)
 +---------------------+
 |      Question       |  variable: QDCOUNT entries
 +---------------------+
 |       Answer        |  variable: ANCOUNT resource records
 +---------------------+
 |      Authority      |  variable: NSCOUNT resource records (used in probes)
 +---------------------+
 |      Additional     |  variable: ARCOUNT resource records
 +---------------------+

Question entry (RFC 1035 s4.1.2):
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 /                     QNAME                     /  variable: encoded name
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QTYPE                     |  2 bytes
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QU|                  QCLASS                    |  2 bytes (QU bit: RFC 6762 s5.4)
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field

from .constants import (
    CLASS_CACHE_FLUSH,
    DNS_HEADER_SIZE,
    LEGACY_RESPONSE_TTL_CAP,
    MDNSFlags,
    QClass,
    QType,
)
from .name import decode_name, encode_name
from .records import MDNSRecord

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class MDNSQuestion:
    """A single question entry in an mDNS message (RFC 6762 s5)."""
    name: str
    qtype: QType
    qclass: QClass = QClass.IN
    unicast_response: bool = False  # QU bit (RFC 6762 s5.4)

    def to_wire(self, buf: bytearray,
                compression: dict[str, int] | None = None) -> None:
        """Serialize this question into wire format, appending to *buf*."""
        encode_name(self.name, buf, compression)
        class_val = self.qclass.value
        if self.unicast_response:
            class_val |= CLASS_CACHE_FLUSH
        buf.extend(struct.pack("!HH", self.qtype.value, class_val))

    @classmethod
    def from_wire(cls, data: bytes, offset: int) -> tuple[MDNSQuestion, int]:
        """Deserialize a question from wire format."""
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Question truncated")
        qtype_val, class_val = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4

        unicast = bool(class_val & CLASS_CACHE_FLUSH)
        class_val &= ~CLASS_CACHE_FLUSH

        qtype = (QType(qtype_val)
                 if qtype_val in QType.__members__.values()
                 else qtype_val)
        qclass = (QClass(class_val)
                  if class_val in QClass.__members__.values()
                  else class_val)

        return cls(name=name, qtype=qtype, qclass=qclass,
                   unicast_response=unicast), offset


@dataclass(slots=True)
class MDNSMessage:
    """A complete mDNS packet (RFC 6762).

    For mDNS:
    - msg_id MUST be zero for multicast responses (RFC 6762 s18.1)
    - Responses MUST set QR and AA flags (RFC 6762 s6)
    - Queries from port 5353 use msg_id=0 (RFC 6762 s18.1)
    """
    msg_id: int = 0
    flags: int = 0
    questions: list[MDNSQuestion] = field(default_factory=list)
    answers: list[MDNSRecord] = field(default_factory=list)
    authorities: list[MDNSRecord] = field(default_factory=list)
    additionals: list[MDNSRecord] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        """True if the QR flag indicates this is a response."""
        return bool(self.flags & MDNSFlags.QR)

    @property
    def is_query(self) -> bool:
        """True if this message is a query (QR flag not set)."""
        return not self.is_response

    @property
    def is_truncated(self) -> bool:
        """True if the TC (truncated) flag is set (RFC 6762 s7.2)."""
        return bool(self.flags & MDNSFlags.TC)

    # -- Wire format ----------------------------------------------------------

    def to_wire(self, max_size: int = 0) -> bytes:
        """Serialize the entire message to wire-format bytes.

        If *max_size* > 0, truncate records that don't fit and set the
        TC flag (RFC 6762 s7.2).  Returns at most *max_size* bytes.
        If *max_size* is 0, no limit is applied.
        """
        buf = bytearray()
        # Reserve header space — fill in counts after serializing sections
        buf.extend(b"\x00" * DNS_HEADER_SIZE)
        compression: dict[str, int] = {}

        qdcount = 0
        for q in self.questions:
            q.to_wire(buf, compression)
            qdcount += 1

        flags = self.flags
        ancount = 0
        for rr in self.answers:
            mark = len(buf)
            rr.to_wire(buf, compression)
            if max_size and len(buf) > max_size:
                del buf[mark:]
                flags |= MDNSFlags.TC.value
                break
            ancount += 1

        nscount = 0
        if not (flags & MDNSFlags.TC):
            for rr in self.authorities:
                mark = len(buf)
                rr.to_wire(buf, compression)
                if max_size and len(buf) > max_size:
                    del buf[mark:]
                    flags |= MDNSFlags.TC.value
                    break
                nscount += 1

        arcount = 0
        if not (flags & MDNSFlags.TC):
            for rr in self.additionals:
                mark = len(buf)
                rr.to_wire(buf, compression)
                if max_size and len(buf) > max_size:
                    del buf[mark:]
                    break
                arcount += 1

        # Fill in header
        struct.pack_into(
            "!HHHHHH", buf, 0,
            self.msg_id, flags, qdcount, ancount, nscount, arcount,
        )
        return bytes(buf)

    @classmethod
    def from_wire(cls, data: bytes) -> MDNSMessage:
        """Parse an mDNS message from raw wire-format bytes."""
        if len(data) < DNS_HEADER_SIZE:
            raise ValueError(
                f"Packet too short ({len(data)} < {DNS_HEADER_SIZE})"
            )

        (msg_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
            "!HHHHHH", data[:DNS_HEADER_SIZE]
        )

        offset = DNS_HEADER_SIZE
        questions: list[MDNSQuestion] = []
        answers: list[MDNSRecord] = []
        authorities: list[MDNSRecord] = []
        additionals: list[MDNSRecord] = []

        for _ in range(qdcount):
            q, offset = MDNSQuestion.from_wire(data, offset)
            questions.append(q)

        for _ in range(ancount):
            rr, offset = MDNSRecord.from_wire(data, offset)
            answers.append(rr)

        for _ in range(nscount):
            rr, offset = MDNSRecord.from_wire(data, offset)
            authorities.append(rr)

        for _ in range(arcount):
            try:
                rr, offset = MDNSRecord.from_wire(data, offset)
                additionals.append(rr)
            except (ValueError, IndexError):
                logger.debug("Skipping malformed additional record")
                break

        return cls(
            msg_id=msg_id,
            flags=flags,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    # -- Convenience builders -------------------------------------------------

    @classmethod
    def build_query(
        cls,
        questions: list[MDNSQuestion],
        known_answers: list[MDNSRecord] | None = None,
    ) -> MDNSMessage:
        """Build a query with optional known-answer suppression (RFC 6762 s7.1)."""
        return cls(
            msg_id=0,
            flags=0,
            questions=questions,
            answers=known_answers or [],
        )

    @classmethod
    def build_response(
        cls,
        answers: list[MDNSRecord],
        additionals: list[MDNSRecord] | None = None,
    ) -> MDNSMessage:
        """Build an authoritative response (RFC 6762 s6: QR=1, AA=1)."""
        return cls(
            msg_id=0,
            flags=MDNSFlags.QR.value | MDNSFlags.AA.value,
            answers=answers,
            additionals=additionals or [],
        )

    @classmethod
    def build_probe(
        cls,
        questions: list[MDNSQuestion],
        authority_records: list[MDNSRecord],
    ) -> MDNSMessage:
        """Build a probe: questions in QD, proposed records in NS (RFC 6762 s8.1)."""
        return cls(
            msg_id=0,
            flags=0,
            questions=questions,
            authorities=authority_records,
        )

    @classmethod
    def build_goodbye(cls, records: list[MDNSRecord]) -> MDNSMessage:
        """Build a goodbye response with TTL=0 (RFC 6762 s10.1)."""
        goodbye_records: list[MDNSRecord] = []
        for rr in records:
            goodbye_records.append(MDNSRecord(
                key=rr.key,
                ttl=0,
                data=rr.data,
                cache_flush=rr.cache_flush,
            ))
        return cls.build_response(goodbye_records)

    @classmethod
    def build_legacy_response(
        cls,
        query: 'MDNSMessage',
        answers: list[MDNSRecord],
    ) -> MDNSMessage:
        """Build a legacy unicast response (RFC 6762 s6.7).

        Echoes the query ID and question.  Cache-flush bit MUST NOT be set.
        TTL capped at 10 seconds.
        """
        capped: list[MDNSRecord] = []
        for rr in answers:
            capped.append(MDNSRecord(
                key=rr.key,
                ttl=min(rr.ttl, LEGACY_RESPONSE_TTL_CAP),
                data=rr.data,
                cache_flush=False,
            ))
        return cls(
            msg_id=query.msg_id,
            flags=MDNSFlags.QR.value | MDNSFlags.AA.value,
            questions=list(query.questions),
            answers=capped,
        )
