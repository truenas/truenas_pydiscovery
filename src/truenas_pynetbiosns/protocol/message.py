"""NetBIOS Name Service message parsing and building (RFC 1002 s4.2).

Packet structure::

    Header (12 bytes):
      NAME_TRN_ID  (2)  — transaction ID
      FLAGS        (2)  — opcode, R, AA, TC, RD, RA, B, RCODE
      QDCOUNT      (2)  — questions
      ANCOUNT      (2)  — answers
      NSCOUNT      (2)  — authority records
      ARCOUNT      (2)  — additional records

    Followed by question and resource record sections.

Resource record (RR) format::

    NAME     (variable) — encoded NetBIOS name
    TYPE     (2)        — RRType (NB=0x20, NBSTAT=0x21)
    CLASS    (2)        — RRClass (IN=1)
    TTL      (4)        — time-to-live in seconds
    RDLENGTH (2)        — length of RDATA
    RDATA    (variable) — for NB: 2-byte flags + 4-byte IP per address
"""
from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address

from .constants import (
    FLAGS_MASK,
    HeaderFlags,
    NB_HEADER_SIZE,
    NETBIOS_NAME_LENGTH,
    NBFlag,
    OPCODE_FIELD_MASK,
    OPCODE_MASK,
    OPCODE_SHIFT,
    Opcode,
    RCODE_MASK,
    Rcode,
    RRClass,
    RRType,
)
from .name import NetBIOSName, decode_netbios_name, encode_netbios_name


# ---------------------------------------------------------------------------
# Resource record dataclass
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NBResourceRecord:
    """A NetBIOS name service resource record."""
    name: NetBIOSName
    rr_type: RRType
    rr_class: RRClass = RRClass.IN
    ttl: int = 0
    rdata: bytes = b""

    def to_wire(self) -> bytes:
        """Serialize this RR to wire format."""
        buf = bytearray()
        buf.extend(encode_netbios_name(
            self.name.name, self.name.name_type, self.name.scope,
        ))
        buf.extend(struct.pack(
            "!HHIH",
            self.rr_type.value, self.rr_class.value,
            self.ttl, len(self.rdata),
        ))
        buf.extend(self.rdata)
        return bytes(buf)

    @classmethod
    def from_wire(cls, data: bytes, offset: int) -> tuple[NBResourceRecord, int]:
        """Parse an RR from wire format at *offset*."""
        name, offset = decode_netbios_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("RR header truncated")
        rr_type_val, rr_class_val, ttl, rdlength = struct.unpack(
            "!HHIH", data[offset:offset + 10],
        )
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("RR rdata truncated")
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        return cls(
            name=name,
            rr_type=RRType(rr_type_val),
            rr_class=RRClass(rr_class_val),
            ttl=ttl,
            rdata=rdata,
        ), offset


# ---------------------------------------------------------------------------
# Question dataclass
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NBQuestion:
    """A question entry in a name service packet."""
    name: NetBIOSName
    q_type: RRType = RRType.NB
    q_class: RRClass = RRClass.IN

    def to_wire(self) -> bytes:
        """Serialize to wire format (RFC 1002 s4.2.1.2)."""
        buf = bytearray()
        buf.extend(encode_netbios_name(
            self.name.name, self.name.name_type, self.name.scope,
        ))
        buf.extend(struct.pack("!HH", self.q_type.value, self.q_class.value))
        return bytes(buf)

    @classmethod
    def from_wire(cls, data: bytes, offset: int) -> tuple[NBQuestion, int]:
        """Parse from wire format (RFC 1002 s4.2.1.2)."""
        name, offset = decode_netbios_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Question truncated")
        q_type_val, q_class_val = struct.unpack(
            "!HH", data[offset:offset + 4],
        )
        offset += 4
        return cls(
            name=name,
            q_type=RRType(q_type_val),
            q_class=RRClass(q_class_val),
        ), offset


# ---------------------------------------------------------------------------
# NB rdata helpers
# ---------------------------------------------------------------------------

def build_nb_rdata(
    ip: IPv4Address, flags: NBFlag = NBFlag(0),
) -> bytes:
    """Build NB resource record rdata: 2-byte flags + 4-byte IP."""
    return struct.pack("!H", flags.value) + ip.packed


def parse_nb_rdata(rdata: bytes) -> list[tuple[NBFlag, IPv4Address]]:
    """Parse NB rdata into a list of (flags, ip) tuples."""
    entries: list[tuple[NBFlag, IPv4Address]] = []
    offset = 0
    while offset + 6 <= len(rdata):
        flags_val, = struct.unpack("!H", rdata[offset:offset + 2])
        ip = IPv4Address(rdata[offset + 2:offset + 6])
        entries.append((NBFlag(flags_val), ip))
        offset += 6
    return entries


# ---------------------------------------------------------------------------
# Transaction ID generator
# ---------------------------------------------------------------------------


def _gen_trn_id() -> int:
    """Return a fresh 16-bit NAME_TRN_ID (RFC 1002 §4.2.1.1).

    The RFC only requires that the transaction ID "uniquely
    identify" a name-service transaction — a monotonic counter
    would satisfy that.  We use a cryptographically secure random
    16-bit value instead so off-path attackers cannot predict the
    ID of an in-flight broadcast query or registration burst.

    Without randomisation, an attacker who sees one of our
    broadcasts on the LAN can compute the next TRN_ID (counter + 1)
    and race a forged response — e.g. spoofing an ``ACT_ERR``
    rcode against our registration to deny the name — before the
    legitimate peer replies.  This is the same class of issue the
    DNS query-ID and source-port randomisation defences address
    after Kaminsky (2008).  Microsoft's NBT stack has randomised
    TRN_IDs since at least Windows 2000.

    ``secrets.randbits(16)`` draws from ``os.urandom`` so the
    output is unpredictable even by a local attacker without
    kernel-level access.
    """
    return secrets.randbits(16)


# ---------------------------------------------------------------------------
# NBNSMessage
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class NBNSMessage:
    """A NetBIOS Name Service packet (RFC 1002 s4.2)."""
    trn_id: int = 0
    opcode: Opcode = Opcode.QUERY
    flags: HeaderFlags = HeaderFlags(0)
    rcode: Rcode = Rcode.OK
    questions: list[NBQuestion] = field(default_factory=list)
    answers: list[NBResourceRecord] = field(default_factory=list)
    authorities: list[NBResourceRecord] = field(default_factory=list)
    additionals: list[NBResourceRecord] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & HeaderFlags.RESPONSE)

    @property
    def is_broadcast(self) -> bool:
        return bool(self.flags & HeaderFlags.BROADCAST)

    # -- Wire format --------------------------------------------------------

    def to_wire(self) -> bytes:
        """Serialize the message to wire-format bytes."""
        buf = bytearray()

        # Build flags word: R(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) 00 B(1) RCODE(4)
        flags_word = self.flags.value & FLAGS_MASK
        flags_word |= (self.opcode.value & OPCODE_MASK) << OPCODE_SHIFT
        flags_word |= self.rcode.value & RCODE_MASK

        buf.extend(struct.pack(
            "!HHHHHH",
            self.trn_id,
            flags_word,
            len(self.questions),
            len(self.answers),
            len(self.authorities),
            len(self.additionals),
        ))

        for q in self.questions:
            buf.extend(q.to_wire())
        for rr in self.answers:
            buf.extend(rr.to_wire())
        for rr in self.authorities:
            buf.extend(rr.to_wire())
        for rr in self.additionals:
            buf.extend(rr.to_wire())

        return bytes(buf)

    @classmethod
    def from_wire(cls, data: bytes) -> NBNSMessage:
        """Parse a message from wire-format bytes."""
        if len(data) < NB_HEADER_SIZE:
            raise ValueError(
                f"Packet too short ({len(data)} < {NB_HEADER_SIZE})"
            )

        trn_id, flags_word, qdcount, ancount, nscount, arcount = (
            struct.unpack("!HHHHHH", data[:NB_HEADER_SIZE])
        )

        # Each section entry is at least 2 bytes; reject absurd counts early
        remaining = len(data) - NB_HEADER_SIZE
        total_entries = qdcount + ancount + nscount + arcount
        if total_entries * 2 > remaining:
            raise ValueError(
                f"Section counts ({total_entries} entries) exceed "
                f"remaining packet size ({remaining} bytes)"
            )

        opcode = (flags_word >> OPCODE_SHIFT) & OPCODE_MASK
        rcode = flags_word & RCODE_MASK
        flags = flags_word & FLAGS_MASK
        # Clear opcode bits from flags
        flags &= ~OPCODE_FIELD_MASK

        offset = NB_HEADER_SIZE

        questions: list[NBQuestion] = []
        for _ in range(qdcount):
            q, offset = NBQuestion.from_wire(data, offset)
            questions.append(q)

        answers: list[NBResourceRecord] = []
        for _ in range(ancount):
            rr, offset = NBResourceRecord.from_wire(data, offset)
            answers.append(rr)

        authorities: list[NBResourceRecord] = []
        for _ in range(nscount):
            rr, offset = NBResourceRecord.from_wire(data, offset)
            authorities.append(rr)

        additionals: list[NBResourceRecord] = []
        for _ in range(arcount):
            rr, offset = NBResourceRecord.from_wire(data, offset)
            additionals.append(rr)

        return cls(
            trn_id=trn_id,
            opcode=Opcode(opcode),
            flags=HeaderFlags(flags),
            rcode=Rcode(rcode),
            questions=questions,
            answers=answers,
            authorities=authorities,
            additionals=additionals,
        )

    # -- Convenience builders -----------------------------------------------

    @classmethod
    def build_name_query(
        cls,
        name: str,
        name_type: int,
        scope: str = "",
        broadcast: bool = True,
    ) -> NBNSMessage:
        """Build a name query request (RFC 1002 s4.2.12)."""
        flags = HeaderFlags.RD
        if broadcast:
            flags |= HeaderFlags.BROADCAST
        return cls(
            trn_id=_gen_trn_id(),
            opcode=Opcode.QUERY,
            flags=flags,
            questions=[NBQuestion(
                name=NetBIOSName(name, name_type, scope),
                q_type=RRType.NB,
            )],
        )

    @classmethod
    def build_registration(
        cls,
        name: str,
        name_type: int,
        ip: IPv4Address,
        *,
        scope: str = "",
        group: bool = False,
        ttl: int = 0,
        broadcast: bool = True,
    ) -> NBNSMessage:
        """Build a name registration request (RFC 1002 s4.2.2)."""
        flags = HeaderFlags.RD
        if broadcast:
            flags |= HeaderFlags.BROADCAST
        nb_flags = NBFlag.GROUP if group else NBFlag(0)
        nb_name = NetBIOSName(name, name_type, scope)
        return cls(
            trn_id=_gen_trn_id(),
            opcode=Opcode.REGISTRATION,
            flags=flags,
            questions=[NBQuestion(name=nb_name, q_type=RRType.NB)],
            additionals=[NBResourceRecord(
                name=nb_name,
                rr_type=RRType.NB,
                ttl=ttl,
                rdata=build_nb_rdata(ip, nb_flags),
            )],
        )

    @classmethod
    def build_release(
        cls,
        name: str,
        name_type: int,
        ip: IPv4Address,
        *,
        scope: str = "",
        group: bool = False,
        broadcast: bool = True,
    ) -> NBNSMessage:
        """Build a name release request (RFC 1002 s4.2.9)."""
        flags = HeaderFlags(0)
        if broadcast:
            flags |= HeaderFlags.BROADCAST
        nb_flags = NBFlag.GROUP if group else NBFlag(0)
        nb_name = NetBIOSName(name, name_type, scope)
        return cls(
            trn_id=_gen_trn_id(),
            opcode=Opcode.RELEASE,
            flags=flags,
            questions=[NBQuestion(name=nb_name, q_type=RRType.NB)],
            additionals=[NBResourceRecord(
                name=nb_name,
                rr_type=RRType.NB,
                ttl=0,
                rdata=build_nb_rdata(ip, nb_flags),
            )],
        )

    @classmethod
    def build_refresh(
        cls,
        name: str,
        name_type: int,
        ip: IPv4Address,
        *,
        scope: str = "",
        group: bool = False,
        ttl: int = 0,
        broadcast: bool = True,
    ) -> NBNSMessage:
        """Build a name refresh request (RFC 1002 s4.2.4)."""
        flags = HeaderFlags(0)
        if broadcast:
            flags |= HeaderFlags.BROADCAST
        nb_flags = NBFlag.GROUP if group else NBFlag(0)
        nb_name = NetBIOSName(name, name_type, scope)
        return cls(
            trn_id=_gen_trn_id(),
            opcode=Opcode.REFRESH,
            flags=flags,
            questions=[NBQuestion(name=nb_name, q_type=RRType.NB)],
            additionals=[NBResourceRecord(
                name=nb_name,
                rr_type=RRType.NB,
                ttl=ttl,
                rdata=build_nb_rdata(ip, nb_flags),
            )],
        )

    @classmethod
    def build_positive_response(
        cls,
        trn_id: int,
        name: str,
        name_type: int,
        ip: IPv4Address,
        *,
        scope: str = "",
        group: bool = False,
        ttl: int = 0,
    ) -> NBNSMessage:
        """Build a positive name query response (RFC 1002 s4.2.13)."""
        nb_flags = NBFlag.GROUP if group else NBFlag(0)
        nb_name = NetBIOSName(name, name_type, scope)
        return cls(
            trn_id=trn_id,
            opcode=Opcode.QUERY,
            flags=HeaderFlags.RESPONSE | HeaderFlags.AA | HeaderFlags.RD,
            rcode=Rcode.OK,
            answers=[NBResourceRecord(
                name=nb_name,
                rr_type=RRType.NB,
                ttl=ttl,
                rdata=build_nb_rdata(ip, nb_flags),
            )],
        )

    @classmethod
    def build_negative_response(
        cls,
        trn_id: int,
        name: str,
        name_type: int,
        rcode: Rcode,
        *,
        scope: str = "",
    ) -> NBNSMessage:
        """Build a negative name registration response (RFC 1002 s4.2.6)."""
        return cls(
            trn_id=trn_id,
            opcode=Opcode.REGISTRATION,
            flags=HeaderFlags.RESPONSE | HeaderFlags.AA | HeaderFlags.RD,
            rcode=rcode,
            answers=[NBResourceRecord(
                name=NetBIOSName(name, name_type, scope),
                rr_type=RRType.NB,
                ttl=0,
                rdata=b"",
            )],
        )

    @classmethod
    def build_node_status_query(
        cls,
        name: str = "*",
        name_type: int = 0x00,
        scope: str = "",
    ) -> NBNSMessage:
        """Build a node status query (NBSTAT, RFC 1002 s4.2.17)."""
        return cls(
            trn_id=_gen_trn_id(),
            opcode=Opcode.QUERY,
            flags=HeaderFlags(0),
            questions=[NBQuestion(
                name=NetBIOSName(name, name_type, scope),
                q_type=RRType.NBSTAT,
            )],
        )

    @classmethod
    def build_node_status_response(
        cls,
        trn_id: int,
        query_name: NetBIOSName,
        names: list[tuple[str, int, int]],
    ) -> NBNSMessage:
        """Build a node status response (RFC 1002 s4.2.18).

        *names* is a list of (name, name_type, nb_flags) tuples
        for all names registered on this node.
        """
        # NBSTAT rdata: 1-byte count + 18 bytes per name entry
        rdata = bytearray()
        rdata.append(len(names))
        for n, ntype, nflags in names:
            # 15-byte padded name + 1-byte type
            padded = n.upper().ljust(NETBIOS_NAME_LENGTH)[:NETBIOS_NAME_LENGTH]
            rdata.extend(padded.encode("ascii"))
            rdata.append(ntype)
            # 2-byte flags
            rdata.extend(struct.pack("!H", nflags))

        # Pad with 46 bytes of statistics (zeros)
        rdata.extend(b"\x00" * 46)

        return cls(
            trn_id=trn_id,
            opcode=Opcode.QUERY,
            flags=HeaderFlags.RESPONSE | HeaderFlags.AA,
            answers=[NBResourceRecord(
                name=query_name,
                rr_type=RRType.NBSTAT,
                rdata=bytes(rdata),
            )],
        )
