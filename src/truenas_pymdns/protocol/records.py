"""mDNS resource record dataclasses with wire serialisation.

Resource record wire format (RFC 1035 s4.1.3):

                                 1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                                               |
 /                      NAME                     /  variable: owner name
 |                                               |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      TYPE                     |  2 bytes
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |CF|                    CLASS                   |  2 bytes (CF = cache-flush, RFC 6762 s10.2)
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      TTL                      |  4 bytes
 |                                               |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    RDLENGTH                   |  2 bytes
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                                               |
 /                     RDATA                     /  RDLENGTH bytes
 |                                               |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

SRV RDATA (RFC 2782):
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                   PRIORITY                    |  2 bytes
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    WEIGHT                     |  2 bytes
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     PORT                      |  2 bytes
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 /                    TARGET                     /  variable: uncompressed name
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

TXT RDATA (RFC 6763 s6):
 +--+--+--+--+--+--+--+--+
 |      STRING LENGTH    |  1 byte
 +--+--+--+--+--+--+--+--+
 |     STRING DATA ...   |  LENGTH bytes ("key=value")
 +--+--+--+--+--+--+--+--+
 ...repeated for each TXT string...
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from .constants import CLASS_CACHE_FLUSH, QClass, QType, TTL_REFRESH_AT, TXT_MAX_ENTRY_LENGTH
from .name import decode_name, encode_name


# ---------------------------------------------------------------------------
# MDNSRecordKey
# ---------------------------------------------------------------------------

@dataclass(frozen=True, order=True, slots=True)
class MDNSRecordKey:
    """Hashable identity for cache and registry lookups.

    Name is normalized to lowercase on construction for
    case-insensitive comparison per RFC 6762 s16.
    Uses object.__setattr__ to bypass frozen guard in __post_init__.
    """
    name: str
    rtype: QType
    rclass: QClass = QClass.IN

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", self.name.lower())


# ---------------------------------------------------------------------------
# Record data base + concrete types
# ---------------------------------------------------------------------------

class RecordData:
    """Base for type-specific record data.

    Every concrete subclass populates ``_identity`` (a canonical,
    case-folded tuple) and ``_hash`` (``hash(_identity)``) in its
    ``__post_init__``; see the module-level note at the top of the
    concrete subclasses block.  Declaring these here gives mypy a
    stable attribute surface for the base class so callers outside
    this module can reference ``data._identity`` without per-site
    ``cast()`` contortions.
    """
    _identity: tuple = ()
    _hash: int = 0

    def to_wire(self, _buf: bytearray | None = None,
                _compression: dict[str, int] | None = None) -> bytes:
        raise NotImplementedError

    @staticmethod
    def parse(rtype: QType, rdata: bytes, msg: bytes,
              rdata_offset: int) -> RecordData:
        """Dispatch to the right subclass parser based on record type."""
        match rtype:
            case QType.A:
                return ARecordData.from_wire(rdata)
            case QType.AAAA:
                return AAAARecordData.from_wire(rdata)
            case QType.PTR:
                return PTRRecordData.from_wire(rdata, msg, rdata_offset)
            case QType.SRV:
                return SRVRecordData.from_wire(rdata, msg, rdata_offset)
            case QType.TXT:
                return TXTRecordData.from_wire(rdata)
            case _:
                return GenericRecordData.from_wire(rdata)


# ``_identity`` is the canonical, case-folded, hashable tuple each
# ``RecordData`` subclass caches in its ``__post_init__``.  It's
# exclusively for equality, hashing, and probe-tiebreak sort ordering
# (``conflict.lexicographic_compare``).  NEVER write ``_identity``
# to the wire — ``to_wire()`` intentionally emits the user's
# original (possibly mixed-case) bytes so RFC 6763 §4.1.1 user-chosen
# case for DNS-SD instance names is preserved on transit and display.
#
# ``_hash`` caches ``hash(_identity)`` at construction so the hot
# paths (set membership, dict lookup) return in one attribute load
# rather than re-hashing the tuple each call; Python tuples don't
# cache their own hash at the tuple-object level.
#
# Mirrors Apple mDNSResponder's identity predicate
# ``IdenticalResourceRecord`` (mDNSCore/DNSCommon.h:317) and
# case-folded hashing in ``DomainNameHashValue``/``SameDomainName``
# (mDNSCore/DNSCommon.c:3014).


@dataclass(frozen=True, slots=True, eq=False)
class ARecordData(RecordData):
    """A record: 4-byte IPv4 address (RFC 1035 s3.4.1)."""
    address: IPv4Address
    _identity: tuple = field(init=False, repr=False, compare=False, default=())
    _hash: int = field(init=False, repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        ident = (self.address.packed,)
        object.__setattr__(self, "_identity", ident)
        object.__setattr__(self, "_hash", hash(ident))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ARecordData):
            return NotImplemented
        return self._identity == other._identity

    def __hash__(self) -> int:
        return self._hash

    def to_wire(self, _buf=None, _compression=None) -> bytes:
        return self.address.packed

    @classmethod
    def from_wire(cls, rdata: bytes) -> ARecordData:
        if len(rdata) != 4:
            raise ValueError(f"A rdata must be 4 bytes, got {len(rdata)}")
        return cls(address=IPv4Address(rdata))


@dataclass(frozen=True, slots=True, eq=False)
class AAAARecordData(RecordData):
    """AAAA record: 16-byte IPv6 address (RFC 3596)."""
    address: IPv6Address
    _identity: tuple = field(init=False, repr=False, compare=False, default=())
    _hash: int = field(init=False, repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        ident = (self.address.packed,)
        object.__setattr__(self, "_identity", ident)
        object.__setattr__(self, "_hash", hash(ident))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AAAARecordData):
            return NotImplemented
        return self._identity == other._identity

    def __hash__(self) -> int:
        return self._hash

    def to_wire(self, _buf=None, _compression=None) -> bytes:
        return self.address.packed

    @classmethod
    def from_wire(cls, rdata: bytes) -> AAAARecordData:
        if len(rdata) != 16:
            raise ValueError(f"AAAA rdata must be 16 bytes, got {len(rdata)}")
        return cls(address=IPv6Address(rdata))


@dataclass(frozen=True, slots=True, eq=False)
class PTRRecordData(RecordData):
    """PTR record: domain name pointer (RFC 1035 s3.3.12)."""
    target: str
    _identity: tuple = field(init=False, repr=False, compare=False, default=())
    _hash: int = field(init=False, repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        # RFC 6762 s16: domain names are compared case-insensitively.
        # We keep ``target`` byte-exact for the wire (RFC 6763 §4.1.1
        # user-friendly instance case) and fold only in ``_identity``.
        ident = (self.target.lower(),)
        object.__setattr__(self, "_identity", ident)
        object.__setattr__(self, "_hash", hash(ident))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PTRRecordData):
            return NotImplemented
        return self._identity == other._identity

    def __hash__(self) -> int:
        return self._hash

    def to_wire(self, buf=None, compression=None) -> bytes:
        if buf is not None:
            # Encode directly into the main buffer so compression
            # offsets are correct relative to the full message.
            encode_name(self.target, buf, compression)
            return b''
        tmp: bytearray = bytearray()
        encode_name(self.target, tmp, None)
        return bytes(tmp)

    @classmethod
    def from_wire(cls, rdata: bytes, msg: bytes,
                  rdata_offset: int) -> PTRRecordData:
        name, _ = decode_name(msg, rdata_offset)
        return cls(target=name)


@dataclass(frozen=True, slots=True, eq=False)
class SRVRecordData(RecordData):
    """SRV record: service locator with priority/weight/port/target (RFC 2782)."""
    priority: int
    weight: int
    port: int
    target: str
    _identity: tuple = field(init=False, repr=False, compare=False, default=())
    _hash: int = field(init=False, repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        # Priority/weight/port are numeric (case-free); target is a
        # domain name and MUST be case-folded for identity
        # (RFC 6762 s16).
        ident = (self.priority, self.weight, self.port, self.target.lower())
        object.__setattr__(self, "_identity", ident)
        object.__setattr__(self, "_hash", hash(ident))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SRVRecordData):
            return NotImplemented
        return self._identity == other._identity

    def __hash__(self) -> int:
        return self._hash

    def to_wire(self, buf=None, compression=None) -> bytes:
        tmp: bytearray = bytearray()
        tmp.extend(struct.pack("!HHH", self.priority, self.weight, self.port))
        # RFC 6762 s18.14: SRV target MUST NOT use name compression
        encode_name(self.target, tmp, None)
        return bytes(tmp)

    @classmethod
    def from_wire(cls, rdata: bytes, msg: bytes,
                  rdata_offset: int) -> SRVRecordData:
        if len(rdata) < 6:
            raise ValueError("SRV rdata too short")
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = decode_name(msg, rdata_offset + 6)
        return cls(priority=priority, weight=weight, port=port, target=target)


@dataclass(frozen=True, slots=True, eq=False)
class TXTRecordData(RecordData):
    """TXT record: length-prefixed key=value strings (RFC 6763 s6)."""
    entries: tuple[bytes, ...]
    _identity: tuple = field(init=False, repr=False, compare=False, default=())
    _hash: int = field(init=False, repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        # RFC 6763 §6.5: TXT values are case-sensitive — no folding.
        # ``entries`` is already a tuple, so we use it verbatim as the
        # identity tuple.
        object.__setattr__(self, "_identity", self.entries)
        object.__setattr__(self, "_hash", hash(self.entries))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TXTRecordData):
            return NotImplemented
        return self._identity == other._identity

    def __hash__(self) -> int:
        return self._hash

    def to_wire(self, _buf=None, _compression=None) -> bytes:
        parts: bytearray = bytearray()
        if not self.entries:
            # RFC 6763 s6: empty TXT is a single zero-length string
            parts.append(0)
            return bytes(parts)
        for entry in self.entries:
            if len(entry) > TXT_MAX_ENTRY_LENGTH:
                raise ValueError(
                    f"TXT entry too long "
                    f"({len(entry)} > {TXT_MAX_ENTRY_LENGTH})"
                )
            parts.append(len(entry))
            parts.extend(entry)
        return bytes(parts)

    @classmethod
    def from_wire(cls, rdata: bytes) -> TXTRecordData:
        entries: list[bytes] = []
        pos = 0
        while pos < len(rdata):
            length = rdata[pos]
            pos += 1
            if pos + length > len(rdata):
                break
            entries.append(rdata[pos:pos + length])
            pos += length
        return cls(entries=tuple(entries))

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> TXTRecordData:
        """Build TXT rdata from a dict of key=value pairs (RFC 6763 s6.3)."""
        entries: list[bytes] = []
        for k, v in d.items():
            entries.append(f"{k}={v}".encode("utf-8"))
        return cls(entries=tuple(entries))


@dataclass(frozen=True, slots=True, eq=False)
class GenericRecordData(RecordData):
    """Fallback for unknown record types — stores raw rdata bytes."""
    raw: bytes
    _identity: tuple = field(init=False, repr=False, compare=False, default=())
    _hash: int = field(init=False, repr=False, compare=False, default=0)

    def __post_init__(self) -> None:
        ident = (self.raw,)
        object.__setattr__(self, "_identity", ident)
        object.__setattr__(self, "_hash", hash(ident))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GenericRecordData):
            return NotImplemented
        return self._identity == other._identity

    def __hash__(self) -> int:
        return self._hash

    def to_wire(self, _buf=None, _compression=None) -> bytes:
        return self.raw

    @classmethod
    def from_wire(cls, rdata: bytes) -> GenericRecordData:
        return cls(raw=bytes(rdata))


# ---------------------------------------------------------------------------
# MDNSRecord
# ---------------------------------------------------------------------------

@dataclass(slots=True, eq=False)
class MDNSRecord:
    """A single mDNS resource record with TTL and cache-flush metadata."""
    key: MDNSRecordKey
    ttl: int
    data: RecordData
    cache_flush: bool = False
    created_at: float = 0.0
    refresh_sent: int = 0

    def __eq__(self, other: object) -> bool:
        """RFC 6762 / Apple ``IdenticalResourceRecord``
        (mDNSCore/DNSCommon.h:317) identity: two records are
        equal iff their name, class, type, and rdata match.
        TTL, cache-flush, and scheduling state are metadata —
        excluded."""
        if not isinstance(other, MDNSRecord):
            return NotImplemented
        return self.key == other.key and self.data == other.data

    def __hash__(self) -> int:
        """Stable across the record's lifetime: ``key`` is
        frozen, ``data`` is frozen with a pre-computed hash, and
        the mutable metadata fields (``ttl``, ``created_at``,
        ``refresh_sent``) aren't in the hash tuple."""
        return hash((self.key, self.data))

    def to_wire(self, buf: bytearray,
                compression: dict[str, int] | None = None) -> None:
        """Serialize this record into wire format, appending to *buf*."""
        encode_name(self.key.name, buf, compression)
        class_val = self.key.rclass.value
        if self.cache_flush:
            class_val |= CLASS_CACHE_FLUSH  # RFC 6762 s10.2
        # Write TYPE, CLASS, TTL and RDLENGTH placeholder before rdata
        # so that rdata name compression offsets are correct.
        buf.extend(struct.pack("!HHI", self.key.rtype.value, class_val,
                               self.ttl))
        rdlen_pos = len(buf)
        buf.extend(b'\x00\x00')  # RDLENGTH placeholder
        rdata_start = len(buf)
        rdata = self.data.to_wire(buf, compression)
        buf.extend(rdata)
        struct.pack_into("!H", buf, rdlen_pos, len(buf) - rdata_start)

    @classmethod
    def from_wire(cls, data: bytes, offset: int) -> tuple[MDNSRecord, int]:
        """Deserialize a record from wire format at *offset*."""
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Record header truncated")
        rtype_val, class_val, ttl, rdlength = struct.unpack(
            "!HHIH", data[offset:offset + 10]
        )
        offset += 10
        cache_flush = bool(class_val & CLASS_CACHE_FLUSH)
        class_val &= ~CLASS_CACHE_FLUSH

        rdata_offset = offset
        if offset + rdlength > len(data):
            raise ValueError("Record rdata truncated")
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        rtype = (QType(rtype_val)
                 if rtype_val in QType.__members__.values()
                 else rtype_val)
        rclass = (QClass(class_val)
                  if class_val in QClass.__members__.values()
                  else class_val)

        record_data = RecordData.parse(rtype, rdata, data, rdata_offset)

        key = MDNSRecordKey(name=name, rtype=rtype, rclass=rclass)
        return cls(key=key, ttl=ttl, data=record_data,
                   cache_flush=cache_flush), offset

    # -- TTL helpers (RFC 6762 s5.2, s11) ------------------------------------

    def is_expired(self, now: float) -> bool:
        """Return True if this record's TTL has elapsed."""
        return now >= self.created_at + self.ttl

    def remaining_ttl(self, now: float) -> int:
        """Return the remaining TTL in seconds, clamped to zero."""
        remaining = self.ttl - (now - self.created_at)
        return max(0, int(remaining))

    def next_refresh_time(self) -> float | None:
        """Return monotonic time for next TTL refresh query (RFC 6762 s5.2).

        Refresh queries are sent at 80%, 85%, 90%, 95% of the original TTL.
        """
        if self.refresh_sent >= len(TTL_REFRESH_AT):
            return None
        fraction = TTL_REFRESH_AT[self.refresh_sent]
        return self.created_at + self.ttl * fraction

    # -- Conflict resolution (RFC 6762 s8.2) ---------------------------------

    def rdata_wire(self) -> bytes:
        """Return the wire-format bytes of this record's rdata."""
        return self.data.to_wire()

    def lexicographic_cmp(self, other: MDNSRecord) -> int:
        """Compare per RFC 6762 §8.2 for probe tiebreaking.

        Returns the sign of ``self - other`` after comparing (class
        excluding cache-flush bit, type, rdata identity).  Uses
        ``RecordData._identity`` (case-folded per RFC 6762 §16) for
        the rdata comparison so BCT's intentional case-flipping on
        probe denials (guideline §820) doesn't skew the tiebreak.
        Per RFC, the GREATER rdata wins, so callers treat a negative
        result as "self loses" and a positive result as "self wins".
        """
        if self.key.rclass.value != other.key.rclass.value:
            return self.key.rclass.value - other.key.rclass.value
        if self.key.rtype.value != other.key.rtype.value:
            return self.key.rtype.value - other.key.rtype.value
        our_identity = self.data._identity
        their_identity = other.data._identity
        if our_identity < their_identity:
            return -1
        if our_identity > their_identity:
            return 1
        return 0
