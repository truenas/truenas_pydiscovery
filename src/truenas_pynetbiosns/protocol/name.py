"""NetBIOS name encoding and decoding (RFC 1002 s4.1).

NetBIOS names are 16 bytes: 15 printable characters (space-padded,
uppercased) plus a 1-byte service type suffix.  On the wire they are
encoded using "first-level encoding" (half-ASCII): each byte becomes
two bytes by splitting into nibbles and adding 0x41 ('A').

Wire format::

    0x20  <32 half-ASCII bytes>  [<scope labels>]  0x00

Example: "TRUENAS" with type 0x20 →
    pad to 16 bytes: b'TRUENAS         \\x20'
    half-ASCII encode each byte: T=0x54 → 0x46,0x45 → "FE"
    prepend length 0x20 (32), append null terminator
"""
from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    DNS_MAX_LABEL_LENGTH,
    NETBIOS_ENCODED_LENGTH,
    NETBIOS_HALF_ASCII_BASE,
    NETBIOS_LABEL_LENGTH,
    NETBIOS_NAME_LENGTH,
    NETBIOS_NIBBLE_MASK,
)


@dataclass(frozen=True, slots=True)
class NetBIOSName:
    """A decoded NetBIOS name with type and optional scope."""
    name: str  # Up to 15 chars, stripped of padding
    name_type: int  # Service type suffix byte (0x00, 0x20, etc.)
    scope: str = ""  # Dot-separated scope ID (rarely used)

    def __str__(self) -> str:
        suffix = f"<{self.name_type:02x}>"
        if self.scope:
            return f"{self.name}{suffix}.{self.scope}"
        return f"{self.name}{suffix}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetBIOSName):
            return NotImplemented
        return (
            self.name.upper() == other.name.upper()
            and self.name_type == other.name_type
            and self.scope.upper() == other.scope.upper()
        )

    def __hash__(self) -> int:
        return hash((self.name.upper(), self.name_type, self.scope.upper()))


def encode_netbios_name(
    name: str, name_type: int, scope: str = "",
) -> bytes:
    """Encode a NetBIOS name to wire format.

    The name is uppercased, padded with spaces to 15 bytes, the type
    byte is appended, then each of the 16 bytes is split into two
    half-ASCII bytes.  A length prefix of 0x20 (32) is prepended,
    optional scope labels are appended, and a null terminator closes.
    """
    # Pad/truncate to 15 chars, uppercase
    padded = name.upper().ljust(NETBIOS_NAME_LENGTH)[:NETBIOS_NAME_LENGTH]
    raw = padded.encode("ascii") + bytes([name_type])

    # Half-ASCII encoding: each byte → 2 bytes (RFC 1002 §4.1)
    buf = bytearray()
    buf.append(NETBIOS_LABEL_LENGTH)  # length prefix = 32
    for b in raw:
        buf.append((b >> 4) + NETBIOS_HALF_ASCII_BASE)
        buf.append((b & NETBIOS_NIBBLE_MASK) + NETBIOS_HALF_ASCII_BASE)

    # Scope: encode as DNS-style labels (RFC 1035 §2.3.4 label limit)
    if scope:
        for label in scope.split("."):
            encoded = label.encode("ascii")
            if len(encoded) > DNS_MAX_LABEL_LENGTH:
                raise ValueError(
                    f"Scope label too long "
                    f"({len(encoded)} > {DNS_MAX_LABEL_LENGTH}): "
                    f"{label!r}"
                )
            buf.append(len(encoded))
            buf.extend(encoded)

    buf.append(0)  # null terminator
    return bytes(buf)


def decode_netbios_name(
    data: bytes, offset: int = 0,
) -> tuple[NetBIOSName, int]:
    """Decode a NetBIOS name from wire format at *offset*.

    Returns ``(NetBIOSName, new_offset)`` where *new_offset* is the
    position immediately after the name encoding.
    """
    if offset >= len(data):
        raise ValueError("NetBIOS name truncated at offset")

    label_len = data[offset]
    offset += 1

    if label_len != NETBIOS_LABEL_LENGTH:
        raise ValueError(
            f"Expected label length {NETBIOS_LABEL_LENGTH}, "
            f"got {label_len}"
        )

    if offset + NETBIOS_ENCODED_LENGTH > len(data):
        raise ValueError("NetBIOS name data truncated")

    # Decode half-ASCII: pairs of bytes → original bytes (RFC 1002 §4.1)
    raw = bytearray()
    for i in range(0, NETBIOS_ENCODED_LENGTH, 2):
        hi = data[offset + i] - NETBIOS_HALF_ASCII_BASE
        lo = data[offset + i + 1] - NETBIOS_HALF_ASCII_BASE
        if not (0 <= hi <= NETBIOS_NIBBLE_MASK
                and 0 <= lo <= NETBIOS_NIBBLE_MASK):
            raise ValueError(
                f"Invalid half-ASCII encoding at offset {offset + i}"
            )
        raw.append((hi << 4) | lo)
    offset += NETBIOS_ENCODED_LENGTH

    # Split into 15-char name + 1-byte type
    name = raw[:NETBIOS_NAME_LENGTH].decode("ascii").rstrip(" ")
    name_type = raw[NETBIOS_NAME_LENGTH]

    # Decode scope labels (DNS-style)
    scope_parts: list[str] = []
    while offset < len(data):
        slen = data[offset]
        offset += 1
        if slen == 0:
            break
        if offset + slen > len(data):
            raise ValueError("Scope label truncated")
        scope_parts.append(
            data[offset:offset + slen].decode("ascii")
        )
        offset += slen

    scope = ".".join(scope_parts)
    return NetBIOSName(name=name, name_type=name_type, scope=scope), offset
