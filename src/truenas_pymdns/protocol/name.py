"""DNS name wire-format encoding and decoding with compression.

DNS names on the wire use a sequence of length-prefixed labels terminated
by a zero byte, with optional pointer compression (RFC 1035 s4.1.4).

Label encoding (RFC 1035 s4.1.2):
    +--+--+--+--+--+--+--+--+
    |         LENGTH        |  1 byte: 0-63
    +--+--+--+--+--+--+--+--+
    |      LABEL OCTETS     |  LENGTH bytes of UTF-8 text
    +--+--+--+--+--+--+--+--+
    ...more labels...
    +--+--+--+--+--+--+--+--+
    |     0x00 (terminator) |
    +--+--+--+--+--+--+--+--+

Pointer compression (RFC 1035 s4.1.4):
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|         OFFSET (14 bits)                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    Top two bits = 11 indicates a pointer.  The remaining 14 bits give
    the byte offset from the start of the message where the name continues.

Example: "myhost.local" encodes as:
    06 6d 79 68 6f 73 74  05 6c 6f 63 61 6c  00
    |6|m  y  h  o  s  t| |5|l  o  c  a  l| |0|
"""
from __future__ import annotations

from .constants import (
    DNS_COMPRESSION_MAX_OFFSET,
    DNS_MAX_LABEL_LENGTH,
    DNS_MAX_NAME_LENGTH,
)

_POINTER_MASK = 0xC0
_MAX_POINTER_DEPTH = 256


def encode_name(
    name: str,
    buf: bytearray,
    compression: dict[str, int] | None = None,
) -> None:
    """Encode a DNS name into *buf* with optional pointer compression.

    *compression* maps previously-seen suffix strings to their byte offsets
    in *buf*.  It is updated in-place with new entries.
    """
    if not name or name == ".":
        buf.append(0)
        return

    # Strip trailing dot if present, then split
    if name.endswith("."):
        name = name[:-1]
    if len(name) > DNS_MAX_NAME_LENGTH:
        raise ValueError(
            f"DNS name too long ({len(name)} > {DNS_MAX_NAME_LENGTH})"
        )
    labels = name.split(".")

    for i, label in enumerate(labels):
        if len(label) > DNS_MAX_LABEL_LENGTH:
            raise ValueError(
                f"Label too long ({len(label)} > {DNS_MAX_LABEL_LENGTH}): "
                f"{label!r}"
            )

        suffix = ".".join(labels[i:]).lower()

        if compression is not None and suffix in compression:
            offset = compression[suffix]
            buf.append((_POINTER_MASK | (offset >> 8)) & 0xFF)
            buf.append(offset & 0xFF)
            return

        if compression is not None and len(buf) < DNS_COMPRESSION_MAX_OFFSET:
            compression[suffix] = len(buf)

        encoded = label.encode("utf-8")
        buf.append(len(encoded))
        buf.extend(encoded)

    buf.append(0)


def decode_name(data: bytes | bytearray, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format starting at *offset*.

    Returns ``(name, new_offset)`` where *new_offset* is the position in
    *data* immediately after the name encoding (pointer targets are followed
    internally but do not advance the returned offset).
    """
    labels: list[str] = []
    first_jump_offset: int | None = None
    visited: set[int] = set()
    depth = 0
    pos = offset

    while True:
        if depth > _MAX_POINTER_DEPTH:
            raise ValueError("DNS name pointer loop detected")
        if pos >= len(data):
            raise ValueError("DNS name truncated")

        length = data[pos]

        if length == 0:
            if first_jump_offset is None:
                first_jump_offset = pos + 1
            break

        if (length & _POINTER_MASK) == _POINTER_MASK:
            if pos + 1 >= len(data):
                raise ValueError("DNS name pointer truncated")
            if first_jump_offset is None:
                first_jump_offset = pos + 2
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if ptr in visited:
                raise ValueError("DNS name pointer loop detected")
            visited.add(ptr)
            pos = ptr
            depth += 1
            continue

        pos += 1
        if pos + length > len(data):
            raise ValueError("DNS name label truncated")
        labels.append(data[pos:pos + length].decode("utf-8"))
        pos += length
        depth += 1

    name = ".".join(labels)
    if len(name) > DNS_MAX_NAME_LENGTH:
        raise ValueError(
            f"DNS name too long ({len(name)} > {DNS_MAX_NAME_LENGTH})"
        )

    return name, first_jump_offset  # type: ignore[return-value]
