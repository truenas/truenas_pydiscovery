"""Shared helpers for the NetBIOS tests."""
from __future__ import annotations

import struct
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import DatagramType
from truenas_pynetbiosns.protocol.name import decode_netbios_name

# NetBIOS datagram header (RFC 1002 §4.4.1): MSG_TYPE, FLAGS, DGM_ID,
# SOURCE_IP, SOURCE_PORT, DGM_LENGTH, PACKET_OFFSET.
DGRAM_HEADER = struct.Struct("!BBH4sHHH")


def decode_mailslot(datagram: bytes) -> dict:
    """Decode a mailslot datagram, asserting what a receiver checks.

    Samba nmbd's ``parse_dgram`` reads the header and, for
    DIRECT_UNIQUE / DIRECT_GROUP / BROADCAST datagrams only, the two
    names; ``process_dgram`` then requires an SMBtrans whose data lies
    inside the datagram (``source3/libsmb/nmblib.c``,
    ``source3/nmbd/nmbd_packets.c``).  ``data`` is the mailslot data,
    found through the transaction's DataOffset and DataCount.
    """
    (msg_type, flags, dgm_id, source_ip, source_port,
     dgm_length, packet_offset) = DGRAM_HEADER.unpack_from(datagram)
    assert msg_type in (
        DatagramType.DIRECT_UNIQUE, DatagramType.DIRECT_GROUP,
        DatagramType.BROADCAST,
    )
    source, offset = decode_netbios_name(datagram, DGRAM_HEADER.size)
    dest, offset = decode_netbios_name(datagram, offset)
    smb = datagram[offset:]

    assert smb[:4] == b"\xffSMB"
    command = smb[4]
    word_count = smb[32]
    words = struct.unpack_from(f"<{word_count}H", smb, 33)
    byte_count, = struct.unpack_from("<H", smb, 33 + 2 * word_count)
    buffer = smb[35 + 2 * word_count:]
    mailslot = buffer[:buffer.index(b"\0")].decode("ascii")
    data_count, data_offset = words[11], words[12]
    assert 0 < data_count and data_offset + data_count <= len(smb)
    return {
        "msg_type": msg_type,
        "flags": flags,
        "dgm_id": dgm_id,
        "source_ip": IPv4Address(source_ip),
        "source_port": source_port,
        "dgm_length": dgm_length,
        "packet_offset": packet_offset,
        "source": source,
        "dest": dest,
        "command": command,
        "word_count": word_count,
        "total_data_count": words[1],
        "setup_count": words[13] & 0xFF,
        "setup": words[14:17],
        "byte_count": byte_count,
        "buffer_length": len(buffer),
        "mailslot": mailslot,
        "data": smb[data_offset:data_offset + data_count],
    }
