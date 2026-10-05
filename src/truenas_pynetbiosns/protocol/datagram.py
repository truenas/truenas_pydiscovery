"""NetBIOS datagram framing for mailslot writes.

Browser frames (MS-BRWS §2.2) travel as mailslot writes: an
SMB_COM_TRANSACTION addressed to a mailslot name (MS-MAIL §2.2.1),
carried as the USER_DATA of a DIRECT_GROUP NetBIOS datagram on UDP 138
(RFC 1002 §4.4.2).

The byte layout is Samba nmbd's (``send_mailslot`` in
``source3/nmbd/nmbd_packets.c``, ``build_dgram`` in
``source3/libsmb/nmblib.c``) except for the datagram's source node
type (see ``build_mailslot_datagram``): every SMB header field other
than the protocol and command is zero, and the data follows the
mailslot name directly.  MS-MAIL §2.2.1 instead requires Padding "large
enough so that the DataBytes field is 32-bit aligned" and suggests
non-zero Flags/Flags2/PIDLow, which receivers must ignore.  A receiver
"MUST read the DataOffset field" to find the data (MS-MAIL §3.2.5.1),
as Samba's ``process_dgram`` does, so either form parses.
"""
from __future__ import annotations

import struct
from ipaddress import IPv4Address

from .constants import (
    DGRAM_PORT,
    DatagramFlag,
    DatagramType,
    MAILSLOT_CLASS_UNRELIABLE,
    MAILSLOT_OPCODE_WRITE,
    MAILSLOT_PRIORITY,
    SMB_COM_TRANSACTION,
)
from .message import gen_trn_id
from .name import encode_netbios_name

# NetBIOS datagram header (RFC 1002 §4.4.1): MSG_TYPE, FLAGS, DGM_ID,
# SOURCE_IP, SOURCE_PORT, DGM_LENGTH, PACKET_OFFSET.
_DGRAM_HEADER = struct.Struct("!BBH4sHHH")

# SMB header (MS-MAIL §2.2.1 lists its fields for a mailslot write):
# Protocol, Command, Status, Flags, Flags2, PIDHigh, SecurityFeatures,
# Reserved, TID, PIDLow, UID, MID.
_SMB_HEADER = struct.Struct("<4sBIBHH8sHHHHH")

# SMB_COM_TRANSACTION request for a mailslot write (MS-MAIL §2.2.1),
# WordCount through ByteCount: 17 parameter words between the two.
_MAILSLOT_WRITE_WORDS = struct.Struct("<BHHHHBBHIHHHHHBBHHHH")
_MAILSLOT_WRITE_WORD_COUNT = 17
_MAILSLOT_WRITE_SETUP_COUNT = 3

_SMB_PROTOCOL = b"\xffSMB"


def build_mailslot_write(mailslot: str, data: bytes) -> bytes:
    """An SMB_COM_TRANSACTION writing *data* to *mailslot* (MS-MAIL §2.2.1).

    *mailslot* is the full name, e.g. ``\\MAILSLOT\\BROWSE``.  There is
    no parameter buffer; DataOffset is measured from the start of the
    SMB header.
    """
    name = mailslot.encode("ascii") + b"\0"
    data_offset = _SMB_HEADER.size + _MAILSLOT_WRITE_WORDS.size + len(name)
    header = _SMB_HEADER.pack(
        _SMB_PROTOCOL, SMB_COM_TRANSACTION,
        0, 0, 0, 0, bytes(8), 0, 0, 0, 0, 0,
    )
    words = _MAILSLOT_WRITE_WORDS.pack(
        _MAILSLOT_WRITE_WORD_COUNT,
        0, len(data),               # TotalParameterCount, TotalDataCount
        0, 0,                       # MaxParameterCount, MaxDataCount
        0, 0,                       # MaxSetupCount, Reserved
        0, 0, 0,                    # Flags, Timeout, Reserved2
        0, 0,                       # ParameterCount, ParameterOffset
        len(data), data_offset,     # DataCount, DataOffset
        _MAILSLOT_WRITE_SETUP_COUNT, 0,
        MAILSLOT_OPCODE_WRITE, MAILSLOT_PRIORITY, MAILSLOT_CLASS_UNRELIABLE,
        len(name) + len(data),      # ByteCount
    )
    return header + words + name + data


def build_mailslot_datagram(
    data: bytes,
    *,
    mailslot: str,
    source_name: str,
    source_type: int,
    dest_name: str,
    dest_type: int,
    source_ip: IPv4Address,
    scope: str = "",
) -> bytes:
    """A DIRECT_GROUP NetBIOS datagram (RFC 1002 §4.4.2) carrying a
    mailslot write of *data* from ``source_name<source_type>`` to
    ``dest_name<dest_type>``.

    MSG_TYPE is DIRECT_GROUP because the datagram is broadcast: Samba
    nmbd's ``send_announcement`` sends every browse announcement with
    ``send_mailslot`` *unique* false to the subnet broadcast address,
    the HostAnnouncement to the unique name ``<workgroup>[0x1D]``
    (MS-BRWS §2.1.1.1) included, and nmbd uses DIRECT_UNIQUE only for
    datagrams it unicasts to one host (``send_browser_reset``,
    ``browse_sync_remote``).  RFC 1002 §5.3.1 likewise broadcasts only
    datagrams for group names.  This departs from MS-MAIL §3.1.4.1,
    whose product note <13> reads "For unique names, MSG_TYPE is 0x10
    (DIRECT_UNIQUE)", and from RFC 1001 §17.2, under which a datagram
    for a unique name "is unicast to the sole owner of the name".
    nmbd's ``process_dgram`` accepts either type and drops a datagram
    for a name it does not hold without a DATAGRAM ERROR.

    The datagram is unfragmented (FIRST set, PACKET_OFFSET 0) and comes
    from a B node: every name this daemon holds is a B-node broadcast
    registration.  nmbd's ``send_mailslot`` marks every datagram as
    from an M node instead.  DGM_LENGTH counts the encoded names and
    the user data, not the fixed header (RFC 1002 §5.3.1).
    """
    names = (
        encode_netbios_name(source_name, source_type, scope)
        + encode_netbios_name(dest_name, dest_type, scope)
    )
    user_data = build_mailslot_write(mailslot, data)
    header = _DGRAM_HEADER.pack(
        DatagramType.DIRECT_GROUP.value,
        DatagramFlag.FIRST.value,
        gen_trn_id(),
        source_ip.packed,
        DGRAM_PORT,
        len(names) + len(user_data),
        0,
    )
    return header + names + user_data
