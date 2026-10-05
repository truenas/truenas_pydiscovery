"""NetBIOS datagram framing of mailslot writes (RFC 1002 §4.4, MS-MAIL §2.2.1).

Datagrams are decoded with the checks a receiver makes
(``decode_mailslot``); Samba nmbd also requires the mailslot name to be
``\\MAILSLOT\\BROWSE`` before it processes a browse frame
(``process_dgram`` in ``source3/nmbd/nmbd_packets.c``).
"""
from __future__ import annotations

import struct
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import (
    DGRAM_PORT,
    DatagramFlag,
    DatagramType,
    MAILSLOT_BROWSE,
    NameType,
)
from truenas_pynetbiosns.protocol.datagram import (
    build_mailslot_datagram,
    build_mailslot_write,
)
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.browse.announcer import build_host_announcement

from .conftest import DGRAM_HEADER, decode_mailslot

_SOURCE_IP = IPv4Address("192.0.2.10")


def _announcement_datagram(payload: bytes) -> bytes:
    return build_mailslot_datagram(
        payload,
        mailslot=MAILSLOT_BROWSE,
        source_name="NAS01", source_type=NameType.WORKSTATION,
        dest_name="WG", dest_type=NameType.LOCAL_MASTER,
        source_ip=_SOURCE_IP,
    )


class TestMailslotDatagram:
    def test_header_is_unfragmented_direct_group_from_port_138(self):
        payload = build_host_announcement("NAS01", "WG")
        d = decode_mailslot(_announcement_datagram(payload))
        assert d["msg_type"] == DatagramType.DIRECT_GROUP
        assert d["flags"] == DatagramFlag.FIRST
        assert d["source_ip"] == _SOURCE_IP
        assert d["source_port"] == DGRAM_PORT
        assert d["packet_offset"] == 0

    def test_dgm_length_counts_names_and_user_data(self):
        """RFC 1002 §5.3.1: DGM_LENGTH = length of data + length of the
        encoded source and destination names (not the 14-byte header)."""
        datagram = _announcement_datagram(b"x" * 20)
        assert decode_mailslot(datagram)["dgm_length"] == (
            len(datagram) - DGRAM_HEADER.size
        )

    def test_names_address_local_master_browser(self):
        d = decode_mailslot(_announcement_datagram(b"x"))
        assert d["source"] == NetBIOSName("NAS01", NameType.WORKSTATION)
        assert d["dest"] == NetBIOSName("WG", NameType.LOCAL_MASTER)

    def test_payload_is_delivered_to_browse_mailslot(self):
        payload = build_host_announcement("NAS01", "WG", "TrueNAS")
        d = decode_mailslot(_announcement_datagram(payload))
        assert d["mailslot"] == "\\MAILSLOT\\BROWSE"
        assert d["data"] == payload

    def test_dgm_id_varies_between_datagrams(self):
        ids = {
            decode_mailslot(_announcement_datagram(b"x"))["dgm_id"]
            for _ in range(8)
        }
        assert len(ids) > 1


class TestMailslotWrite:
    """MS-MAIL §2.2.1 field values."""

    def test_transaction_fields(self):
        data = b"payload-bytes"
        smb = build_mailslot_write(MAILSLOT_BROWSE, data)
        word_count = smb[32]
        words = struct.unpack_from(f"<{word_count}H", smb, 33)
        assert smb[4] == 0x25                     # SMB_COM_TRANSACTION
        assert word_count == 17
        assert words[0] == 0                      # TotalParameterCount
        assert words[1] == len(data)              # TotalDataCount
        assert words[9] == 0                      # ParameterCount
        assert words[11] == len(data)             # DataCount
        assert words[13] & 0xFF == 3              # SetupCount
        assert words[14:17] == (1, 1, 2)          # opcode, priority, class

    def test_data_offset_and_byte_count(self):
        """DataOffset is measured from the SMB header and lands right
        after the NUL-terminated name, as Samba's ``send_mailslot``
        lays it out (70 + strlen(mailslot)); ByteCount covers the name
        and the data."""
        data = b"abc"
        smb = build_mailslot_write(MAILSLOT_BROWSE, data)
        words = struct.unpack_from("<17H", smb, 33)
        assert words[12] == 70 + len(MAILSLOT_BROWSE)
        assert smb[words[12]:] == data
        byte_count, = struct.unpack_from("<H", smb, 67)
        assert byte_count == len(MAILSLOT_BROWSE) + 1 + len(data)
        assert len(smb) == 69 + byte_count
