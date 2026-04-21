"""Additional MS-BRWS browser payloads:

* ``build_domain_announcement`` (§2.2.3, opcode 0x0C)
* ``build_local_master_announcement`` (§2.2.6, opcode 0x0F)
* ``build_election_request`` + ``parse_election_request`` (§2.2.19, opcode 0x08)
"""
from __future__ import annotations

import struct

from truenas_pynetbiosns.protocol.constants import (
    BrowseOpcode,
    ServerType,
)
from truenas_pynetbiosns.server.browse.announcer import (
    build_domain_announcement,
    build_election_request,
    build_local_master_announcement,
    parse_election_request,
)


class TestDomainAnnouncement:
    def test_opcode_is_domain_announcement(self):
        pl = build_domain_announcement("host", "WORKGROUP", "MASTER")
        assert pl[0] == BrowseOpcode.DOMAIN_ANNOUNCEMENT

    def test_hostname_field_carries_workgroup(self):
        pl = build_domain_announcement("host", "TESTDOM", "MASTER")
        # Bytes 6..22 are the "hostname" field; for DomainAnnouncement
        # it conveys the DOMAIN name, not the host.
        domain_field = pl[6:22].rstrip(b"\x00")
        assert domain_field == b"TESTDOM"

    def test_comment_carries_master_browser_name(self):
        pl = build_domain_announcement("host", "WG", "LMASTER")
        comment = pl[32:].split(b"\x00", 1)[0]
        assert comment == b"LMASTER"

    def test_default_server_type_includes_domain_enum_bit(self):
        pl = build_domain_announcement("host", "WG", "LMASTER")
        (server_type_val,) = struct.unpack("<I", pl[24:28])
        assert server_type_val & ServerType.DOMAIN_ENUM.value
        assert server_type_val & ServerType.MASTER_BROWSER.value


class TestLocalMasterAnnouncement:
    def test_opcode_is_local_master_announcement(self):
        pl = build_local_master_announcement("HOSTA")
        assert pl[0] == BrowseOpcode.LOCAL_MASTER_ANNOUNCEMENT

    def test_hostname_field_carries_host(self):
        pl = build_local_master_announcement("HOSTA")
        field = pl[6:22].rstrip(b"\x00")
        assert field == b"HOSTA"

    def test_default_server_type_marks_master_browser(self):
        pl = build_local_master_announcement("HOSTA")
        (server_type_val,) = struct.unpack("<I", pl[24:28])
        assert server_type_val & ServerType.MASTER_BROWSER.value


class TestElectionRequest:
    def test_opcode_and_version(self):
        pl = build_election_request("HOSTA")
        assert pl[0] == BrowseOpcode.ELECTION_REQUEST
        assert pl[1] == 1

    def test_round_trip_preserves_fields(self):
        original = build_election_request(
            "HOSTA",
            version=1,
            criteria=0x20010F03,
            election_uptime_ms=12345,
        )
        parsed = parse_election_request(original)
        assert parsed is not None
        assert parsed["version"] == 1
        assert parsed["criteria"] == 0x20010F03
        assert parsed["election_uptime_ms"] == 12345
        assert parsed["server_name"] == "HOSTA"

    def test_parse_rejects_wrong_opcode(self):
        pl = bytearray(build_election_request("HOSTA"))
        pl[0] = 0x01  # HostAnnouncement opcode
        assert parse_election_request(bytes(pl)) is None

    def test_parse_rejects_truncated_payload(self):
        assert parse_election_request(b"\x08") is None  # only opcode

    def test_server_name_truncated_to_fifteen_chars(self):
        pl = build_election_request("A" * 30)
        parsed = parse_election_request(pl)
        assert parsed["server_name"] == "A" * 15
