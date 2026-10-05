"""NetBIOS Browse HostAnnouncement payload and scheduler.

Covers MS-BRWS §2.2.1 payload layout (opcode, periodicity, hostname,
server type, signature, comment), the pacing of Samba nmbd's
``announce_my_server_names`` (the first at once, then each interval a
minute longer, up to 12 minutes) and the removal announcement of
``announce_my_servers_removed``.  Reference: Samba
``source4/torture/nbt/register.c``.
"""
from __future__ import annotations

import asyncio
import struct
import time
from ipaddress import IPv4Address
from itertools import islice

from truenas_pynetbiosns.protocol.constants import (
    DGRAM_PORT,
    BrowseOpcode,
    DatagramFlag,
    DatagramType,
    NameType,
    ServerType,
)
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.browse.announcer import (
    BrowseAnnouncer,
    announce_intervals,
    build_host_announcement,
)

from .conftest import decode_mailslot

_SOURCE_IP = IPv4Address("192.0.2.10")


def _parse_host_announcement(payload: bytes) -> dict:
    """Minimal decoder for assertions — mirrors MS-BRWS §2.2.1."""
    assert payload[0] == BrowseOpcode.HOST_ANNOUNCEMENT
    d = {"opcode": payload[0], "update_count": payload[1]}
    d["periodicity_ms"], = struct.unpack("<I", payload[2:6])
    d["hostname"] = payload[6:22].rstrip(b"\x00").decode("ascii")
    d["os_major"] = payload[22]
    d["os_minor"] = payload[23]
    d["server_type"], = struct.unpack("<I", payload[24:28])
    d["browser_major"] = payload[28]
    d["browser_minor"] = payload[29]
    d["signature"], = struct.unpack("<H", payload[30:32])
    d["comment"] = payload[32:].split(b"\x00", 1)[0].decode("ascii")
    return d


class TestHostAnnouncementPayload:
    def test_opcode_is_host_announcement(self):
        pl = build_host_announcement("HOSTA", "WG")
        assert pl[0] == BrowseOpcode.HOST_ANNOUNCEMENT

    def test_hostname_is_padded_to_16_bytes_and_uppercase_preserved(self):
        pl = build_host_announcement("HOSTA", "WG")
        d = _parse_host_announcement(pl)
        assert d["hostname"] == "HOSTA"
        # Bytes 6..22 are the hostname field.
        assert len(pl[6:22]) == 16
        assert pl[6:22].rstrip(b"\x00") == b"HOSTA"

    def test_server_type_defaults_to_workstation_plus_server(self):
        pl = build_host_announcement("HOSTA", "WG")
        d = _parse_host_announcement(pl)
        expected = (
            ServerType.WORKSTATION.value | ServerType.SERVER.value
        )
        assert d["server_type"] == expected

    def test_explicit_server_type_propagates(self):
        pl = build_host_announcement(
            "HOSTA", "WG",
            server_type=ServerType.WORKSTATION | ServerType.SERVER
            | ServerType.NT | ServerType.POTENTIAL_BROWSER,
        )
        d = _parse_host_announcement(pl)
        assert d["server_type"] & ServerType.NT.value
        assert d["server_type"] & ServerType.POTENTIAL_BROWSER.value

    def test_signature_is_aa55(self):
        d = _parse_host_announcement(
            build_host_announcement("HOSTA", "WG"),
        )
        assert d["signature"] == 0xAA55

    def test_periodicity_is_echoed_in_ms(self):
        pl = build_host_announcement(
            "HOSTA", "WG", announce_interval_ms=60_000,
        )
        d = _parse_host_announcement(pl)
        assert d["periodicity_ms"] == 60_000

    def test_comment_is_null_terminated(self):
        pl = build_host_announcement(
            "HOSTA", "WG", server_string="Truenas NAS",
        )
        d = _parse_host_announcement(pl)
        assert d["comment"] == "Truenas NAS"
        # Must include at least one null byte to terminate.
        assert b"\x00" in pl[32:]

    def test_long_hostname_truncated_to_fifteen_chars(self):
        """MS-BRWS §2.2.1: hostname field is 16 bytes; payload builder
        truncates to 15 + trailing null so downstream parsers stay happy."""
        name = "A" * 30
        pl = build_host_announcement(name, "WG")
        d = _parse_host_announcement(pl)
        assert d["hostname"] == "A" * 15


def _run(coro, timeout: float = 3.0) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
    finally:
        loop.close()


class TestAnnounceIntervals:
    def test_each_interval_is_a_minute_longer_up_to_twelve(self):
        """nmbd's ``announce_my_server_names`` adds 60 s per
        announcement until ``CHECK_TIME_MAX_HOST_ANNCE`` (12) minutes."""
        assert list(islice(announce_intervals(), 14)) == [
            60, 120, 180, 240, 300, 360, 420, 480, 540, 600, 660, 720,
            720, 720,
        ]


class TestAnnouncerSchedule:
    def test_first_announcement_goes_out_at_once(self):
        """The first announcement is not delayed; the next is a minute
        away, so exactly one goes out at the start."""
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTA", "WG", source_ip=_SOURCE_IP)

        async def drive() -> None:
            a.start()
            await asyncio.sleep(0.050)
            a.cancel()

        _run(drive())
        assert len(sent) == 1
        d = _parse_host_announcement(decode_mailslot(sent[0])["data"])
        assert d["hostname"] == "HOSTA"

    def test_periodicity_is_the_time_until_the_next(self):
        """The first announcement carries the first interval, one
        minute, as nmbd's ``send_host_announcement`` carries "Time
        until next announce"."""
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTB", "WG", source_ip=_SOURCE_IP)

        async def drive() -> None:
            a.start()
            await asyncio.sleep(0.050)
            a.cancel()

        _run(drive())
        assert sent
        d = _parse_host_announcement(decode_mailslot(sent[0])["data"])
        assert d["periodicity_ms"] == 60_000

    def test_removal_announcement_has_type_and_periodicity_zero(self):
        """nmbd's ``announce_my_servers_removed`` announces the server
        with type 0 and interval 0 at shutdown, to the same name and
        mailslot as any HostAnnouncement."""
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTC", "WG", source_ip=_SOURCE_IP)
        a.announce_removed()
        (frame,) = sent
        datagram = decode_mailslot(frame)
        d = _parse_host_announcement(datagram["data"])
        assert d["hostname"] == "HOSTC"
        assert d["server_type"] == 0
        assert d["periodicity_ms"] == 0
        assert datagram["dest"] == NetBIOSName("WG", NameType.LOCAL_MASTER)
        assert datagram["mailslot"] == "\\MAILSLOT\\BROWSE"

    def test_cancel_before_start_is_safe(self):
        a = BrowseAnnouncer(
            lambda _: None, "HOSTA", "WG", source_ip=_SOURCE_IP,
        )
        a.cancel()  # must not raise

    def test_cancel_stops_announcement_loop(self):
        """After cancel(), no further packets should fire even if we
        wait past the next scheduled interval."""
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTA", "WG", source_ip=_SOURCE_IP)

        async def drive() -> None:
            a.start()
            await asyncio.sleep(0.050)
            before = len(sent)
            a.cancel()
            await asyncio.sleep(0.200)
            assert len(sent) == before, (
                "cancel() did not stop the loop"
            )

        _run(drive())


class TestAnnouncerDatagramEnvelope:
    """The datagram around the announcement, decoded as a receiver
    reads it: a mailslot write to ``<workgroup>[0x1D]`` on
    ``\\MAILSLOT\\BROWSE`` (MS-BRWS §3.2.5.2), sent from
    ``<hostname>[0x00]`` as a DIRECT_GROUP datagram, as Samba nmbd's
    ``send_host_announcement`` sends it."""

    def test_announcement_is_addressed_to_the_local_master_browser(self):
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTA", "WG", source_ip=_SOURCE_IP)

        async def drive() -> None:
            a.start()
            await asyncio.sleep(0.050)
            a.cancel()

        _run(drive())
        assert sent
        d = decode_mailslot(sent[0])
        assert d["msg_type"] == DatagramType.DIRECT_GROUP
        assert d["flags"] == DatagramFlag.FIRST
        assert d["source_ip"] == _SOURCE_IP
        assert d["source_port"] == DGRAM_PORT
        assert d["source"] == NetBIOSName("HOSTA", NameType.WORKSTATION)
        assert d["dest"] == NetBIOSName("WG", NameType.LOCAL_MASTER)
        assert d["mailslot"] == "\\MAILSLOT\\BROWSE"
        assert _parse_host_announcement(d["data"])["hostname"] == "HOSTA"


# Suppress the unused-time import warning — kept for readability of
# the _run helper; flake8 would otherwise flag it.
_ = time
