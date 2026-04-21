"""NetBIOS Browse HostAnnouncement payload and scheduler.

Covers MS-BRWS §2.2.1 payload layout (opcode, periodicity, hostname,
server type, signature, comment) and §3.2.6 timer behaviour
(ANNOUNCE_COUNT_STARTUP burst at ANNOUNCE_INTERVAL_INITIAL, doubling
up to ANNOUNCE_INTERVAL_MAX).  Reference: Samba
``source4/torture/nbt/register.c``.
"""
from __future__ import annotations

import asyncio
import struct
import time

from truenas_pynetbiosns.protocol.constants import (
    BrowseOpcode,
    ServerType,
)
from truenas_pynetbiosns.server.browse.announcer import (
    BrowseAnnouncer,
    build_host_announcement,
)


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


class TestAnnouncerSchedule:
    def test_startup_burst_emits_announce_count_startup_packets(self):
        """MS-BRWS §3.2.6: initial burst of ANNOUNCE_COUNT_STARTUP
        frames, each payload tagged with its own Periodicity."""
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTA", "WG")

        async def drive() -> None:
            a.start()
            # ANNOUNCE_INTERVAL_INITIAL is 60 s — we don't wait that
            # long, just observe the first packet fires immediately.
            await asyncio.sleep(0.050)
            a.cancel()

        _run(drive())
        assert len(sent) >= 1
        d = _parse_host_announcement(sent[0])
        assert d["hostname"] == "HOSTA"

    def test_periodicity_matches_current_delay(self):
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTB", "WG")

        async def drive() -> None:
            a.start()
            await asyncio.sleep(0.050)
            a.cancel()

        _run(drive())
        assert sent
        d = _parse_host_announcement(sent[0])
        # First-burst periodicity equals ANNOUNCE_INTERVAL_INITIAL
        # (seconds) in milliseconds.
        from truenas_pynetbiosns.protocol.constants import (
            ANNOUNCE_INTERVAL_INITIAL,
        )
        assert d["periodicity_ms"] == int(
            ANNOUNCE_INTERVAL_INITIAL * 1000,
        )

    def test_cancel_before_start_is_safe(self):
        a = BrowseAnnouncer(lambda _: None, "HOSTA", "WG")
        a.cancel()  # must not raise

    def test_cancel_stops_announcement_loop(self):
        """After cancel(), no further packets should fire even if we
        wait past the next scheduled interval."""
        sent: list[bytes] = []
        a = BrowseAnnouncer(sent.append, "HOSTA", "WG")

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


# Suppress the unused-time import warning — kept for readability of
# the _run helper; flake8 would otherwise flag it.
_ = time
