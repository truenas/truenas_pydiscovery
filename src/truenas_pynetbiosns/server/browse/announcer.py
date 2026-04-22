"""Browser announcements via NetBIOS datagram service (port 138).

Builders and periodic sender for the MS-BRWS mailslot payloads:

* ``HostAnnouncement``        (§2.2.1, opcode 0x01)
* ``DomainAnnouncement``      (§2.2.3, opcode 0x0C)
* ``LocalMasterAnnouncement`` (§2.2.6, opcode 0x0F)
* ``ElectionRequest``         (§2.2.19, opcode 0x08)

The ``BrowseAnnouncer`` class drives the HostAnnouncement cadence.
Higher-level browser-election state is not implemented — TrueNAS
leaves master-browser duties to Samba — but the payload builders
are available for integrations that want them.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import Callable

from truenas_pynetbiosns.protocol.constants import (
    ANNOUNCE_COUNT_STARTUP,
    ANNOUNCE_INTERVAL_INITIAL,
    ANNOUNCE_INTERVAL_MAX,
    BROWSE_ANNOUNCE_PERIODICITY_DEFAULT_MS,
    BROWSE_COMMENT_MAX,
    BROWSE_ELECTION_CRITERIA_DEFAULT,
    BROWSE_OS_MAJOR,
    BROWSE_OS_MINOR,
    BROWSE_SIGNATURE,
    BROWSER_VERSION_MAJOR,
    BROWSER_VERSION_MINOR,
    BrowseOpcode,
    NETBIOS_NAME_LENGTH,
    ServerType,
)

logger = logging.getLogger(__name__)

SendFn = Callable[[bytes], None]


def _build_announcement(
    opcode: BrowseOpcode,
    hostname: str,
    server_type: ServerType,
    os_major: int,
    os_minor: int,
    periodicity_ms: int,
    comment: str,
) -> bytes:
    """Common payload builder for HostAnnouncement, DomainAnnouncement
    and LocalMasterAnnouncement — identical layout (MS-BRWS §2.2.1,
    §2.2.3, §2.2.6), only the opcode changes."""
    buf = bytearray()
    buf.append(opcode)
    buf.append(0)  # update count
    buf.extend(struct.pack("<I", periodicity_ms))
    name_bytes = hostname.encode("ascii")[:NETBIOS_NAME_LENGTH].ljust(
        NETBIOS_NAME_LENGTH + 1, b"\x00",
    )
    buf.extend(name_bytes)
    buf.append(os_major)
    buf.append(os_minor)
    buf.extend(struct.pack("<I", server_type.value))
    buf.extend(struct.pack(
        "BB", BROWSER_VERSION_MAJOR, BROWSER_VERSION_MINOR,
    ))
    buf.extend(struct.pack("<H", BROWSE_SIGNATURE))
    buf.extend(comment.encode("ascii")[:BROWSE_COMMENT_MAX] + b"\x00")
    return bytes(buf)


def build_domain_announcement(
    hostname: str,
    workgroup: str,
    master_browser_name: str,
    *,
    server_type: ServerType = ServerType.WORKSTATION | ServerType.SERVER
    | ServerType.DOMAIN_ENUM | ServerType.MASTER_BROWSER,
    os_major: int = BROWSE_OS_MAJOR,
    os_minor: int = BROWSE_OS_MINOR,
    announce_interval_ms: int = BROWSE_ANNOUNCE_PERIODICITY_DEFAULT_MS,
) -> bytes:
    """Build a DomainAnnouncement browse payload (MS-BRWS §2.2.3).

    The ``hostname`` field carries the DOMAIN name (not the host)
    and the comment carries the master-browser name.  Emitted by
    the domain master browser to the ``\\MAILSLOT\\BROWSE`` mailslot
    addressed to the ``<01>\x01\\__MSBROWSE__\\x01<02>`` group.
    """
    return _build_announcement(
        BrowseOpcode.DOMAIN_ANNOUNCEMENT,
        workgroup,  # DomainAnnouncement uses workgroup in hostname field
        server_type,
        os_major, os_minor,
        announce_interval_ms,
        master_browser_name,
    )


def build_local_master_announcement(
    hostname: str,
    *,
    server_type: ServerType = ServerType.WORKSTATION | ServerType.SERVER
    | ServerType.MASTER_BROWSER | ServerType.POTENTIAL_BROWSER,
    os_major: int = BROWSE_OS_MAJOR,
    os_minor: int = BROWSE_OS_MINOR,
    announce_interval_ms: int = BROWSE_ANNOUNCE_PERIODICITY_DEFAULT_MS,
    server_string: str = "",
) -> bytes:
    """Build a LocalMasterAnnouncement browse payload (MS-BRWS §2.2.6).

    Emitted periodically by the local master browser to the
    ``WORKGROUP<1D>`` unique name via the ``\\MAILSLOT\\BROWSE``
    mailslot so potential browsers learn who the current LMB is.
    """
    return _build_announcement(
        BrowseOpcode.LOCAL_MASTER_ANNOUNCEMENT,
        hostname,
        server_type,
        os_major, os_minor,
        announce_interval_ms,
        server_string,
    )


def build_election_request(
    server_name: str,
    *,
    version: int = 1,
    criteria: int = BROWSE_ELECTION_CRITERIA_DEFAULT,
    election_uptime_ms: int = 0,
) -> bytes:
    """Build an ElectionRequest browse payload (MS-BRWS §2.2.19).

    Used to kick off a browser election.  The bitfield in
    ``criteria`` (MS-BRWS §2.2.19 "Criteria") combines OS type,
    revision and role bits — higher value wins.  The default value
    (``BROWSE_ELECTION_CRITERIA_DEFAULT``) is Windows-Server-revision
    + NT-Server + Potential-Browser — a moderate, non-aggressive
    claim.
    """
    buf = bytearray()
    buf.append(BrowseOpcode.ELECTION_REQUEST)
    buf.append(version & 0xFF)
    buf.extend(struct.pack("<I", criteria & 0xFFFFFFFF))
    buf.extend(struct.pack("<I", election_uptime_ms & 0xFFFFFFFF))
    buf.extend(struct.pack("<I", 0))  # reserved
    buf.extend(
        server_name.encode("ascii")[:NETBIOS_NAME_LENGTH].ljust(
            NETBIOS_NAME_LENGTH + 1, b"\x00",
        ),
    )
    return bytes(buf)


def parse_election_request(payload: bytes) -> dict | None:
    """Parse an ElectionRequest payload; return ``None`` if malformed."""
    if len(payload) < 1 + 1 + 4 + 4 + 4 + 1:
        return None
    if payload[0] != BrowseOpcode.ELECTION_REQUEST:
        return None
    version = payload[1]
    criteria, = struct.unpack("<I", payload[2:6])
    uptime_ms, = struct.unpack("<I", payload[6:10])
    # 4 reserved bytes at 10..14.
    name_bytes = payload[14:].split(b"\x00", 1)[0]
    server_name = name_bytes.decode("ascii", errors="replace")
    return {
        "version": version,
        "criteria": criteria,
        "election_uptime_ms": uptime_ms,
        "server_name": server_name,
    }


def build_host_announcement(
    hostname: str,
    workgroup: str,
    server_string: str = "",
    server_type: ServerType = ServerType.WORKSTATION | ServerType.SERVER,
    os_major: int = BROWSE_OS_MAJOR,
    os_minor: int = BROWSE_OS_MINOR,
    announce_interval_ms: int = BROWSE_ANNOUNCE_PERIODICITY_DEFAULT_MS,
) -> bytes:
    """Build a HostAnnouncement browse payload (MS-BRWS §2.2.1).

    *announce_interval_ms* is the Periodicity field in milliseconds.
    The payload goes inside a ``\\MAILSLOT\\BROWSE`` datagram; all
    three announcement flavours (Host / Domain / LocalMaster) share
    the same layout and are built via ``_build_announcement``.
    """
    return _build_announcement(
        BrowseOpcode.HOST_ANNOUNCEMENT,
        hostname,
        server_type,
        os_major, os_minor,
        announce_interval_ms,
        server_string,
    )


class BrowseAnnouncer:
    """Sends periodic host announcements on port 138."""

    def __init__(
        self,
        send_fn: SendFn,
        hostname: str,
        workgroup: str,
        server_string: str = "",
    ) -> None:
        self._send = send_fn
        self._hostname = hostname
        self._workgroup = workgroup
        self._server_string = server_string
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        """Start the announcement loop."""
        self._task = asyncio.create_task(self._loop())

    def cancel(self) -> None:
        """Cancel the announcement loop."""
        if self._task is not None:
            self._task.cancel()
            self._task = None

    def set_hostname(self, hostname: str) -> None:
        """Update the advertised hostname for future announcements.

        The next ``_send_announcement`` iteration picks up the new
        value; the ongoing sleep backoff is not disturbed.  Used by
        the SIGHUP live-update path so a NetBIOS name change doesn't
        need the whole announcer cancelled + recreated."""
        self._hostname = hostname

    def set_workgroup(self, workgroup: str) -> None:
        """Update the advertised workgroup for future announcements.

        See ``set_hostname`` — same cadence preservation semantics."""
        self._workgroup = workgroup

    def set_server_string(self, server_string: str) -> None:
        """Update the advertised server comment for future announcements.

        See ``set_hostname`` — same cadence preservation semantics."""
        self._server_string = server_string

    async def _loop(self) -> None:
        """Startup burst then exponential backoff (MS-BRWS s3.2.6)."""
        server_type = ServerType.WORKSTATION | ServerType.SERVER

        delay = ANNOUNCE_INTERVAL_INITIAL

        # Initial burst
        for _ in range(ANNOUNCE_COUNT_STARTUP):
            self._send_announcement(server_type, int(delay))
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return
            delay = min(delay * 2, ANNOUNCE_INTERVAL_MAX)

        # Steady state
        while True:
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return
            self._send_announcement(server_type, int(delay))
            delay = min(delay * 2, ANNOUNCE_INTERVAL_MAX)

    def _send_announcement(
        self, server_type: ServerType, interval_s: int,
    ) -> None:
        """Send a HostAnnouncement via \\MAILSLOT\\BROWSE (MS-BRWS s3.2.5.2)."""
        payload = build_host_announcement(
            hostname=self._hostname,
            workgroup=self._workgroup,
            server_string=self._server_string,
            server_type=server_type,
            announce_interval_ms=interval_s * 1000,
        )
        self._send(payload)
        logger.debug("Host announcement sent for %s", self._hostname)
