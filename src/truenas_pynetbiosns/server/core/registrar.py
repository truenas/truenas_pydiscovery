"""NetBIOS name registration via broadcast.

Sends registration requests (3 retries at 250ms intervals per RFC 1002).
If no negative response is received, the name is considered registered.
"""
from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Address
from typing import Callable

from truenas_pynetbiosns.protocol.constants import (
    NBFlag,
    REGISTRATION_RETRY_COUNT,
    REGISTRATION_RETRY_INTERVAL,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from .nametable import NameTable

logger = logging.getLogger(__name__)

SendFn = Callable[[NBNSMessage], None]


class Registrar:
    """Registers NetBIOS names on the network via broadcast."""

    def __init__(
        self, send_fn: SendFn, name_table: NameTable,
    ) -> None:
        self._send = send_fn
        self._table = name_table
        self._conflicts: set[NetBIOSName] = set()

    async def register(
        self,
        name: str,
        name_type: int,
        ip: IPv4Address,
        *,
        scope: str = "",
        group: bool = False,
        ttl: int = 0,
    ) -> bool:
        """Register a name via broadcast.

        Sends REGISTRATION_RETRY_COUNT broadcast registration packets
        at REGISTRATION_RETRY_INTERVAL apart.  Returns True if no
        conflict was detected.
        """
        nb_name = NetBIOSName(name, name_type, scope)
        nb_flags = NBFlag.GROUP if group else NBFlag(0)

        # Add to local table first (pending)
        self._table.add(nb_name, ip, nb_flags, ttl)
        self._conflicts.discard(nb_name)

        for i in range(REGISTRATION_RETRY_COUNT):
            msg = NBNSMessage.build_registration(
                name, name_type, ip,
                scope=scope, group=group, ttl=ttl,
            )
            self._send(msg)
            logger.debug(
                "Registration %d/%d for %s",
                i + 1, REGISTRATION_RETRY_COUNT, nb_name,
            )
            if i < REGISTRATION_RETRY_COUNT - 1:
                await asyncio.sleep(REGISTRATION_RETRY_INTERVAL)

        if nb_name in self._conflicts:
            logger.warning("Name conflict for %s", nb_name)
            self._table.remove(nb_name)
            return False

        self._table.mark_registered(nb_name)
        logger.info("Registered %s -> %s", nb_name, ip)
        return True

    def on_conflict(self, name: NetBIOSName) -> None:
        """Called when a negative response is received for a registration."""
        self._conflicts.add(name)
