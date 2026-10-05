"""NetBIOS name registration via broadcast.

Broadcasts one registration request, then resends it 3 times, each
transmission followed by a 1 s wait, as Samba nmbd times a broadcast
registration (see ``REGISTRATION_RETRY_COUNT``).  A negative response
carrying the request's NAME_TRN_ID ends the claim; if none has arrived
by the end of the last wait, the name is considered registered.
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
        self,
        send_fn: SendFn,
        name_table: NameTable,
        *,
        retry_interval: float = REGISTRATION_RETRY_INTERVAL,
    ) -> None:
        self._send = send_fn
        self._table = name_table
        self._retry_interval = retry_interval
        # NAME_TRN_ID of the request being broadcast for each name
        # whose claim is in progress.
        self._pending: dict[NetBIOSName, int] = {}
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

        Broadcasts one registration request and resends it
        REGISTRATION_RETRY_COUNT times, each transmission followed by a
        *retry_interval* wait, and stops early once a negative response
        has arrived.  Returns True if none arrived by the end of the
        last wait.
        """
        nb_name = NetBIOSName(name, name_type, scope)
        nb_flags = NBFlag.GROUP if group else NBFlag(0)

        # Add to local table first (pending)
        self._table.add(nb_name, ip, nb_flags, ttl)
        self._conflicts.discard(nb_name)

        # nmbd resends the one packet
        # (``retransmit_or_expire_response_records``), finds the request
        # a response belongs to by NAME_TRN_ID (``find_response_record``)
        # and takes the name only once the interval after the last
        # resend has passed, so a defender answering it is heard.
        # RFC 1002 §5.1.1.1 likewise repeats the broadcast "UNTIL
        # response packet is received or retransmit count has been
        # exceeded" and ignores a response unless "response tid =
        # request tid".
        msg = NBNSMessage.build_registration(
            name, name_type, ip,
            scope=scope, group=group, ttl=ttl,
        )
        self._pending[nb_name] = msg.trn_id
        try:
            transmissions = 1 + REGISTRATION_RETRY_COUNT
            for i in range(transmissions):
                self._send(msg)
                logger.debug(
                    "Registration %d/%d for %s",
                    i + 1, transmissions, nb_name,
                )
                await asyncio.sleep(self._retry_interval)
                if nb_name in self._conflicts:
                    break
        finally:
            self._pending.pop(nb_name, None)

        if nb_name in self._conflicts:
            logger.warning("Name conflict for %s", nb_name)
            self._table.remove(nb_name)
            return False

        # An unchallenged claim takes the name without further traffic,
        # as Samba nmbd does (``register_name_timeout_response`` in
        # source3/nmbd/nmbd_nameregister.c).  This departs from
        # RFC 1001 §15.2.1 ("A B node proclaims its new ownership by
        # broadcasting a NAME OVERWRITE DEMAND") and the matching NAME
        # UPDATE REQUEST broadcast in RFC 1002 §5.1.1.1.
        self._table.mark_registered(nb_name)
        logger.info("Registered %s -> %s", nb_name, ip)
        return True

    def on_conflict(self, name: NetBIOSName, trn_id: int) -> None:
        """Called when a negative response is received for *name*.

        Ignored unless *trn_id* is the NAME_TRN_ID of the registration
        request being broadcast for *name*."""
        if self._pending.get(name) == trn_id:
            self._conflicts.add(name)
