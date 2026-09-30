"""NetBIOS name registration via broadcast.

Broadcasts one registration request up to 3 times, each followed by a
250ms wait (RFC 1002 §5.1.1.1: BCAST_REQ_RETRY_COUNT,
BCAST_REQ_RETRY_TIMEOUT).  A negative response carrying the request's
NAME_TRN_ID ends the claim; if none has arrived by the end of the last
wait, the name is considered registered.
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

        Broadcasts one registration request up to
        REGISTRATION_RETRY_COUNT times, each followed by a
        REGISTRATION_RETRY_INTERVAL wait, and stops early once a
        negative response has arrived.  Returns True if none arrived
        by the end of the last wait.
        """
        nb_name = NetBIOSName(name, name_type, scope)
        nb_flags = NBFlag.GROUP if group else NBFlag(0)

        # Add to local table first (pending)
        self._table.add(nb_name, ip, nb_flags, ttl)
        self._conflicts.discard(nb_name)

        # RFC 1002 §5.1.1.1 repeats the broadcast, each one followed by
        # pause(BCAST_REQ_RETRY_TIMEOUT), "UNTIL response packet is
        # received or retransmit count has been exceeded", and ignores
        # a response unless "response tid = request tid".  The pause
        # after the last request lets a defender answering it be
        # heard.  nmbd likewise resends the one packet
        # (``retransmit_or_expire_response_records``) and finds the
        # request a response belongs to by NAME_TRN_ID
        # (``find_response_record``).
        msg = NBNSMessage.build_registration(
            name, name_type, ip,
            scope=scope, group=group, ttl=ttl,
        )
        self._pending[nb_name] = msg.trn_id
        try:
            for i in range(REGISTRATION_RETRY_COUNT):
                self._send(msg)
                logger.debug(
                    "Registration %d/%d for %s",
                    i + 1, REGISTRATION_RETRY_COUNT, nb_name,
                )
                await asyncio.sleep(REGISTRATION_RETRY_INTERVAL)
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
