"""NetBIOS name query responder (RFC 1002 s4.2.13, s4.2.18).

Answers incoming name queries (NB) and node status requests (NBSTAT)
for names in our local name table.
"""
from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import Callable

from truenas_pynetbiosns.protocol.constants import NBFlag, Opcode, RRType
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from ..core.nametable import NameTable

logger = logging.getLogger(__name__)

SendFn = Callable[[NBNSMessage, tuple[str, int]], None]


class Responder:
    """Answers incoming name queries from the network."""

    def __init__(
        self, send_fn: SendFn, name_table: NameTable,
    ) -> None:
        self._send = send_fn
        self._table = name_table

    def handle_query(
        self,
        msg: NBNSMessage,
        source: tuple[str, int],
    ) -> None:
        """Process an incoming name query and send a response if we own the name."""
        if msg.opcode != Opcode.QUERY:
            return

        for q in msg.questions:
            if q.q_type == RRType.NB:
                self._handle_nb_query(msg.trn_id, q.name, source)
            elif q.q_type == RRType.NBSTAT:
                self._handle_nbstat_query(msg.trn_id, q.name, source)

    def _handle_nb_query(
        self,
        trn_id: int,
        name: 'NetBIOSName',
        source: tuple[str, int],
    ) -> None:
        """Build positive name query response (RFC 1002 s4.2.13)."""
        entry = self._table.lookup(name)
        if entry is None or not entry.registered:
            return

        ip = entry.addresses[0] if entry.addresses else IPv4Address("0.0.0.0")

        # Group names respond with broadcast address per RFC 1002
        if entry.is_group:
            ip = IPv4Address("255.255.255.255")

        response = NBNSMessage.build_positive_response(
            trn_id=trn_id,
            name=name.name,
            name_type=name.name_type,
            ip=ip,
            scope=name.scope,
            group=entry.is_group,
            ttl=entry.ttl,
        )
        self._send(response, source)
        logger.debug("Answered query for %s from %s", name, source[0])

    def _handle_nbstat_query(
        self,
        trn_id: int,
        name: 'NetBIOSName',
        source: tuple[str, int],
    ) -> None:
        """Respond with all registered names (node status)."""
        entries = self._table.all_registered()
        if not entries:
            return

        names: list[tuple[str, int, int]] = []
        for entry in entries:
            flags = entry.nb_flags.value | NBFlag.ACTIVE.value
            names.append((entry.name.name, entry.name.name_type, flags))

        response = NBNSMessage.build_node_status_response(
            trn_id=trn_id,
            query_name=name,
            names=names,
        )
        self._send(response, source)
        logger.debug(
            "Answered NBSTAT from %s with %d names",
            source[0], len(names),
        )
