"""NetBIOS name defense (RFC 1002 s5.1.1.5).

When another node attempts to register or refresh a name we own,
respond with RCODE_ACT (active error) to defend our registration.
This mirrors Samba's nbt_register_own / nbt_refresh_own behavior
tested in source4/torture/nbt/register.c.
"""
from __future__ import annotations

import logging
from typing import Callable

from truenas_pynetbiosns.protocol.constants import Opcode, Rcode
from truenas_pynetbiosns.protocol.message import NBNSMessage
from .nametable import NameTable

logger = logging.getLogger(__name__)

SendFn = Callable[[NBNSMessage, tuple[str, int]], None]


class Defender:
    """Defends locally registered names against registration by others."""

    def __init__(
        self, send_fn: SendFn, name_table: NameTable,
    ) -> None:
        self._send = send_fn
        self._table = name_table

    def handle_registration(
        self,
        msg: NBNSMessage,
        source: tuple[str, int],
    ) -> bool:
        """Check if an incoming registration conflicts with our names.

        Sends a negative response (RFC 1002 s4.2.6) with ACT_ERR if
        a conflict is found.  Returns True if defended, False otherwise.
        """
        if msg.opcode not in (
            Opcode.REGISTRATION, Opcode.REFRESH, Opcode.MULTIHOMED_REG,
        ):
            return False

        for q in msg.questions:
            entry = self._table.lookup(q.name)
            if entry is None or not entry.registered:
                continue
            if entry.is_group:
                # Group names don't conflict
                continue

            # Our unique name is being challenged — defend it
            logger.info(
                "Defending %s against %s", q.name, source[0],
            )
            response = NBNSMessage.build_negative_response(
                trn_id=msg.trn_id,
                name=q.name.name,
                name_type=q.name.name_type,
                rcode=Rcode.ACT_ERR,
                scope=q.name.scope,
            )
            self._send(response, source)
            return True

        return False
