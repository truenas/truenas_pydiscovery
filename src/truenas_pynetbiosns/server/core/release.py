"""NetBIOS name release on shutdown.

Sends release packets (TTL=0) for all registered names so other
nodes know we are leaving the network.  Analogous to mDNS goodbye.
"""
from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import Callable

from truenas_pynetbiosns.protocol.message import NBNSMessage
from .nametable import NameTable

logger = logging.getLogger(__name__)

SendFn = Callable[[NBNSMessage], None]


def release_all_names(
    send_fn: SendFn,
    name_table: NameTable,
    ip: IPv4Address,
) -> None:
    """Send release packets for all registered names."""
    entries = name_table.all_registered()
    if not entries:
        return

    for entry in entries:
        msg = NBNSMessage.build_release(
            entry.name.name,
            entry.name.name_type,
            ip,
            scope=entry.name.scope,
            group=entry.is_group,
        )
        send_fn(msg)

    logger.info("Released %d names", len(entries))
