"""NetBIOS name release for names given up while running.

Sends release packets (TTL=0) for the names a reload drops, as Samba
nmbd releases a name it gives up while running
(``unbecome_local_master_browser`` calling ``release_name``).  Nothing
is released at shutdown: nmbd's ``terminate`` releases only names
registered with a WINS server (``release_wins_names``).
"""
from __future__ import annotations

import logging
from ipaddress import IPv4Address
from typing import Callable

from truenas_pynetbiosns.protocol.constants import NameType
from truenas_pynetbiosns.protocol.message import NBNSMessage
from .nametable import NameTable

logger = logging.getLogger(__name__)

SendFn = Callable[[NBNSMessage], None]

# (name, name_type, is_group) — identity of one NBNS registration.
NameRecord = tuple[str, NameType, bool]


def release_names(
    send_fn: SendFn,
    name_table: NameTable,
    ip: IPv4Address,
    names: set[NameRecord],
) -> None:
    """Send release packets for a specific subset of registrations.

    *names* is a set of ``(name, name_type, is_group)`` tuples.  Each
    currently-registered entry in *name_table* whose identity matches
    a tuple in *names* is released (TTL=0 broadcast) and removed
    from the table so the responder stops answering for it.  Tuples
    not in the table are silently skipped.

    Used by the SIGHUP live-update path to surrender only the names
    that actually went away (e.g. when the primary NetBIOS name
    changes or an alias is removed) without disturbing the names
    we're still keeping."""
    if not names:
        return

    entries = name_table.all_registered()
    released = 0
    for entry in entries:
        key = (entry.name.name, entry.name.name_type, entry.is_group)
        if key not in names:
            continue
        msg = NBNSMessage.build_release(
            entry.name.name,
            entry.name.name_type,
            ip,
            scope=entry.name.scope,
            group=entry.is_group,
        )
        send_fn(msg)
        name_table.remove(entry.name)
        released += 1

    if released:
        logger.info(
            "Released %d of %d requested names", released, len(names),
        )
