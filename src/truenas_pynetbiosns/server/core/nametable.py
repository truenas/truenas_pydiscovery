"""Local NetBIOS name table.

Stores all names this node has registered on the network.
Each entry maps a (name, type) pair to IP addresses, flags,
and registration state.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import NBFlag
from truenas_pynetbiosns.protocol.name import NetBIOSName

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class NameEntry:
    """A single registered name with its addresses and flags."""
    name: NetBIOSName
    addresses: list[IPv4Address] = field(default_factory=list)
    nb_flags: NBFlag = NBFlag(0)
    ttl: int = 0
    registered: bool = False

    @property
    def is_group(self) -> bool:
        return bool(self.nb_flags & NBFlag.GROUP)


class NameTable:
    """Registry of locally-owned NetBIOS names."""

    def __init__(self) -> None:
        self._entries: dict[NetBIOSName, NameEntry] = {}

    def add(
        self,
        name: NetBIOSName,
        ip: IPv4Address,
        nb_flags: NBFlag = NBFlag(0),
        ttl: int = 0,
    ) -> NameEntry:
        """Add or update a name entry."""
        if name in self._entries:
            entry = self._entries[name]
            if ip not in entry.addresses:
                entry.addresses.append(ip)
            return entry

        entry = NameEntry(
            name=name,
            addresses=[ip],
            nb_flags=nb_flags,
            ttl=ttl,
        )
        self._entries[name] = entry
        return entry

    def remove(self, name: NetBIOSName) -> NameEntry | None:
        """Remove a name entry.  Returns the removed entry or None."""
        return self._entries.pop(name, None)

    def lookup(self, name: NetBIOSName) -> NameEntry | None:
        """Find a name entry (case-insensitive via NetBIOSName.__eq__)."""
        return self._entries.get(name)

    def mark_registered(self, name: NetBIOSName) -> None:
        """Transition a name from pending to registered state."""
        entry = self._entries.get(name)
        if entry is not None:
            entry.registered = True

    def all_entries(self) -> list[NameEntry]:
        """Return all entries."""
        return list(self._entries.values())

    def all_registered(self) -> list[NameEntry]:
        """Return only successfully registered entries."""
        return [e for e in self._entries.values() if e.registered]

    def stats(self) -> dict:
        """Summary of table contents, for SIGUSR1 status dumps."""
        registered = 0
        unique = 0
        group = 0
        by_type: dict[str, int] = {}
        for entry in self._entries.values():
            if entry.registered:
                registered += 1
            if entry.is_group:
                group += 1
            else:
                unique += 1
            hex_type = f"0x{entry.name.name_type:02x}"
            by_type[hex_type] = by_type.get(hex_type, 0) + 1
        return {
            "total": len(self._entries),
            "registered": registered,
            "pending": len(self._entries) - registered,
            "unique": unique,
            "group": group,
            "by_type": by_type,
        }

    def __len__(self) -> int:
        return len(self._entries)
