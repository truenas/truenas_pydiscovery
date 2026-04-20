"""Authoritative record store for records owned by this server."""
from __future__ import annotations

import logging

from truenas_pymdns.protocol.constants import QType
from ..core.entry_group import EntryGroup, OwnedRecord

logger = logging.getLogger(__name__)

_META_QUERY_NAME = "_services._dns-sd._udp.local"


class ServiceRegistry:
    """Stores all records this server is authoritative for.

    Distinct from the cache (which stores records learned from the network).
    Lookup returns OwnedRecord wrappers so the Responder can read/write
    per-record scheduling state (last_multicast, last_peer_answer) in
    place, instead of keeping a side dict that would need pruning.
    """

    def __init__(self) -> None:
        self._groups: list[EntryGroup] = []

    def add_group(self, group: EntryGroup) -> None:
        """Register an entry group so its records become authoritative."""
        self._groups.append(group)

    def remove_group(self, group: EntryGroup) -> None:
        """Unregister an entry group; no-op if not present."""
        try:
            self._groups.remove(group)
        except ValueError:
            pass

    def lookup(
        self,
        name: str,
        qtype: QType,
        interface_index: int | None = None,
    ) -> list[OwnedRecord]:
        """Find records matching name and type.

        Handles ANY type and the _services._dns-sd._udp.local meta-query.
        Filters by interface if the entry group is interface-bound.
        """
        name_lower = name.lower()
        results: list[OwnedRecord] = []

        for group in self._groups:
            if interface_index is not None and group.interfaces is not None:
                if interface_index not in group.interfaces:
                    continue

            for ow in group.owned_records:
                if ow.record.key.name != name_lower:
                    continue
                if qtype == QType.ANY or ow.record.key.rtype == qtype:
                    results.append(ow)

        return results

    def get_all_records(
        self, interface_index: int | None = None
    ) -> list[OwnedRecord]:
        """Return all registered records, optionally filtered by interface."""
        results: list[OwnedRecord] = []
        for group in self._groups:
            if interface_index is not None and group.interfaces is not None:
                if interface_index not in group.interfaces:
                    continue
            results.extend(group.owned_records)
        return results

    def has_name(self, name: str) -> bool:
        """Return True if any registered record matches the given name."""
        name_lower = name.lower()
        for group in self._groups:
            for ow in group.owned_records:
                if ow.record.key.name == name_lower:
                    return True
        return False

    @property
    def groups(self) -> list[EntryGroup]:
        """Return a copy of the registered entry groups."""
        return list(self._groups)
