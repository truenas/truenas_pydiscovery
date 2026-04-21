"""Periodic NetBIOS name refresh (RFC 1002 s4.2.4).

Re-sends registration packets for all registered names at a fixed
interval (default 15 minutes) to maintain presence on the network.
"""
from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Address
from typing import Callable

from truenas_pynetbiosns.protocol.constants import REFRESH_INTERVAL
from truenas_pynetbiosns.protocol.message import NBNSMessage
from .nametable import NameTable

logger = logging.getLogger(__name__)

SendFn = Callable[[NBNSMessage], None]


class Refresher:
    """Periodically refreshes all registered names."""

    def __init__(
        self,
        send_fn: SendFn,
        name_table: NameTable,
        ip: IPv4Address,
        interval: float = REFRESH_INTERVAL,
    ) -> None:
        self._send = send_fn
        self._table = name_table
        self._ip = ip
        self._interval = interval
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        """Start the periodic refresh loop."""
        self._task = asyncio.create_task(self._loop())

    def cancel(self) -> None:
        """Cancel the refresh loop."""
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        """Send periodic name refresh requests (RFC 1002 s4.2.4)."""
        while True:
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                return

            for entry in self._table.all_registered():
                msg = NBNSMessage.build_refresh(
                    entry.name.name,
                    entry.name.name_type,
                    self._ip,
                    scope=entry.name.scope,
                    group=entry.is_group,
                    ttl=entry.ttl,
                )
                self._send(msg)

            logger.debug(
                "Refreshed %d names",
                len(self._table.all_registered()),
            )
