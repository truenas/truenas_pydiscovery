"""Goodbye packet sending on shutdown."""
from __future__ import annotations

import logging

from truenas_pymdns.protocol.constants import GOODBYE_COUNT
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import MDNSRecord

logger = logging.getLogger(__name__)


def send_goodbye(send_fn, records: list[MDNSRecord]) -> None:
    """Send goodbye packets (TTL=0) for all registered records.

    Per RFC 6762 Section 10.1: on shutdown, multicast all records
    with TTL=0 so remote caches expire them immediately.

    Sent GOODBYE_COUNT times (matching Apple mDNSResponder) to
    guard against packet loss on lossy networks.
    """
    if not records:
        return

    msg = MDNSMessage.build_goodbye(records)
    for _ in range(GOODBYE_COUNT):
        send_fn(msg)
    logger.info("Sent goodbye for %d records (%dx)", len(records), GOODBYE_COUNT)
