"""Drop the second copy of a datagram that reached two sockets.

A subnet broadcast is delivered both to the subnet's broadcast-address
socket (``NBNSTransport``) and to the daemon-wide ``0.0.0.0`` receiver
(``NBNSGlobalReceiver``), and both hand their copy to the same
dispatcher.  Samba nmbd opens the same pair of sockets
(``nmbd bind explicit broadcast = yes``) and drops the second copy in
``listen_for_packets`` with ``is_processed_packet``, which remembers
(source IP, packet type, transaction ID) for the packets read in one
poll() round (``source3/nmbd/nmbd_packets.c``).

An asyncio loop has no "one poll() round", so a packet is a duplicate
when the same key was seen less than ``DUPLICATE_PACKET_WINDOW`` ago.
The window is shorter than the 250 ms between retransmissions of a
request, which reuse its NAME_TRN_ID and are still answered.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Hashable

from truenas_pynetbiosns.protocol.constants import DUPLICATE_PACKET_WINDOW


class PacketDedup:
    """Remembers recently dispatched packet keys for a short window."""

    def __init__(self, window: float = DUPLICATE_PACKET_WINDOW) -> None:
        self._window = window
        # Insertion order is arrival order, so expiry pops from the front.
        self._seen: OrderedDict[Hashable, float] = OrderedDict()

    def is_duplicate(self, key: Hashable) -> bool:
        """Return True if *key* was seen within the window; else record it."""
        now = time.monotonic()
        while self._seen:
            oldest_key, seen_at = next(iter(self._seen.items()))
            if now - seen_at < self._window:
                break
            del self._seen[oldest_key]
        if key in self._seen:
            return True
        self._seen[key] = now
        return False
