"""WS-Discovery message deduplication (SOAP-over-UDP 1.1 s3.4).

Tracks recently seen MessageIDs to prevent processing the same
Probe or Resolve multiple times (SOAP-over-UDP retransmission).
"""
from __future__ import annotations

import time
from collections import deque

from truenas_pywsd.protocol.constants import PROBE_TIMEOUT, WSD_MAX_KNOWN_MESSAGES


class MessageDedup:
    """Tracks recent message IDs for duplicate detection."""

    def __init__(
        self,
        max_entries: int = WSD_MAX_KNOWN_MESSAGES,
        ttl: float = PROBE_TIMEOUT * 2,
    ) -> None:
        self._entries: deque[tuple[str, float]] = deque(
            maxlen=max_entries,
        )
        self._ttl = ttl

    def is_duplicate(self, message_id: str) -> bool:
        """Return True if this message ID was seen recently."""
        now = time.monotonic()

        # Expire old entries
        while self._entries and now - self._entries[0][1] > self._ttl:
            self._entries.popleft()

        for mid, _ in self._entries:
            if mid == message_id:
                return True

        self._entries.append((message_id, now))
        return False

    def stats(self) -> dict:
        """Summary of dedup state, for SIGUSR1 status dumps."""
        return {
            "tracked_ids": len(self._entries),
            "max_capacity": self._entries.maxlen or 0,
            "ttl_seconds": self._ttl,
        }
