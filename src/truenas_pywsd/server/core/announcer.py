"""WSD Hello and Bye announcements with SOAP-over-UDP retransmission.

Hello is sent on startup (multicast, repeated 4x with jitter).
Bye is sent on shutdown (same pattern).

References:
    SOAP-over-UDP 1.1 s3.4 — retransmission algorithm
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import Callable

from truenas_pywsd.protocol.constants import (
    MULTICAST_UDP_REPEAT,
    UDP_MAX_DELAY,
    UDP_MIN_DELAY,
    UDP_UPPER_DELAY,
)
from truenas_pywsd.protocol.messages import build_bye, build_hello

logger = logging.getLogger(__name__)

SendFn = Callable[[bytes], None]


async def send_hello(
    send_fn: SendFn,
    endpoint_uuid: str,
    xaddrs: str,
    app_sequence: int = 0,
    message_number: int = 1,
    metadata_version: int = 1,
) -> None:
    """Send Hello announcement with retransmission.

    *metadata_version* goes into the ``<wsd:MetadataVersion>`` element;
    WSD 1.1 §4.1 requires clients to re-acquire metadata when the
    value they see is greater than what they have cached."""
    data = build_hello(
        endpoint_uuid, xaddrs,
        metadata_version=metadata_version,
        app_sequence=app_sequence, message_number=message_number,
    )
    await _retransmit_multicast(send_fn, data, "Hello")


async def send_bye(
    send_fn: SendFn,
    endpoint_uuid: str,
    app_sequence: int = 0,
    message_number: int = 1,
) -> None:
    """Send Bye announcement with retransmission."""
    data = build_bye(
        endpoint_uuid,
        app_sequence=app_sequence, message_number=message_number,
    )
    await _retransmit_multicast(send_fn, data, "Bye")


async def _retransmit_multicast(
    send_fn: SendFn, data: bytes, label: str,
) -> None:
    """Send data multiple times with exponential backoff jitter (SOAP-over-UDP 1.1 s3.4)."""
    delay = random.uniform(UDP_MIN_DELAY, UDP_MAX_DELAY)
    for i in range(MULTICAST_UDP_REPEAT):
        send_fn(data)
        logger.debug("%s sent (%d/%d)", label, i + 1, MULTICAST_UDP_REPEAT)
        if i < MULTICAST_UDP_REPEAT - 1:
            await asyncio.sleep(delay)
            delay = min(delay * 2, UDP_UPPER_DELAY)
