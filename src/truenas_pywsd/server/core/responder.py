"""WSD Probe and Resolve responder (WS-Discovery 1.1 s5/s6).

Handles incoming Probe and Resolve messages, responds with
ProbeMatch and ResolveMatch respectively.  Includes random
delay before responding to avoid UDP collision.
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import Callable

from truenas_pywsd.protocol.constants import (
    Action,
    DeviceType,
    UNICAST_UDP_REPEAT,
    UDP_MAX_DELAY,
    UDP_MIN_DELAY,
    UDP_UPPER_DELAY,
    urn_uuid,
)
from truenas_pywsd.protocol.messages import (
    build_probe_match,
    build_resolve_match,
    parse_probe_scopes,
    parse_probe_types,
    parse_resolve_endpoint,
    scope_matches,
)
from truenas_pywsd.protocol.soap import SOAPEnvelope
from .dedup import MessageDedup

logger = logging.getLogger(__name__)

SendUnicastFn = Callable[[bytes, tuple], None]


class WSDResponder:
    """Responds to WSD Probe and Resolve messages."""

    def __init__(
        self,
        send_unicast_fn: SendUnicastFn,
        endpoint_uuid: str,
        xaddrs: str,
        dedup: MessageDedup,
        scopes: list[str] | None = None,
    ) -> None:
        self._send_unicast = send_unicast_fn
        self._endpoint_uuid = endpoint_uuid
        self._xaddrs = xaddrs
        self._dedup = dedup
        # WS-Discovery 1.1 §5.1: scopes this device advertises.
        # Empty list means we match every scoped probe implicitly —
        # hosts that want scope filtering must configure scopes
        # explicitly.
        self._scopes: list[str] = list(scopes or [])
        self._tasks: list[asyncio.Task] = []

    def handle_message(
        self, envelope: SOAPEnvelope, source: tuple,
    ) -> None:
        """Process a parsed SOAP envelope and schedule response if needed."""
        if self._dedup.is_duplicate(envelope.message_id):
            return

        if envelope.action == Action.PROBE:
            types = parse_probe_types(envelope.body)
            probe_scopes = parse_probe_scopes(envelope.body)
            # Respond iff type filter is satisfied AND (RFC 3986)
            # scope matching succeeds against our configured scopes.
            type_ok = not types or DeviceType.DEVICE in types
            scope_ok = scope_matches(probe_scopes, self._scopes)
            if type_ok and scope_ok:
                self._spawn_response_task(
                    self._respond_probe(envelope.message_id, source),
                )

        elif envelope.action == Action.RESOLVE:
            endpoint = parse_resolve_endpoint(envelope.body)
            if endpoint == urn_uuid(self._endpoint_uuid):
                self._spawn_response_task(
                    self._respond_resolve(envelope.message_id, source),
                )

    def cancel_all(self) -> None:
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

    def _spawn_response_task(self, coro) -> None:
        """Schedule *coro* as a background task and remove it from
        ``_tasks`` when it finishes.

        Used by both the Probe and Resolve paths of ``handle_message``:
        each response (ProbeMatch or ResolveMatch) runs asynchronously
        so the main receive loop keeps servicing other datagrams while
        the responder sleeps out the WS-Discovery 1.1 §8.3 jitter
        window and SOAP-over-UDP 1.1 §3.4 retransmissions.
        """
        task = asyncio.get_event_loop().create_task(coro)
        self._tasks.append(task)
        task.add_done_callback(
            lambda t: self._tasks.remove(t) if t in self._tasks else None,
        )

    async def _respond_probe(
        self, relates_to: str, source: tuple,
    ) -> None:
        """Send ProbeMatch with random delay (WS-Discovery 1.1 s5.3)."""
        data = build_probe_match(self._endpoint_uuid, relates_to)
        await self._send_with_jitter(data, source, "ProbeMatch")

    async def _respond_resolve(
        self, relates_to: str, source: tuple,
    ) -> None:
        """Send ResolveMatch with random delay (WS-Discovery 1.1 s6.3)."""
        data = build_resolve_match(
            self._endpoint_uuid, self._xaddrs, relates_to,
        )
        await self._send_with_jitter(data, source, "ResolveMatch")

    async def _send_with_jitter(
        self, data: bytes, source: tuple, label: str,
    ) -> None:
        """Apply the WS-Discovery 1.1 §8.3 response jitter then
        retransmit per SOAP-over-UDP 1.1 §3.4.

        §8.3 requires a uniform random delay in
        ``[0, APP_MAX_DELAY]`` (we use ``UDP_UPPER_DELAY``) before a
        unicast response to prevent synchronized storms when many
        responders answer the same Probe.  The delay applies to
        both ProbeMatch (§5.3) and ResolveMatch (§6.3), which is
        why both call sites share this helper.
        """
        await asyncio.sleep(random.uniform(0, UDP_UPPER_DELAY))
        await self._retransmit_unicast(data, source)
        logger.debug("%s sent to %s", label, source[0])

    async def _retransmit_unicast(
        self, data: bytes, addr: tuple,
    ) -> None:
        """Unicast retransmission with exponential backoff (SOAP-over-UDP 1.1 s3.4)."""
        delay = random.uniform(UDP_MIN_DELAY, UDP_MAX_DELAY)
        for i in range(UNICAST_UDP_REPEAT):
            self._send_unicast(data, addr)
            if i < UNICAST_UDP_REPEAT - 1:
                await asyncio.sleep(delay)
                delay = min(delay * 2, UDP_UPPER_DELAY)
