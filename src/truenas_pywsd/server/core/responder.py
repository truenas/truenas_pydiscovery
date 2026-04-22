"""WSD Probe and Resolve responder (WS-Discovery 1.1 s5/s6).

Handles incoming Probe and Resolve messages, responds with
ProbeMatch and ResolveMatch respectively.  Includes random
delay before responding to avoid UDP collision.
"""
from __future__ import annotations

import asyncio
import logging
import random
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    ip_address,
)
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
    """Responds to WSD Probe and Resolve messages.

    **On-link source filter.**  ``handle_message`` drops any Probe or
    Resolve whose source IP isn't reachable on the interface we're
    listening on (see ``_is_on_link``).  The purpose is to remove this
    responder from the set of UDP reflectors available to a
    cross-subnet attacker: a spoofed Probe with ``src = victim`` from
    off-link would otherwise elicit ``UNICAST_UDP_REPEAT`` replies
    aimed at the victim.

    The filter is spec-consistent:

    * WS-Discovery 1.1 §3.1.1 pairs port 3702 with the link-local
      multicast group ``ff02::c`` (IPv6) and the administratively-
      scoped ``239.255.255.250`` (IPv4, paired with SOAP-over-UDP
      1.1 §3.3's TTL=1 recommendation).  The protocol is designed
      to be link-local.
    * WS-Discovery 1.1 §8.1 explicitly permits a Target Service to
      decline responding to a Probe/Resolve whose client is "in a
      different administrative domain" — the textual hook for this
      kind of filtering.

    **Known limitation — directed unicast Probes (§5.2.2).**
    WS-Discovery 1.1 §5.2.2 allows a Target Service to accept a
    unicast Probe sent directly to its transport address (not via
    the multicast group).  A legitimate off-link client that
    already knows our ``XAddrs`` may do this, and the filter
    silently drops its Probe.  If that scenario becomes load-
    bearing the transport can switch from ``recvfrom`` to
    ``recvmsg`` with ``IP_PKTINFO`` / ``IPV6_PKTINFO`` and skip
    the on-link check when the destination address on the
    incoming datagram is a unicast interface address rather than
    the multicast group.

    **Known limitation — same-link attackers.**  An attacker already
    on our link can spoof a source IP inside our subnet and still
    get amplified replies aimed at another on-link host.  The
    ``IP_TTL=1`` / ``IPV6_UNICAST_HOPS=1`` caps on the unicast send
    sockets (see ``net/transport.py``) confine any reflected traffic
    to the link, but cannot prevent same-link reflection.  This is
    inherent to unauthenticated UDP discovery on a shared broadcast
    domain — same-link attackers already have direct access and
    don't need our amplification.
    """

    def __init__(
        self,
        send_unicast_fn: SendUnicastFn,
        endpoint_uuid: str,
        xaddrs: str,
        dedup: MessageDedup,
        *,
        addrs_v4: list[IPv4Interface],
        addrs_v6: list[IPv6Interface],
        scopes: list[str] | None = None,
        metadata_version: Callable[[], int] = lambda: 1,
    ) -> None:
        self._send_unicast = send_unicast_fn
        self._endpoint_uuid = endpoint_uuid
        self._xaddrs = xaddrs
        self._dedup = dedup
        self._addrs_v4 = list(addrs_v4)
        self._addrs_v6 = list(addrs_v6)
        # WS-Discovery 1.1 §5.1: scopes this device advertises.
        # Empty list means we match every scoped probe implicitly —
        # hosts that want scope filtering must configure scopes
        # explicitly.
        self._scopes: list[str] = list(scopes or [])
        # Callable so SIGHUP-driven metadata changes on the server
        # propagate to future ProbeMatch/ResolveMatch responses
        # without needing to rebuild the responder.  WSD 1.1 §4.1
        # requires the version to increment monotonically whenever
        # metadata changes so clients know to re-fetch.
        self._get_metadata_version = metadata_version
        self._tasks: list[asyncio.Task] = []

    def _is_on_link(self, source: tuple) -> bool:
        """Return True if *source* is reachable on our interface.

        Decision rules:

        * IPv4: source ∈ any of our configured IPv4 networks.
        * IPv6 link-local (``fe80::/10``): always True.  ``fe80::/10``
          is per-interface and our receive socket is scoped to a
          single interface via ``SO_BINDTODEVICE``; any reply we send
          to a link-local destination cannot leave the link
          physically, so off-link reflection via forged link-local
          sources is impossible.
        * IPv6 global / ULA: source ∈ any of our configured IPv6
          networks.

        A source that fails to parse or isn't covered by any rule is
        rejected.  Fail-safe: an interface configured without any
        addresses answers nothing.
        """
        try:
            addr = ip_address(source[0])
        except (ValueError, IndexError):
            return False
        if isinstance(addr, IPv4Address):
            return any(addr in a.network for a in self._addrs_v4)
        if isinstance(addr, IPv6Address):
            if addr.is_link_local:
                return True
            return any(addr in a.network for a in self._addrs_v6)
        return False

    def handle_message(
        self, envelope: SOAPEnvelope, source: tuple,
    ) -> None:
        """Process a parsed SOAP envelope and schedule response if needed."""
        if self._dedup.is_duplicate(envelope.message_id):
            return

        if not self._is_on_link(source):
            logger.debug(
                "Dropping off-link %s from %s",
                envelope.action, source[0] if source else "?",
            )
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
        """Send ProbeMatch with random delay (WS-Discovery 1.1 s5.3).

        Includes ``<wsd:XAddrs>`` so peers skip the usual follow-up
        multicast Resolve — matches Windows WSDAPI behaviour (the
        Samba ``wsdd.py`` convention of omitting XAddrs was based
        on an incorrect assumption about Windows's privacy stance)."""
        data = build_probe_match(
            self._endpoint_uuid, relates_to,
            xaddrs=self._xaddrs,
            metadata_version=self._get_metadata_version(),
        )
        await self._send_with_jitter(data, source, "ProbeMatch")

    async def _respond_resolve(
        self, relates_to: str, source: tuple,
    ) -> None:
        """Send ResolveMatch with random delay (WS-Discovery 1.1 s6.3)."""
        data = build_resolve_match(
            self._endpoint_uuid, self._xaddrs, relates_to,
            metadata_version=self._get_metadata_version(),
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
