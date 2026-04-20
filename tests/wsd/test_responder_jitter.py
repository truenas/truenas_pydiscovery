"""WSD responder jitter (WS-Discovery §8.3) + unicast retransmission.

Before responding to a Probe or Resolve, the responder must insert a
random delay in [0, APP_MAX_DELAY] to avoid multicast UDP storms.
Subsequent retransmissions follow the SOAP-over-UDP §3.4 pattern.
"""
from __future__ import annotations

import asyncio
import time
import uuid
import xml.etree.ElementTree as ET

from truenas_pywsd.protocol.constants import (
    Action,
    Namespace,
    UDP_MAX_DELAY,
    UDP_MIN_DELAY,
    UDP_UPPER_DELAY,
    UNICAST_UDP_REPEAT,
    WSD_DEVICE_TYPES,
    urn_uuid,
)
from truenas_pywsd.protocol.soap import SOAPEnvelope
from truenas_pywsd.server.core.dedup import MessageDedup
from truenas_pywsd.server.core.responder import WSDResponder


def _run(coro, timeout: float = 5.0) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
    finally:
        loop.close()


class _Capture:
    def __init__(self) -> None:
        self.stamps: list[float] = []
        self.payloads: list[bytes] = []
        self.dests: list[tuple] = []

    def __call__(self, data: bytes, addr: tuple) -> None:
        self.stamps.append(time.monotonic())
        self.payloads.append(data)
        self.dests.append(addr)


def _probe_envelope(types: str = WSD_DEVICE_TYPES) -> SOAPEnvelope:
    """Build a Probe SOAPEnvelope.  ``body`` is the SOAP Body
    container with a WSD Probe child — matching what
    ``parse_probe_types`` expects after ``parse_envelope`` strips
    the outer Envelope."""
    body = ET.Element(f"{{{Namespace.SOAP}}}Body")
    probe = ET.SubElement(body, f"{{{Namespace.WSD}}}Probe")
    ET.SubElement(probe, f"{{{Namespace.WSD}}}Types").text = types
    env = SOAPEnvelope()
    env.action = Action.PROBE
    env.message_id = f"urn:uuid:{uuid.uuid4()}"
    env.body = body
    return env


def _resolve_envelope(endpoint: str) -> SOAPEnvelope:
    body = ET.Element(f"{{{Namespace.SOAP}}}Body")
    resolve = ET.SubElement(body, f"{{{Namespace.WSD}}}Resolve")
    epr = ET.SubElement(resolve, f"{{{Namespace.WSA}}}EndpointReference")
    ET.SubElement(epr, f"{{{Namespace.WSA}}}Address").text = endpoint
    env = SOAPEnvelope()
    env.action = Action.RESOLVE
    env.message_id = f"urn:uuid:{uuid.uuid4()}"
    env.body = body
    return env


class TestProbeResponseJitter:
    def test_response_delayed_by_at_least_zero_up_to_upper_delay(self):
        """Response time must be within [0, UDP_UPPER_DELAY].
        Statistically unlikely to come in under 1 ms every run, so
        we just bound the upper side and verify a non-zero delay
        occurs at least once across several probes."""
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        dedup = MessageDedup()
        responder = WSDResponder(cap, endpoint_uuid, "http://x", dedup)

        saw_delay = False

        async def drive() -> None:
            nonlocal saw_delay
            loop = asyncio.get_running_loop()
            responder._loop = loop
            for _ in range(5):
                env = _probe_envelope()
                t0 = time.monotonic()
                responder.handle_message(env, ("10.0.0.9", 3702))
                # Give the task room to run.
                await asyncio.sleep(UDP_UPPER_DELAY + UDP_MAX_DELAY + 0.1)
                # At least one probe must land within the bound.
                if cap.stamps and (cap.stamps[0] - t0) >= 0.001:
                    saw_delay = True
                cap.stamps.clear()
                cap.payloads.clear()
                cap.dests.clear()
                # Reset dedup so each iteration responds afresh.
                dedup._entries.clear()

        _run(drive(), timeout=10.0)
        assert saw_delay, (
            "every probe responded instantly — jitter window not applied"
        )

    def test_response_lands_before_upper_delay_plus_retransmit(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = WSDResponder(
            cap, endpoint_uuid, "http://x", MessageDedup(),
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            responder._loop = loop
            env = _probe_envelope()
            t0 = time.monotonic()
            responder.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(
                UDP_UPPER_DELAY + UDP_UPPER_DELAY * 2 + 0.2,
            )
            assert cap.stamps, "no ProbeMatch fired"
            first_gap = cap.stamps[0] - t0
            # Upper bound: jitter can be up to UDP_UPPER_DELAY.
            assert first_gap <= UDP_UPPER_DELAY + 0.2, (
                f"ProbeMatch took too long: {first_gap:.3f}s"
            )

        _run(drive(), timeout=5.0)


class TestUnicastRetransmit:
    def test_probe_match_sent_unicast_udp_repeat_times(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = WSDResponder(
            cap, endpoint_uuid, "http://x", MessageDedup(),
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            responder._loop = loop
            env = _probe_envelope()
            responder.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(
                UDP_UPPER_DELAY + UDP_UPPER_DELAY * 2 + 0.3,
            )

        _run(drive(), timeout=5.0)
        assert len(cap.payloads) == UNICAST_UDP_REPEAT

    def test_retransmit_gap_within_expected_window(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = WSDResponder(
            cap, endpoint_uuid, "http://x", MessageDedup(),
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            responder._loop = loop
            env = _probe_envelope()
            responder.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(
                UDP_UPPER_DELAY + UDP_UPPER_DELAY * 2 + 0.3,
            )

        _run(drive(), timeout=5.0)
        assert len(cap.stamps) >= 2
        retransmit_gap = cap.stamps[1] - cap.stamps[0]
        # Initial retransmit delay is in [UDP_MIN_DELAY, UDP_MAX_DELAY].
        assert (
            UDP_MIN_DELAY * 0.8 <= retransmit_gap
            <= UDP_MAX_DELAY * 1.5
        ), f"retransmit gap {retransmit_gap:.3f}s out of bounds"


class TestResolveResponse:
    def test_matching_endpoint_gets_resolve_match(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = WSDResponder(
            cap, endpoint_uuid, "http://x", MessageDedup(),
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            responder._loop = loop
            env = _resolve_envelope(urn_uuid(endpoint_uuid))
            responder.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(
                UDP_UPPER_DELAY + UDP_UPPER_DELAY * 2 + 0.3,
            )

        _run(drive(), timeout=5.0)
        assert len(cap.payloads) == UNICAST_UDP_REPEAT

    def test_non_matching_endpoint_is_ignored(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = WSDResponder(
            cap, endpoint_uuid, "http://x", MessageDedup(),
        )

        async def drive() -> None:
            loop = asyncio.get_running_loop()
            responder._loop = loop
            # Resolve for someone else — should be ignored.
            env = _resolve_envelope(urn_uuid(str(uuid.uuid4())))
            responder.handle_message(env, ("10.0.0.9", 3702))
            await asyncio.sleep(UDP_UPPER_DELAY + 0.2)

        _run(drive(), timeout=3.0)
        assert cap.payloads == []
