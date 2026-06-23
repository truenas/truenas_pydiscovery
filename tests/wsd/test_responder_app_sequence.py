"""WS-Discovery §5.3/§6.3: the responder stamps AppSequence on matches.

A ProbeMatches / ResolveMatches sent in ad-hoc (multicast) mode MUST
carry the §7 ``<wsd:AppSequence>`` header so a receiver (Windows
WSDAPI) can order and age the host's announcements.  A match that
drops it is the failure that makes a host vanish from Explorer's
Network view after the client re-Probes (cache aged out / client
rebooted).

Exercises the real ``WSDResponder`` (real ``MessageDedup``, real
event loop, a real send sink, and a real monotonic MessageNumber
counter) so the regression is caught at the responder layer, not just
the builder layer.
"""
from __future__ import annotations

import asyncio
import itertools
import re
import uuid
import xml.etree.ElementTree as ET
from ipaddress import IPv4Interface

from truenas_pywsd.protocol.constants import (
    Action,
    Namespace,
    UDP_UPPER_DELAY,
    WSD_DEVICE_TYPES,
    urn_uuid,
)
from truenas_pywsd.protocol.soap import SOAPEnvelope
from truenas_pywsd.server.core.dedup import MessageDedup
from truenas_pywsd.server.core.responder import WSDResponder

# Source 10.0.0.9 must sit inside the responder's /24 or the on-link
# filter drops the Probe/Resolve before a response is scheduled.
_ADDRS_V4 = [IPv4Interface("10.0.0.1/24")]
_SOURCE = ("10.0.0.9", 3702)

# Mirrors the extractor in test_app_sequence.py: attribute order is
# InstanceId, SequenceId, MessageNumber (build_envelope insertion
# order, preserved by ElementTree on Python >= 3.8).
_APPSEQ_RE = re.compile(
    rb'<wsd:AppSequence\s+[^/]*InstanceId="(?P<inst>\d+)"\s+'
    rb'SequenceId="urn:uuid:[^"]+"\s+'
    rb'MessageNumber="(?P<msgnum>\d+)"',
)


def _run(coro, timeout: float = 5.0) -> object:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro, timeout=timeout)
        )
    finally:
        loop.close()


class _Capture:
    """Send sink: records the datagrams the responder would transmit."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def __call__(self, data: bytes, addr: tuple) -> None:
        self.payloads.append(data)


def _probe_envelope() -> SOAPEnvelope:
    body = ET.Element(f"{{{Namespace.SOAP}}}Body")
    probe = ET.SubElement(body, f"{{{Namespace.WSD}}}Probe")
    ET.SubElement(probe, f"{{{Namespace.WSD}}}Types").text = WSD_DEVICE_TYPES
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


def _make_responder(
    send_fn, endpoint_uuid: str, *, instance_id: int, next_msg,
) -> WSDResponder:
    return WSDResponder(
        send_fn, endpoint_uuid, "http://10.0.0.1:5357/x", MessageDedup(),
        addrs_v4=_ADDRS_V4, addrs_v6=[],
        instance_id=instance_id,
        next_message_number=next_msg,
    )


class TestResponderStampsAppSequence:
    def test_probe_match_carries_instance_id(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = _make_responder(
            cap, endpoint_uuid,
            instance_id=1700000000,
            next_msg=itertools.count(1).__next__,
        )

        async def drive() -> None:
            responder.handle_message(_probe_envelope(), _SOURCE)
            await asyncio.sleep(UDP_UPPER_DELAY + 0.3)

        _run(drive())
        assert cap.payloads, "no ProbeMatch fired"
        m = _APPSEQ_RE.search(cap.payloads[0])
        assert m is not None, "ProbeMatch missing <wsd:AppSequence>"
        assert int(m.group("inst")) == 1700000000

    def test_resolve_match_carries_instance_id(self):
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = _make_responder(
            cap, endpoint_uuid,
            instance_id=1700000042,
            next_msg=itertools.count(1).__next__,
        )

        async def drive() -> None:
            responder.handle_message(
                _resolve_envelope(urn_uuid(endpoint_uuid)), _SOURCE,
            )
            await asyncio.sleep(UDP_UPPER_DELAY + 0.3)

        _run(drive())
        assert cap.payloads, "no ResolveMatch fired"
        m = _APPSEQ_RE.search(cap.payloads[0])
        assert m is not None, "ResolveMatch missing <wsd:AppSequence>"
        assert int(m.group("inst")) == 1700000042

    def test_message_number_monotonic_across_matches(self):
        """One number is drawn per logical response; the unicast
        retransmits reuse the same datagram, so they share it, and a
        later response gets a higher number."""
        cap = _Capture()
        endpoint_uuid = str(uuid.uuid4())
        responder = _make_responder(
            cap, endpoint_uuid,
            instance_id=1700000000,
            next_msg=itertools.count(1).__next__,
        )
        settle = UDP_UPPER_DELAY + UDP_UPPER_DELAY * 2 + 0.3

        async def drive():
            responder.handle_message(_probe_envelope(), _SOURCE)
            await asyncio.sleep(settle)
            first = list(cap.payloads)
            cap.payloads.clear()
            responder.handle_message(_probe_envelope(), _SOURCE)
            await asyncio.sleep(settle)
            return first, list(cap.payloads)

        first, second = _run(drive(), timeout=8.0)
        nums_first = {
            int(_APPSEQ_RE.search(p).group("msgnum")) for p in first
        }
        nums_second = {
            int(_APPSEQ_RE.search(p).group("msgnum")) for p in second
        }
        assert len(nums_first) == 1, f"retransmits differ: {nums_first}"
        assert len(nums_second) == 1, f"retransmits differ: {nums_second}"
        assert min(nums_second) > min(nums_first), (
            f"MessageNumber not monotonic: {nums_first} -> {nums_second}"
        )
