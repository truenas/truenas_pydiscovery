"""WSD Hello/Bye retransmission (SOAP-over-UDP §3.4).

Each announcement is sent ``MULTICAST_UDP_REPEAT`` times with an
initial delay in [``UDP_MIN_DELAY``, ``UDP_MAX_DELAY``] that
doubles, capped at ``UDP_UPPER_DELAY``.
"""
from __future__ import annotations

import asyncio
import time
import uuid

from truenas_pywsd.protocol.constants import (
    MULTICAST_UDP_REPEAT,
    UDP_MAX_DELAY,
    UDP_MIN_DELAY,
    UDP_UPPER_DELAY,
)
from truenas_pywsd.server.core.announcer import send_bye, send_hello


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

    def __call__(self, data: bytes) -> None:
        self.stamps.append(time.monotonic())
        self.payloads.append(data)


class TestHelloRetransmission:
    def test_emits_multicast_udp_repeat_packets(self):
        cap = _Capture()
        uid = str(uuid.uuid4())
        _run(send_hello(cap, uid, xaddrs="http://10.0.0.1:5357/"))
        assert len(cap.payloads) == MULTICAST_UDP_REPEAT

    def test_first_delay_within_udp_min_max(self):
        cap = _Capture()
        uid = str(uuid.uuid4())
        _run(send_hello(cap, uid, xaddrs="http://10.0.0.1:5357/"))
        assert len(cap.stamps) >= 2
        first_gap = cap.stamps[1] - cap.stamps[0]
        # Allow generous slack for CI jitter.
        assert (
            UDP_MIN_DELAY * 0.8 <= first_gap
            <= UDP_MAX_DELAY * 1.5
        ), f"first gap {first_gap:.3f}s outside [{UDP_MIN_DELAY}, {UDP_MAX_DELAY}]"

    def test_subsequent_gaps_do_not_shrink(self):
        """§3.4 says delay is doubled each retry; it must not go
        BACKWARD.  Check gap(i+1) >= gap(i) - tolerance."""
        cap = _Capture()
        uid = str(uuid.uuid4())
        _run(send_hello(cap, uid, xaddrs="http://10.0.0.1:5357/"))
        gaps = [
            cap.stamps[i + 1] - cap.stamps[i]
            for i in range(len(cap.stamps) - 1)
        ]
        for i in range(len(gaps) - 1):
            assert gaps[i + 1] >= gaps[i] * 0.9, (
                f"gap shrank: gaps={gaps}"
            )

    def test_no_gap_exceeds_udp_upper_delay(self):
        cap = _Capture()
        _run(send_hello(cap, str(uuid.uuid4()),
                        xaddrs="http://10.0.0.1:5357/"))
        gaps = [
            cap.stamps[i + 1] - cap.stamps[i]
            for i in range(len(cap.stamps) - 1)
        ]
        for g in gaps:
            assert g <= UDP_UPPER_DELAY * 1.2


class TestByeRetransmission:
    def test_emits_multicast_udp_repeat_packets(self):
        cap = _Capture()
        _run(send_bye(cap, str(uuid.uuid4())))
        assert len(cap.payloads) == MULTICAST_UDP_REPEAT
