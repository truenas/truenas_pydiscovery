"""Link-flap throttling on hot-plug re-probing.

Mirrors Apple mDNSResponder's ``mDNS_RegisterInterface`` flap
handling at ``mDNSCore/mDNS.c:14262-14273``: re-registration within
``LINK_FLAP_WINDOW`` triggers a longer probe delay and reduces the
announcement count to one packet.

These tests drive ``MDNSServer._on_link_up`` directly under a real
asyncio loop and verify:
  - a steady-state link-up uses the normal 0.5s delay and full
    ``ANNOUNCE_COUNT`` announcements;
  - a follow-up link-up within the flap window uses the extended
    5s delay and drops to ``LINK_FLAP_ANNOUNCE_COUNT``;
  - overlapping link-up tasks for the same ifindex are coalesced
    (the earlier task is cancelled when a newer one arrives during
    its defer window).
"""
from __future__ import annotations

import asyncio
import time
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import (
    ANNOUNCE_COUNT,
    EntryGroupState,
    LINK_FLAP_ANNOUNCE_COUNT,
    QType,
)
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.service.registry import ServiceRegistry
from truenas_pymdns.server.server import MDNSServer


def _a(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=1800,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


class _Captured:
    """Captures calls to ``_probe_and_announce`` + arguments."""

    def __init__(self) -> None:
        self.calls: list[tuple[EntryGroup, int]] = []

    async def handler(
        self, group: EntryGroup, announce_count: int = ANNOUNCE_COUNT,
    ) -> None:
        self.calls.append((group, announce_count))
        # Simulate probe success so subsequent _on_link_up calls find
        # the group back in ESTABLISHED state.
        group.set_state(EntryGroupState.REGISTERING)
        group.set_state(EntryGroupState.ESTABLISHED)


def _build_server() -> tuple[MDNSServer, EntryGroup, _Captured]:
    group = EntryGroup()
    group.add_record(_a("host.local", "10.0.0.1"))
    group.set_state(EntryGroupState.REGISTERING)
    group.set_state(EntryGroupState.ESTABLISHED)

    reg = ServiceRegistry()
    reg.add_group(group)

    class _Iface:
        index = 1
        name = "eth0"

    class _IfState:
        iface = _Iface()

    server = MDNSServer.__new__(MDNSServer)
    server._registry = reg
    server._entry_groups = [group]
    server._conflict_tasks = []
    server._interfaces = {1: _IfState()}
    server._last_link_up = {}
    server._pending_link_ups = {}

    captured = _Captured()
    server._probe_and_announce = captured.handler  # type: ignore[method-assign]
    return server, group, captured


class TestLinkFlap:
    def test_first_up_uses_normal_delay_and_full_announce_count(self):
        server, group, captured = _build_server()

        async def runner() -> float:
            start = time.monotonic()
            await server._on_link_up(1)
            return time.monotonic() - start

        elapsed = asyncio.run(runner())
        assert captured.calls == [(group, ANNOUNCE_COUNT)]
        # Normal delay = 0.5s; allow generous upper bound for CI.
        assert 0.4 < elapsed < 1.5, (
            f"expected ~0.5s normal delay, got {elapsed:.3f}s"
        )

    def test_flap_within_window_uses_extended_delay_and_single_announce(
        self,
    ):
        server, group, captured = _build_server()
        # Pretend the interface came up very recently.
        server._last_link_up[1] = time.monotonic() - 1.0  # 1s ago

        async def runner() -> float:
            start = time.monotonic()
            # Bound execution so the test doesn't wait the full 5s —
            # we only need to observe that the coroutine was STILL
            # sleeping when we hit 1s, i.e. delay > 0.5s.
            try:
                await asyncio.wait_for(server._on_link_up(1), timeout=1.0)
            except asyncio.TimeoutError:
                return 999.0
            return time.monotonic() - start

        elapsed = asyncio.run(runner())
        # We expect the defer to exceed the 1s timeout — proving
        # extended flap delay kicked in.
        assert elapsed >= 1.0, (
            f"flap path should sleep > 1s, got {elapsed:.3f}s"
        )
        # No probe-and-announce calls should have landed yet because
        # the task was still in its 5s defer when we timed out.
        assert captured.calls == []

    def test_overlapping_linkup_coalesced(self):
        """If a second _on_link_up arrives while the first is still
        in its defer window, the older task must be cancelled (not
        pile up)."""
        server, group, captured = _build_server()

        async def runner() -> list:
            # Schedule two back-to-back link-ups.
            t1 = asyncio.create_task(server._on_link_up(1))
            await asyncio.sleep(0.05)   # let t1 enter its sleep
            t2 = asyncio.create_task(server._on_link_up(1))
            await asyncio.gather(t1, t2, return_exceptions=True)
            return list(captured.calls)

        calls = asyncio.run(runner())
        # t2 replaced t1; only t2 should have probed.  And because
        # the first (uncoalesced) run recorded no prior up-time,
        # t2 sees "last was just now" → flap mode → announce_count=1.
        assert len(calls) == 1, (
            f"expected exactly one probe-and-announce call, got {len(calls)}"
        )
        _, announce_count = calls[0]
        assert announce_count == LINK_FLAP_ANNOUNCE_COUNT, (
            "second back-to-back link-up should trigger flap mode"
        )
