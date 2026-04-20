"""RFC 6762 §9 / BCT II.6 "SUBSEQUENT CONFLICT".

When a peer response arrives with the same name+type as one of our
ESTABLISHED unique records but different rdata, the group MUST be
reset to probing state (same name) so a re-probe can distinguish
stale echoes from a real competing peer.

Covers ``MDNSServer._check_established_conflicts`` in
``server/server.py``.  Mirrors Apple mDNSResponder's
``kDNSRecordTypeVerified`` branch at ``mDNSCore/mDNS.c:10315-10328``.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import EntryGroupState, QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.service.registry import ServiceRegistry
from truenas_pymdns.server.server import MDNSServer


def _a(name: str, addr: str, ttl: int = 1800) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


class _Captured:
    """Tracks calls to _probe_and_announce so the test can assert it
    was invoked without needing a full prober/announcer stack."""

    def __init__(self) -> None:
        self.groups: list[EntryGroup] = []

    async def capture(self, group: EntryGroup) -> None:
        self.groups.append(group)
        # Simulate probe success — let state transition so re-probe
        # calls in subsequent tests start clean.
        group.set_state(EntryGroupState.REGISTERING)
        group.set_state(EntryGroupState.ESTABLISHED)


def _build_server() -> tuple[MDNSServer, EntryGroup, _Captured]:
    """Build a bare MDNSServer with one ESTABLISHED group on ifindex 1."""
    group = EntryGroup()
    group.add_record(_a("myhost.local", "10.0.0.1"))
    group.set_state(EntryGroupState.REGISTERING)
    group.set_state(EntryGroupState.ESTABLISHED)

    reg = ServiceRegistry()
    reg.add_group(group)

    server = MDNSServer.__new__(MDNSServer)
    server._registry = reg
    server._entry_groups = [group]
    server._conflict_tasks = []
    server._interfaces = {}

    captured = _Captured()
    server._probe_and_announce = captured.capture  # type: ignore[method-assign]
    return server, group, captured


def _run_check(server: MDNSServer, message: MDNSMessage, ifindex: int) -> None:
    """Run _check_established_conflicts under a live event loop so
    ``loop.create_task`` works.  Await all conflict tasks before
    returning so assertions see the effect."""
    async def runner() -> None:
        server._check_established_conflicts(message, ifindex)
        if server._conflict_tasks:
            await asyncio.gather(
                *server._conflict_tasks, return_exceptions=True,
            )

    asyncio.run(runner())


class TestEstablishedConflict:
    def test_peer_different_rdata_resets_group_and_reprobes(self):
        """BCT II.6: peer announces different rdata for our
        established unique record → reset to REGISTERING, re-probe."""
        server, group, captured = _build_server()
        peer = _a("myhost.local", "10.0.0.99")  # different IP
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)
        assert captured.groups == [group], (
            "must re-probe the conflicted group"
        )
        # Registry should have removed then re-added (via the stubbed
        # _probe_and_announce that transitions back to ESTABLISHED).
        assert group.state == EntryGroupState.ESTABLISHED

    def test_peer_identical_rdata_is_noop(self):
        """Same rdata from peer is §7.1 / §6.6 territory, not §9.
        Must NOT trigger a re-probe."""
        server, group, captured = _build_server()
        peer = _a("myhost.local", "10.0.0.1")  # identical
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)
        assert captured.groups == []

    def test_peer_conflict_on_shared_record_ignored(self):
        """Shared records (cache_flush=False) are allowed to coexist
        with peers having different rdata — classic PTR case.  Must
        not trigger a §9 re-probe."""
        # Build a group whose A record is SHARED (atypical, but
        # exercises the code path).
        shared_rec = MDNSRecord(
            key=MDNSRecordKey("shared.local", QType.A),
            ttl=1800,
            data=ARecordData(IPv4Address("10.0.0.1")),
            cache_flush=False,
        )
        group = EntryGroup()
        group.add_record(shared_rec)
        group.set_state(EntryGroupState.REGISTERING)
        group.set_state(EntryGroupState.ESTABLISHED)
        reg = ServiceRegistry()
        reg.add_group(group)
        server = MDNSServer.__new__(MDNSServer)
        server._registry = reg
        server._entry_groups = [group]
        server._conflict_tasks = []
        server._interfaces = {}
        captured = _Captured()
        server._probe_and_announce = captured.capture  # type: ignore[method-assign]

        peer = MDNSRecord(
            key=MDNSRecordKey("shared.local", QType.A),
            ttl=1800,
            data=ARecordData(IPv4Address("10.0.0.99")),
            cache_flush=True,
        )
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)
        assert captured.groups == []

    def test_registering_group_not_touched(self):
        """A group still in REGISTERING is the prober's territory
        (§8.2) — the §9 handler must skip it."""
        group = EntryGroup()
        group.add_record(_a("myhost.local", "10.0.0.1"))
        group.set_state(EntryGroupState.REGISTERING)  # NOT ESTABLISHED
        reg = ServiceRegistry()
        reg.add_group(group)
        server = MDNSServer.__new__(MDNSServer)
        server._registry = reg
        server._entry_groups = [group]
        server._conflict_tasks = []
        server._interfaces = {}
        captured = _Captured()
        server._probe_and_announce = captured.capture  # type: ignore[method-assign]

        peer = _a("myhost.local", "10.0.0.99")
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)
        assert captured.groups == []

    def test_wrong_interface_filters_out_group(self):
        """Groups bound to specific interfaces must not be re-probed
        when the conflicting peer arrived on a different interface."""
        group = EntryGroup()
        group.add_record(_a("myhost.local", "10.0.0.1"))
        group.interfaces = [2]  # only interface 2
        group.set_state(EntryGroupState.REGISTERING)
        group.set_state(EntryGroupState.ESTABLISHED)
        reg = ServiceRegistry()
        reg.add_group(group)
        server = MDNSServer.__new__(MDNSServer)
        server._registry = reg
        server._entry_groups = [group]
        server._conflict_tasks = []
        server._interfaces = {}
        captured = _Captured()
        server._probe_and_announce = captured.capture  # type: ignore[method-assign]

        peer = _a("myhost.local", "10.0.0.99")
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)  # interface 1, not 2
        assert captured.groups == []
