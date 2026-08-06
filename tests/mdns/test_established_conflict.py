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

from truenas_pymdns.protocol.constants import (
    MDNS_PORT,
    EntryGroupState,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
)
from truenas_pymdns.server.core.announcer import Announcer
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.net.interface import InterfaceInfo
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
    server._announce_tasks = {}
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
        server._announce_tasks = {}
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
        server._announce_tasks = {}
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
        server._announce_tasks = {}
        server._interfaces = {}
        captured = _Captured()
        server._probe_and_announce = captured.capture  # type: ignore[method-assign]

        peer = _a("myhost.local", "10.0.0.99")
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)  # interface 1, not 2
        assert captured.groups == []


def _build_server_with_address() -> tuple[MDNSServer, EntryGroup, _Captured]:
    """Server whose group came from ``add_address``: the A record is
    probed, the reverse PTR is exempt (RFC 6762 §8.1)."""
    group = EntryGroup()
    group.add_address("myhost.local", "192.0.2.10")
    group.set_state(EntryGroupState.REGISTERING)
    group.set_state(EntryGroupState.ESTABLISHED)

    reg = ServiceRegistry()
    reg.add_group(group)

    server = MDNSServer.__new__(MDNSServer)
    server._registry = reg
    server._entry_groups = [group]
    server._conflict_tasks = []
    server._announce_tasks = {}
    server._interfaces = {}

    captured = _Captured()
    server._probe_and_announce = captured.capture  # type: ignore[method-assign]
    return server, group, captured


def _conflicting_reverse_ptr(ttl: int = 1800) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(
            IPv4Address("192.0.2.10").reverse_pointer, QType.PTR,
        ),
        ttl=ttl,
        data=PTRRecordData("otherhost.local"),
        cache_flush=True,
    )


class TestReversePTRConflictDiscardsRecord:
    """A record whose uniqueness was assumed rather than claimed by
    probing (RFC 6762 §8.1 reverse PTR) cannot be rescued by
    re-probing: its name is derived from the address, so no rename
    moves it out of the peer's way.  mDNSResponder's
    ``kDNSRecordTypeKnownUnique`` branch in ``mDNSCoreReceiveResponse``
    discards the record instead — "We just discard our record to avoid
    continued conflicts (as we do for a conflict on our Unique
    records) and get on with life" — with no goodbye, per
    ``mDNS_Deregister_internal``'s shared-records-only goodbye rule.
    """

    def test_conflicting_reverse_ptr_is_discarded_not_reprobed(self):
        server, _group, captured = _build_server_with_address()
        rev = IPv4Address("192.0.2.10").reverse_pointer
        msg = MDNSMessage()
        msg.answers = [_conflicting_reverse_ptr()]
        _run_check(server, msg, 1)

        assert captured.groups == []
        # Ours is withdrawn: reverse queries go unanswered, leaving
        # the peer's assertion uncontested.
        assert server._registry.lookup(rev, QType.PTR, 1) == []
        # The probed A record is untouched.
        assert server._registry.lookup("myhost.local", QType.A, 1)

    def test_goodbye_with_conflicting_rdata_is_not_a_conflict(self):
        """RFC 6762 §10.1: TTL=0 is a withdrawal, not an assertion —
        a peer retracting its own record must not cost us ours.
        mDNSResponder gates conflicts on ``rroriginalttl > 0``; avahi
        ignores goodbyes matching none of its records."""
        server, _group, captured = _build_server_with_address()
        rev = IPv4Address("192.0.2.10").reverse_pointer
        msg = MDNSMessage()
        msg.answers = [_conflicting_reverse_ptr(ttl=0)]
        _run_check(server, msg, 1)

        assert captured.groups == []
        assert server._registry.lookup(rev, QType.PTR, 1)

    def test_identical_rdata_is_not_a_conflict(self):
        """A cooperating responder (or our own multicast-loop echo)
        asserting the same rdata is agreement, not conflict."""
        server, _group, captured = _build_server_with_address()
        rev = IPv4Address("192.0.2.10").reverse_pointer
        peer = MDNSRecord(
            key=MDNSRecordKey(rev, QType.PTR),
            ttl=1800,
            data=PTRRecordData("myhost.local"),
            cache_flush=True,
        )
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_check(server, msg, 1)

        assert captured.groups == []
        assert server._registry.lookup(rev, QType.PTR, 1)

    def test_peer_conflicting_address_still_reprobes(self):
        """Control: the same group does re-probe when the conflict is
        on the record that was actually probed."""
        server, group, captured = _build_server_with_address()
        msg = MDNSMessage()
        msg.answers = [_a("myhost.local", "192.0.2.99")]
        _run_check(server, msg, 1)
        assert captured.groups == [group]

    def test_goodbye_for_probed_record_does_not_reprobe(self):
        """The §10.1 goodbye gate covers the probed branch too: a
        peer withdrawing a different-rdata A record is not claiming
        our name."""
        server, _group, captured = _build_server_with_address()
        msg = MDNSMessage()
        msg.answers = [_a("myhost.local", "192.0.2.99", ttl=0)]
        _run_check(server, msg, 1)
        assert captured.groups == []


class TestDiscardCancelsAnnounceStragglers:
    """Withdrawing an un-probed record must also stop the in-flight
    announce sequence that snapshotted it (RFC 6762 §8.4 / §10.1):
    a straggler tick would re-assert the conceded reverse PTR with
    the cache-flush bit seconds after the discard.  The group's
    surviving records get a fresh sequence so they still reach
    §8.3's "at least two unsolicited responses"."""

    def test_discard_cancels_snapshot_and_reannounces_survivors(
        self, tmp_path, make_server, started_state,
    ):
        loop = asyncio.new_event_loop()
        server = make_server(tmp_path, hostname="myhost")
        state = started_state(loop, server._config, InterfaceInfo(
            name="lan0", index=7, addrs_v4=[IPv4Address("192.0.2.10")],
        ))
        state.announcer = Announcer(state.transport.send_message)
        server._interfaces = {7: state}
        try:
            server._register_host_addresses()
            group = server._host_groups[0]
            loop.run_until_complete(server._probe_and_announce(group))
            stale = list(server._announce_tasks.get(id(group), []))
            assert stale, "announce sequence must be in flight"

            rev = IPv4Address("192.0.2.10").reverse_pointer
            msg = MDNSMessage()
            msg.answers = [MDNSRecord(
                key=MDNSRecordKey(rev, QType.PTR),
                ttl=1800,
                data=PTRRecordData("otherhost.local"),
                cache_flush=True,
            )]

            async def inject() -> None:
                server._check_established_conflicts(
                    msg, 7, ("192.0.2.99", MDNS_PORT),
                )

            loop.run_until_complete(inject())

            # Ours is withdrawn from the registry...
            assert server._registry.lookup(rev, QType.PTR, 7) == []
            # ...and the snapshot-holding announce tasks are dead.
            loop.run_until_complete(
                asyncio.gather(*stale, return_exceptions=True),
            )
            assert all(t.cancelled() for t in stale)
            # The survivors (the A record) re-announce on a fresh
            # task built from the post-removal record list.
            fresh = server._announce_tasks.get(id(group), [])
            assert fresh and not (set(fresh) & set(stale))
            assert group.records and all(
                r.key.rtype != QType.PTR for r in group.records
            )
        finally:
            loop.run_until_complete(state.stop())
            leftover = [
                t for ts in server._announce_tasks.values() for t in ts
            ]
            if leftover:
                loop.run_until_complete(
                    asyncio.gather(*leftover, return_exceptions=True),
                )
            loop.close()
