"""RFC 6762 §6.6 cooperating-responders re-announce.

When a peer multicasts an answer for a record we also own, and the
peer's TTL has dropped below 50 % of ours, we MUST schedule a
re-announcement so caches don't expire the record prematurely.

This covers ``MDNSServer._check_cooperating_responders`` at
``server/server.py:356``.
"""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)


def _a(name: str, addr: str, ttl: int) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=ttl,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


class _FakeAnnouncer:
    """Captures records passed to schedule_announce without mocks."""

    def __init__(self) -> None:
        self.calls: list[list[MDNSRecord]] = []

    def schedule_announce(self, records: list[MDNSRecord]) -> None:
        self.calls.append(list(records))


class _FakeIfState:
    def __init__(self, announcer: _FakeAnnouncer) -> None:
        self.announcer = announcer


def _run_cooperating_check(
    server_instance, message: MDNSMessage, ifindex: int,
) -> None:
    """Invoke the server's cooperating-responders check."""
    server_instance._check_cooperating_responders(message, ifindex)


class TestCooperatingResponders:
    def _setup(self) -> tuple[object, _FakeAnnouncer, MDNSRecord]:
        """Build an MDNSServer-ish object with enough attributes for
        ``_check_cooperating_responders`` to run, without touching
        real sockets or the full daemon lifecycle.
        """
        from truenas_pymdns.server.core.entry_group import EntryGroup
        from truenas_pymdns.server.service.registry import ServiceRegistry
        from truenas_pymdns.server.server import MDNSServer

        our_rec = _a("coop.local", "10.0.0.1", ttl=1800)
        group = EntryGroup()
        group.add_record(our_rec)
        reg = ServiceRegistry()
        reg.add_group(group)

        server = MDNSServer.__new__(MDNSServer)
        server._registry = reg
        announcer = _FakeAnnouncer()
        server._interfaces = {1: _FakeIfState(announcer)}
        return server, announcer, our_rec

    def test_peer_ttl_below_half_triggers_reannounce(self):
        server, announcer, our = self._setup()
        # Peer asserts same rdata but TTL = our TTL // 3 → below half.
        peer = _a("coop.local", "10.0.0.1", ttl=our.ttl // 3)
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_cooperating_check(server, msg, 1)
        assert len(announcer.calls) == 1
        scheduled = announcer.calls[0]
        assert scheduled == [our], "must re-announce our copy of the record"

    def test_peer_ttl_above_half_does_not_trigger(self):
        server, announcer, our = self._setup()
        # Peer TTL well above 50 % → no re-announce needed.
        peer = _a("coop.local", "10.0.0.1", ttl=our.ttl - 10)
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_cooperating_check(server, msg, 1)
        assert announcer.calls == []

    def test_peer_for_different_rdata_ignored(self):
        """The 50 % check is rdata-specific — a peer announcing a
        different address for the same name must not trigger our
        re-announcement."""
        server, announcer, _our = self._setup()
        peer = _a("coop.local", "10.0.0.99", ttl=1)  # different rdata
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_cooperating_check(server, msg, 1)
        assert announcer.calls == []

    def test_peer_for_unowned_name_ignored(self):
        server, announcer, _our = self._setup()
        peer = _a("nothers.local", "10.0.0.1", ttl=1)
        msg = MDNSMessage()
        msg.answers = [peer]
        _run_cooperating_check(server, msg, 1)
        assert announcer.calls == []

    def test_missing_interface_state_is_noop(self):
        """If the peer arrived on an interface we no longer know
        about, the check must not raise — just skip silently."""
        server, announcer, our = self._setup()
        peer = _a("coop.local", "10.0.0.1", ttl=1)
        msg = MDNSMessage()
        msg.answers = [peer]
        # Use an ifindex that's not in _interfaces.
        _run_cooperating_check(server, msg, 99)
        assert announcer.calls == []
