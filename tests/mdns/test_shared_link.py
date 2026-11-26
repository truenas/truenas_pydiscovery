"""Two of the host's interfaces on one link (RFC 6762 §14).

"If the two networks are bridged together, then packets the host sends
on one interface will arrive on the other interface a few milliseconds
later, and care must be taken to ensure that this bridging does not
cause problems."  What arrives carries the other interface's
addresses, which §6.2 keeps out of the receiving interface's records,
and the host must still recognise it as its own.

The field report: a NAS with two ports on one LAN renamed itself
every few seconds.  Its interfaces probe one after the other, the
first answers the second's probe from its own host group, and the
second took that answer for another host's -- losing the name to
itself on every rename after.

Covers ``MDNSServer._owns_record`` and its use by the prober and by
``_check_established_conflicts``.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from ipaddress import IPv4Address, IPv6Address

import pytest

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
)
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.net.interface import InterfaceInfo
from truenas_pymdns.server.server import MDNSServer, PerInterfaceState

# RFC 5737 / RFC 3849 documentation addresses for two ports on one
# LAN.  The second port's IPv4 address sorts before the first's, as in
# the field the first port's AAAA-only answer sorted after the second
# port's A record: under the §8.2 tiebreak the second port lost to the
# first.
FIRST_INDEX = 41
SECOND_INDEX = 42
FIRST_V4 = IPv4Address("192.0.2.40")
SECOND_V4 = IPv4Address("192.0.2.4")
FIRST_V6 = IPv6Address("2001:db8::40")
SECOND_V6 = IPv6Address("2001:db8::4")
PEER_V4 = IPv4Address("192.0.2.99")

HOST_FQDN = "nas.local"


def _host_group(server: MDNSServer, index: int) -> EntryGroup:
    (group,) = [g for g in server._host_groups if g.interfaces == [index]]
    return group


def _a(name: str, address: IPv4Address) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(address),
        cache_flush=True,
    )


def _drain(loop: asyncio.AbstractEventLoop, server: MDNSServer) -> None:
    """Stop every interface and let no task outlive *loop*."""
    async def shutdown() -> None:
        for task in list(server._conflict_tasks):
            task.cancel()
        for state in server._interfaces.values():
            await state.stop()
        current = asyncio.current_task()
        pending = [t for t in asyncio.all_tasks() if t is not current]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    loop.run_until_complete(shutdown())
    loop.close()


@pytest.fixture
def two_ports(tmp_path, make_server, started_state):
    """A server with two interfaces, each with its own IPv4 and IPv6
    address and its host group registered.  The transports are open
    but hand nothing they receive to the server: every message a test
    sends in goes through ``_handle_message`` on the index it names."""
    loop = asyncio.new_event_loop()
    server = make_server(tmp_path, hostname="nas")
    first = started_state(loop, server._config, InterfaceInfo(
        name="lan0", index=FIRST_INDEX,
        addrs_v4=[FIRST_V4], addrs_v6=[FIRST_V6],
    ))
    second = started_state(loop, server._config, InterfaceInfo(
        name="lan1", index=SECOND_INDEX,
        addrs_v4=[SECOND_V4], addrs_v6=[SECOND_V6],
    ))
    server._interfaces = {FIRST_INDEX: first, SECOND_INDEX: second}
    server._register_host_addresses()
    try:
        yield server, loop
    finally:
        _drain(loop, server)


def _on_one_link(
    loop: asyncio.AbstractEventLoop,
    server: MDNSServer,
    iface: InterfaceInfo,
) -> PerInterfaceState:
    """*iface* as an interface of *server* on a link it shares with the
    server's other interfaces.

    The transport sits on loopback, where every socket joined to the
    mDNS group receives each multicast any of them sends -- one link
    -- and reports *iface*'s index to ``_handle_message``, so each
    interface's real responder, prober and announcer hear the others
    as on a LAN.  IPv4 only: the IPv6 group is joined by interface
    index, and the made-up index has no device.
    """
    config = replace(
        server._config,
        server=replace(
            server._config.server,
            disallow_other_stacks=False,
            use_ipv6=False,
        ),
    )
    state = PerInterfaceState(
        InterfaceInfo(
            name="lo",
            index=iface.index,
            addrs_v4=[IPv4Address("127.0.0.1")],
        ),
        config,
    )
    loop.run_until_complete(
        state.transport.start(loop, server._handle_message),
    )
    assert state.transport.has_ipv4
    state.iface = iface
    server._attach_handlers(state, loop)
    return state


@pytest.fixture
def shared_link(tmp_path, make_server):
    """A server whose two interfaces hear each other, nothing else."""
    loop = asyncio.new_event_loop()
    server = make_server(tmp_path, hostname="nas")
    server._interfaces = {
        FIRST_INDEX: _on_one_link(loop, server, InterfaceInfo(
            name="lan0", index=FIRST_INDEX, addrs_v4=[FIRST_V4],
        )),
        SECOND_INDEX: _on_one_link(loop, server, InterfaceInfo(
            name="lan1", index=SECOND_INDEX, addrs_v4=[SECOND_V4],
        )),
    }
    try:
        yield server, loop
    finally:
        _drain(loop, server)


class TestOwnsRecord:
    def test_another_interfaces_records_are_ours(self, two_ports):
        server, _loop = two_ports
        first = _host_group(server, FIRST_INDEX)
        for group in server._host_groups:
            group.set_state(EntryGroupState.ESTABLISHED)
        for record in first.records:
            assert server._owns_record(record)

    def test_records_still_being_probed_are_ours(self, two_ports):
        """A group mid-probe is ours too: its own probes and the answers
        they draw come back on the other interface."""
        server, _loop = two_ports
        second = _host_group(server, SECOND_INDEX)
        second.set_state(EntryGroupState.REGISTERING)
        assert all(server._owns_record(r) for r in second.records)

    def test_identity_ignores_name_case(self, two_ports):
        """RFC 6762 §16: names compare case-insensitively."""
        server, _loop = two_ports
        assert server._owns_record(_a("NAS.Local", FIRST_V4))

    def test_another_hosts_address_is_not_ours(self, two_ports):
        server, _loop = two_ports
        assert not server._owns_record(_a(HOST_FQDN, PEER_V4))

    def test_conceded_records_are_not_ours(self, two_ports):
        """RFC 6762 §9: the loser "MUST cease using the name"; a
        group in COLLISION no longer vouches for its records."""
        server, _loop = two_ports
        second = _host_group(server, SECOND_INDEX)
        second.set_state(EntryGroupState.COLLISION)
        assert not any(server._owns_record(r) for r in second.records)


class TestEstablishedRecords:
    """``_check_established_conflicts`` with both interfaces
    established, as after startup."""

    def _establish(self, server: MDNSServer, loop) -> None:
        for group in list(server._entry_groups):
            loop.run_until_complete(server._probe_and_announce(group))
        assert all(
            g.state == EntryGroupState.ESTABLISHED
            for g in server._host_groups
        )

    def _deliver(self, server: MDNSServer, loop, message: MDNSMessage,
                 source: tuple, ifindex: int) -> int:
        """Hand *message* in on *ifindex*; return the re-probes it
        started."""
        async def run() -> int:
            server._handle_message(message, source, ifindex)
            started = len(server._conflict_tasks)
            await asyncio.gather(
                *server._conflict_tasks, return_exceptions=True,
            )
            return started

        return loop.run_until_complete(run())

    def test_announcement_from_the_other_interface_is_ours(
        self, two_ports,
    ):
        """The second interface's announcement arrives on the first:
        its address records differ from the first's, but they are the
        host's own, not another host's (RFC 6762 §14)."""
        server, loop = two_ports
        self._establish(server, loop)
        first = _host_group(server, FIRST_INDEX)
        second = _host_group(server, SECOND_INDEX)

        reprobes = self._deliver(
            server, loop, MDNSMessage.build_response(second.records),
            (str(SECOND_V4), MDNS_PORT), FIRST_INDEX,
        )

        assert reprobes == 0
        assert first.state == EntryGroupState.ESTABLISHED
        assert server._registry.lookup(HOST_FQDN, QType.A, FIRST_INDEX)

    def test_another_hosts_address_still_conflicts(self, two_ports):
        """The control: a peer's different address for our name is a
        conflict (§9), re-probed under the same name."""
        server, loop = two_ports
        self._establish(server, loop)

        reprobes = self._deliver(
            server, loop,
            MDNSMessage.build_response([_a(HOST_FQDN, PEER_V4)]),
            (str(PEER_V4), MDNS_PORT), FIRST_INDEX,
        )

        assert reprobes == 1


class TestInterfacesOnOneLink:
    def test_host_name_survives_hearing_itself(self, shared_link, caplog):
        """Both interfaces probe and announce over one link and hear
        everything the other sends: the second's probes draw the
        first's answers, and each interface's announcements reach the
        other.  The host keeps its name and both host groups hold.

        Before the fix the second interface lost every probe to the
        first's answer and the host renamed itself again and again."""
        server, loop = shared_link
        caplog.set_level(logging.INFO, logger="truenas_pymdns")
        server._register_host_addresses()

        async def run() -> None:
            await server._probe_and_announce_all()
            # The first announcement goes out at once and the next a
            # second later (RFC 6762 §8.3): let the second interface's
            # reach the first, established, one.
            await asyncio.sleep(2.5)

        loop.run_until_complete(run())

        assert server._fqdn == HOST_FQDN
        assert [g.state for g in server._host_groups] == [
            EntryGroupState.ESTABLISHED, EntryGroupState.ESTABLISHED,
        ]
        for index, address in (
            (FIRST_INDEX, FIRST_V4), (SECOND_INDEX, SECOND_V4),
        ):
            (owned,) = server._registry.lookup(HOST_FQDN, QType.A, index)
            assert owned.record.data.address == address
        conflicts = [
            r.getMessage() for r in caplog.records
            if "conflict" in r.getMessage().lower()
        ]
        assert conflicts == []

    def test_link_really_is_shared(self, shared_link):
        """The premise: what one interface multicasts, the other hears.
        A peer's answer sent on the first interface's socket must reach
        the second interface's prober as a conflict."""
        server, loop = shared_link
        server._register_host_addresses()
        first = server._interfaces[FIRST_INDEX]
        second = server._interfaces[SECOND_INDEX]
        group = _host_group(server, SECOND_INDEX)

        async def run() -> int:
            task = asyncio.create_task(
                second.prober.probe(group.get_unique_records()),
            )
            session = None
            while session is None or session.probes_sent == 0:
                await asyncio.sleep(0.005)
                session = next(iter(second.prober._sessions.values()), None)
            first.transport.send_message(
                MDNSMessage.build_response([_a(HOST_FQDN, PEER_V4)]),
            )
            await asyncio.sleep(0.2)
            seen = session.conflicts_seen
            second.prober.cancel_all()
            await task
            return seen

        assert loop.run_until_complete(run()) == 1
