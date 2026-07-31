"""Per-interface scoping of host A/AAAA records (RFC 6762 §6.2, §14).

A responder "MUST include all addresses that are valid on the
interface on which it is sending the message, and MUST NOT include
addresses that are not valid on that interface (such as addresses
that may be configured on the host's other interfaces)", restated as
a MUST for multihomed hosts in §14.

On a multihomed host the practical failure is a client on the LAN
learning an address that only exists on an isolated link — a dedicated
replication DAC, a storage VLAN — and stalling when it picks that one
to connect to.  Scoping is carried by ``EntryGroup.interfaces``, which
``ServiceRegistry.lookup`` already honours, so these tests cover both
halves: that ``_register_host_addresses`` builds one bound group per
interface, and that the registry and responder then keep direct
answers *and* DNS-SD additionals on their own link.

§14 adds the counterweight: the name itself stays global, so a
conflict seen on one interface has to rename the host on all of them.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address, IPv6Address

import pytest

from truenas_pymdns.protocol.constants import (
    MDNS_PORT,
    EntryGroupState,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage, MDNSQuestion
from truenas_pymdns.server.core.entry_group import EntryGroup
from truenas_pymdns.server.net.interface import InterfaceInfo
from truenas_pymdns.server.query.responder import Responder
from truenas_pymdns.server.server import MDNSServer
from truenas_pymdns.server.service.registry import ServiceRegistry

# RFC 5737 / RFC 3849 documentation ranges standing in for a LAN
# interface and an isolated point-to-point replication link.
LAN_V4 = IPv4Address("192.0.2.10")
LAN_V4_ALT = IPv4Address("192.0.2.11")
LAN_V6 = IPv6Address("2001:db8:1::10")
P2P_V4 = IPv4Address("198.51.100.1")

LAN_INDEX = 11
P2P_INDEX = 22

HOST_FQDN = "nas.local"


@pytest.fixture
def multihomed(tmp_path, make_server, started_state):
    """A server with two interfaces: a LAN link and an isolated one."""
    loop = asyncio.new_event_loop()
    server = make_server(tmp_path, hostname="nas")
    lan = started_state(loop, server._config, InterfaceInfo(
        name="lan0", index=LAN_INDEX,
        addrs_v4=[LAN_V4], addrs_v6=[LAN_V6],
    ))
    p2p = started_state(loop, server._config, InterfaceInfo(
        name="repl0", index=P2P_INDEX, addrs_v4=[P2P_V4],
    ))
    server._interfaces = {LAN_INDEX: lan, P2P_INDEX: p2p}
    try:
        yield server, loop
    finally:
        for state in server._interfaces.values():
            loop.run_until_complete(state.stop())
        loop.close()


def _addresses(group: EntryGroup) -> set:
    return {
        r.data.address for r in group.records
        if r.key.rtype in (QType.A, QType.AAAA)
    }


def _answer_addresses(msg: MDNSMessage) -> set:
    return {
        r.data.address for r in msg.answers
        if r.key.rtype in (QType.A, QType.AAAA)
    }


def _additional_addresses(msg: MDNSMessage) -> set:
    return {
        r.data.address for r in msg.additionals
        if r.key.rtype in (QType.A, QType.AAAA)
    }


def _host_names(group: EntryGroup) -> set:
    return {
        r.key.name for r in group.records
        if r.key.rtype in (QType.A, QType.AAAA)
    }


class TestRegisterHostAddresses:
    def test_one_group_per_interface_bound_to_its_own_index(
        self, multihomed,
    ):
        server, _loop = multihomed
        server._register_host_addresses()

        assert len(server._host_groups) == 2
        assert [g.interfaces for g in server._host_groups] == [
            [LAN_INDEX], [P2P_INDEX],
        ]
        # An unbound group (interfaces is None) publishes on every
        # link, so no host group may carry one.
        assert all(g.interfaces is not None for g in server._host_groups)

    def test_group_holds_only_its_own_interfaces_addresses(
        self, multihomed,
    ):
        server, _loop = multihomed
        server._register_host_addresses()

        lan_group, p2p_group = server._host_groups
        assert _addresses(lan_group) == {LAN_V4, LAN_V6}
        assert _addresses(p2p_group) == {P2P_V4}

    def test_interface_with_no_addresses_registers_no_group(
        self, multihomed, started_state,
    ):
        server, loop = multihomed
        bare = started_state(loop, server._config, InterfaceInfo(
            name="bare0", index=33,
        ))
        server._interfaces[33] = bare
        server._register_host_addresses()

        assert [g.interfaces for g in server._host_groups] == [
            [LAN_INDEX], [P2P_INDEX],
        ]


class TestResponderScoping:
    """RFC 6762 §6.2 as observed on the wire."""

    def _responder(self, server: MDNSServer):
        # Registered through ``_entry_groups`` — whatever
        # ``_register_host_addresses`` published, bound or not — so
        # these assertions turn on the addresses that come back on the
        # wire rather than on how the groups happen to be indexed.
        registry = ServiceRegistry()
        for group in server._entry_groups:
            registry.add_group(group)
        loop = asyncio.new_event_loop()
        unicast: list[tuple] = []
        resp = Responder(
            lambda *a, **kw: None,
            lambda msg, dest: unicast.append((msg, dest)),
            registry,
        )
        resp.start(loop)
        return resp, unicast, loop, registry

    def test_address_query_answers_only_with_that_links_address(
        self, multihomed,
    ):
        server, _loop = multihomed
        server._register_host_addresses()
        resp, unicast, loop, _reg = self._responder(server)
        try:
            # QU query so the response is emitted synchronously.
            query = MDNSMessage(questions=[
                MDNSQuestion(HOST_FQDN, QType.ANY, unicast_response=True),
            ])
            resp.handle_query(
                query, ("192.0.2.50", MDNS_PORT),
                interface_index=LAN_INDEX,
            )
            assert len(unicast) == 1
            msg, _dest = unicast[0]
            assert _answer_addresses(msg) == {LAN_V4, LAN_V6}
            assert P2P_V4 not in _answer_addresses(msg)
        finally:
            resp.cancel_all()
            loop.close()

    def test_isolated_link_does_not_learn_the_lan_address(
        self, multihomed,
    ):
        server, _loop = multihomed
        server._register_host_addresses()
        resp, unicast, loop, _reg = self._responder(server)
        try:
            query = MDNSMessage(questions=[
                MDNSQuestion(HOST_FQDN, QType.ANY, unicast_response=True),
            ])
            resp.handle_query(
                query, ("198.51.100.2", MDNS_PORT),
                interface_index=P2P_INDEX,
            )
            assert len(unicast) == 1
            msg, _dest = unicast[0]
            assert _answer_addresses(msg) == {P2P_V4}
        finally:
            resp.cancel_all()
            loop.close()

    def test_browse_additionals_carry_only_that_links_address(
        self, multihomed,
    ):
        """RFC 6763 §12 additionals inherit the §6.2 scoping.

        This is the path Finder uses: a client browsing ``_smb._tcp``
        takes the connect address straight out of the additional
        records attached to the PTR answer, so an unreachable address
        handed out here is what makes ``smb://nas.local``
        intermittently hang.  Apple applies the same interface filter
        to additionals (``AddAdditionalsToResponseList``).
        """
        server, _loop = multihomed
        server._register_host_addresses()
        resp, unicast, loop, registry = self._responder(server)
        try:
            # A services.d-style group: not bound to any interface,
            # SRV pointing at the host name.
            svc = EntryGroup()
            svc.add_service(
                instance="nas", service_type="_smb._tcp",
                domain="local", host=HOST_FQDN, port=445,
            )
            registry.add_group(svc)

            def _browse(source: str, ifindex: int) -> set:
                unicast.clear()
                resp.handle_query(
                    MDNSMessage(questions=[
                        MDNSQuestion(
                            "_smb._tcp.local", QType.PTR,
                            unicast_response=True,
                        ),
                    ]),
                    (source, MDNS_PORT), interface_index=ifindex,
                )
                assert len(unicast) == 1
                msg, _dest = unicast[0]
                return _additional_addresses(msg)

            assert _browse("192.0.2.50", LAN_INDEX) == {LAN_V4, LAN_V6}
            # Browsing from the isolated link is the discriminating
            # direction: the additionals come from a registry lookup,
            # and this asserts that lookup filters by the arrival
            # interface rather than handing out the LAN's addresses,
            # which are unreachable from this link.
            assert _browse("198.51.100.2", P2P_INDEX) == {P2P_V4}
        finally:
            resp.cancel_all()
            loop.close()

    def test_additionals_carry_every_address_on_the_link(
        self, multihomed,
    ):
        """RFC 6762 §6.2 also sets a floor, not just a ceiling.

        A response "MUST include all addresses that are valid on the
        interface on which it is sending the message", so an interface
        holding two addresses of the same family has to contribute
        both: every member of the RRSet must survive the additionals
        de-duplication.
        """
        server, _loop = multihomed
        server._interfaces[LAN_INDEX].iface = InterfaceInfo(
            name="lan0", index=LAN_INDEX,
            addrs_v4=[LAN_V4, LAN_V4_ALT], addrs_v6=[LAN_V6],
        )
        server._register_host_addresses()
        resp, unicast, loop, registry = self._responder(server)
        try:
            svc = EntryGroup()
            svc.add_service(
                instance="nas", service_type="_smb._tcp",
                domain="local", host=HOST_FQDN, port=445,
            )
            registry.add_group(svc)
            resp.handle_query(
                MDNSMessage(questions=[
                    MDNSQuestion(
                        "_smb._tcp.local", QType.PTR,
                        unicast_response=True,
                    ),
                ]),
                ("192.0.2.50", MDNS_PORT), interface_index=LAN_INDEX,
            )
            assert len(unicast) == 1
            msg, _dest = unicast[0]
            assert _additional_addresses(msg) == {
                LAN_V4, LAN_V4_ALT, LAN_V6,
            }
        finally:
            resp.cancel_all()
            loop.close()


class TestHostRenameEscalation:
    """RFC 6762 §14: the host name stays global across interfaces.

    A collision only ever marks the group for the interface the
    conflicting response arrived on, but the name is not per-link.
    ``_rename_host_after_conflict`` re-registers the whole registry,
    so every interface's host group is rebuilt from the new FQDN —
    these check that no link is left on the conceded name and that
    §6.2 scoping survives the rebuild.
    """

    def _collide(self, server, loop):
        server._register_host_addresses()
        for group in list(server._entry_groups):
            loop.run_until_complete(server._probe_and_announce(group))
        assert all(
            _host_names(g) == {HOST_FQDN} for g in server._host_groups
        )
        server._host_groups[0].set_state(EntryGroupState.COLLISION)
        loop.run_until_complete(server._resolve_conflict([]))

    def test_conflict_on_one_interface_renames_host_on_all(
        self, multihomed,
    ):
        server, loop = multihomed
        self._collide(server, loop)

        # "In the event of a name conflict on *any* interface, a host
        # should configure a new host name" — the isolated link must
        # not keep answering to the name that just lost.
        assert len(server._host_groups) == 2
        assert _host_names(server._host_groups[0]) == {"nas-2.local"}
        assert _host_names(server._host_groups[1]) == {"nas-2.local"}

    def test_rename_keeps_each_group_on_its_own_addresses(
        self, multihomed,
    ):
        server, loop = multihomed
        self._collide(server, loop)

        # The §6.2 scoping has to survive a §14 rename: re-registering
        # rebuilds the groups from the same per-interface addresses.
        lan_group, p2p_group = server._host_groups
        assert _addresses(lan_group) == {LAN_V4, LAN_V6}
        assert _addresses(p2p_group) == {P2P_V4}
        assert lan_group.interfaces == [LAN_INDEX]
        assert p2p_group.interfaces == [P2P_INDEX]

    def test_reverse_ptr_targets_follow_the_rename(self, multihomed):
        server, loop = multihomed
        self._collide(server, loop)

        for group in server._host_groups:
            targets = {
                r.data.target for r in group.records
                if r.key.rtype == QType.PTR
            }
            assert targets == {"nas-2.local"}
