"""What can and cannot move the name the daemon answers to.

The mDNS host name is established by probing at startup and is then
fixed for the life of the process, with exactly one thing allowed to
move it: RFC 6762 §9 conflict resolution, where the loser of a probe
"MUST cease using the name, and reconfigure".

SIGHUP deliberately does not.  Re-deriving the name from config on
every reload would silently revert a name the daemon had legitimately
won, putting it back onto the contested name and re-colliding.
Middleware already restarts rather than reloads for a hostname edit,
so nothing depends on the reload path carrying it.

Ceasing to use a name means more than moving the A/AAAA records: the
host FQDN is also every service's SRV target, and a stale target
points clients at the host that just won the name — they resolve it
and connect to the wrong machine rather than failing.  So the whole
registry re-registers, which also gives §14 ("in the event of a name
conflict on *any* interface, a host should configure a new host name")
for free.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address

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
from truenas_pymdns.server.config import (
    DaemonConfig,
    ServerConfig,
    ServiceConfig,
    generate_service_config,
)
from truenas_pymdns.server.core.prober import Prober
from truenas_pymdns.server.net.interface import InterfaceInfo

LAN_INDEX = 11
LAN_V4 = IPv4Address("192.0.2.10")
P2P_INDEX = 22
P2P_V4 = IPv4Address("198.51.100.1")


def _write_svc(server, filename="smb.conf", instance_name="%h") -> None:
    (server._config.service_dir / filename).write_bytes(
        generate_service_config(ServiceConfig(
            service_type="_smb._tcp", port=445,
            instance_name=instance_name,
        )),
    )


def _srv_targets(server) -> set:
    return {
        r.data.target
        for group in server._entry_groups
        for r in group.records
        if r.key.rtype == QType.SRV
    }


def _host_names(server) -> set:
    return {
        r.key.name
        for group in server._host_groups
        for r in group.records
        if r.key.rtype in (QType.A, QType.AAAA)
    }


@pytest.fixture
def server_with_service(tmp_path, make_server, started_state):
    """A running-ish server: one interface, one services.d service."""
    loop = asyncio.new_event_loop()
    server = make_server(tmp_path, hostname="nas")
    _write_svc(server)
    state = started_state(loop, server._config, InterfaceInfo(
        name="lan0", index=LAN_INDEX, addrs_v4=[LAN_V4],
    ))
    server._interfaces = {LAN_INDEX: state}
    loop.run_until_complete(server._load_static_services())
    server._register_host_addresses()
    for group in list(server._entry_groups):
        loop.run_until_complete(server._probe_and_announce(group))
    try:
        yield server, loop
    finally:
        loop.run_until_complete(state.stop())
        loop.close()


class TestSighupDoesNotRename:
    """A reload must never move the name we answer to."""

    def test_configured_host_name_change_is_ignored(
        self, tmp_path, make_server,
    ):
        server = make_server(tmp_path, hostname="oldhost")
        _write_svc(server)
        asyncio.run(server._reload())
        assert server._fqdn == "oldhost.local"

        server.apply_config(DaemonConfig(
            server=ServerConfig(host_name="newhost"),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        ))
        asyncio.run(server._reload())

        assert server._hostname == "oldhost"
        assert server._fqdn == "oldhost.local"
        assert _srv_targets(server) == {"oldhost.local"}

    def test_configured_domain_change_is_ignored(
        self, tmp_path, make_server,
    ):
        server = make_server(tmp_path, hostname="host")
        _write_svc(server)
        asyncio.run(server._reload())
        assert server._fqdn == "host.local"

        server.apply_config(DaemonConfig(
            server=ServerConfig(host_name="host", domain_name="lan"),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        ))
        asyncio.run(server._reload())

        assert server._fqdn == "host.local"

    def test_a_won_name_survives_a_reload(self, server_with_service):
        """The regression this design exists to prevent.

        A daemon that renamed itself to settle a conflict must not be
        put back on the contested name by an unrelated reload — a
        services.d edit, an interface change, anything.
        """
        server, loop = server_with_service
        server._host_groups[0].set_state(EntryGroupState.COLLISION)
        loop.run_until_complete(server._resolve_conflict([]))
        won = server._fqdn
        assert won == "nas-2.local"

        # An unrelated SIGHUP: config still carries the original name.
        server.apply_config(DaemonConfig(
            server=ServerConfig(host_name="nas"),
            service_dir=server._config.service_dir,
            rundir=server._config.rundir,
        ))
        loop.run_until_complete(server._reload())

        assert server._fqdn == won
        assert _host_names(server) == {won}
        assert _srv_targets(server) == {won}


class TestConflictRenamePropagates:
    """RFC 6762 §9: the loser MUST cease using the name."""

    def test_service_srv_targets_follow_the_host_rename(
        self, server_with_service,
    ):
        server, loop = server_with_service
        assert _srv_targets(server) == {"nas.local"}

        server._host_groups[0].set_state(EntryGroupState.COLLISION)
        loop.run_until_complete(server._resolve_conflict([]))

        # The contested name must appear nowhere: not as an address
        # record name, and not as an SRV target pointing at the host
        # that won it.
        assert server._fqdn == "nas-2.local"
        assert _host_names(server) == {"nas-2.local"}
        assert _srv_targets(server) == {"nas-2.local"}

    def test_templated_instance_name_follows_too(
        self, tmp_path, make_server, started_state,
    ):
        """``instance_name = %h`` bakes the host name into the
        instance, so it has to be re-templated, not just re-targeted."""
        loop = asyncio.new_event_loop()
        server = make_server(tmp_path, hostname="nas")
        _write_svc(server, instance_name="%h")
        state = started_state(loop, server._config, InterfaceInfo(
            name="lan0", index=LAN_INDEX, addrs_v4=[LAN_V4],
        ))
        server._interfaces = {LAN_INDEX: state}
        loop.run_until_complete(server._load_static_services())
        server._register_host_addresses()
        for group in list(server._entry_groups):
            loop.run_until_complete(server._probe_and_announce(group))
        try:
            assert {k.instance_name for k in server._service_groups} == {
                "nas",
            }

            server._host_groups[0].set_state(EntryGroupState.COLLISION)
            loop.run_until_complete(server._resolve_conflict([]))

            assert {
                k.instance_name for k in server._service_groups
            } == {"nas-2"}
        finally:
            loop.run_until_complete(state.stop())
            loop.close()

    def test_status_reports_the_won_name(self, server_with_service):
        """Middleware's only view of the won name is the status file."""
        server, loop = server_with_service
        server._host_groups[0].set_state(EntryGroupState.COLLISION)
        loop.run_until_complete(server._resolve_conflict([]))

        server._write_status()
        import json
        status = json.loads(
            (server._config.rundir / "status.json").read_text(),
        )
        assert status["hostname"] == "nas-2.local"

    def test_repeated_conflicts_keep_incrementing(
        self, server_with_service,
    ):
        """RFC 6762 §9 step 2: "Probe again, and repeat as necessary
        until a unique name is found"."""
        server, loop = server_with_service
        for expected in ("nas-2.local", "nas-3.local", "nas-4.local"):
            server._host_groups[0].set_state(EntryGroupState.COLLISION)
            loop.run_until_complete(server._resolve_conflict([]))
            assert server._fqdn == expected
            assert _srv_targets(server) == {expected}

    def test_nested_conflict_during_rebuild_is_dropped(
        self, server_with_service,
    ):
        """A conflict raised against the half-published records must
        not start a second rename on top of the first.

        Renaming again from inside the rebuild would abandon it partway
        (the rebuild cancels the conflict tasks it runs among), so the
        second is dropped; convergence is carried by the rename loop
        instead, which re-checks the host groups after every rebuild
        (``TestRenameConvergence``).
        """
        server, loop = server_with_service

        async def _concurrent() -> None:
            server._host_groups[0].set_state(EntryGroupState.COLLISION)
            await asyncio.gather(
                server._rename_host_after_conflict(),
                server._rename_host_after_conflict(),
            )

        loop.run_until_complete(_concurrent())

        # One increment, not two.
        assert server._fqdn == "nas-2.local"
        assert _srv_targets(server) == {"nas-2.local"}
        # And the guard released, so a later conflict still works.
        assert server._rehoming is False

    def test_service_conflict_does_not_touch_the_host_name(
        self, server_with_service,
    ):
        """A service-instance collision is local to its group — it must
        not drag the host name along with it."""
        server, loop = server_with_service
        svc_group = next(iter(server._service_groups.values()))
        svc_group.set_state(EntryGroupState.COLLISION)
        loop.run_until_complete(server._resolve_conflict([]))

        assert server._fqdn == "nas.local"
        assert _host_names(server) == {"nas.local"}
        # The SRV target still points at the host; only the instance
        # name moved.
        assert _srv_targets(server) == {"nas.local"}


class TestRenameConvergence:
    """RFC 6762 §9: "Probe again, and repeat as necessary until a
    unique name is found."

    Both references re-fire the rename on every conflict — Apple's
    ``mDNS_HostNameCallback`` runs ``IncrementLabelSuffix`` +
    ``mDNS_SetFQDN`` again each time, avahi re-enters
    ``AVAHI_SERVER_COLLISION`` and picks another alternative name — so
    a renamed-to name that is *also* taken must lead to a third name,
    never to a wedged half-registered state.
    """

    def test_second_conflict_during_rebuild_renames_again(
        self, tmp_path, make_server, started_state,
    ):
        """A peer owns the renamed-to name on one of two links.

        The LAN host group's re-probe for the new name fails while the
        rebuild is still walking the remaining groups, so the nested
        rename attempt it raises lands inside the ``_rehoming`` window
        and is dropped.  The rename loop's post-rebuild check carries
        the retry: every link must come back established under a third
        name, with no host group left in COLLISION and no link silent
        for the host name.
        """
        loop = asyncio.new_event_loop()
        server = make_server(tmp_path, hostname="nas")
        lan = started_state(loop, server._config, InterfaceInfo(
            name="lan0", index=LAN_INDEX, addrs_v4=[LAN_V4],
        ))
        p2p = started_state(loop, server._config, InterfaceInfo(
            name="repl0", index=P2P_INDEX, addrs_v4=[P2P_V4],
        ))
        server._interfaces = {LAN_INDEX: lan, P2P_INDEX: p2p}
        try:
            async def scenario() -> None:
                # Establish under "nas" with no probers attached, then
                # bolt real probers on so only the conflict-driven
                # rebuilds go through actual probing.
                server._register_host_addresses()
                for group in list(server._entry_groups):
                    await server._probe_and_announce(group)

                # The LAN peer owns "nas-2.local" and defends it: any
                # probe naming it is answered straight back into the
                # prober, the way a zero-latency network would.  Its A
                # rdata (203.0.113.200) is lexicographically greater
                # than ours (192.0.2.10), so we lose every §8.2
                # tiebreak.  "nas-3.local" is undefended.
                contested = "nas-2.local"
                peer = MDNSRecord(
                    key=MDNSRecordKey(contested, QType.A),
                    ttl=120,
                    data=ARecordData(IPv4Address("203.0.113.200")),
                    cache_flush=True,
                )

                def lan_send(msg: MDNSMessage) -> None:
                    if any(
                        q.name.lower() == contested
                        for q in msg.questions
                    ):
                        lan.prober.handle_incoming(
                            MDNSMessage.build_response([peer]),
                            ("203.0.113.200", MDNS_PORT),
                        )

                lan.prober = Prober(lan_send, server._on_conflict)
                p2p.prober = Prober(
                    lambda *a, **kw: None, server._on_conflict,
                )

                server._host_groups[0].set_state(
                    EntryGroupState.COLLISION,
                )
                await server._resolve_conflict([])

            loop.run_until_complete(scenario())

            assert server._fqdn == "nas-3.local"
            assert server._rehoming is False
            assert _host_names(server) == {"nas-3.local"}
            assert all(
                g.state == EntryGroupState.ESTABLISHED
                for g in server._host_groups
            )
            # §6.2 scoping survives the double rename.
            lan_group, p2p_group = server._host_groups
            assert lan_group.interfaces == [LAN_INDEX]
            assert p2p_group.interfaces == [P2P_INDEX]
            # The conceded names answer nowhere.
            for dead in ("nas.local", "nas-2.local"):
                assert server._registry.lookup(
                    dead, QType.A, LAN_INDEX,
                ) == []
        finally:
            loop.run_until_complete(lan.stop())
            loop.run_until_complete(p2p.stop())
            loop.close()
