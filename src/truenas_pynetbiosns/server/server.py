"""Main NetBIOS Name Service daemon orchestrator."""
from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Address
from typing import Iterable

from truenas_pydiscovery_utils.daemon import ConfigDaemon
from truenas_pydiscovery_utils.status import StatusWriter

from .config import DaemonConfig, get_netbios_name
from .browse.announcer import BrowseAnnouncer
from .core.defender import Defender
from .core.nametable import NameTable
from .core.registrar import Registrar
from .core.release import NameRecord, release_names
from .net.dedup import PacketDedup
from .net.global_receiver import NBNSGlobalReceiver
from .net.subnet import NbnsSubnet, resolve_subnets
from .net.transport import NBNSTransport
from .query.responder import Responder
from truenas_pynetbiosns.protocol.constants import (
    DGRAM_PORT,
    NBNS_PORT,
    NameType,
    Opcode,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName

logger = logging.getLogger(__name__)


class PerSubnetState:
    """Holds all per-subnet NetBIOS NS state.

    Analogous to Samba's ``subnet_record``: one entry per broadcast
    domain the daemon participates in.  A single interface with IPs in
    two subnets yields two ``PerSubnetState`` instances sharing the
    same underlying ``NBNSTransport``.
    """

    __slots__ = (
        "subnet", "transport", "name_table",
        "registrar", "defender", "responder",
        "browse_announcer",
    )

    def __init__(
        self, subnet: NbnsSubnet, transport: NBNSTransport,
    ) -> None:
        self.subnet = subnet
        self.transport = transport
        self.name_table = NameTable()
        self.registrar: Registrar | None = None
        self.defender: Defender | None = None
        self.responder: Responder | None = None
        self.browse_announcer: BrowseAnnouncer | None = None

    def stop(self) -> None:
        """Cancel owned periodic tasks.

        The transport is NOT stopped here: it's shared across every
        subnet living on the same interface, so its lifecycle is
        daemon-owned (``_transports`` dict).
        """
        if self.browse_announcer is not None:
            self.browse_announcer.cancel()


class NBNSServer(ConfigDaemon):
    """Top-level NetBIOS Name Service daemon."""

    def __init__(self, config: DaemonConfig) -> None:
        # ``ConfigDaemon`` initialises ``_config`` and
        # ``_prev_config`` (and provides the stash-on-apply_config
        # scaffolding ``_reload`` diffs against).
        super().__init__(logger, config)
        self._netbios_name = get_netbios_name(config.server)
        self._workgroup = config.server.workgroup.upper()
        # ifname -> transport shared by all subnets on that interface
        self._transports: dict[str, NBNSTransport] = {}
        # One PerSubnetState per NbnsSubnet resolved from config
        self._subnets: list[PerSubnetState] = []
        # What ``interfaces`` resolved to when ``_subnets`` was built,
        # including any subnet whose transport then failed to open.
        self._resolved_subnets: list[NbnsSubnet] = []
        # Daemon-level catchall receiver on (0.0.0.0, 137/138) for
        # limited broadcasts and anything not matching a per-interface
        # specific-IP bind.  Mirrors Samba 4.23's ``ClientNMB`` /
        # ``ClientDGRAM`` in ``open_sockets``
        # (``source3/nmbd/nmbd.c``).
        self._global_recv: NBNSGlobalReceiver | None = None
        # A subnet broadcast reaches both the subnet's broadcast socket
        # and ``_global_recv``; this drops the second copy.  Its lookups
        # evict keys older than ``DUPLICATE_PACKET_WINDOW``, so it needs
        # no clearing.
        self._dedup = PacketDedup()
        self._status = StatusWriter(config.rundir, logger)

    async def _start(self, loop) -> None:
        logger.info(
            "Starting NetBIOS NS daemon: %s (workgroup %s)",
            self._netbios_name, self._workgroup,
        )

        if not self._config.server.interfaces:
            logger.error("No interfaces configured — refusing to start")
            self._shutdown_event.set()
            return

        try:
            subnets = await loop.run_in_executor(
                None, resolve_subnets, list(self._config.server.interfaces),
            )
        except ValueError as e:
            logger.error("Cannot resolve interfaces: %s", e)
            self._shutdown_event.set()
            return

        self._resolved_subnets = subnets
        for subnet in subnets:
            await self._setup_subnet(subnet, loop)

        # Samba 4.23 ``source3/nmbd/nmbd.c:open_sockets()`` opens the
        # catchall ``ClientNMB`` / ``ClientDGRAM`` AFTER interface-
        # specific sockets are up.  We mirror that ordering.
        self._global_recv = NBNSGlobalReceiver(
            subnets=subnets,
            handler=self._handle_message,
            # No dgram_handler — the server sends port 138 browse
            # announcements but doesn't process incoming browse
            # traffic today; we'd add one here if/when that changes.
            dgram_handler=None,
        )
        await self._global_recv.start(loop)

        await asyncio.gather(*(
            self._register_names(state) for state in self._subnets
        ))

        logger.info(
            "NetBIOS NS daemon started on %d subnets across %d interfaces",
            len(self._subnets), len(self._transports),
        )

    async def _stop(self) -> None:
        logger.info("Stopping NetBIOS NS daemon")

        # As nmbd's ``terminate`` does: announce the server as gone
        # (``announce_my_servers_removed``) and release no name.  nmbd
        # releases only names registered with a WINS server
        # (``release_wins_names``).
        for state in self._subnets:
            if state.browse_announcer is not None:
                state.browse_announcer.announce_removed()

        for state in self._subnets:
            state.stop()

        if self._global_recv is not None:
            await self._global_recv.stop()
            self._global_recv = None

        for transport in self._transports.values():
            await transport.stop()

        self._subnets.clear()
        self._transports.clear()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_status)
        logger.info("NetBIOS NS daemon stopped")

    async def _reload(self) -> None:
        """SIGHUP: reconcile live state with the new config, minimally.

        Resolves ``interfaces`` again and, as nmbd's SIGHUP handler
        runs ``reload_interfaces`` (``source3/nmbd/nmbd.c``), leaves
        alone the subnets it still resolves to:

        * the subnets that are gone are closed, releasing no name
          (``_close_subnets``);
        * on the subnets that remain, the names follow the config if
          the name set, workgroup or server_string changed
          (``_live_update_reload``);
        * the subnets that are new are set up and claim the names
          (``_open_subnets``).

        With no configuration applied before (no ``_prev_config`` to
        diff against), everything is rebuilt (``_full_rebuild_reload``).

        Interface and address changes between reloads are followed by
        ``_reconcile_interfaces``; resolving again here keeps a reload
        consistent with the interfaces as they are when it runs.  If
        the new ``interfaces`` value cannot be resolved, the current
        state is kept."""
        prev = self._prev_config
        cur = self._config

        loop = asyncio.get_running_loop()
        try:
            subnets = await loop.run_in_executor(
                None, resolve_subnets, list(cur.server.interfaces),
            )
        except ValueError as e:
            logger.error("Reload: cannot resolve interfaces: %s", e)
            return

        if prev is None:
            await self._full_rebuild_reload(subnets)
            return

        changed = await self._close_subnets(set(subnets))
        if prev.server != cur.server:
            await self._live_update_reload()
        elif not changed:
            logger.info("Reload: no config changes")
            return
        if changed:
            await self._open_subnets(subnets, changed, loop)

    async def _full_rebuild_reload(self, subnets: list[NbnsSubnet]) -> None:
        """Tear down transports and registrations, rebuild on *subnets*.

        Runs when no configuration has been applied yet.  No name is
        released, as nmbd's ``close_subnet`` releases none when
        ``reload_interfaces`` closes a subnet."""
        logger.info("Reload: full rebuild")

        for state in self._subnets:
            state.stop()

        for transport in self._transports.values():
            await transport.stop()
        self._subnets.clear()
        self._transports.clear()

        self._netbios_name = get_netbios_name(self._config.server)
        self._workgroup = self._config.server.workgroup.upper()

        loop = asyncio.get_running_loop()
        self._resolved_subnets = subnets
        for subnet in subnets:
            await self._setup_subnet(subnet, loop)

        # Refresh the global receiver's subnet list so source-IP
        # dispatch matches the new config.  We don't restart the
        # underlying socket — it stays bound to 0.0.0.0:137
        # regardless of interface changes.
        if self._global_recv is not None:
            self._global_recv.update_subnets(subnets)

        await asyncio.gather(*(
            self._register_names(state) for state in self._subnets
        ))

        logger.info(
            "Full rebuild complete: %d subnets across %d interfaces",
            len(self._subnets), len(self._transports),
        )

    async def _reconcile_interfaces(self) -> None:
        """Serve the subnets ``interfaces`` resolves to now.

        Called once interface and address changes have settled (the
        composite's ``InterfaceMonitor``), as nmbd's
        ``reload_interfaces`` follows them: a subnet for each new
        address, which claims its names (``make_normal_subnet``,
        ``register_my_workgroup_one_subnet``); the subnet of each
        vanished address closed without releasing its names
        (``close_subnet``); and every other subnet left alone, its
        names still held.  nmbd polls for changes every
        ``NMBD_INTERFACES_RELOAD`` (120 s).

        nmbd opens sockets for each subnet, where one transport serves
        all the subnets of an interface here, bound to one of their
        addresses.  When that address goes away, the interface is set
        up afresh and its remaining subnets claim their names again.
        If ``interfaces`` cannot be resolved, the current state is
        kept."""
        if not self._config.server.interfaces:
            return
        loop = asyncio.get_running_loop()
        try:
            subnets = await loop.run_in_executor(
                None, resolve_subnets, list(self._config.server.interfaces),
            )
        except ValueError as e:
            logger.error("Interface update: cannot resolve interfaces: %s", e)
            return
        await self._apply_subnets(subnets, loop)

    async def _apply_subnets(
        self, subnets: list[NbnsSubnet], loop: asyncio.AbstractEventLoop,
    ) -> None:
        """``_reconcile_interfaces`` for the resolved *subnets*."""
        changed = await self._close_subnets(set(subnets))
        if changed:
            await self._open_subnets(subnets, changed, loop)

    async def _close_subnets(self, current: set[NbnsSubnet]) -> set[str]:
        """Close each served subnet not in *current*, releasing no name,
        and every subnet of an interface whose transport is bound to an
        address that went away; return the names of the interfaces
        whose subnets changed."""
        changed = {
            subnet.interface_name
            for subnet in set(self._resolved_subnets) ^ current
        }
        if not changed:
            return changed
        logger.info("Subnets changed on %s", ", ".join(sorted(changed)))
        bound = {
            name: transport.interface_addr
            for name, transport in self._transports.items()
        }
        rebuilt = {
            name for name in changed
            if not any(
                subnet.interface_name == name
                and str(subnet.my_ip) == bound.get(name)
                for subnet in current
            )
        }
        for state in [
            state for state in self._subnets
            if state.subnet.interface_name in rebuilt
            or state.subnet not in current
        ]:
            state.stop()
            self._subnets.remove(state)
        for name in sorted(rebuilt):
            transport = self._transports.pop(name, None)
            if transport is not None:
                await transport.stop()
        return changed

    async def _open_subnets(
        self,
        subnets: list[NbnsSubnet],
        changed: set[str],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Serve *subnets*: set up those of the *changed* interfaces
        not served yet, and claim the names on them."""
        self._resolved_subnets = subnets
        served = {state.subnet for state in self._subnets}
        kept = len(self._subnets)
        for subnet in subnets:
            if subnet.interface_name in changed and subnet not in served:
                await self._setup_subnet(subnet, loop)
        if self._global_recv is not None:
            self._global_recv.update_subnets(subnets)
        await asyncio.gather(*(
            self._register_names(state) for state in self._subnets[kept:]
        ))

    async def _live_update_reload(self) -> None:
        """In-place reconciliation of the names on the served subnets.

        Runs when the [netbiosns] config differs from the previous one
        — a new alias, a workgroup rename, a server-string tweak from
        middleware — on the subnets that remain after
        ``_close_subnets``.  Diffs the set of (name, type, is_group)
        registrations implied by the old vs. new config:

        * Names that went away are released on every subnet, as
          nmbd releases a name it gives up while running
          (``unbecome_local_master_browser``), and pulled from each
          name table so the responder stops answering for them.
        * Names newly present are registered via the existing
          registrar.
        * Each subnet's ``BrowseAnnouncer`` gets its cached
          hostname / workgroup / server_string updated in place so
          the next HostAnnouncement iteration carries the new
          payload without resetting the announce cadence.

        Transports stay bound.  No release packets go out for
        names we're keeping — that was the whole point of the
        delta path."""
        assert self._prev_config is not None
        prev_srv = self._prev_config.server
        cur_srv = self._config.server

        prev_netbios = get_netbios_name(prev_srv)
        prev_workgroup = prev_srv.workgroup.upper()
        new_netbios = get_netbios_name(cur_srv)
        new_workgroup = cur_srv.workgroup.upper()

        old_names = _expected_name_records(
            prev_srv, prev_netbios, prev_workgroup,
        )
        new_names = _expected_name_records(
            cur_srv, new_netbios, new_workgroup,
        )

        to_release = old_names - new_names
        to_register = new_names - old_names

        if to_release:
            for state in self._subnets:
                release_names(
                    _broadcast_sender(state.transport, state.subnet),
                    state.name_table,
                    state.subnet.my_ip,
                    to_release,
                )

        self._netbios_name = new_netbios
        self._workgroup = new_workgroup

        if to_register:
            await asyncio.gather(*(
                _register_records(state, to_register)
                for state in self._subnets
            ))

        for state in self._subnets:
            if state.browse_announcer is None:
                continue
            state.browse_announcer.set_hostname(new_netbios)
            state.browse_announcer.set_workgroup(new_workgroup)
            state.browse_announcer.set_server_string(cur_srv.server_string)

        logger.info(
            "Live update complete: released %d, registered %d, "
            "kept %d (%d subnets)",
            len(to_release), len(to_register),
            len(new_names & old_names), len(self._subnets),
        )

    def _write_status(self) -> None:
        ifaces: dict[str, dict] = {}
        for state in self._subnets:
            entry = ifaces.setdefault(
                state.subnet.interface_name,
                {"subnets": []},
            )
            entry["subnets"].append({
                "ipv4": str(state.subnet.my_ip),
                "netmask": str(state.subnet.netmask),
                "broadcast": str(state.subnet.broadcast),
                "name_table": state.name_table.stats(),
            })

        self._status.write({
            "netbios_name": self._netbios_name,
            "workgroup": self._workgroup,
            "state": "running",
            "interfaces": ifaces,
        })

    # -- Interface setup ----------------------------------------------------

    async def _setup_subnet(
        self, subnet: NbnsSubnet, loop,
    ) -> None:
        transport = self._transports.get(subnet.interface_name)
        if transport is None:
            transport = NBNSTransport(
                interface_name=subnet.interface_name,
                interface_addr=str(subnet.my_ip),
                broadcast_addr=str(subnet.broadcast),
            )
            await transport.start(loop, self._handle_message)
            if not transport.is_active:
                return
            self._transports[subnet.interface_name] = transport

        state = PerSubnetState(subnet, transport)
        send_broadcast = _broadcast_sender(transport, subnet)
        state.registrar = Registrar(
            send_broadcast, state.name_table,
        )
        state.defender = Defender(
            transport.send_unicast, state.name_table,
        )
        state.responder = Responder(
            transport.send_unicast, state.name_table,
        )
        # No name refresh: nmbd refreshes only names registered with a
        # WINS server (``refresh_my_names``), and RFC 1001 §15.5.1
        # leaves refresh to P and M nodes.

        # MS-BRWS §3.2.5.2: periodic HostAnnouncement on port 138.
        state.browse_announcer = BrowseAnnouncer(
            send_fn=_dgram_broadcast_sender(transport, subnet),
            hostname=self._netbios_name,
            workgroup=self._workgroup,
            server_string=self._config.server.server_string,
            source_ip=subnet.my_ip,
        )
        state.browse_announcer.start()

        self._subnets.append(state)
        logger.info(
            "Subnet ready: %s on %s (bcast %s)",
            subnet.my_ip, subnet.interface_name, subnet.broadcast,
        )

    # -- Name registration --------------------------------------------------

    async def _register_names(self, state: PerSubnetState) -> None:
        """Register all configured names on one subnet at once."""
        await _register_records(state, _expected_name_records(
            self._config.server, self._netbios_name, self._workgroup,
        ))

    # -- Message handling ---------------------------------------------------

    def _handle_message(
        self,
        msg: NBNSMessage,
        source: tuple[str, int],
        ifname: str,
    ) -> None:
        """Dispatch an inbound NBNS message to the matching subnet handler.

        Multiple subnets may share one interface; pick the one whose
        network contains the source address.  A broadcast arrives here
        once per socket that received it; only the first copy is
        dispatched (see ``PacketDedup``).
        """
        try:
            src_ip = IPv4Address(source[0])
        except ValueError:
            return

        state = self._find_subnet_for(ifname, src_ip)
        if state is None:
            return

        if self._dedup.is_duplicate(
            (source, msg.trn_id, msg.opcode, msg.is_response),
        ):
            return

        if msg.is_response:
            if msg.rcode != 0 and state.registrar:
                for rr in msg.answers:
                    state.registrar.on_conflict(rr.name, msg.trn_id)
        else:
            if msg.opcode in (
                Opcode.REGISTRATION,
                Opcode.REFRESH,
                Opcode.MULTIHOMED_REG,
            ):
                if state.defender:
                    state.defender.handle_registration(msg, source)
            elif msg.opcode == Opcode.QUERY:
                if state.responder:
                    state.responder.handle_query(msg, source)

    def _find_subnet_for(
        self, ifname: str, src_ip,
    ) -> PerSubnetState | None:
        """Return the subnet state for *ifname* whose network covers *src_ip*.

        Falls back to the first matching ifname if no network matches
        (e.g. packets from outside any configured subnet — rare, and
        safe to let a responder filter them downstream).
        """
        fallback: PerSubnetState | None = None
        for state in self._subnets:
            if state.subnet.interface_name != ifname:
                continue
            if fallback is None:
                fallback = state
            if src_ip in state.subnet.network:
                return state
        return fallback


def _broadcast_sender(transport: NBNSTransport, subnet: NbnsSubnet):
    """Build a send-broadcast callable targeting this subnet's bcast addr."""
    dst = (str(subnet.broadcast), NBNS_PORT)

    def send(message: NBNSMessage) -> None:
        transport.send_unicast(message, dst)

    return send


def _dgram_broadcast_sender(transport: NBNSTransport, subnet: NbnsSubnet):
    """Build a send-datagram callable targeting this subnet's bcast addr."""
    dst = (str(subnet.broadcast), DGRAM_PORT)

    def send(data: bytes) -> None:
        transport.send_dgram(data, dst)

    return send


async def _register_records(
    state: PerSubnetState, records: Iterable[NameRecord],
) -> None:
    """Claim every name in *records* on *state*'s subnet concurrently.

    Each claim is its own registration request with its own NAME_TRN_ID
    and its own retransmissions, as Samba nmbd queues one response
    record per name (``register_name``, called for each name by
    ``register_my_workgroup_one_subnet``) and retransmits them all from
    one loop.  A NetBIOS name listed more than once (names compare
    case-insensitively) is claimed once; for one name listed both as a
    unique and as a group name, the unique claim is made."""
    registrar = state.registrar
    if registrar is None:
        return
    claims: dict[NetBIOSName, NameRecord] = {}
    for record in sorted(records):
        name, name_type, _is_group = record
        claims.setdefault(NetBIOSName(name, name_type), record)
    ip = state.subnet.my_ip
    await asyncio.gather(*(
        registrar.register(name, name_type, ip, group=is_group)
        for name, name_type, is_group in claims.values()
    ))


def _expected_name_records(
    server_cfg, netbios_name: str, workgroup: str,
) -> set[NameRecord]:
    """Full set of (name, type, is_group) registrations implied by *cfg*.

    The names ``NBNSServer._register_names`` claims: every
    ``(primary + alias)`` times three service types (workstation,
    messenger, server) as unique names, plus the workgroup as a
    group-name registration.  Diffing the old and new sets yields
    the exact names to release and to register on a live-update
    reload."""
    names: set[NameRecord] = set()
    all_hostnames = [netbios_name] + list(server_cfg.netbios_aliases)
    for hostname in all_hostnames:
        for nt in (
            NameType.WORKSTATION,
            NameType.MESSENGER,
            NameType.SERVER,
        ):
            names.add((hostname, nt, False))
    names.add((workgroup, NameType.WORKSTATION, True))
    return names
