"""Main NetBIOS Name Service daemon orchestrator."""
from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Address

from truenas_pydiscovery_utils.daemon import ConfigDaemon
from truenas_pydiscovery_utils.status import StatusWriter

from .config import DaemonConfig, get_netbios_name
from .browse.announcer import BrowseAnnouncer
from .core.defender import Defender
from .core.nametable import NameTable
from .core.refresher import Refresher
from .core.registrar import Registrar
from .core.release import NameRecord, release_all_names, release_names
from .net.global_receiver import NBNSGlobalReceiver
from .net.subnet import NbnsSubnet, resolve_subnets
from .net.transport import NBNSTransport
from .query.responder import Responder
from truenas_pynetbiosns.protocol.constants import (
    NBNS_PORT,
    NameType,
    Opcode,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage

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
        "registrar", "defender", "refresher", "responder",
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
        self.refresher: Refresher | None = None
        self.responder: Responder | None = None
        self.browse_announcer: BrowseAnnouncer | None = None

    def stop(self) -> None:
        """Cancel owned periodic tasks.

        The transport is NOT stopped here: it's shared across every
        subnet living on the same interface, so its lifecycle is
        daemon-owned (``_transports`` dict).  Name releases are
        protocol-level behaviour and stay in the daemon where the
        broadcast-send closure is built.
        """
        if self.refresher is not None:
            self.refresher.cancel()
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
        # Daemon-level catchall receiver on (0.0.0.0, 137/138) for
        # limited broadcasts and anything not matching a per-interface
        # specific-IP bind.  Mirrors Samba 4.23's ``ClientNMB`` /
        # ``ClientDGRAM`` at ``source3/nmbd/nmbd.c:735-744``.
        self._global_recv: NBNSGlobalReceiver | None = None
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

        for state in self._subnets:
            await self._register_names(state)

        logger.info(
            "NetBIOS NS daemon started on %d subnets across %d interfaces",
            len(self._subnets), len(self._transports),
        )

    async def _stop(self) -> None:
        logger.info("Stopping NetBIOS NS daemon")

        for state in self._subnets:
            release_all_names(
                _broadcast_sender(state.transport, state.subnet),
                state.name_table,
                state.subnet.my_ip,
            )

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

        Picks one of two paths based on what changed since the
        previous ``apply_config``:

        * **full rebuild** — interfaces changed, or this is the
          first SIGHUP (no ``_prev_config`` to diff against).
          Broadcasts release for every registered name, tears down
          transports, rebuilds.
        * **live update** — name set, workgroup, or server_string
          changed.  Releases only the names that actually went
          away, registers newly-added names, updates browse
          announcer payloads in place; transports stay bound."""
        prev = self._prev_config
        cur = self._config

        if (
            prev is None
            or prev.server.interfaces != cur.server.interfaces
        ):
            await self._full_rebuild_reload()
            return

        if prev.server == cur.server:
            logger.info("Reload: no config changes")
            return

        await self._live_update_reload()

    async def _full_rebuild_reload(self) -> None:
        """Tear down transports and registrations, rebuild from scratch.

        The only path that closes and re-opens per-interface NBNS
        transports.  Fires on ``interfaces`` changes and on first
        SIGHUP."""
        logger.info("Reload: full rebuild")

        for state in self._subnets:
            state.stop()
            release_all_names(
                _broadcast_sender(state.transport, state.subnet),
                state.name_table,
                state.subnet.my_ip,
            )

        for transport in self._transports.values():
            await transport.stop()
        self._subnets.clear()
        self._transports.clear()

        self._netbios_name = get_netbios_name(self._config.server)
        self._workgroup = self._config.server.workgroup.upper()

        loop = asyncio.get_running_loop()
        try:
            subnets = await loop.run_in_executor(
                None, resolve_subnets, list(self._config.server.interfaces),
            )
        except ValueError as e:
            logger.error("Reload: cannot resolve interfaces: %s", e)
            return

        for subnet in subnets:
            await self._setup_subnet(subnet, loop)

        # Refresh the global receiver's subnet list so source-IP
        # dispatch matches the new config.  We don't restart the
        # underlying sockets — they stay bound to 0.0.0.0:137/138
        # regardless of interface changes.
        if self._global_recv is not None:
            self._global_recv.update_subnets(subnets)

        for state in self._subnets:
            await self._register_names(state)

        logger.info(
            "Full rebuild complete: %d subnets across %d interfaces",
            len(self._subnets), len(self._transports),
        )

    async def _live_update_reload(self) -> None:
        """In-place reconciliation for non-interface config changes.

        Runs when the set of interfaces is unchanged but something
        else in the [netbiosns] config differs — a new alias, a
        workgroup rename, a server-string tweak from middleware.
        Diffs the set of (name, type, is_group) registrations
        implied by the old vs. new config:

        * Names that went away are released on every subnet and
          pulled from each name table so the refresher and
          responder stop touching them.
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
            for state in self._subnets:
                if state.registrar is None:
                    continue
                ip = state.subnet.my_ip
                for name, name_type, is_group in to_register:
                    await state.registrar.register(
                        name, name_type, ip, group=is_group,
                    )

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
        state.refresher = Refresher(
            send_broadcast,
            state.name_table,
            subnet.my_ip,
        )
        state.refresher.start()

        # MS-BRWS §3.2.5.2: periodic HostAnnouncement on port 138.
        state.browse_announcer = BrowseAnnouncer(
            send_fn=transport.send_dgram_broadcast,
            hostname=self._netbios_name,
            workgroup=self._workgroup,
            server_string=self._config.server.server_string,
        )
        state.browse_announcer.start()

        self._subnets.append(state)
        logger.info(
            "Subnet ready: %s on %s (bcast %s)",
            subnet.my_ip, subnet.interface_name, subnet.broadcast,
        )

    # -- Name registration --------------------------------------------------

    async def _register_names(self, state: PerSubnetState) -> None:
        """Register all configured names on one subnet."""
        if state.registrar is None:
            return
        ip = state.subnet.my_ip

        all_names = (
            [self._netbios_name] + self._config.server.netbios_aliases
        )
        for hostname in all_names:
            for name_type in (
                NameType.WORKSTATION,
                NameType.MESSENGER,
                NameType.SERVER,
            ):
                await state.registrar.register(
                    hostname, name_type, ip,
                )

        await state.registrar.register(
            self._workgroup, NameType.WORKSTATION, ip, group=True,
        )

    # -- Message handling ---------------------------------------------------

    def _handle_message(
        self,
        msg: NBNSMessage,
        source: tuple[str, int],
        ifname: str,
    ) -> None:
        """Dispatch an inbound NBNS message to the matching subnet handler.

        Multiple subnets may share one interface; pick the one whose
        network contains the source address.
        """
        try:
            src_ip = IPv4Address(source[0])
        except ValueError:
            return

        state = self._find_subnet_for(ifname, src_ip)
        if state is None:
            return

        if msg.is_response:
            if msg.rcode != 0 and state.registrar:
                for rr in msg.answers:
                    state.registrar.on_conflict(rr.name)
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


def _expected_name_records(
    server_cfg, netbios_name: str, workgroup: str,
) -> set[NameRecord]:
    """Full set of (name, type, is_group) registrations implied by *cfg*.

    Matches the iteration order of ``NBNSServer._register_names``:
    every ``(primary + alias)`` times three service types (workstation,
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
