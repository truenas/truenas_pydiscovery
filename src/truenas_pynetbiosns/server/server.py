"""Main NetBIOS Name Service daemon orchestrator."""
from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv4Address

from truenas_pydiscovery_utils.daemon import BaseDaemon
from truenas_pydiscovery_utils.status import StatusWriter

from .config import DaemonConfig, get_netbios_name
from .browse.announcer import BrowseAnnouncer
from .core.defender import Defender
from .core.nametable import NameTable
from .core.refresher import Refresher
from .core.registrar import Registrar
from .core.release import release_all_names
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


class NBNSServer(BaseDaemon):
    """Top-level NetBIOS Name Service daemon."""

    def __init__(self, config: DaemonConfig) -> None:
        super().__init__(logger)
        self._config = config
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
            if state.refresher:
                state.refresher.cancel()
            if state.browse_announcer:
                state.browse_announcer.cancel()

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

    def apply_config(self, new_config: DaemonConfig) -> None:
        """Swap in a freshly-parsed config.

        ``_reload()`` already re-derives ``_netbios_name`` and
        ``_workgroup`` from ``self._config.server`` on every SIGHUP,
        so simply replacing the config reference is sufficient — the
        subsequent reload will pick up the new values."""
        self._config = new_config

    async def _reload(self) -> None:
        """SIGHUP: release names, re-resolve subnets, re-register."""
        logger.info("Reloading configuration")

        for state in self._subnets:
            if state.refresher:
                state.refresher.cancel()
            if state.browse_announcer:
                state.browse_announcer.cancel()
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
            "Reload complete: %d subnets across %d interfaces",
            len(self._subnets), len(self._transports),
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
