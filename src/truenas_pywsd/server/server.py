"""Main WSD daemon orchestrator."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid

from truenas_pydiscovery_utils.daemon import BaseDaemon
from truenas_pydiscovery_utils.status import StatusWriter

from .config import DaemonConfig, get_hostname
from .core.announcer import send_bye, send_hello
from .core.dedup import MessageDedup
from .core.metadata import MetadataHandler
from .core.responder import WSDResponder
from .net.http import WSDHttpServer
from .net.interface import InterfaceInfo, resolve_interface
from .net.transport import WSDTransport
from truenas_pywsd.protocol.constants import WSD_HTTP_PORT
from truenas_pywsd.protocol.soap import parse_envelope

logger = logging.getLogger(__name__)


class PerInterfaceState:
    """Holds all per-interface WSD state."""

    __slots__ = (
        "iface", "transport", "http_servers",
        "responder", "dedup",
    )

    def __init__(self, iface: InterfaceInfo) -> None:
        self.iface = iface
        self.transport: WSDTransport | None = None
        self.http_servers: list[WSDHttpServer] = []
        self.responder: WSDResponder | None = None
        self.dedup = MessageDedup()


class WSDServer(BaseDaemon):
    """Top-level WSD daemon."""

    def __init__(self, config: DaemonConfig) -> None:
        super().__init__(logger)
        self._config = config
        self._hostname = get_hostname(config.server)
        self._endpoint_uuid = str(uuid.uuid5(
            uuid.NAMESPACE_DNS, self._hostname,
        ))
        self._interfaces: dict[int, PerInterfaceState] = {}
        self._status = StatusWriter(config.rundir, logger)
        # WS-Discovery AppSequence: InstanceId is fixed per daemon
        # lifetime, MessageNumber increments globally.
        self._instance_id = int(time.time())
        self._message_number = 0

    async def _start(self, loop: asyncio.AbstractEventLoop) -> None:
        logger.info(
            "Starting WSD daemon: %s (uuid %s)",
            self._hostname, self._endpoint_uuid,
        )

        if not self._config.server.interfaces:
            logger.error("No interfaces configured — refusing to start")
            self._shutdown_event.set()
            return

        for name in self._config.server.interfaces:
            iface = await loop.run_in_executor(
                None, resolve_interface, name,
            )
            if iface is None:
                continue
            await self._setup_interface(iface, loop)

        # Send Hello on all interfaces
        for ifstate in self._interfaces.values():
            if ifstate.transport:
                await send_hello(
                    ifstate.transport.send_multicast,
                    self._endpoint_uuid,
                    self._build_xaddrs(ifstate.iface),
                    app_sequence=self._instance_id,
                    message_number=self._next_msg_number(),
                )

        logger.info(
            "WSD daemon started on %d interfaces",
            len(self._interfaces),
        )

    async def _stop(self) -> None:
        logger.info("Stopping WSD daemon")

        # Send Bye
        for ifstate in self._interfaces.values():
            if ifstate.transport:
                await send_bye(
                    ifstate.transport.send_multicast,
                    self._endpoint_uuid,
                    app_sequence=self._instance_id,
                    message_number=self._next_msg_number(),
                )

        # Stop HTTP servers and transports
        for ifstate in self._interfaces.values():
            if ifstate.responder:
                ifstate.responder.cancel_all()
            for http in ifstate.http_servers:
                await http.stop()
            if ifstate.transport:
                await ifstate.transport.stop()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_status)
        logger.info("WSD daemon stopped")

    def apply_config(self, new_config: DaemonConfig) -> None:
        """Swap in a freshly-parsed config.

        ``_reload()`` already re-derives ``_hostname`` and
        ``_endpoint_uuid`` from ``self._config.server`` on every
        SIGHUP, so replacing the config reference is sufficient — the
        subsequent reload picks up the new values."""
        self._config = new_config

    async def _reload(self) -> None:
        logger.info("Reloading WSD configuration")

        # Bye on old interfaces
        for ifstate in self._interfaces.values():
            if ifstate.transport:
                await send_bye(
                    ifstate.transport.send_multicast,
                    self._endpoint_uuid,
                    app_sequence=self._instance_id,
                    message_number=self._next_msg_number(),
                )
            if ifstate.responder:
                ifstate.responder.cancel_all()
            for http in ifstate.http_servers:
                await http.stop()
            if ifstate.transport:
                await ifstate.transport.stop()
        self._interfaces.clear()

        # Re-setup
        self._hostname = get_hostname(self._config.server)
        self._endpoint_uuid = str(uuid.uuid5(
            uuid.NAMESPACE_DNS, self._hostname,
        ))

        loop = asyncio.get_running_loop()
        for name in self._config.server.interfaces:
            iface = await loop.run_in_executor(
                None, resolve_interface, name,
            )
            if iface is None:
                continue
            await self._setup_interface(iface, loop)

        # Hello on new interfaces
        for ifstate in self._interfaces.values():
            if ifstate.transport:
                await send_hello(
                    ifstate.transport.send_multicast,
                    self._endpoint_uuid,
                    self._build_xaddrs(ifstate.iface),
                    app_sequence=self._instance_id,
                    message_number=self._next_msg_number(),
                )

        logger.info(
            "Reload complete: %d interfaces", len(self._interfaces),
        )

    def _write_status(self) -> None:
        ifaces = {}
        for ifstate in self._interfaces.values():
            ifaces[ifstate.iface.name] = {
                "ipv4": [str(a.ip) for a in ifstate.iface.addrs_v4],
                "ipv6": [str(a.ip) for a in ifstate.iface.addrs_v6],
                "transport_active": (
                    ifstate.transport.is_active
                    if ifstate.transport else False
                ),
                "http_servers": len(ifstate.http_servers),
                "dedup": ifstate.dedup.stats(),
            }

        self._status.write({
            "hostname": self._hostname,
            "endpoint_uuid": self._endpoint_uuid,
            "state": "running",
            "interfaces": ifaces,
        })

    # -- Interface setup ----------------------------------------------------

    async def _setup_interface(
        self,
        iface: InterfaceInfo,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        if iface.index in self._interfaces:
            return

        ifstate = PerInterfaceState(iface)

        transport = WSDTransport(
            interface_index=iface.index,
            interface_name=iface.name,
            # IP_MULTICAST_IF takes exactly one source address; the
            # primary is a sensible default even when the interface
            # carries multiple subnets (clients see our multicast
            # regardless — the per-subnet reachability is solved by
            # the multi-URL XAddrs in ``_build_xaddrs``).
            interface_addr_v4=(
                str(iface.addrs_v4[0].ip) if iface.addrs_v4 else None
            ),
            use_ipv4=self._config.server.use_ipv4,
            use_ipv6=self._config.server.use_ipv6,
        )
        await transport.start(loop, self._handle_message)

        if not transport.is_active:
            return

        ifstate.transport = transport

        xaddrs = self._build_xaddrs(iface)
        ifstate.responder = WSDResponder(
            send_unicast_fn=transport.send_unicast,
            endpoint_uuid=self._endpoint_uuid,
            xaddrs=xaddrs,
            dedup=ifstate.dedup,
            addrs_v4=iface.addrs_v4,
            addrs_v6=iface.addrs_v6,
        )

        # Metadata handler for HTTP
        is_domain = bool(self._config.server.domain)
        wg_or_domain = (
            self._config.server.domain
            if is_domain
            else self._config.server.workgroup
        )
        meta_handler = MetadataHandler(
            endpoint_uuid=self._endpoint_uuid,
            hostname=self._hostname,
            workgroup_or_domain=wg_or_domain,
            is_domain=is_domain,
        )

        # Bind a metadata HTTP server on every IPv4 address so clients
        # on any of this interface's subnets can reach the URL we
        # advertise in XAddrs.
        for iface_addr in iface.addrs_v4:
            http = WSDHttpServer(
                str(iface_addr.ip),
                WSD_HTTP_PORT,
                meta_handler.handle_request,
            )
            await http.start()
            ifstate.http_servers.append(http)

        self._interfaces[iface.index] = ifstate
        logger.info("Interface %s ready", iface.name)

    # -- Message handling ---------------------------------------------------

    def _handle_message(
        self, data: bytes, source: tuple, ifname: str,
    ) -> None:
        """Parse incoming UDP datagram and dispatch to the interface responder."""
        ifstate = None
        for s in self._interfaces.values():
            if s.iface.name == ifname:
                ifstate = s
                break
        if ifstate is None:
            return

        try:
            envelope = parse_envelope(data)
        except (ValueError, Exception):
            return

        if ifstate.responder:
            ifstate.responder.handle_message(envelope, source)

    # -- Helpers ------------------------------------------------------------

    def _next_msg_number(self) -> int:
        """Return the next global message number for AppSequence."""
        self._message_number += 1
        return self._message_number

    def _build_xaddrs(self, iface: InterfaceInfo) -> str:
        """Build the ``wsd:XAddrs`` string for metadata exchange.

        WS-Discovery 1.1 §5.3 defines ``XAddrs`` as a whitespace-
        separated list of transport addresses.  When an interface has
        multiple IPv4 addresses (one per subnet), we advertise one
        URL per address so a client on any of those subnets gets a
        reachable metadata endpoint — otherwise secondary-subnet
        clients receive a URL they can't route to.
        """
        if iface.addrs_v4:
            urls = [
                f"http://{a.ip}:{WSD_HTTP_PORT}/{self._endpoint_uuid}"
                for a in iface.addrs_v4
            ]
            return " ".join(urls)
        return ""
