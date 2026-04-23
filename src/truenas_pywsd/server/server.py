"""Main WSD daemon orchestrator."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid

from truenas_pydiscovery_utils.daemon import ConfigDaemon
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
        "responder", "dedup", "meta_handler",
    )

    def __init__(self, iface: InterfaceInfo) -> None:
        self.iface = iface
        self.transport: WSDTransport | None = None
        self.http_servers: list[WSDHttpServer] = []
        self.responder: WSDResponder | None = None
        self.dedup = MessageDedup()
        # Shared by every http_server on this interface (all IPv4
        # addresses point at the same handler).  Held on the state
        # so the live-update reload path can update its cached
        # workgroup/domain without closing and re-opening the HTTP
        # listeners.
        self.meta_handler: MetadataHandler | None = None

    async def stop(self) -> None:
        """Cancel owned sub-tasks and stop owned sockets / servers.

        Bye traffic is the daemon's job — it needs access to
        endpoint UUID, instance id, and message counter — so that
        stays in ``_stop`` / reload paths.  This method handles
        resource teardown only.
        """
        if self.responder is not None:
            self.responder.cancel_all()
        for http in self.http_servers:
            await http.stop()
        if self.transport is not None:
            await self.transport.stop()


class WSDServer(ConfigDaemon):
    """Top-level WSD daemon."""

    def __init__(self, config: DaemonConfig) -> None:
        # ``ConfigDaemon`` initialises ``_config`` and
        # ``_prev_config`` (and provides the stash-on-apply_config
        # scaffolding ``_reload`` diffs against).
        super().__init__(logger, config)
        self._hostname = get_hostname(config.server)
        self._endpoint_uuid = str(uuid.uuid5(
            uuid.NAMESPACE_DNS, self._hostname,
        ))
        self._interfaces: dict[int, PerInterfaceState] = {}
        self._status = StatusWriter(config.rundir, logger)
        # WS-Discovery AppSequence (§4.2.1): InstanceId identifies
        # the app's current instance, MessageNumber increments
        # globally.  InstanceId is fixed for the life of the
        # process — per spec it only changes on restart — so
        # config reloads do NOT bump it.
        self._instance_id = int(time.time())
        self._message_number = 0
        # WSD 1.1 §4.1 MetadataVersion: monotonically increasing
        # per-endpoint counter clients use to detect metadata
        # changes and re-fetch via WS-MetadataExchange Get.  The
        # live-update reload path bumps this when workgroup/domain
        # changes; the full rebuild resets it to 1 when the
        # endpoint UUID changes (new UUID = new endpoint = fresh
        # initial value per spec).
        self._metadata_version = 1

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
                    metadata_version=self._metadata_version,
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
            await ifstate.stop()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_status)
        logger.info("WSD daemon stopped")

    async def _reload(self) -> None:
        """SIGHUP: reconcile live state with the new config, minimally.

        Picks one of two paths based on what changed since the
        previous ``apply_config``:

        * **full rebuild** — interfaces, IPv4/IPv6 toggle, or
          ``hostname`` changed, or this is the first SIGHUP.
          Hostname change flips ``_endpoint_uuid``, which WSD
          clients treat as a new device — Bye+Hello is the right
          wire behaviour.
        * **metadata live update** — only ``workgroup`` or
          ``domain`` changed.  Updates each per-interface
          ``MetadataHandler`` in place and bumps ``_instance_id``;
          no Bye on the wire."""
        prev = self._prev_config
        cur = self._config

        if (
            prev is None
            or prev.server.interfaces != cur.server.interfaces
            or prev.server.use_ipv4 != cur.server.use_ipv4
            or prev.server.use_ipv6 != cur.server.use_ipv6
            or prev.server.hostname != cur.server.hostname
        ):
            await self._full_rebuild_reload()
            return

        if prev.server == cur.server:
            logger.info("Reload: no config changes")
            return

        await self._metadata_live_update_reload()

    async def _full_rebuild_reload(self) -> None:
        """Bye everywhere, tear down, rebuild, Hello.

        The only path that touches transports or the endpoint UUID.
        Fires on interface/protocol/hostname changes and on first
        SIGHUP."""
        logger.info("Reload: full rebuild")

        for ifstate in self._interfaces.values():
            if ifstate.transport:
                await send_bye(
                    ifstate.transport.send_multicast,
                    self._endpoint_uuid,
                    app_sequence=self._instance_id,
                    message_number=self._next_msg_number(),
                )
            await ifstate.stop()
        self._interfaces.clear()

        old_endpoint_uuid = self._endpoint_uuid
        self._hostname = get_hostname(self._config.server)
        self._endpoint_uuid = str(uuid.uuid5(
            uuid.NAMESPACE_DNS, self._hostname,
        ))
        # Per WSD 1.1 §4.1, MetadataVersion is per-endpoint and the
        # initial value for each endpoint MUST be 1.  A hostname
        # change produces a new endpoint UUID from the client's
        # perspective, so reset the counter.  If only interfaces
        # changed, the endpoint is the same and the counter carries
        # over.
        if self._endpoint_uuid != old_endpoint_uuid:
            self._metadata_version = 1

        loop = asyncio.get_running_loop()
        for name in self._config.server.interfaces:
            iface = await loop.run_in_executor(
                None, resolve_interface, name,
            )
            if iface is None:
                continue
            await self._setup_interface(iface, loop)

        for ifstate in self._interfaces.values():
            if ifstate.transport:
                await send_hello(
                    ifstate.transport.send_multicast,
                    self._endpoint_uuid,
                    self._build_xaddrs(ifstate.iface),
                    app_sequence=self._instance_id,
                    message_number=self._next_msg_number(),
                    metadata_version=self._metadata_version,
                )

        logger.info(
            "Full rebuild complete: %d interfaces",
            len(self._interfaces),
        )

    async def _metadata_live_update_reload(self) -> None:
        """Metadata-only reconciliation: workgroup or domain changed.

        Updates each per-interface ``MetadataHandler``'s cached
        workgroup/domain fields so future HTTP Get responses carry
        the new value, and bumps ``_metadata_version`` so future
        Hello / ProbeMatch / ResolveMatch messages carry the new
        ``<wsd:MetadataVersion>``.  WSD 1.1 §4.1 requires clients
        to re-acquire metadata when the advertised version exceeds
        what they have cached — without the bump, clients that
        re-Probe would see the same version and keep using the old
        workgroup.

        Does NOT bump ``_instance_id`` — that counter identifies
        the app's current instance (§4.2.1) and should only change
        on process restart.

        Does not send a Bye — already-cached clients that don't
        re-Probe will continue to show the old workgroup until
        their cache expires.  That's the accepted tradeoff vs. a
        Bye+Hello storm on every middleware workgroup edit, which
        is exactly the behaviour the delta path exists to avoid."""
        cur_srv = self._config.server
        is_domain = bool(cur_srv.domain)
        wg_or_domain = cur_srv.domain if is_domain else cur_srv.workgroup

        for ifstate in self._interfaces.values():
            if ifstate.meta_handler is None:
                continue
            ifstate.meta_handler.update_workgroup(
                wg_or_domain, is_domain,
            )

        self._metadata_version += 1

        logger.info(
            "Metadata live update: workgroup_or_domain=%s "
            "is_domain=%s (metadata_version=%d, %d interfaces)",
            wg_or_domain, is_domain, self._metadata_version,
            len(self._interfaces),
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
            # WSD 1.1 §4.1: responder reads the live version at
            # response build time so live-update reloads
            # propagate to future ProbeMatch/ResolveMatch without
            # rebuilding the responder.
            metadata_version=lambda: self._metadata_version,
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
        ifstate.meta_handler = meta_handler

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
        except ValueError as e:
            # Malformed SOAP / XML from a peer.  Log at debug — this
            # is the remote peer's bug, not ours, and noisy peers
            # shouldn't fill the ERROR log.  The per-class counter
            # in status.json lets operators tell "network full of
            # broken clients" from "our server has never seen a
            # packet" without tailing the log.
            logger.debug(
                "Discarded malformed WSD datagram from %s: %s",
                source, e,
            )
            self._status.inc("parse_errors")
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
