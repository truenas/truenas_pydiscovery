"""Main mDNS daemon orchestrator."""
from __future__ import annotations

import asyncio
import logging
import time

from truenas_pydiscovery_utils.daemon import BaseDaemon
from truenas_pydiscovery_utils.status import StatusWriter

from .config import DaemonConfig, ServiceConfig, get_hostname
from .core.announcer import Announcer
from .core.conflict import generate_alternative_name
from .core.entry_group import EntryGroup
from .core.goodbye import send_goodbye
from .core.prober import Prober
from truenas_pymdns.protocol.constants import (
    ANNOUNCE_COUNT,
    EntryGroupState,
    LINK_FLAP_ANNOUNCE_COUNT,
    LINK_FLAP_PROBE_DELAY,
    LINK_FLAP_WINDOW,
    LINK_NORMAL_PROBE_DELAY,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
)
from .net.interface import InterfaceInfo, resolve_interface
from .net.link_monitor import LinkMonitor
from .net.transport import MDNSTransport
from .query.responder import Responder
from .service.file_loader import (
    ServiceKey,
    load_service_directory,
    service_to_entry_group,
)
from .service.registry import ServiceRegistry

logger = logging.getLogger(__name__)


class PerInterfaceState:
    """Holds all per-interface mDNS state."""

    __slots__ = (
        "iface", "transport",
        "responder", "prober", "announcer",
    )

    def __init__(self, iface: InterfaceInfo, config: DaemonConfig) -> None:
        self.iface = iface
        self.transport = MDNSTransport(
            interface_index=iface.index,
            interface_name=iface.name,
            interface_addr_v4=(
                str(iface.addrs_v4[0]) if iface.addrs_v4 else None
            ),
            use_ipv4=config.server.use_ipv4,
            use_ipv6=config.server.use_ipv6,
        )
        self.responder: Responder | None = None
        self.prober: Prober | None = None
        self.announcer: Announcer | None = None


class MDNSServer(BaseDaemon):
    """Top-level mDNS daemon."""

    def __init__(self, config: DaemonConfig) -> None:
        super().__init__(logger)
        self._config = config
        # Set by ``apply_config`` on SIGHUP so ``_reload`` can diff
        # the outgoing config against the new one and pick a minimally
        # disruptive reconciliation path.  ``None`` until the first
        # SIGHUP, which forces a full rebuild.
        self._prev_config: DaemonConfig | None = None
        self._hostname = get_hostname(config.server)
        self._fqdn = f"{self._hostname}.{config.server.domain_name}"
        self._interfaces: dict[int, PerInterfaceState] = {}
        self._registry = ServiceRegistry()
        self._entry_groups: list[EntryGroup] = []
        # Index from service identity to its registered ``EntryGroup``.
        # Populated by ``_load_static_services`` and drained by the
        # delta-reload path so services.d edits can add or remove
        # individual services without goodbyeing the whole registry.
        # Kept in lock-step with the subset of ``_entry_groups`` that
        # came from services.d; the host-addresses group lives only
        # in ``_entry_groups``.
        self._service_groups: dict[ServiceKey, EntryGroup] = {}
        self._status = StatusWriter(config.rundir, logger)
        self._wake = asyncio.Event()
        # Tracks in-flight conflict-resolution tasks spawned by
        # _on_conflict() so they can be cancelled on shutdown.
        self._conflict_tasks: list[asyncio.Task] = []
        self._link_monitor: LinkMonitor | None = None
        # Flap-detection state per ifindex (mDNS.c:14262-14273):
        # time of most recent re-probe-triggering link-up and the
        # currently-pending _on_link_up task (used to coalesce
        # multiple flaps into a single re-probe).
        self._last_link_up: dict[int, float] = {}
        self._pending_link_ups: dict[int, asyncio.Task] = {}

    async def _start(self, loop: asyncio.AbstractEventLoop) -> None:
        logger.info(
            "Starting mDNS daemon: %s.%s",
            self._hostname, self._config.server.domain_name,
        )

        if not self._config.server.interfaces:
            logger.error("No interfaces configured — refusing to start")
            self._shutdown_event.set()
            return

        # Resolve interface names to indexes + addresses, start transports
        await self._setup_interfaces(loop)

        # Load static services
        await self._load_static_services()

        # Register host address records (discovered from interfaces)
        self._register_host_addresses()

        # Probe and announce
        for group in self._entry_groups:
            await self._probe_and_announce(group)

        # RFC 6762 §8.3 / §13 + BCT II.17 "HOT-PLUGGING": listen for
        # link state changes and re-probe all affected groups when a
        # link comes back up.  Mirrors mDNSPosix's
        # RTMGRP_LINK netlink subscription (mDNSPosix/mDNSPosix.c:1620).
        try:
            self._link_monitor = LinkMonitor(self._on_link_up)
            self._link_monitor.start(loop)
        except OSError as e:
            # Non-Linux or unprivileged sandbox — log and continue
            # without hot-plug support.
            logger.warning("LinkMonitor unavailable: %s", e)
            self._link_monitor = None

        logger.info(
            "mDNS daemon started with %d services on %d interfaces",
            len(self._entry_groups), len(self._interfaces),
        )

    async def _stop(self) -> None:
        logger.info("Stopping mDNS daemon")

        if self._link_monitor is not None:
            self._link_monitor.stop()
            self._link_monitor = None

        for task in self._conflict_tasks:
            task.cancel()
        self._conflict_tasks.clear()

        for ifstate in self._interfaces.values():
            owned = self._registry.get_all_records(ifstate.iface.index)
            logger.info(
                "Goodbye: %d records for interface %s",
                len(owned), ifstate.iface.name,
            )
            if owned:
                send_goodbye(
                    ifstate.transport.send_message,
                    [ow.record for ow in owned],
                )

        for ifstate in self._interfaces.values():
            if ifstate.responder:
                ifstate.responder.cancel_all()
            if ifstate.prober:
                ifstate.prober.cancel_all()
            if ifstate.announcer:
                ifstate.announcer.cancel_all()
            await ifstate.transport.stop()

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._write_status)
        logger.info("mDNS daemon stopped")

    # -- Interface setup ------------------------------------------------------

    async def _setup_interfaces(
        self, loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Resolve configured interface names and start transports."""
        for name in self._config.server.interfaces:
            iface = await loop.run_in_executor(
                None, resolve_interface, name,
            )
            if iface is None:
                continue
            await self._setup_transport(iface, loop)

    async def _setup_transport(
        self, iface: InterfaceInfo, loop: asyncio.AbstractEventLoop,
    ) -> None:
        if iface.index in self._interfaces:
            return

        ifstate = PerInterfaceState(iface, self._config)
        await ifstate.transport.start(loop, self._handle_message)

        if not ifstate.transport.is_active:
            return

        transport = ifstate.transport

        def _unicast_send(
            msg: MDNSMessage, addr: tuple,
            _t: MDNSTransport = transport,
        ) -> None:
            _t.send_message(msg, addr)

        ifstate.responder = Responder(
            transport.send_message,
            _unicast_send,
            self._registry,
        )
        ifstate.responder.start(loop)

        ifstate.prober = Prober(
            ifstate.transport.send_message,
            self._on_conflict,
        )

        ifstate.announcer = Announcer(ifstate.transport.send_message)

        self._interfaces[iface.index] = ifstate
        logger.info(
            "Interface %s (index %d, v4=%s, v6=%d addrs) ready",
            iface.name, iface.index,
            iface.addrs_v4[0] if iface.addrs_v4 else "none",
            len(iface.addrs_v6),
        )

    # -- Message handling -----------------------------------------------------

    def _handle_message(
        self, message: MDNSMessage, source: tuple, ifindex: int,
    ) -> None:
        ifstate = self._interfaces.get(ifindex)
        if ifstate is None:
            return

        self._status.inc(
            "queries_received" if message.is_query
            else "responses_received"
        )

        if message.is_query:
            if ifstate.responder:
                ifstate.responder.handle_query(message, source, ifindex)
                if message.authorities:
                    ifstate.responder.handle_probe_query(
                        message, source, ifindex,
                    )
        else:
            if ifstate.responder:
                ifstate.responder.suppress_if_answered(message)
            if ifstate.prober:
                ifstate.prober.handle_incoming(message, source)

            self._check_cooperating_responders(message, ifindex)
            self._check_established_conflicts(message, ifindex, source)

        self._wake.set()

    # -- Service management ---------------------------------------------------

    async def _load_static_services(self) -> None:
        loop = asyncio.get_running_loop()
        services = await loop.run_in_executor(
            None, load_service_directory, self._config.service_dir,
        )
        for svc in services:
            key = ServiceKey.from_config(svc, self._hostname, self._fqdn)
            if key in self._service_groups:
                # Two .conf files defining the same service would
                # otherwise register the same records twice; the
                # second copy contributes nothing to the wire and
                # breaks the delta reload's service-key index.
                logger.warning(
                    "Duplicate service %s.%s on port %d — skipping",
                    key.instance_name, key.service_type, key.port,
                )
                continue
            iface_indexes = None
            if svc.interfaces:
                iface_indexes = []
                for name in svc.interfaces:
                    iface = await loop.run_in_executor(
                        None, resolve_interface, name,
                    )
                    if iface is not None:
                        iface_indexes.append(iface.index)

            group = service_to_entry_group(
                svc, self._hostname, self._fqdn, iface_indexes,
            )
            self._entry_groups.append(group)
            self._service_groups[key] = group

    def _register_host_addresses(self) -> None:
        """Create A/AAAA records from discovered interface addresses.

        Only registers addresses for address families where the
        transport is actually active.
        """
        group = EntryGroup()
        for ifstate in self._interfaces.values():
            if ifstate.transport.has_ipv4:
                for v4 in ifstate.iface.addrs_v4:
                    group.add_address(self._fqdn, str(v4))
            if ifstate.transport.has_ipv6:
                for v6 in ifstate.iface.addrs_v6:
                    if v6.is_link_local:
                        continue
                    group.add_address(self._fqdn, str(v6))
        if group.records:
            self._entry_groups.append(group)

    async def _probe_and_announce(
        self, group: EntryGroup,
        announce_count: int = ANNOUNCE_COUNT,
    ) -> None:
        """Drive *group* through probing and announcing.

        *announce_count* lets callers scale back announcement traffic —
        link-flap handling passes ``LINK_FLAP_ANNOUNCE_COUNT`` (1) to
        avoid flooding the network when an interface bounces rapidly
        (matches Apple mDNSResponder's flap handling at
        ``mDNSCore/mDNS.c:14262-14273``).
        """
        unique = group.get_unique_records()
        if not unique:
            group.set_state(EntryGroupState.ESTABLISHED)
            self._registry.add_group(group)
            return

        group.set_state(EntryGroupState.REGISTERING)

        for ifstate in self._interfaces.values():
            if (group.interfaces is not None
                    and ifstate.iface.index not in group.interfaces):
                continue
            if ifstate.prober is None:
                continue

            success = await ifstate.prober.probe(unique)
            if not success:
                group.set_state(EntryGroupState.COLLISION)
                logger.warning(
                    "Probe conflict, will retry with alternative name"
                )
                return

        group.set_state(EntryGroupState.ESTABLISHED)
        self._registry.add_group(group)

        for ifstate in self._interfaces.values():
            if (group.interfaces is not None
                    and ifstate.iface.index not in group.interfaces):
                continue
            if ifstate.announcer:
                ifstate.announcer.schedule_announce(
                    group.records, count=announce_count,
                )

    def _on_conflict(self, records: list[MDNSRecord]) -> None:
        """RFC 6762 s9: on conflict, rename and re-probe."""
        loop = asyncio.get_running_loop()
        task = loop.create_task(self._resolve_conflict(records))
        self._conflict_tasks.append(task)
        task.add_done_callback(
            lambda t: self._conflict_tasks.remove(t)
            if t in self._conflict_tasks else None
        )

    async def _resolve_conflict(self, records: list[MDNSRecord]) -> None:
        """RFC 6762 §9: pick an alternative name, rewrite every record
        in the colliding group to use it, then re-probe."""
        for group in self._entry_groups:
            if group.state != EntryGroupState.COLLISION:
                continue
            # Snapshot every record reference BEFORE rename.  The
            # MDNSRecord objects are not mutated by ``_rename_group``;
            # it rebinds ``ow.record`` to a new instance, so these
            # snapshots still point at the pre-rename (old-name) form.
            pre_records = [ow.record for ow in group.owned_records]
            old_primary, new_primary = _rename_group(group)
            if old_primary is None or new_primary is None:
                logger.error(
                    "Cannot resolve conflict for group with no "
                    "SRV/A/AAAA records — giving up"
                )
                continue
            logger.warning(
                "Name conflict: %s -> %s", old_primary, new_primary,
            )
            # RFC 6762 §8.4 / BCT II.16: emit TTL=0 goodbyes for the
            # OLD form of every shared record whose identity changes
            # on rename.  Unique records (SRV/TXT/A/AAAA) are excluded:
            # their new announcement carries the cache-flush bit which
            # evicts old rdata from peer caches.  Mirrors Apple
            # mDNSResponder's ``mDNS_Deregister_internal``
            # (mDNSCore/mDNS.c:2230-2243), which only schedules TTL=0
            # retransmits for ``kDNSRecordTypeShared`` records on
            # ``mDNS_Dereg_conflict``.
            obsolete = _obsolete_shared_records(pre_records, old_primary)
            if obsolete:
                for ifstate in self._interfaces.values():
                    if (group.interfaces is not None
                            and ifstate.iface.index not in group.interfaces):
                        continue
                    send_goodbye(ifstate.transport.send_message, obsolete)
            group.set_state(EntryGroupState.UNCOMMITTED)
            group.set_state(EntryGroupState.REGISTERING)
            await self._probe_and_announce(group)
            break

    def _check_cooperating_responders(
        self, message: MDNSMessage, ifindex: int,
    ) -> None:
        """RFC 6762 s6.6: re-announce if peer's TTL < 50% of ours."""
        for rr in message.answers:
            our_owned = self._registry.lookup(
                rr.key.name, rr.key.rtype, ifindex,
            )
            for ow in our_owned:
                # RFC 6762 §16: case-insensitive rdata comparison for
                # name-bearing types (PTR/SRV targets).  Byte-exact
                # ``rdata_wire()`` would miss compression-driven case
                # differences when our own packets echo back via
                # IP_MULTICAST_LOOP.
                if ow.record.data == rr.data:
                    if rr.ttl < ow.record.ttl // 2:
                        ifstate = self._interfaces.get(ifindex)
                        if ifstate and ifstate.announcer:
                            ifstate.announcer.schedule_announce([ow.record])

    def _check_established_conflicts(
        self, message: MDNSMessage, ifindex: int, source: tuple = (),
    ) -> None:
        """RFC 6762 §9 / BCT II.6 "SUBSEQUENT CONFLICT".

        When a peer response carries a unique (cache-flush) record
        with the same name+type as one of our ESTABLISHED records but
        different rdata, we MUST reset that record back to probing
        state and re-probe with the SAME name.  A real peer will
        answer our re-probe (triggering the §8.2 path → rename), a
        stale echo will go unanswered (re-probe succeeds, no rename).

        Mirrors Apple mDNSResponder's ``kDNSRecordTypeVerified``
        branch in ``mDNSCoreReceiveResponse`` (mDNSCore/mDNS.c:10315-10328):
        ``RecordType`` resets to ``kDNSRecordTypeUnique``,
        ``ProbeCount`` to ``DefaultProbeCountForTypeUnique`` (3),
        ``RecordProbeFailure`` increments the rate-limit counter.
        """
        # Collect (name_lower, rtype) pairs whose peer rdata differs
        # from *every* UNIQUE (cache-flush) record we own on this
        # interface.  Shared records (e.g. service PTR) can coexist;
        # different rdata is not a conflict for them.
        #
        # The peer's rdata is a conflict iff it isn't already in our
        # RRSET.  A host with multiple IPv6 addresses on one
        # interface owns several AAAA records for the same (name,
        # type); ``IP_MULTICAST_LOOP=1`` echoes each back to us.  A
        # naive loop that flags on the first mismatch would see
        # echoed-AAAA-#2 as a conflict against our owned-AAAA-#1 and
        # trip the probe loop even though #2 is in our own RRSET.
        #
        # RFC 6762 §16 requires case-insensitive rdata comparison for
        # name-bearing record types (PTR/SRV target) — ``data ==``
        # delegates to ``RecordData._identity`` which case-folds
        # appropriately.  A byte-exact ``rdata_wire()`` compare would
        # flag our own multicast-loopback echo as a conflict whenever
        # name compression re-encodes a target in a different case
        # than our in-memory copy.
        conflicts: set[tuple[str, QType]] = set()
        for rr in message.answers:
            owned = self._registry.lookup(
                rr.key.name, rr.key.rtype, ifindex,
            )
            unique_owned = [
                ow for ow in owned if ow.record.cache_flush
            ]
            if not unique_owned:
                continue
            if any(ow.record.data == rr.data for ow in unique_owned):
                continue
            conflicts.add((rr.key.name.lower(), rr.key.rtype))
        if not conflicts:
            return

        loop = asyncio.get_running_loop()
        for group in self._entry_groups:
            if group.state != EntryGroupState.ESTABLISHED:
                continue
            if (group.interfaces is not None
                    and ifindex not in group.interfaces):
                continue
            matched = any(
                ow.record.cache_flush and (
                    ow.record.key.name.lower(), ow.record.key.rtype,
                ) in conflicts
                for ow in group.owned_records
            )
            if not matched:
                continue
            src_desc = (
                f"{source[0]}" if source else "unknown"
            )
            logger.warning(
                "RFC 6762 §9: peer rdata conflict from %s on %s — "
                "resetting group to probing state (same name)",
                src_desc,
                sorted(
                    name for name, _rt in conflicts
                ),
            )
            self._registry.remove_group(group)
            group.set_state(EntryGroupState.UNCOMMITTED)
            task = loop.create_task(self._probe_and_announce(group))
            self._conflict_tasks.append(task)
            task.add_done_callback(
                lambda t: self._conflict_tasks.remove(t)
                if t in self._conflict_tasks else None
            )

    async def _on_link_up(self, ifindex: int) -> None:
        """BCT II.17 / RFC 6762 §8.3 hot-plug re-probe with flap
        throttling.

        Mirrors Apple mDNSResponder's ``mDNS_RegisterInterface``
        (``mDNSCore/mDNS.c:14174``).  The 0.5s normal probe delay
        guards against stale echoed packets from the cable
        transition; a longer 5s delay plus single-announcement mode
        kicks in if this interface has re-registered within
        ``LINK_FLAP_WINDOW`` (Apple: *"In the case of a flapping
        interface, we pause for five seconds, and reduce the
        announcement count to one packet."*, ``mDNS.c:14262``).

        If a second link-up arrives for the same ifindex during the
        defer window, the still-sleeping prior task is cancelled so
        we coalesce into a single re-probe rather than pile up
        overlapping tasks.
        """
        # Coalesce: cancel any in-flight _on_link_up for this ifindex.
        prior = self._pending_link_ups.get(ifindex)
        if prior is not None and not prior.done():
            prior.cancel()
        current = asyncio.current_task()
        if current is not None:
            self._pending_link_ups[ifindex] = current

        now = time.monotonic()
        last = self._last_link_up.get(ifindex)
        # Stamp *now* as the most recent link-up event BEFORE the
        # defer; this way a follow-up flap detects "we just saw an
        # up event" even when the prior task was cancelled mid-defer
        # and never completed its re-probe.
        self._last_link_up[ifindex] = now
        if last is not None and (now - last) < LINK_FLAP_WINDOW:
            delay = LINK_FLAP_PROBE_DELAY
            announce_count = LINK_FLAP_ANNOUNCE_COUNT
            logger.warning(
                "Interface %d flapping (last up %.1fs ago) — extended "
                "probe delay %.1fs, reduced announcements to %d",
                ifindex, now - last, delay, announce_count,
            )
        else:
            delay = LINK_NORMAL_PROBE_DELAY
            announce_count = ANNOUNCE_COUNT

        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            # A newer _on_link_up supplanted us; let it take over.
            return
        finally:
            # Stop advertising ourselves as the pending task if we
            # haven't been superseded (cancel sets prior != current).
            if self._pending_link_ups.get(ifindex) is current:
                self._pending_link_ups.pop(ifindex, None)

        if self._interfaces.get(ifindex) is None:
            return
        affected: list[EntryGroup] = []
        for group in self._entry_groups:
            if group.state != EntryGroupState.ESTABLISHED:
                continue
            if (
                group.interfaces is not None
                and ifindex not in group.interfaces
            ):
                continue
            affected.append(group)
        if not affected:
            return
        logger.info(
            "Link up on ifindex %d — re-probing %d group(s)",
            ifindex, len(affected),
        )
        for group in affected:
            self._registry.remove_group(group)
            group.set_state(EntryGroupState.UNCOMMITTED)
        for group in affected:
            await self._probe_and_announce(
                group, announce_count=announce_count,
            )

    # -- Reload ---------------------------------------------------------------

    def apply_config(self, new_config: DaemonConfig) -> None:
        """Swap in a freshly-parsed config and re-derive cached attrs.

        Called by the composite parent before ``_reload()`` fans out,
        so the reload picks up on-disk changes to hostname/domain/
        interfaces/service-dir.  Without this, ``self._config`` stays
        frozen at the value captured in ``__init__`` and SIGHUP is
        only useful for files the daemon re-reads directly (the
        services.d directory).

        Stashes the outgoing config as ``_prev_config`` so the
        subsequent ``_reload`` can diff old vs new and pick a
        minimally disruptive reconciliation path."""
        self._prev_config = self._config
        self._config = new_config
        self._hostname = get_hostname(new_config.server)
        self._fqdn = f"{self._hostname}.{new_config.server.domain_name}"

    async def _reload(self) -> None:
        """SIGHUP: reconcile live state with the new config, minimally.

        Picks one of three paths based on what actually changed since
        the previous ``apply_config``:

        * **full rebuild** — interfaces or IPv4/IPv6 toggle changed,
          or this is the first SIGHUP (``_prev_config is None``).
          Transports rebuild, every record goodbyes.
        * **host rename** — hostname or domain changed.  Every record
          goodbyes + re-probes under the new name but transports and
          per-interface tasks stay up.
        * **service delta** — only ``services.d`` on disk may have
          changed.  Removed services get a targeted goodbye, added
          services probe + announce individually; host A/AAAA
          records and untouched services keep running."""
        prev = self._prev_config
        cur = self._config

        if (
            prev is None
            or prev.server.interfaces != cur.server.interfaces
            or prev.server.use_ipv4 != cur.server.use_ipv4
            or prev.server.use_ipv6 != cur.server.use_ipv6
        ):
            await self._full_rebuild_reload()
            return

        if (
            prev.server.host_name != cur.server.host_name
            or prev.server.domain_name != cur.server.domain_name
        ):
            await self._host_rename_reload()
            return

        await self._service_delta_reload()

    async def _full_rebuild_reload(self) -> None:
        """Tear down transports + registry and re-build from scratch.

        The only path that closes and re-opens sockets.  Fires on
        ``interfaces`` / ``use_ipv4`` / ``use_ipv6`` changes (which
        require rebinding) and on first SIGHUP (no ``_prev_config``
        to diff against, so we don't know what changed)."""
        logger.info("Reload: full rebuild")

        for task in self._conflict_tasks:
            task.cancel()
        self._conflict_tasks.clear()

        for ifstate in self._interfaces.values():
            owned = self._registry.get_all_records(ifstate.iface.index)
            if owned:
                send_goodbye(
                    ifstate.transport.send_message,
                    [ow.record for ow in owned],
                )

        # Cancel per-interface schedulers and tasks before dropping the
        # ifstate refs — otherwise their TimerHandles and Tasks survive
        # the clear() and keep firing against closed transports.
        for ifstate in self._interfaces.values():
            if ifstate.responder:
                ifstate.responder.cancel_all()
            if ifstate.prober:
                ifstate.prober.cancel_all()
            if ifstate.announcer:
                ifstate.announcer.cancel_all()
            await ifstate.transport.stop()
        self._interfaces.clear()

        for group in self._entry_groups:
            self._registry.remove_group(group)
        self._entry_groups.clear()
        self._service_groups.clear()

        loop = asyncio.get_running_loop()
        await self._setup_interfaces(loop)
        await self._load_static_services()
        self._register_host_addresses()

        for group in self._entry_groups:
            await self._probe_and_announce(group)

        self._wake.set()

        logger.info(
            "Full rebuild complete: %d services on %d interfaces",
            len(self._entry_groups), len(self._interfaces),
        )

    async def _host_rename_reload(self) -> None:
        """Hostname or domain changed: goodbye + re-probe everything.

        Every owned record references the host FQDN somehow — A/AAAA
        keys, SRV targets, and (for ``instance_name = %h``) service
        PTR targets — so every record needs a fresh advertisement
        under the new name.  Transports and per-interface tasks stay
        up because interfaces didn't change; responder/prober/
        announcer resume against the new records as soon as they're
        re-registered."""
        logger.info("Reload: host rename -> %s", self._fqdn)

        for task in self._conflict_tasks:
            task.cancel()
        self._conflict_tasks.clear()

        for ifstate in self._interfaces.values():
            owned = self._registry.get_all_records(ifstate.iface.index)
            if owned:
                send_goodbye(
                    ifstate.transport.send_message,
                    [ow.record for ow in owned],
                )

        for group in self._entry_groups:
            self._registry.remove_group(group)
        self._entry_groups.clear()
        self._service_groups.clear()

        await self._load_static_services()
        self._register_host_addresses()

        for group in self._entry_groups:
            await self._probe_and_announce(group)

        self._wake.set()

        logger.info(
            "Host rename complete: %d services under %s",
            len(self._service_groups), self._fqdn,
        )

    def _record_still_asserted(self, record: MDNSRecord) -> bool:
        """True if some other registered group owns an identical record.

        Two services of the same DNS-SD type share the meta-PTR
        ``_services._dns-sd._udp.<domain>`` → ``<type>.<domain>``
        (RFC 6763 §9) with byte-identical (name, rdata).  When only
        one such service is being withdrawn, its meta-PTR is still
        asserted by every kept service — RFC 6762 §10.1 goodbye is
        only appropriate for records actually being withdrawn, so
        this check lets the service-delta path filter those shared
        records out of its goodbye set.

        Must be called after the removed group has been dropped
        from ``_entry_groups`` so the walk only sees records that
        remain authoritative."""
        for group in self._entry_groups:
            for ow in group.owned_records:
                if (
                    ow.record.key == record.key
                    and ow.record.data == record.data
                ):
                    return True
        return False

    async def _service_delta_reload(self) -> None:
        """Services-only reload: add/remove individual service groups.

        Runs when the config sections are byte-identical to the
        previous SIGHUP — the only thing that could have changed is
        ``services.d`` on disk (SMB share added/removed via
        middleware, for example).  Diffs the set of currently-
        registered service groups against the newly-loaded directory
        and emits per-service actions: removed services get a
        targeted goodbye + registry drop, added services probe +
        announce individually.  Host A/AAAA records, untouched
        services, responders, probers, and announcers all keep
        running untouched."""
        loop = asyncio.get_running_loop()
        services = await loop.run_in_executor(
            None, load_service_directory, self._config.service_dir,
        )

        new_key_to_svc: dict[ServiceKey, ServiceConfig] = {}
        for svc in services:
            key = ServiceKey.from_config(svc, self._hostname, self._fqdn)
            if key in new_key_to_svc:
                logger.warning(
                    "Duplicate service %s.%s on port %d in services.d "
                    "— skipping duplicate",
                    key.instance_name, key.service_type, key.port,
                )
                continue
            new_key_to_svc[key] = svc

        old_keys = set(self._service_groups.keys())
        new_keys = set(new_key_to_svc.keys())
        to_remove = old_keys - new_keys
        to_add = new_keys - old_keys

        if not to_remove and not to_add:
            logger.info("Reload: service delta (no changes)")
            return

        logger.info(
            "Reload: service delta (-%d +%d)",
            len(to_remove), len(to_add),
        )

        for key in to_remove:
            group = self._service_groups.pop(key)
            if group in self._entry_groups:
                self._entry_groups.remove(group)
            # RFC 6762 §10.1 goodbye is a TTL=0 assertion that a
            # record is being withdrawn.  The DNS-SD meta-PTR
            # ``_services._dns-sd._udp.<domain>`` → ``<type>.<domain>``
            # (RFC 6763 §9) has byte-identical (name, rdata) across
            # every service of a given type, so when another kept
            # service still asserts it, the record is NOT being
            # withdrawn — goodbye would falsely flush peers' "type
            # exists" cache entry.  Filter such records out of the
            # goodbye set; all instance-specific records (service
            # PTR, SRV, TXT, subtype PTR) carry unique rdata and
            # pass the filter.
            to_goodbye = [
                r for r in group.records
                if not self._record_still_asserted(r)
            ]
            if to_goodbye:
                # Send goodbye only on interfaces the group is
                # published on; matches the scoping in
                # _resolve_conflict so peers on other interfaces
                # aren't spammed with records they never cached.
                for ifstate in self._interfaces.values():
                    if (
                        group.interfaces is not None
                        and ifstate.iface.index not in group.interfaces
                    ):
                        continue
                    send_goodbye(
                        ifstate.transport.send_message, to_goodbye,
                    )
            self._registry.remove_group(group)

        for key in to_add:
            svc = new_key_to_svc[key]
            iface_indexes = None
            if svc.interfaces:
                iface_indexes = []
                for name in svc.interfaces:
                    iface = await loop.run_in_executor(
                        None, resolve_interface, name,
                    )
                    if iface is not None:
                        iface_indexes.append(iface.index)

            group = service_to_entry_group(
                svc, self._hostname, self._fqdn, iface_indexes,
            )
            self._entry_groups.append(group)
            self._service_groups[key] = group
            await self._probe_and_announce(group)

        self._wake.set()

    # -- Status ---------------------------------------------------------------

    def _write_status(self) -> None:
        ifaces = {}
        for ifstate in self._interfaces.values():
            ifaces[ifstate.iface.name] = {
                "ipv4": [str(a) for a in ifstate.iface.addrs_v4],
                "ipv6": [str(a) for a in ifstate.iface.addrs_v6],
                "multicast_joined": ifstate.transport.is_active,
            }

        services = []
        for group in self._entry_groups:
            for rec in group.records:
                if (rec.key.rtype == QType.SRV
                        and isinstance(rec.data, SRVRecordData)):
                    services.append({
                        "instance": rec.key.name,
                        "port": rec.data.port,
                        "target": rec.data.target,
                        "state": group.state.name.lower(),
                    })

        self._status.write({
            "hostname": self._fqdn,
            "state": "running",
            "interfaces": ifaces,
            "services_registered": services,
            "records_published": sum(
                len(g.records) for g in self._entry_groups
            ),
        })


def _obsolete_shared_records(
    pre_records: list[MDNSRecord], old_primary: str,
) -> list[MDNSRecord]:
    """Return the shared records from *pre_records* whose identity
    changes on a rename that moves *old_primary* to a new name.

    "Shared" means ``cache_flush is False`` — these are the records
    that do NOT get flushed from peer caches by the new
    announcement's cache-flush bit, and therefore need an explicit
    TTL=0 goodbye packet (RFC 6762 §8.4 / §10.1).  "Identity
    changes" means the record's ``key.name`` is *old_primary* or its
    PTR rdata points at it.

    Mirrors Apple mDNSResponder's ``mDNS_Deregister_internal`` with
    ``mDNS_Dereg_conflict`` (mDNSCore/mDNS.c:2230-2243), which only
    emits goodbyes for ``kDNSRecordTypeShared`` records.
    """
    return [
        r for r in pre_records
        if not r.cache_flush and (
            r.key.name == old_primary
            or (
                isinstance(r.data, PTRRecordData)
                and r.data.target.lower() == old_primary
            )
        )
    ]


def _rename_group(group: EntryGroup) -> tuple[str | None, str | None]:
    """RFC 6762 §9: rewrite every record in *group* to use a new first
    label, returning ``(old_primary, new_primary)``.

    "Primary name" is the SRV instance FQDN for a service group, or
    the A/AAAA host FQDN for a host-address group.  The first DNS
    label is renamed via ``generate_alternative_name`` and every
    record whose ``key.name`` or ``PTRRecordData.target`` references
    the old primary is rewritten in place.  Per-record scheduling
    state (``last_multicast`` / ``last_peer_answer``) is reset so the
    re-probe starts with a clean slate.
    """
    primary: str | None = None
    for ow in group.owned_records:
        if ow.record.key.rtype == QType.SRV:
            primary = ow.record.key.name
            break
    if primary is None:
        for ow in group.owned_records:
            if ow.record.key.rtype in (QType.A, QType.AAAA):
                primary = ow.record.key.name
                break
    if primary is None:
        return (None, None)

    if "." in primary:
        first_label, rest = primary.split(".", 1)
    else:
        first_label, rest = primary, ""
    new_first = generate_alternative_name(first_label)
    new_primary = (f"{new_first}.{rest}" if rest else new_first).lower()

    for ow in group.owned_records:
        old_rec = ow.record
        new_key = old_rec.key
        new_data = old_rec.data

        if old_rec.key.name == primary:
            new_key = MDNSRecordKey(
                name=new_primary,
                rtype=old_rec.key.rtype,
                rclass=old_rec.key.rclass,
            )

        if (isinstance(old_rec.data, PTRRecordData)
                and old_rec.data.target.lower() == primary):
            new_data = PTRRecordData(target=new_primary)

        ow.record = MDNSRecord(
            key=new_key, ttl=old_rec.ttl, data=new_data,
            cache_flush=old_rec.cache_flush,
        )
        ow.last_multicast = 0.0
        ow.last_peer_answer = 0.0

    return (primary, new_primary)
