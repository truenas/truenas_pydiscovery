"""Factory that builds a ``CompositeDaemon`` from ``UnifiedConfig``.

Each enabled protocol's existing server class is instantiated with
its own ``DaemonConfig`` dataclass; the composite wraps them into one
lifecycle so ``truenas-discoveryd`` can host all three.

When a ``config_reloader`` callable is supplied the composite
re-reads the unified config file on SIGHUP and hands the fresh
per-protocol sub-config to each child's ``apply_config`` before the
normal reload fan-out.  Without that step a SIGHUP only picks up
changes the child daemons read directly from disk (the mDNS
services.d directory); the hostname / netbios-name / workgroup /
interfaces recorded in ``truenas-discoveryd.conf`` would stay frozen
at the values captured at daemon startup.
"""
from __future__ import annotations

import enum
import logging
from typing import Callable, Sequence

from truenas_pydiscovery_utils.composite import CompositeDaemon
from truenas_pydiscovery_utils.daemon import BaseDaemon
from truenas_pymdns.server.server import MDNSServer
from truenas_pynetbiosns.server.server import NBNSServer
from truenas_pywsd.server.server import WSDServer

from .config import UnifiedConfig

logger = logging.getLogger(__name__)


class ChildName(enum.StrEnum):
    """Stable identifiers for the per-protocol children of the composite.

    Used as the ``name`` half of ``CompositeDaemon``'s
    ``(name, daemon)`` pairs and to project ``UnifiedConfig`` to the
    per-protocol sub-config on SIGHUP reload.
    """
    MDNS = "mdns"
    NETBIOSNS = "netbiosns"
    WSD = "wsd"


def build_composite_daemon(
    config: UnifiedConfig,
    config_reloader: Callable[[], UnifiedConfig] | None = None,
) -> CompositeDaemon:
    """Instantiate the enabled per-protocol servers and return a composite.

    When *config_reloader* is given, the composite re-reads the unified
    config on SIGHUP and hands the fresh per-protocol sub-config to
    each child's ``apply_config`` before its ``_reload()`` runs.
    """
    children: list[tuple[str, BaseDaemon]] = []
    if config.mdns is not None:
        children.append((ChildName.MDNS.value, MDNSServer(config.mdns)))
    if config.netbiosns is not None:
        children.append((ChildName.NETBIOSNS.value, NBNSServer(config.netbiosns)))
    if config.wsd is not None:
        children.append((ChildName.WSD.value, WSDServer(config.wsd)))
    return CompositeDaemon(
        logger,
        children,
        config_reloader=config_reloader,
        config_dispatch=(
            _dispatch_unified_config if config_reloader is not None else None
        ),
        pidfile=config.rundir / "truenas-discoveryd.pid",
    )


def _child_sub_config(config: UnifiedConfig, child_name: str):
    """Project the unified config down to the sub-config for *child_name*.

    Returns ``None`` when the protocol is disabled in the new config;
    callers keep the running child with its previous sub-config in
    that case (stopping mid-reload is out of scope for SIGHUP — the
    unit must be restarted to change the enabled set of protocols).
    """
    match child_name:
        case ChildName.MDNS.value:
            return config.mdns
        case ChildName.NETBIOSNS.value:
            return config.netbiosns
        case ChildName.WSD.value:
            return config.wsd
    return None


def _dispatch_unified_config(
    children: Sequence[tuple[str, BaseDaemon]],
    new_config: UnifiedConfig,
) -> None:
    """Push the fresh per-protocol sub-config into each running child.

    Wired into ``CompositeDaemon`` as the ``config_dispatch`` hook so
    SIGHUP reload updates each child's stored config before its
    ``_reload()`` runs.  Per-child exceptions are logged and swallowed
    so one misbehaving child doesn't block the others from seeing the
    new config.
    """
    for name, child in children:
        sub = _child_sub_config(new_config, name)
        if sub is None:
            logger.warning(
                "Reload: %s disabled in new config — "
                "restart truenas-discoveryd to apply", name,
            )
            continue
        # ``apply_config`` is declared on ``BaseDaemon`` with a
        # no-op default (see truenas_pydiscovery_utils/daemon.py),
        # so the call is always safe.  Subclasses that want to
        # support live-reload override it; those that don't will
        # silently skip their config update and re-read at
        # ``_reload`` time.
        try:
            child.apply_config(sub)
        except Exception:
            logger.exception(
                "Reload: child %s failed to apply new config", name,
            )
