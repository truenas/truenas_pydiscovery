"""Factory that builds a ``CompositeDaemon`` from ``UnifiedConfig``.

Each enabled protocol's existing server class is instantiated with
its own ``DaemonConfig`` dataclass; the composite wraps them into one
lifecycle so ``truenas-pydiscoveryd`` can host all three.
"""
from __future__ import annotations

import logging

from truenas_pydiscovery_utils.composite import CompositeDaemon
from truenas_pydiscovery_utils.daemon import BaseDaemon
from truenas_pymdns.server.server import MDNSServer
from truenas_pynetbiosns.server.server import NBNSServer
from truenas_pywsd.server.server import WSDServer

from .config import UnifiedConfig

logger = logging.getLogger(__name__)


def build_composite_daemon(config: UnifiedConfig) -> CompositeDaemon:
    """Instantiate the enabled per-protocol servers and return a composite."""
    children: list[tuple[str, BaseDaemon]] = []
    if config.mdns is not None:
        children.append(("mdns", MDNSServer(config.mdns)))
    if config.netbiosns is not None:
        children.append(("netbiosns", NBNSServer(config.netbiosns)))
    if config.wsd is not None:
        children.append(("wsd", WSDServer(config.wsd)))
    return CompositeDaemon(logger, children)
