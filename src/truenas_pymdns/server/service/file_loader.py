"""Load service definitions from config directory and convert to entry groups."""
from __future__ import annotations

import logging
from pathlib import Path

from ..config import ServiceConfig, load_service_config
from ..core.entry_group import EntryGroup

logger = logging.getLogger(__name__)


def load_service_directory(directory: Path) -> list[ServiceConfig]:
    """Load all .conf service files from a directory."""
    if not directory.is_dir():
        logger.info("Service directory %s does not exist", directory)
        return []

    services: list[ServiceConfig] = []
    for path in sorted(directory.glob("*.conf")):
        svc = load_service_config(path)
        if svc is not None:
            logger.info(
                "Loaded service: %s (%s port %d) from %s",
                svc.instance_name, svc.service_type, svc.port, path.name,
            )
            services.append(svc)
    return services


def service_to_entry_group(
    svc: ServiceConfig,
    hostname: str,
    fqdn: str,
    interface_indexes: list[int] | None = None,
) -> EntryGroup:
    """Convert a ServiceConfig into an EntryGroup with mDNS records."""
    instance = svc.instance_name.replace("%h", hostname)
    host = svc.host or fqdn

    group = EntryGroup()
    group.interfaces = interface_indexes
    group.add_service(
        instance=instance,
        service_type=svc.service_type,
        domain=svc.domain,
        host=host,
        port=svc.port,
        txt=svc.txt or None,
        priority=svc.priority,
        weight=svc.weight,
        subtypes=svc.subtypes or None,
    )
    return group
