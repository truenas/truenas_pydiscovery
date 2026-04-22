"""Load service definitions from config directory and convert to entry groups."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ..config import ServiceConfig, load_service_config
from ..core.entry_group import EntryGroup

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ServiceKey:
    """Identity of a published service for delta-reload purposes.

    Two ``ServiceConfig`` instances with the same ``ServiceKey`` would
    publish byte-identical mDNS records and need no re-registration
    when the service directory is reloaded.  Every field that reaches
    the wire (TXT, subtypes, SRV priority/weight/port/target/instance,
    service type, domain, interface binding) is part of the key;
    fields that don't (the .conf filename) are not.

    Used by ``MDNSServer``'s delta-reload path to diff the set of
    currently-registered service groups against the newly-loaded
    service directory and emit per-service add/remove actions instead
    of tearing every record down on every SIGHUP.
    """
    service_type: str
    instance_name: str
    domain: str
    host: str
    port: int
    priority: int
    weight: int
    interfaces: frozenset[str]
    subtypes: frozenset[str]
    txt: tuple[tuple[str, str], ...]

    @classmethod
    def from_config(
        cls, svc: ServiceConfig, hostname: str, fqdn: str,
    ) -> ServiceKey:
        """Build a key from *svc* resolved at the current hostname.

        The ``%h`` substitution in ``instance_name`` and the default
        of *fqdn* for an unset ``host`` are both applied here, so two
        configs that produce the same wire records via different
        paths (explicit name vs. ``%h``, explicit host vs. default)
        yield equal keys.
        """
        return cls(
            service_type=svc.service_type,
            instance_name=svc.instance_name.replace("%h", hostname),
            domain=svc.domain,
            host=svc.host or fqdn,
            port=svc.port,
            priority=svc.priority,
            weight=svc.weight,
            interfaces=frozenset(svc.interfaces),
            subtypes=frozenset(svc.subtypes),
            txt=tuple(sorted(svc.txt.items())),
        )


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
