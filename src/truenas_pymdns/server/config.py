"""mDNS daemon configuration: validated dataclasses with INI
generation and parsing.

The middleware calls ``generate_daemon_config()`` and
``generate_service_config()`` to produce config bytes from
validated parameters.  The daemon side is driven by the unified
loader in ``truenas_pydiscovery.config``, which reads the
``[mdns]`` section of ``truenas-discoveryd.conf`` into a
``DaemonConfig`` (defined here); ``load_daemon_config()`` below
remains for compatibility with tests and any caller that wants to
load a free-standing mDNS-only config file.

Unified daemon config (the sole production path):

    /etc/truenas-discovery/truenas-discoveryd.conf

    [mdns]
    enabled = yes
    host-name = truenas
    domain-name = local
    interfaces = eth0, eth1
    use-ipv4 = yes
    use-ipv6 = yes
    cache-entries-max = 4096
    service-dir = /etc/truenas-discovery/services.d

Per-service file format
(``/etc/truenas-discovery/services.d/SMB.conf``):

    [service]
    type = _smb._tcp
    port = 445
    interfaces = eth0

    [txt]
    model = MacPro7,1
"""
from __future__ import annotations

import configparser
import io
import socket
from dataclasses import dataclass, field
from pathlib import Path

from truenas_pymdns.protocol.constants import (
    DEFAULT_CACHE_MAX_ENTRIES,
    MAX_UINT16,
)

# Legacy stand-alone config path (no longer used by the production
# daemon — kept as the parameter default for ``load_daemon_config``
# so tests and external callers get a predictable path).
DEFAULT_CONFIG_PATH = Path(
    "/etc/truenas-discovery/truenas-discoveryd.conf",
)

# Bounds for config values parsed from INI files
_MIN_CACHE_ENTRIES = 64
_MAX_CACHE_ENTRIES = 1_000_000
_MAX_RATELIMIT_INTERVAL_USEC = 60_000_000
_MAX_RATELIMIT_BURST = 100_000
DEFAULT_SERVICE_DIR = Path("/etc/truenas-discovery/services.d")
DEFAULT_RUNDIR = Path("/run/truenas-discovery/mdns")


# ---------------------------------------------------------------------------
# Daemon config dataclasses
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ServerConfig:
    """Core server settings: hostname, interfaces, protocols."""
    host_name: str = ""
    domain_name: str = "local"
    interfaces: list[str] = field(default_factory=list)
    use_ipv4: bool = True
    use_ipv6: bool = True
    cache_entries_max: int = DEFAULT_CACHE_MAX_ENTRIES
    ratelimit_interval_usec: int = 1_000_000
    ratelimit_burst: int = 1000


@dataclass(slots=True)
class ReflectorConfig:
    """Configuration for cross-interface mDNS reflector mode."""
    enable_reflector: bool = False


@dataclass(slots=True)
class DaemonConfig:
    """Top-level daemon configuration aggregating all config sections."""
    server: ServerConfig = field(default_factory=ServerConfig)
    reflector: ReflectorConfig = field(default_factory=ReflectorConfig)
    service_dir: Path = DEFAULT_SERVICE_DIR
    rundir: Path = DEFAULT_RUNDIR


@dataclass(slots=True)
class ServiceConfig:
    """A single mDNS service definition.

    Validated parameters for generating a service .conf file.
    """
    service_type: str
    port: int
    instance_name: str = "%h"
    domain: str = "local"
    host: str | None = None
    interfaces: list[str] = field(default_factory=list)
    txt: dict[str, str] = field(default_factory=dict)
    priority: int = 0
    weight: int = 0
    subtypes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.service_type:
            raise ValueError("service_type is required")
        if not self.service_type.startswith("_"):
            raise ValueError(
                f"service_type must start with underscore: "
                f"{self.service_type!r}"
            )
        if not (0 <= self.port <= MAX_UINT16):
            raise ValueError(
                f"port must be 0-{MAX_UINT16}, got {self.port}"
            )
        if not (0 <= self.priority <= MAX_UINT16):
            raise ValueError(
                f"priority must be 0-{MAX_UINT16}, got {self.priority}"
            )
        if not (0 <= self.weight <= MAX_UINT16):
            raise ValueError(
                f"weight must be 0-{MAX_UINT16}, got {self.weight}"
            )


# ---------------------------------------------------------------------------
# Generation: dataclass -> INI bytes
# ---------------------------------------------------------------------------

def _bool_str(val: bool) -> str:
    return "yes" if val else "no"


def generate_daemon_config(config: DaemonConfig) -> bytes:
    """Generate daemon INI config bytes from a validated DaemonConfig."""
    cp = configparser.ConfigParser()

    cp.add_section("server")
    s = config.server
    if s.host_name:
        cp.set("server", "host-name", s.host_name)
    cp.set("server", "domain-name", s.domain_name)
    cp.set("server", "interfaces", ", ".join(s.interfaces))
    cp.set("server", "use-ipv4", _bool_str(s.use_ipv4))
    cp.set("server", "use-ipv6", _bool_str(s.use_ipv6))
    cp.set("server", "cache-entries-max", str(s.cache_entries_max))
    cp.set("server", "ratelimit-interval-usec",
           str(s.ratelimit_interval_usec))
    cp.set("server", "ratelimit-burst", str(s.ratelimit_burst))

    cp.add_section("reflector")
    cp.set("reflector", "enable-reflector",
           _bool_str(config.reflector.enable_reflector))

    cp.add_section("paths")
    cp.set("paths", "service-dir", str(config.service_dir))
    cp.set("paths", "rundir", str(config.rundir))

    buf = io.StringIO()
    cp.write(buf)
    return buf.getvalue().encode("utf-8")


def generate_service_config(service: ServiceConfig) -> bytes:
    """Generate a service .conf file bytes from a validated ServiceConfig."""
    cp = configparser.ConfigParser()

    cp.add_section("service")
    cp.set("service", "type", service.service_type)
    cp.set("service", "port", str(service.port))
    if service.instance_name != "%h":
        cp.set("service", "name", service.instance_name)
    if service.domain != "local":
        cp.set("service", "domain", service.domain)
    if service.host:
        cp.set("service", "host", service.host)
    if service.interfaces:
        cp.set("service", "interfaces",
               ", ".join(service.interfaces))
    if service.priority:
        cp.set("service", "priority", str(service.priority))
    if service.weight:
        cp.set("service", "weight", str(service.weight))

    if service.txt:
        cp.add_section("txt")
        for key, value in service.txt.items():
            cp.set("txt", key, value)

    buf = io.StringIO()
    cp.write(buf)
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# Parsing: INI file/bytes -> dataclass
# ---------------------------------------------------------------------------

def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("yes", "true", "1", "on")


def _parse_list(val: str) -> list[str]:
    if not val.strip():
        return []
    return [s.strip() for s in val.split(",") if s.strip()]


def load_daemon_config(
    path: Path = DEFAULT_CONFIG_PATH,
) -> DaemonConfig:
    """Load daemon configuration from an INI file."""
    cfg = DaemonConfig()
    if not path.exists():
        return cfg

    cp = configparser.ConfigParser()
    cp.read(str(path))

    if cp.has_section("server"):
        s = cp["server"]
        cfg.server.host_name = s.get("host-name", cfg.server.host_name)
        cfg.server.domain_name = s.get(
            "domain-name", cfg.server.domain_name
        )
        if "interfaces" in s:
            cfg.server.interfaces = _parse_list(s["interfaces"])
        if "use-ipv4" in s:
            cfg.server.use_ipv4 = _parse_bool(s["use-ipv4"])
        if "use-ipv6" in s:
            cfg.server.use_ipv6 = _parse_bool(s["use-ipv6"])
        if "cache-entries-max" in s:
            val = int(s["cache-entries-max"])
            cfg.server.cache_entries_max = max(
                _MIN_CACHE_ENTRIES, min(val, _MAX_CACHE_ENTRIES)
            )
        if "ratelimit-interval-usec" in s:
            val = int(s["ratelimit-interval-usec"])
            cfg.server.ratelimit_interval_usec = max(
                0, min(val, _MAX_RATELIMIT_INTERVAL_USEC)
            )
        if "ratelimit-burst" in s:
            val = int(s["ratelimit-burst"])
            cfg.server.ratelimit_burst = max(
                1, min(val, _MAX_RATELIMIT_BURST)
            )

    if cp.has_section("reflector"):
        r = cp["reflector"]
        if "enable-reflector" in r:
            cfg.reflector.enable_reflector = _parse_bool(
                r["enable-reflector"]
            )

    if cp.has_section("paths"):
        paths = cp["paths"]
        if "service-dir" in paths:
            cfg.service_dir = Path(paths["service-dir"])
        if "rundir" in paths:
            cfg.rundir = Path(paths["rundir"])

    return cfg


def load_service_config(path: Path) -> ServiceConfig | None:
    """Load a single service .conf file into a validated ServiceConfig."""
    cp = configparser.ConfigParser()
    try:
        cp.read(str(path))
    except configparser.Error:
        return None

    if not cp.has_section("service"):
        return None

    s = cp["service"]
    svc_type = s.get("type")
    if not svc_type:
        return None

    try:
        port = int(s.get("port", "0"))
    except ValueError:
        return None

    txt: dict[str, str] = {}
    if cp.has_section("txt"):
        for key, value in cp.items("txt"):
            txt[key] = value

    ifaces: list[str] = []
    if "interfaces" in s:
        ifaces = _parse_list(s["interfaces"])

    try:
        return ServiceConfig(
            service_type=svc_type,
            port=port,
            instance_name=s.get("name", "%h"),
            domain=s.get("domain", "local"),
            host=s.get("host") or None,
            interfaces=ifaces,
            txt=txt,
            priority=int(s.get("priority", "0")),
            weight=int(s.get("weight", "0")),
        )
    except (ValueError, TypeError):
        return None


def get_hostname(config: ServerConfig) -> str:
    """Resolve effective hostname from config or system."""
    if config.host_name:
        return config.host_name
    hostname = socket.gethostname()
    if "." in hostname:
        hostname = hostname.split(".")[0]
    return hostname
