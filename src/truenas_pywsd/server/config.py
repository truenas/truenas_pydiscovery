"""Configuration for the WSD daemon.

In production the unified loader in ``truenas_pydiscovery.config``
reads the ``[wsd]`` section of
``/etc/truenas-discovery/truenas-discoveryd.conf`` into the
``DaemonConfig`` dataclass defined here.  The free-standing
``load_daemon_config`` function below is kept for tests and any
caller that wants to parse a WSD-only INI file directly.
"""
from __future__ import annotations

import configparser
import io
import socket
from dataclasses import dataclass, field
from pathlib import Path

# Legacy stand-alone config path (no longer used by the production
# daemon — retained as the parameter default for ``load_daemon_config``
# so tests and external callers get a predictable path).
DEFAULT_CONFIG_PATH = Path(
    "/etc/truenas-discovery/truenas-discoveryd.conf",
)
DEFAULT_RUNDIR = Path("/run/truenas-discovery/wsd")


@dataclass(slots=True)
class ServerConfig:
    """Core server settings."""
    hostname: str = ""
    workgroup: str = "WORKGROUP"
    domain: str = ""
    interfaces: list[str] = field(default_factory=list)
    use_ipv4: bool = True
    use_ipv6: bool = True


@dataclass(slots=True)
class DaemonConfig:
    """Top-level daemon configuration."""
    server: ServerConfig = field(default_factory=ServerConfig)
    rundir: Path = DEFAULT_RUNDIR


def get_hostname(config: ServerConfig) -> str:
    """Return the configured hostname, or the system hostname."""
    if config.hostname:
        return config.hostname
    return socket.gethostname().split(".")[0]


# ---------------------------------------------------------------------------
# Generation: dataclass -> INI bytes
# ---------------------------------------------------------------------------

def generate_daemon_config(config: DaemonConfig) -> bytes:
    """Generate daemon INI config bytes."""
    cp = configparser.ConfigParser()

    cp.add_section("server")
    s = config.server
    if s.hostname:
        cp.set("server", "hostname", s.hostname)
    cp.set("server", "workgroup", s.workgroup)
    if s.domain:
        cp.set("server", "domain", s.domain)
    cp.set("server", "interfaces", ", ".join(s.interfaces))
    cp.set("server", "use-ipv4", "yes" if s.use_ipv4 else "no")
    cp.set("server", "use-ipv6", "yes" if s.use_ipv6 else "no")

    cp.add_section("paths")
    cp.set("paths", "rundir", str(config.rundir))

    buf = io.StringIO()
    cp.write(buf)
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# Parsing: INI file -> dataclass
# ---------------------------------------------------------------------------

def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("yes", "true", "1", "on")


def _parse_list(val: str) -> list[str]:
    if not val.strip():
        return []
    return [s.strip() for s in val.split(",") if s.strip()]


def load_daemon_config(path: Path) -> DaemonConfig:
    """Load daemon config from an INI file."""
    cfg = DaemonConfig()

    if not path.exists():
        return cfg

    cp = configparser.ConfigParser()
    cp.read(str(path))

    if cp.has_section("server"):
        s = cp["server"]
        cfg.server.hostname = s.get("hostname", cfg.server.hostname)
        cfg.server.workgroup = s.get("workgroup", cfg.server.workgroup)
        cfg.server.domain = s.get("domain", cfg.server.domain)
        if "interfaces" in s:
            cfg.server.interfaces = _parse_list(s["interfaces"])
        if "use-ipv4" in s:
            cfg.server.use_ipv4 = _parse_bool(s["use-ipv4"])
        if "use-ipv6" in s:
            cfg.server.use_ipv6 = _parse_bool(s["use-ipv6"])

    if cp.has_section("paths"):
        p = cp["paths"]
        if "rundir" in p:
            cfg.rundir = Path(p["rundir"])

    return cfg
