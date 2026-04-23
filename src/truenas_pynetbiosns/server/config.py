"""Configuration for the NetBIOS Name Service daemon.

In production the unified loader in ``truenas_pydiscovery.config``
reads the ``[netbiosns]`` section of
``/etc/truenas-discovery/truenas-discoveryd.conf`` into the
``DaemonConfig`` dataclass defined here.  The free-standing
``load_daemon_config`` function below is kept for tests and any
caller that wants to parse an NBNS-only INI file directly.
"""
from __future__ import annotations

import configparser
import io
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from truenas_pydiscovery_utils.interface_tokens import classify_token

# Legacy stand-alone config path (no longer used by the production
# daemon — retained as the parameter default for ``load_daemon_config``
# so tests and external callers get a predictable path).
DEFAULT_CONFIG_PATH = Path(
    "/etc/truenas-discovery/truenas-discoveryd.conf",
)
DEFAULT_RUNDIR = Path("/run/truenas-discovery/netbiosns")
NETBIOS_NAME_MAX_LEN = 15

# Valid characters for NetBIOS computer names (no dots).
# Mirrors middlewared/utils/netbios.py RE_NETBIOSNAME.
_RE_NETBIOS_NAME = re.compile(
    r"^(?![0-9]*$)[a-zA-Z0-9\-_!@#\$%^&\(\)'\{\}~]{1,15}$"
)

# Valid characters for NetBIOS domain/workgroup names (dots allowed for scope).
_RE_NETBIOS_DOMAIN = re.compile(
    r"^(?![0-9]*$)[a-zA-Z0-9\.\-_!@#\$%^&\(\)'\{\}~]{1,15}$"
)

# Microsoft and RFC 852 reserved words that cannot be NetBIOS names.
_RESERVED_WORDS = frozenset({
    "anonymous", "authenticated user", "batch", "builtin",
    "dialup", "enterprise", "interactive", "internet",
    "network", "null", "proxy", "restricted", "self",
    "users", "world", "gateway", "gw", "tac",
})


def validate_netbios_name(name: str) -> None:
    """Raise ValueError if *name* is not a valid NetBIOS computer name."""
    if not _RE_NETBIOS_NAME.match(name):
        raise ValueError(
            f"Invalid NetBIOS name {name!r}: must be 1-15 characters, "
            r"alphanumeric or -_!@#$%^&()\'{}~, not all digits"
        )
    if name.casefold() in _RESERVED_WORDS:
        raise ValueError(
            f"NetBIOS name {name!r} is a reserved word"
        )


def validate_netbios_domain(name: str) -> None:
    """Raise ValueError if *name* is not a valid NetBIOS domain/workgroup."""
    if not _RE_NETBIOS_DOMAIN.match(name):
        raise ValueError(
            f"Invalid NetBIOS workgroup {name!r}: must be 1-15 characters, "
            r"alphanumeric or .-_!@#$%^&()\'{}~, not all digits"
        )
    if name.casefold() in _RESERVED_WORDS:
        raise ValueError(
            f"NetBIOS workgroup {name!r} is a reserved word"
        )


@dataclass(slots=True)
class ServerConfig:
    """Core server settings.

    ``interfaces`` accepts a mix of three token forms, resolved at
    daemon startup against the live network state:

    - Interface name (``eth0``) — every IPv4 address on the interface
    - Bare IPv4 (``10.0.0.5``) — one specific local address
    - CIDR (``192.168.1.0/24``) — any local address inside the network;
      the user-supplied prefix overrides the kernel netmask

    Each resolved entry becomes one broadcast domain the daemon
    participates in, matching Samba's ``subnet_record`` model.
    """
    netbios_name: str = ""
    netbios_aliases: list[str] = field(default_factory=list)
    workgroup: str = "WORKGROUP"
    server_string: str = ""
    interfaces: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.netbios_name:
            validate_netbios_name(self.netbios_name)
        for alias in self.netbios_aliases:
            validate_netbios_name(alias)
        if self.workgroup:
            validate_netbios_domain(self.workgroup)
        # Accept all three token kinds (name / IPv4 / CIDR) — NBNS
        # is the one protocol that uses the richer forms — but
        # fail loudly on empty strings or malformed CIDRs rather
        # than deferring the discovery of bad tokens to startup.
        for tok in self.interfaces:
            classify_token(tok)


@dataclass(slots=True)
class DaemonConfig:
    """Top-level daemon configuration."""
    server: ServerConfig = field(default_factory=ServerConfig)
    rundir: Path = DEFAULT_RUNDIR


def get_netbios_name(config: ServerConfig) -> str:
    """Return the configured NetBIOS name, or the system hostname."""
    if config.netbios_name:
        return config.netbios_name.upper()
    return socket.gethostname().split(".")[0].upper()[:15]


# ---------------------------------------------------------------------------
# Generation: dataclass -> INI bytes
# ---------------------------------------------------------------------------

def generate_daemon_config(config: DaemonConfig) -> bytes:
    """Generate daemon INI config bytes from a DaemonConfig."""
    cp = configparser.ConfigParser()

    cp.add_section("server")
    s = config.server
    if s.netbios_name:
        cp.set("server", "netbios-name", s.netbios_name)
    if s.netbios_aliases:
        cp.set("server", "netbios-aliases", ", ".join(s.netbios_aliases))
    cp.set("server", "workgroup", s.workgroup)
    if s.server_string:
        cp.set("server", "server-string", s.server_string)
    cp.set("server", "interfaces", ", ".join(s.interfaces))

    cp.add_section("paths")
    cp.set("paths", "rundir", str(config.rundir))

    buf = io.StringIO()
    cp.write(buf)
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# Parsing: INI file -> dataclass
# ---------------------------------------------------------------------------

def _parse_list(val: str) -> list[str]:
    if not val.strip():
        return []
    return [s.strip() for s in val.split(",") if s.strip()]


def load_daemon_config(path: Path) -> DaemonConfig:
    """Load daemon config from an INI file.  Missing file uses defaults."""
    cfg = DaemonConfig()

    if not path.exists():
        return cfg

    cp = configparser.ConfigParser()
    cp.read(str(path))

    if cp.has_section("server"):
        s = cp["server"]
        cfg.server.netbios_name = s.get(
            "netbios-name", cfg.server.netbios_name,
        )
        if "netbios-aliases" in s:
            cfg.server.netbios_aliases = _parse_list(s["netbios-aliases"])
        cfg.server.workgroup = s.get("workgroup", cfg.server.workgroup)
        cfg.server.server_string = s.get(
            "server-string", cfg.server.server_string,
        )
        if "interfaces" in s:
            cfg.server.interfaces = _parse_list(s["interfaces"])

    if cp.has_section("paths"):
        p = cp["paths"]
        if "rundir" in p:
            cfg.rundir = Path(p["rundir"])

    return cfg
