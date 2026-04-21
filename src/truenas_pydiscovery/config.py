"""Unified configuration for ``truenas-discoveryd``.

One INI file with a shared ``[discovery]`` section and three
per-protocol sections (``[mdns]``, ``[netbiosns]``, ``[wsd]``).
Shared fields from ``[discovery]`` (``interfaces``, ``hostname``,
``workgroup``) are used as defaults for any protocol section that
omits them.  Each section has an ``enabled = true|false`` flag; if
absent, the section is enabled.

The loader produces an existing per-protocol ``DaemonConfig``
dataclass for each enabled section, leaving the per-protocol config
types unchanged.  Disabled protocols are represented by ``None`` in
the returned ``UnifiedConfig``.
"""
from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path

from truenas_pymdns.server.config import (
    DaemonConfig as MdnsConfig,
    DEFAULT_SERVICE_DIR as MDNS_DEFAULT_SERVICE_DIR,
)
from truenas_pynetbiosns.server.config import (
    DaemonConfig as NbnsConfig,
)
from truenas_pywsd.server.config import (
    DaemonConfig as WsdConfig,
)

DEFAULT_CONFIG_PATH = Path(
    "/etc/truenas-discovery/truenas-discoveryd.conf",
)
DEFAULT_RUNDIR = Path("/run/truenas-discovery")


@dataclass(slots=True)
class UnifiedConfig:
    """The three per-protocol configs assembled from the unified file.

    ``None`` means the protocol is disabled (or its section missing).
    """
    mdns: MdnsConfig | None = None
    netbiosns: NbnsConfig | None = None
    wsd: WsdConfig | None = None
    rundir: Path = DEFAULT_RUNDIR


class NoProtocolsEnabledError(ValueError):
    """Raised when every protocol section is disabled or absent.

    The server entry point catches this and exits 0 so systemd's
    ``Restart=on-failure`` does not crash-loop when the operator has
    intentionally disabled every protocol.
    """


def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("yes", "true", "1", "on")


def _parse_list(val: str) -> list[str]:
    if not val.strip():
        return []
    return [s.strip() for s in val.split(",") if s.strip()]


def _section_enabled(
    cp: configparser.ConfigParser, section: str,
) -> bool:
    """Return True if *section* is present and not explicitly disabled."""
    if not cp.has_section(section):
        return False
    val = cp[section].get("enabled")
    if val is None:
        return True
    return _parse_bool(val)


def _build_mdns(
    cp: configparser.ConfigParser,
    shared_interfaces: list[str],
    shared_hostname: str,
    rundir: Path,
) -> MdnsConfig:
    cfg = MdnsConfig()
    cfg.server.interfaces = list(shared_interfaces)
    cfg.server.host_name = shared_hostname

    if cp.has_section("mdns"):
        s = cp["mdns"]
        if "interfaces" in s:
            cfg.server.interfaces = _parse_list(s["interfaces"])
        if "host-name" in s:
            cfg.server.host_name = s["host-name"]
        cfg.server.domain_name = s.get("domain-name", cfg.server.domain_name)
        if "use-ipv4" in s:
            cfg.server.use_ipv4 = _parse_bool(s["use-ipv4"])
        if "use-ipv6" in s:
            cfg.server.use_ipv6 = _parse_bool(s["use-ipv6"])
        if "cache-entries-max" in s:
            cfg.server.cache_entries_max = int(s["cache-entries-max"])
        if "ratelimit-interval-usec" in s:
            cfg.server.ratelimit_interval_usec = int(
                s["ratelimit-interval-usec"],
            )
        if "ratelimit-burst" in s:
            cfg.server.ratelimit_burst = int(s["ratelimit-burst"])
        if "enable-reflector" in s:
            cfg.reflector.enable_reflector = _parse_bool(
                s["enable-reflector"],
            )
        if "service-dir" in s:
            cfg.service_dir = Path(s["service-dir"])
        else:
            cfg.service_dir = MDNS_DEFAULT_SERVICE_DIR

    cfg.rundir = rundir / "mdns"
    return cfg


def _build_netbiosns(
    cp: configparser.ConfigParser,
    shared_interfaces: list[str],
    shared_hostname: str,
    shared_workgroup: str,
    rundir: Path,
) -> NbnsConfig:
    cfg = NbnsConfig()
    cfg.server.interfaces = list(shared_interfaces)
    cfg.server.netbios_name = shared_hostname
    cfg.server.workgroup = shared_workgroup or cfg.server.workgroup

    if cp.has_section("netbiosns"):
        s = cp["netbiosns"]
        if "interfaces" in s:
            cfg.server.interfaces = _parse_list(s["interfaces"])
        if "netbios-name" in s:
            cfg.server.netbios_name = s["netbios-name"]
        if "netbios-aliases" in s:
            cfg.server.netbios_aliases = _parse_list(s["netbios-aliases"])
        if "workgroup" in s:
            cfg.server.workgroup = s["workgroup"]
        if "server-string" in s:
            cfg.server.server_string = s["server-string"]

    # Re-run ServerConfig validation now that we've mutated it: the
    # dataclass only validates at construction, so build a fresh one.
    cfg.server = type(cfg.server)(
        netbios_name=cfg.server.netbios_name,
        netbios_aliases=cfg.server.netbios_aliases,
        workgroup=cfg.server.workgroup,
        server_string=cfg.server.server_string,
        interfaces=cfg.server.interfaces,
    )

    cfg.rundir = rundir / "netbiosns"
    return cfg


def _build_wsd(
    cp: configparser.ConfigParser,
    shared_interfaces: list[str],
    shared_hostname: str,
    shared_workgroup: str,
    rundir: Path,
) -> WsdConfig:
    """Build the WSD config from shared defaults + the ``[wsd]`` section.

    ``workgroup`` is shared with NetBIOS NS but is not NetBIOS-specific:
    WSD advertises it through the MS-PBSD ``pub:Computer`` element
    (``<hostname>/<label>:<workgroup-or-domain>``) so Windows clients
    can filter discovered hosts by workgroup membership.
    """
    cfg = WsdConfig()
    cfg.server.interfaces = list(shared_interfaces)
    cfg.server.hostname = shared_hostname
    cfg.server.workgroup = shared_workgroup or cfg.server.workgroup

    if cp.has_section("wsd"):
        s = cp["wsd"]
        if "interfaces" in s:
            cfg.server.interfaces = _parse_list(s["interfaces"])
        if "hostname" in s:
            cfg.server.hostname = s["hostname"]
        if "workgroup" in s:
            cfg.server.workgroup = s["workgroup"]
        if "domain" in s:
            cfg.server.domain = s["domain"]
        if "use-ipv4" in s:
            cfg.server.use_ipv4 = _parse_bool(s["use-ipv4"])
        if "use-ipv6" in s:
            cfg.server.use_ipv6 = _parse_bool(s["use-ipv6"])

    cfg.rundir = rundir / "wsd"
    return cfg


def load_unified_config(
    path: Path = DEFAULT_CONFIG_PATH,
) -> UnifiedConfig:
    """Load the unified config file into three per-protocol configs.

    Raises ``NoProtocolsEnabledError`` if all three protocols are
    disabled (or absent) — the daemon would have nothing to do.
    """
    cp = configparser.ConfigParser()
    if path.exists():
        cp.read(str(path))

    # Shared fields applied as fallback defaults to every protocol.
    shared_interfaces: list[str] = []
    shared_hostname: str = ""
    shared_workgroup: str = ""
    rundir = DEFAULT_RUNDIR

    if cp.has_section("discovery"):
        d = cp["discovery"]
        if "interfaces" in d:
            shared_interfaces = _parse_list(d["interfaces"])
        if "hostname" in d:
            shared_hostname = d["hostname"]
        if "workgroup" in d:
            shared_workgroup = d["workgroup"]
        if "rundir" in d:
            rundir = Path(d["rundir"])

    unified = UnifiedConfig(rundir=rundir)
    if _section_enabled(cp, "mdns"):
        unified.mdns = _build_mdns(
            cp, shared_interfaces, shared_hostname, rundir,
        )
    if _section_enabled(cp, "netbiosns"):
        unified.netbiosns = _build_netbiosns(
            cp, shared_interfaces, shared_hostname,
            shared_workgroup, rundir,
        )
    if _section_enabled(cp, "wsd"):
        unified.wsd = _build_wsd(
            cp, shared_interfaces, shared_hostname,
            shared_workgroup, rundir,
        )

    if (unified.mdns is None
            and unified.netbiosns is None
            and unified.wsd is None):
        raise NoProtocolsEnabledError(
            f"No protocols enabled in {path} — "
            "at least one of [mdns], [netbiosns], [wsd] must be present "
            "and have enabled = true",
        )

    return unified
