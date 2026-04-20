"""Integration test fixtures: interface detection, daemon lifecycle.

These tests start the unified ``truenas-pydiscoveryd`` daemon on a
real network interface and drive the client CLI tools via subprocess
to validate behavior.  Requires root for ``SO_BINDTODEVICE`` and
privileged port binding.
"""
from __future__ import annotations

import array
import configparser
import fcntl
import io
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from truenas_pymdns.server.config import (
    ServiceConfig,
    generate_service_config,
)


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

_SIOCGIFCONF = 0x8912
_SIOCGIFFLAGS = 0x8913
_SIOCGIFBRDADDR = 0x8919
_IFF_UP = 0x1
_IFF_BROADCAST = 0x2
_IFF_LOOPBACK = 0x8
_IFF_MULTICAST = 0x1000
_IFREQ_SIZE = 40 if sys.maxsize > 2**32 else 32


def _get_flags(sock: socket.socket, ifname: str) -> int:
    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
    try:
        result = fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, ifreq)
    except OSError:
        return 0
    return struct.unpack("H", result[16:18])[0]


def _get_broadcast(sock: socket.socket, ifname: str) -> str | None:
    ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])
    try:
        result = fcntl.ioctl(sock.fileno(), _SIOCGIFBRDADDR, ifreq)
    except OSError:
        return None
    return str(IPv4Address(result[20:24]))


def _find_candidate_interface() -> tuple[str, str, str | None]:
    """Find a usable interface.

    Returns (name, ipv4_addr, broadcast_addr_or_None).
    Prefers a real interface with broadcast + multicast over loopback.
    """
    max_bytes = 16384
    addr_buf = array.array("B", b"\0" * max_bytes)
    buf_addr, _ = addr_buf.buffer_info()
    ifconf = struct.pack("iL", max_bytes, buf_addr)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        result = fcntl.ioctl(s.fileno(), _SIOCGIFCONF, ifconf)
        used_bytes = struct.unpack("iL", result)[0]
        raw = addr_buf.tobytes()[:used_bytes]

        for offset in range(0, used_bytes, _IFREQ_SIZE):
            chunk = raw[offset:offset + _IFREQ_SIZE]
            if len(chunk) < 24:
                break
            name = chunk[:16].split(b"\0", 1)[0].decode(
                "utf-8", errors="replace",
            )
            family = struct.unpack("<H", chunk[16:18])[0]
            if family != socket.AF_INET:
                continue
            addr = str(IPv4Address(chunk[20:24]))
            flags = _get_flags(s, name)
            if flags & _IFF_LOOPBACK:
                continue
            if not (flags & _IFF_UP):
                continue
            if not (flags & _IFF_BROADCAST):
                continue
            if not (flags & _IFF_MULTICAST):
                continue
            return (name, addr, _get_broadcast(s, name))
    finally:
        s.close()

    # Fallback: loopback (multicast only, no broadcast)
    return ("lo", "127.0.0.1", None)


@pytest.fixture(scope="session")
def candidate_interface():
    """Detect a usable network interface for integration tests."""
    return _find_candidate_interface()


@pytest.fixture(scope="session")
def has_broadcast(candidate_interface):
    """True if the candidate interface supports broadcast."""
    return candidate_interface[2] is not None


@pytest.fixture(scope="session")
def is_root():
    """True if running as root."""
    return os.getuid() == 0


@pytest.fixture(autouse=True)
def _require_root(is_root):
    """Skip all integration tests if not root."""
    if not is_root:
        pytest.skip("integration tests require root")


# ---------------------------------------------------------------------------
# Daemon info dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MDNSDaemonInfo:
    proc: subprocess.Popen
    hostname: str
    interface_name: str
    interface_addr: str
    config_path: Path
    service_dir: Path


@dataclass
class NBNSDaemonInfo:
    proc: subprocess.Popen
    netbios_name: str
    interface_name: str
    interface_addr: str
    config_path: Path


@dataclass
class WSDDaemonInfo:
    proc: subprocess.Popen
    hostname: str
    interface_name: str
    interface_addr: str
    config_path: Path


# ---------------------------------------------------------------------------
# Daemon lifecycle helpers
# ---------------------------------------------------------------------------

STARTUP_WAIT = 3  # seconds for probing + announcing

# Use sys.executable so we always run the local source via PYTHONPATH,
# even when the package isn't installed system-wide.
_PYTHON = [sys.executable]
_ENV = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")}

_UNIFIED_MODULE = "truenas_pydiscovery.server"


# Map CLI tool names to their -m module paths
_TOOL_MODULES = {
    "mdns-browse": "truenas_pymdns.client.cli.browse",
    "mdns-resolve": "truenas_pymdns.client.cli.resolve",
    "mdns-lookup": "truenas_pymdns.client.cli.lookup",
    "nbt-lookup": "truenas_pynetbiosns.client.cli.lookup",
    "nbt-status": "truenas_pynetbiosns.client.cli.status",
    "wsd-discover": "truenas_pywsd.client.cli.discover",
    "wsd-info": "truenas_pywsd.client.cli.info",
}


def run_tool(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a client CLI tool via ``python -m``.

    First argument must be the tool name (e.g. "mdns-browse").
    Remaining arguments are passed through.
    """
    tool = args[0]
    module = _TOOL_MODULES[tool]
    cmd = _PYTHON + ["-m", module] + args[1:]
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 15)
    kwargs.setdefault("env", _ENV)
    return subprocess.run(cmd, **kwargs)


def _start_daemon(cmd: list[str]) -> subprocess.Popen:
    """Start a daemon subprocess using the current Python interpreter."""
    proc = subprocess.Popen(
        _PYTHON + cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_ENV,
    )
    time.sleep(STARTUP_WAIT)
    if proc.poll() is not None:
        stdout = proc.stdout.read().decode() if proc.stdout else ""
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        raise RuntimeError(
            f"Daemon exited early (rc={proc.returncode})\n"
            f"stdout: {stdout}\nstderr: {stderr}"
        )
    return proc


def _stop_daemon(proc: subprocess.Popen) -> None:
    """Stop a daemon gracefully."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


# ---------------------------------------------------------------------------
# Unified config writer
# ---------------------------------------------------------------------------

def _write_unified_config(
    path: Path,
    *,
    interfaces: list[str],
    hostname: str,
    workgroup: str,
    rundir: Path,
    mdns: dict | None = None,
    netbiosns: dict | None = None,
    wsd: dict | None = None,
) -> None:
    """Write a ``truenas-pydiscoveryd.conf`` enabling only the
    protocols that receive a (possibly empty) options dict.
    """
    cp = configparser.ConfigParser()

    cp.add_section("discovery")
    cp.set("discovery", "interfaces", ", ".join(interfaces))
    cp.set("discovery", "hostname", hostname)
    cp.set("discovery", "workgroup", workgroup)
    cp.set("discovery", "rundir", str(rundir))

    for name, opts in (("mdns", mdns), ("netbiosns", netbiosns), ("wsd", wsd)):
        if opts is None:
            continue
        cp.add_section(name)
        cp.set(name, "enabled", "true")
        for k, v in opts.items():
            cp.set(name, k, str(v))

    buf = io.StringIO()
    cp.write(buf)
    path.write_bytes(buf.getvalue().encode("utf-8"))


# ---------------------------------------------------------------------------
# mDNS daemon fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def mdns_daemon(candidate_interface, tmp_path):
    """Start truenas-pydiscoveryd (mDNS only) with a test service."""
    iface_name, iface_addr, _ = candidate_interface
    hostname = "pytest-mdns"

    svc_dir = tmp_path / "services.d"
    svc_dir.mkdir()
    svc = ServiceConfig(
        service_type="_test._tcp",
        port=9999,
        instance_name="%h",
    )
    (svc_dir / "TEST.conf").write_bytes(generate_service_config(svc))

    config_path = tmp_path / "truenas-pydiscoveryd.conf"
    _write_unified_config(
        config_path,
        interfaces=[iface_name],
        hostname=hostname,
        workgroup="WORKGROUP",
        rundir=tmp_path / "run",
        mdns={
            "use-ipv4": "yes",
            "use-ipv6": "no",
            "service-dir": str(svc_dir),
        },
    )

    proc = _start_daemon([
        "-m", _UNIFIED_MODULE, "-c", str(config_path), "-v",
    ])

    yield MDNSDaemonInfo(
        proc=proc,
        hostname=hostname,
        interface_name=iface_name,
        interface_addr=iface_addr,
        config_path=config_path,
        service_dir=svc_dir,
    )

    _stop_daemon(proc)


# ---------------------------------------------------------------------------
# mDNS daemon with custom services fixture factory
# ---------------------------------------------------------------------------

@pytest.fixture
def mdns_daemon_factory(candidate_interface, tmp_path_factory):
    """Factory fixture: start the unified daemon with the given services."""
    daemons: list[subprocess.Popen] = []

    def _create(services: list[dict], hostname: str = "pytest-mdns"):
        iface_name, iface_addr, _ = candidate_interface
        tmp_path = tmp_path_factory.mktemp("mdns")

        svc_dir = tmp_path / "services.d"
        svc_dir.mkdir()
        for svc_def in services:
            svc = ServiceConfig(
                service_type=svc_def["type"],
                port=svc_def["port"],
                instance_name="%h",
                txt=svc_def.get("txt", {}),
            )
            fname = svc_def["name"] + ".conf"
            (svc_dir / fname).write_bytes(generate_service_config(svc))

        config_path = tmp_path / "truenas-pydiscoveryd.conf"
        _write_unified_config(
            config_path,
            interfaces=[iface_name],
            hostname=hostname,
            workgroup="WORKGROUP",
            rundir=tmp_path / "run",
            mdns={
                "use-ipv4": "yes",
                "use-ipv6": "no",
                "service-dir": str(svc_dir),
            },
        )

        proc = _start_daemon([
            "-m", _UNIFIED_MODULE, "-c", str(config_path), "-v",
        ])
        daemons.append(proc)

        return MDNSDaemonInfo(
            proc=proc,
            hostname=hostname,
            interface_name=iface_name,
            interface_addr=iface_addr,
            config_path=config_path,
            service_dir=svc_dir,
        )

    yield _create

    for proc in daemons:
        _stop_daemon(proc)


# ---------------------------------------------------------------------------
# NetBIOS NS daemon fixtures
# ---------------------------------------------------------------------------

def _start_netbiosns(
    candidate_interface, tmp_path, interfaces_token: str | None,
) -> NBNSDaemonInfo:
    iface_name, iface_addr, _ = candidate_interface
    netbios_name = "PYTESTHOST"

    netbiosns_opts: dict = {}
    if interfaces_token is not None:
        netbiosns_opts["interfaces"] = interfaces_token

    config_path = tmp_path / "truenas-pydiscoveryd.conf"
    _write_unified_config(
        config_path,
        interfaces=[iface_name],
        hostname=netbios_name,
        workgroup="TESTGROUP",
        rundir=tmp_path / "run",
        netbiosns=netbiosns_opts,
    )

    proc = _start_daemon([
        "-m", _UNIFIED_MODULE, "-c", str(config_path), "-v",
    ])

    return NBNSDaemonInfo(
        proc=proc,
        netbios_name=netbios_name,
        interface_name=iface_name,
        interface_addr=iface_addr,
        config_path=config_path,
    )


@pytest.fixture
def netbiosns_daemon(candidate_interface, has_broadcast, tmp_path):
    """Start truenas-pydiscoveryd (NetBIOS NS only) using the iface name."""
    if not has_broadcast:
        pytest.skip("NetBIOS NS requires broadcast-capable interface")

    info = _start_netbiosns(candidate_interface, tmp_path, None)
    yield info
    _stop_daemon(info.proc)


@pytest.fixture
def netbiosns_daemon_factory(candidate_interface, has_broadcast, tmp_path):
    """Factory: start NetBIOS NS with a caller-supplied interfaces token."""
    if not has_broadcast:
        pytest.skip("NetBIOS NS requires broadcast-capable interface")

    started: list[NBNSDaemonInfo] = []

    def _create(interfaces_token: str) -> NBNSDaemonInfo:
        info = _start_netbiosns(
            candidate_interface, tmp_path, interfaces_token,
        )
        started.append(info)
        return info

    yield _create

    for info in started:
        _stop_daemon(info.proc)


# ---------------------------------------------------------------------------
# WSD daemon fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def wsd_daemon(candidate_interface, tmp_path):
    """Start truenas-pydiscoveryd (WSD only)."""
    iface_name, iface_addr, _ = candidate_interface
    hostname = "pytest-wsd"

    config_path = tmp_path / "truenas-pydiscoveryd.conf"
    _write_unified_config(
        config_path,
        interfaces=[iface_name],
        hostname=hostname,
        workgroup="TESTGROUP",
        rundir=tmp_path / "run",
        wsd={
            "use-ipv4": "yes",
            "use-ipv6": "no",
        },
    )

    proc = _start_daemon([
        "-m", _UNIFIED_MODULE, "-c", str(config_path), "-v",
    ])

    yield WSDDaemonInfo(
        proc=proc,
        hostname=hostname,
        interface_name=iface_name,
        interface_addr=iface_addr,
        config_path=config_path,
    )

    _stop_daemon(proc)
