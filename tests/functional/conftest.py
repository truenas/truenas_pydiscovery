"""Functional tests: the installed daemon, run by systemd.

The CI QEMU job (``.github/workflows/scripts/qemu-4-test.sh``) installs
the built package in a Debian VM and runs these as root.  Each test
puts ``truenas-discoveryd`` on veth links whose far ends sit in their
own network namespaces, and talks to it from there with the client
tools the package ships, as a host on the network would.

They reconfigure the host's network and its ``truenas-discoveryd``
service, so they run only when ``TRUENAS_PYDISCOVERY_FUNCTIONAL=1`` is
set, as root, on a host booted with systemd.

Addresses come from RFC 5737 ranges other than 192.0.2.0/24, which the
integration tests' dummy interface uses on the same host.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

import pytest

FUNCTIONAL_ENV = "TRUENAS_PYDISCOVERY_FUNCTIONAL"
UNIT = "truenas-discoveryd"
CONFIG_PATH = Path("/etc/truenas-discovery/truenas-discoveryd.conf")

NETBIOS_NAME = "NAS01"
HOST_NAME = "nas01"
WORKGROUP = "WG"

# How long a newly started or reconfigured daemon gets to start
# answering: name registration, mDNS probing and the WSD Hello all
# finish within a few seconds.
SERVE_TIMEOUT = 30.0


def _host_problem() -> str | None:
    if os.geteuid() != 0:
        return "the functional tests need root"
    if not Path("/run/systemd/system").is_dir():
        return "the functional tests need systemd as init"
    for tool in ("ip", UNIT, "nbt-lookup", "mdns-resolve", "wsd-discover"):
        if shutil.which(tool) is None:
            return f"{tool} is not installed"
    return None


@pytest.fixture(autouse=True)
def _require_functional_host() -> None:
    """Skip unless asked for; once asked for, a host that cannot run
    them fails the test, so a misconfigured CI run cannot pass by
    skipping."""
    if os.environ.get(FUNCTIONAL_ENV) != "1":
        pytest.skip(f"set {FUNCTIONAL_ENV}=1 to run the functional tests")
    problem = _host_problem()
    if problem is not None:
        pytest.fail(problem)


def run(*args: str, timeout: float = 60.0) -> str:
    """Run a command that must succeed; return its stdout."""
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{' '.join(args)} failed ({result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def wait_for(check: Callable[[], bool], what: str,
             timeout: float = SERVE_TIMEOUT) -> None:
    """Poll *check* until it returns True; fail naming *what*."""
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Links into client namespaces
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Link:
    """A veth pair: ``server`` stays with the daemon, ``client`` lives
    in network namespace ``netns``, where nothing else is configured."""
    server: str
    client: str
    netns: str

    def add_ipv4(self, server_address: str, client_address: str) -> None:
        """Address both ends (CIDR notation) and route the client
        namespace through the link, so that its limited broadcasts and
        multicast leave by it."""
        run("ip", "addr", "add", server_address, "brd", "+",
            "dev", self.server)
        run("ip", "-n", self.netns, "addr", "add", client_address,
            "brd", "+", "dev", self.client)
        run("ip", "-n", self.netns, "route", "replace", "default",
            "dev", self.client)

    def remove_ipv4(self, server_address: str) -> None:
        run("ip", "addr", "del", server_address, "dev", self.server)

    def client_run(self, *args: str, timeout: float = 30.0,
                   ) -> subprocess.CompletedProcess:
        """Run a command in the client namespace; its result is not checked."""
        return subprocess.run(
            ("ip", "netns", "exec", self.netns) + args,
            capture_output=True, text=True, timeout=timeout,
        )


LinkFactory = Callable[[int], Link]


def _ipv6_link_local_ready(device: str) -> bool:
    """True once *device*'s IPv6 link-local address has passed
    duplicate address detection, or if it gets none."""
    conf = Path("/proc/sys/net/ipv6/conf") / device
    if not conf.is_dir():
        return True
    if (conf / "disable_ipv6").read_text().strip() != "0":
        return True
    if (conf / "addr_gen_mode").read_text().strip() == "1":
        return True
    out = run("ip", "-6", "-o", "addr", "show", "dev", device,
              "scope", "link")
    return bool(out.strip()) and "tentative" not in out


@pytest.fixture
def links() -> Iterator[LinkFactory]:
    """Create ``Link`` number *n* on demand; every link and namespace
    is removed after the test."""
    created: list[Link] = []

    def create(number: int) -> Link:
        link = Link(
            server=f"pdsrv{number}", client=f"pdcli{number}",
            netns=f"pdns{number}",
        )
        run("ip", "netns", "add", link.netns)
        created.append(link)
        run("ip", "link", "add", link.server, "type", "veth",
            "peer", "name", link.client, "netns", link.netns)
        run("ip", "link", "set", link.server, "up")
        run("ip", "-n", link.netns, "link", "set", "lo", "up")
        run("ip", "-n", link.netns, "link", "set", link.client, "up")
        # The daemon counts an address only once duplicate address
        # detection has passed, so the link-local address becoming
        # usable a second or so after the link comes up is an interface
        # change of its own.  Let it happen here, so that a daemon
        # started on this link starts on its settled state and a test
        # sees only the changes it makes.
        wait_for(lambda: _ipv6_link_local_ready(link.server),
                 f"IPv6 duplicate address detection on {link.server}")
        return link

    try:
        yield create
    finally:
        for link in created:
            subprocess.run(["ip", "link", "del", link.server],
                           capture_output=True)
            subprocess.run(["ip", "netns", "del", link.netns],
                           capture_output=True)


# ---------------------------------------------------------------------------
# The daemon
# ---------------------------------------------------------------------------


def systemctl(*args: str, timeout: float = 120.0,
              ) -> subprocess.CompletedProcess:
    return subprocess.run(
        ("systemctl",) + args, capture_output=True, text=True,
        timeout=timeout,
    )


def unit_properties(*names: str) -> dict[str, str]:
    out = run("systemctl", "show", UNIT, "-p", ",".join(names))
    return dict(line.split("=", 1) for line in out.splitlines() if line)


class Discoveryd:
    """The ``truenas-discoveryd`` unit, configured by the test."""

    def configure(self, interfaces: list[str]) -> None:
        """Write a configuration serving *interfaces* with every
        protocol enabled."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(
            "[discovery]\n"
            f"interfaces = {', '.join(interfaces)}\n"
            f"hostname = {HOST_NAME}\n"
            f"workgroup = {WORKGROUP}\n"
            "\n"
            "[mdns]\n"
            "enabled = yes\n"
            "\n"
            "[netbiosns]\n"
            "enabled = yes\n"
            f"netbios-name = {NETBIOS_NAME}\n"
            "\n"
            "[wsd]\n"
            "enabled = yes\n"
        )

    def restart(self) -> None:
        # Every test restarts the unit; clear systemd's start rate
        # limit so a fast run of tests does not trip it.
        systemctl("reset-failed", UNIT)
        result = systemctl("restart", UNIT)
        assert result.returncode == 0, result.stderr

    def reload(self) -> subprocess.CompletedProcess:
        return systemctl("reload", UNIT)

    def stop(self) -> subprocess.CompletedProcess:
        return systemctl("stop", UNIT)

    def journal_since(self, since: float) -> str:
        return run(
            "journalctl", "-u", UNIT, f"--since=@{since:.6f}",
            "--no-pager", "-o", "cat",
        )


@pytest.fixture
def discoveryd() -> Iterator[Discoveryd]:
    """The daemon unit; stopped, and its previous configuration put
    back, after the test."""
    saved = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    try:
        yield Discoveryd()
    finally:
        systemctl("stop", UNIT)
        systemctl("reset-failed", UNIT)
        if saved is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(saved)


# ---------------------------------------------------------------------------
# Queries from a client namespace, with the shipped client tools
# ---------------------------------------------------------------------------


def _json_lines(stdout: str) -> list[dict]:
    return [json.loads(line) for line in stdout.splitlines() if line]


def netbios_addresses(link: Link, client_ip: str,
                      name: str = NETBIOS_NAME) -> set[str]:
    """Addresses the broadcast name query for *name*<20> gets back."""
    result = link.client_run(
        "nbt-lookup", name, "--json", "-t", "1", "-i", client_ip,
    )
    return {entry["ip"] for entry in _json_lines(result.stdout)}


def mdns_addresses(link: Link, client_ip: str,
                   host: str = f"{HOST_NAME}.local") -> set[str]:
    """Addresses an mDNS query for *host* gets back."""
    result = link.client_run(
        "mdns-resolve", "-n", host, "--json", "-t", "1", "-i", client_ip,
    )
    return {
        address
        for entry in _json_lines(result.stdout)
        for address in entry.get("addresses", [])
    }


def wsd_xaddrs(link: Link, client_ip: str) -> set[str]:
    """Transport addresses of every endpoint answering a WSD Probe."""
    result = link.client_run(
        "wsd-discover", "--json", "-t", "2", "-i", client_ip,
    )
    return {
        url
        for entry in _json_lines(result.stdout)
        for url in entry.get("xaddrs", "").split()
    }
