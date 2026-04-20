"""Integration tests for RFC 6762 conflict resolution and goodbye.

Covers two end-to-end behaviours that aren't exercised by the unit
suite because they involve the full daemon → wire → daemon path:

1. Two daemons publishing the same service name — the loser must
   rename to ``<name>-2`` after probing.
2. SIGTERM triggers goodbye (TTL=0) packets visible on the wire.
"""
from __future__ import annotations

import json
import signal
import socket
import time

import pytest

from truenas_pymdns.protocol.constants import (
    MDNS_IPV4_GROUP,
    MDNS_PORT,
)
from truenas_pymdns.protocol.message import MDNSMessage

from .conftest import run_tool

pytestmark = pytest.mark.integration


def _listener_socket(interface_addr: str) -> socket.socket:
    """Open an mDNS receive socket joined to the IPv4 group on
    *interface_addr*.  Uses SO_REUSEPORT so it coexists with the
    daemon's own bind on 5353."""
    sock = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
    )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind(("", MDNS_PORT))
    mreq = (
        socket.inet_aton(MDNS_IPV4_GROUP)
        + socket.inet_aton(interface_addr)
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(0.5)
    return sock


def _drain_packets(
    sock: socket.socket, deadline: float,
) -> list[MDNSMessage]:
    """Collect mDNS messages until *deadline* (monotonic) passes."""
    messages: list[MDNSMessage] = []
    while time.monotonic() < deadline:
        try:
            data, _addr = sock.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            messages.append(MDNSMessage.from_wire(data))
        except ValueError:
            continue
    return messages


class TestGoodbyeOnSigterm:
    def test_sigterm_emits_ttl_zero_responses_on_wire(self, mdns_daemon):
        """After SIGTERM the daemon must multicast TTL=0 responses
        (RFC 6762 s10.1) so peers flush stale cache entries."""
        listener = _listener_socket(mdns_daemon.interface_addr)
        try:
            # Start listening AFTER the daemon has announced; drain
            # any residual announce traffic first.
            _drain_packets(listener, time.monotonic() + 0.3)

            mdns_daemon.proc.send_signal(signal.SIGTERM)

            # Give the daemon up to 4 s to emit goodbye and exit.
            messages = _drain_packets(
                listener, time.monotonic() + 4.0,
            )

            fqdn = f"{mdns_daemon.hostname}.local"
            ttl_zero_records = []
            for msg in messages:
                for rr in msg.answers:
                    if rr.key.name == fqdn and rr.ttl == 0:
                        ttl_zero_records.append(rr)
            assert ttl_zero_records, (
                "expected TTL=0 goodbye records for "
                f"{fqdn} after SIGTERM"
            )
        finally:
            listener.close()
            # Ensure fixture teardown doesn't re-signal a dead proc.
            try:
                mdns_daemon.proc.wait(timeout=3)
            except Exception:
                pass


class TestProbeConflictRename:
    def test_loser_reregisters_under_renamed_instance(
        self, mdns_daemon_factory,
    ):
        """Two daemons with the same hostname and service name but
        different SRV rdata (different ports) trigger a conflict
        during probing.  The loser must rename its instance label
        via ``generate_alternative_name`` and re-register — so after
        the dust settles, browse sees BOTH ``pytest-conflict`` and
        ``pytest-conflict-2`` (or similar suffix)."""
        a_services = [{"type": "_test._tcp", "port": 9999, "name": "A"}]
        b_services = [{"type": "_test._tcp", "port": 8888, "name": "B"}]

        mdns_daemon_factory(a_services, hostname="pytest-conflict")
        time.sleep(1.5)  # let A finish probing + announce
        second = mdns_daemon_factory(b_services, hostname="pytest-conflict")
        # Allow B to detect conflict, rename, re-probe, and announce.
        time.sleep(6.0)

        result = run_tool([
            "mdns-browse", "_test._tcp", "-t", "5", "--json",
            "-i", second.interface_addr,
        ])
        assert result.returncode == 0, result.stderr

        entries = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        instances = {
            e["target"] for e in entries
            if e.get("target", "").endswith("._test._tcp.local")
        }
        pc_instances = {
            t for t in instances
            if t.startswith("pytest-conflict")
        }
        # Expect both the winner and a renamed loser.
        assert any(
            t.startswith("pytest-conflict.") for t in pc_instances
        ), f"winner missing from {pc_instances}"
        assert any(
            t.startswith("pytest-conflict-2.") for t in pc_instances
        ), f"renamed loser missing from {pc_instances}"
