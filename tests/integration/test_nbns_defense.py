"""Integration tests for NetBIOS registration and defense on the
wire.

Note on defender coverage: the ACT_ERR defensive-response path is
exercised end-to-end by ``tests/netbiosns/test_defender.py`` using
real ``NameTable`` and ``Defender`` objects.  A full same-host
integration test is impractical because the NBNS transport filters
out packets whose source IP matches the daemon's bound interface
(``if addr[0] == self._ifaddr: return``) and because unicast
replies to a spoofed source IP are not routable back to this
machine.  Reproducing the full flow reliably needs a secondary IP,
network namespace, or second host.

What we CAN integration-test on a single box is the *observable*
NetBIOS behaviour: the daemon broadcasts REGISTRATION packets on
port 137 at startup.  A receive socket on the broadcast group can
capture and validate them.
"""
from __future__ import annotations

import socket
import subprocess
import threading
import time

import pytest

from truenas_pynetbiosns.protocol.constants import (
    NBNS_PORT,
    Opcode,
    REGISTRATION_RETRY_COUNT,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage

from .conftest import (
    _ENV,
    _PYTHON,
    _UNIFIED_MODULE,
    _write_unified_config,
)

pytestmark = [pytest.mark.integration, pytest.mark.broadcast]


def _capture_registrations(
    listener: socket.socket,
    deadline: float,
    name: str,
) -> list[NBNSMessage]:
    """Collect broadcast REGISTRATION packets for *name* until *deadline*."""
    collected: list[NBNSMessage] = []
    while time.monotonic() < deadline:
        try:
            data, _addr = listener.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            msg = NBNSMessage.from_wire(data)
        except ValueError:
            continue
        if msg.opcode != Opcode.REGISTRATION:
            continue
        if any(
            q.name.name.upper() == name.upper() for q in msg.questions
        ):
            collected.append(msg)
    return collected


class TestRegistrationBroadcastOnStartup:
    def test_daemon_emits_retry_count_registration_packets(
        self, candidate_interface, has_broadcast, tmp_path,
    ):
        """At startup the daemon emits ``REGISTRATION_RETRY_COUNT``
        broadcast REGISTRATION packets for each of its NetBIOS
        names.  Capture them on the wire before the daemon has
        finished broadcasting."""
        if not has_broadcast:
            pytest.skip("NetBIOS NS requires broadcast-capable interface")

        iface_name, iface_addr, bcast = candidate_interface
        assert bcast is not None

        # Bind listener on port 137.  SO_REUSEPORT lets it coexist
        # with the daemon's own bind once that starts up.
        listener = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
        )
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        listener.bind(("", NBNS_PORT))
        listener.settimeout(0.3)

        # Write config + start daemon in-background so we can run the
        # listener concurrently from the moment the daemon boots.
        netbios_name = "PYTESTHOST"
        config_path = tmp_path / "truenas-pydiscoveryd.conf"
        _write_unified_config(
            config_path,
            interfaces=[iface_name],
            hostname=netbios_name,
            workgroup="TESTGROUP",
            rundir=tmp_path / "run",
            netbiosns={},
        )

        proc = subprocess.Popen(
            _PYTHON + [
                "-m", _UNIFIED_MODULE, "-c", str(config_path), "-v",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_ENV,
        )

        collected: list[NBNSMessage] = []

        def capture() -> None:
            collected.extend(_capture_registrations(
                listener, time.monotonic() + 4.0, netbios_name,
            ))

        capturer = threading.Thread(target=capture, daemon=True)
        capturer.start()
        capturer.join(timeout=5.0)

        try:
            # We don't assert an exact count because REGISTRATION
            # and REFRESH may both go out; the invariant is "at
            # least RETRY_COUNT packets naming PYTESTHOST".
            assert len(collected) >= REGISTRATION_RETRY_COUNT, (
                f"expected at least {REGISTRATION_RETRY_COUNT} "
                f"REGISTRATION packets for {netbios_name}, got "
                f"{len(collected)}"
            )
            for msg in collected:
                assert msg.opcode == Opcode.REGISTRATION
                assert msg.is_broadcast
        finally:
            listener.close()
            proc.send_signal(15)  # SIGTERM
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
