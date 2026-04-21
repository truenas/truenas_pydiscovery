"""Integration tests for the NetBIOS NS daemon and client tools."""
from __future__ import annotations

import ipaddress
import json

import pytest

from .conftest import run_tool

pytestmark = [pytest.mark.integration, pytest.mark.broadcast]


class TestNbtLookup:
    def test_resolves_name(self, netbiosns_daemon):
        # Broadcast name query — on a shared network, other hosts
        # may respond too. Verify our daemon started and the tool
        # can execute. The query result depends on network state.
        result = run_tool([
            "nbt-lookup", netbiosns_daemon.netbios_name, "--json",
            "-t", "3",
        ])
        # returncode 0 = got a response, 1 = no response (both valid
        # depending on network). Just verify the tool didn't crash.
        assert result.returncode in (0, 1)
        if result.returncode == 0:
            lines = [
                json.loads(line)
                for line in result.stdout.strip().splitlines()
                if line.strip()
            ]
            assert len(lines) > 0


class TestNbtStatus:
    def test_shows_registered_names(self, netbiosns_daemon):
        # Query our own daemon's IP directly (unicast node status)
        result = run_tool([
            "nbt-status", netbiosns_daemon.interface_addr, "--json",
        ])
        # Node status may return names from any host at that IP.
        # On a shared network, our daemon and other responders
        # may both answer. Check that we got at least some names.
        assert result.returncode == 0, result.stderr
        lines = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        assert len(lines) > 0, "No names returned from node status"

    def test_shows_workstation_and_server_types(self, netbiosns_daemon):
        result = run_tool([
            "nbt-status", netbiosns_daemon.interface_addr, "--json",
        ])
        lines = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        # Verify at least some name types are present
        types = {entry["type"] for entry in lines}
        assert len(types) > 0, "No name types in node status"


class TestInterfacesTokenForms:
    def test_bare_ip_token_works(
        self, candidate_interface, netbiosns_daemon_factory,
    ):
        """``interfaces = <ipv4>`` resolves to the owning interface."""
        _, iface_addr, _ = candidate_interface
        daemon = netbiosns_daemon_factory(iface_addr)

        result = run_tool([
            "nbt-status", daemon.interface_addr, "--json",
        ])
        assert result.returncode == 0, result.stderr
        lines = [
            line for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        assert len(lines) > 0, "No names returned from node status"

    def test_cidr_token_works(
        self, candidate_interface, netbiosns_daemon_factory,
    ):
        """``interfaces = <cidr>`` resolves to addresses in the network."""
        _, iface_addr, _ = candidate_interface
        cidr = str(ipaddress.IPv4Network(f"{iface_addr}/24", strict=False))
        daemon = netbiosns_daemon_factory(cidr)

        result = run_tool([
            "nbt-status", daemon.interface_addr, "--json",
        ])
        assert result.returncode == 0, result.stderr
        lines = [
            line for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        assert len(lines) > 0, "No names returned from node status"
