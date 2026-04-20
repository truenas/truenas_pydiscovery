"""Integration tests for the mDNS daemon and client tools."""
from __future__ import annotations

import json

import pytest

from .conftest import run_tool

pytestmark = pytest.mark.integration


class TestMDNSBrowse:
    def test_browse_discovers_service(self, mdns_daemon):
        result = run_tool([
            "mdns-browse", "_test._tcp", "-t", "5", "--json",
            "-i", mdns_daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        lines = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        targets = [entry["target"] for entry in lines]
        assert any("_test._tcp" in t for t in targets)


class TestMDNSLookup:
    def test_lookup_resolves_service(self, mdns_daemon):
        result = run_tool([
            "mdns-lookup", mdns_daemon.hostname, "_test._tcp",
            "--json", "-i", mdns_daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["port"] == 9999
        assert data["host"]


class TestMDNSResolve:
    def test_resolve_hostname(self, mdns_daemon):
        fqdn = f"{mdns_daemon.hostname}.local"
        result = run_tool([
            "mdns-resolve", "-n", fqdn, "--json",
            "-i", mdns_daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert len(data["addresses"]) > 0
