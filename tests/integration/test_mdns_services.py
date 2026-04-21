"""Integration tests for middleware mDNS service configurations.

Exercises each real TrueNAS service config (SMB, HTTP, DEV_INFO,
ADISK, NUT) by starting the daemon and querying with client tools.
"""
from __future__ import annotations

import json

import pytest

from .conftest import run_tool

pytestmark = pytest.mark.integration

MIDDLEWARE_SERVICES = [
    {
        "name": "SMB",
        "type": "_smb._tcp",
        "port": 445,
        "txt": {},
    },
    {
        "name": "HTTP",
        "type": "_http._tcp",
        "port": 443,
        "txt": {},
    },
    {
        "name": "DEV_INFO",
        "type": "_device-info._tcp",
        "port": 9,
        "txt": {"model": "MacPro7,1@ECOLOR=226,226,224"},
    },
    {
        "name": "ADISK",
        "type": "_adisk._tcp",
        "port": 9,
        "txt": {
            "sys": "waMa=0,adVF=0x100",
            "dk0": "adVN=TimeMachine,adVF=0x82,adVU=test-uuid-1234",
        },
    },
    {
        "name": "NUT",
        "type": "_nut._tcp",
        "port": 3493,
        "txt": {},
    },
]


@pytest.mark.parametrize(
    "svc", MIDDLEWARE_SERVICES, ids=lambda s: s["name"],
)
class TestServiceDiscoverable:
    def test_browse_finds_service(self, mdns_daemon_factory, svc):
        daemon = mdns_daemon_factory([svc])
        result = run_tool([
            "mdns-browse", svc["type"], "-t", "5", "--json",
            "-i", daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        lines = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        assert len(lines) > 0, f"No services found for {svc['type']}"
        assert any(svc["type"] in entry["target"] for entry in lines)

    def test_port_matches(self, mdns_daemon_factory, svc):
        daemon = mdns_daemon_factory([svc])
        result = run_tool([
            "mdns-lookup", daemon.hostname, svc["type"],
            "--json", "-i", daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert data["port"] == svc["port"]


SERVICES_WITH_TXT = [s for s in MIDDLEWARE_SERVICES if s["txt"]]


@pytest.mark.parametrize(
    "svc", SERVICES_WITH_TXT, ids=lambda s: s["name"],
)
class TestServiceTxtRecords:
    def test_txt_records_match(self, mdns_daemon_factory, svc):
        daemon = mdns_daemon_factory([svc])
        result = run_tool([
            "mdns-lookup", daemon.hostname, svc["type"],
            "--json", "-i", daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        for key, value in svc["txt"].items():
            assert key in data["txt"], (
                f"TXT key {key!r} not found in {data['txt']}"
            )
            assert data["txt"][key] == value


class TestAdiskMultipleShares:
    def test_two_timemachine_shares(self, mdns_daemon_factory):
        svc = {
            "name": "ADISK_MULTI",
            "type": "_adisk._tcp",
            "port": 9,
            "txt": {
                "sys": "waMa=0,adVF=0x100",
                "dk0": "adVN=Share1,adVF=0x82,adVU=uuid-1111",
                "dk1": "adVN=Share2,adVF=0x82,adVU=uuid-2222",
            },
        }
        daemon = mdns_daemon_factory([svc])
        result = run_tool([
            "mdns-lookup", daemon.hostname, "_adisk._tcp",
            "--json", "-i", daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert "dk0" in data["txt"]
        assert "dk1" in data["txt"]
        assert "Share1" in data["txt"]["dk0"]
        assert "Share2" in data["txt"]["dk1"]


class TestBrowseAllTypes:
    def test_all_service_types_visible(self, mdns_daemon_factory):
        daemon = mdns_daemon_factory(MIDDLEWARE_SERVICES)
        result = run_tool([
            "mdns-browse", "--all", "-t", "10", "--json",
            "-i", daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        lines = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        discovered = {entry.get("target", "") for entry in lines}
        for svc in MIDDLEWARE_SERVICES:
            expected = f"{svc['type']}.local"
            assert any(expected in t for t in discovered), (
                f"Service type {svc['type']} not found in browse --all"
            )
