"""Integration tests for the WSD daemon and client tools."""
from __future__ import annotations

import json
import uuid

import pytest

from .conftest import run_tool

pytestmark = pytest.mark.integration


class TestWsdDiscover:
    def test_discovers_device(self, wsd_daemon):
        result = run_tool([
            "wsd-discover", "-t", "5", "--json",
            "-i", wsd_daemon.interface_addr,
        ])
        assert result.returncode == 0, result.stderr
        lines = [
            json.loads(line)
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
        assert len(lines) > 0, "No WSD devices discovered"
        endpoints = [entry["endpoint"] for entry in lines]
        assert any("urn:uuid:" in ep for ep in endpoints)


class TestWsdInfo:
    def test_fetches_metadata(self, wsd_daemon):
        # Construct the metadata URL directly — the daemon's endpoint
        # UUID is deterministic (uuid5 from hostname).
        endpoint_uuid = str(uuid.uuid5(
            uuid.NAMESPACE_DNS, wsd_daemon.hostname,
        ))
        url = (
            f"http://{wsd_daemon.interface_addr}:5357"
            f"/{endpoint_uuid}"
        )
        result = run_tool(["wsd-info", url, "--json"])
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert "friendly_name" in data
        assert wsd_daemon.hostname in data["friendly_name"]
        assert "computer" in data
        assert "TESTGROUP" in data["computer"]
