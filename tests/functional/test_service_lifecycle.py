"""The systemd unit: start, reload and stop under ``Type=notify-reload``.

``systemctl start`` returns once the daemon reports ``READY=1``, and
``systemctl reload`` once it reports the reload done (``RELOADING=1``
then ``READY=1``), so these tests read the unit's state and journal
right after each command returns.
"""
from __future__ import annotations

import time

import pytest

from .conftest import (
    NETBIOS_NAME,
    Discoveryd,
    LinkFactory,
    netbios_addresses,
    unit_properties,
    wait_for,
)

pytestmark = pytest.mark.functional

SERVER_IP = "203.0.113.1"
CLIENT_IP = "203.0.113.2"


@pytest.fixture
def serving(links: LinkFactory, discoveryd: Discoveryd) -> Discoveryd:
    """The daemon on one addressed link, answering its NetBIOS name."""
    link = links(0)
    link.add_ipv4(f"{SERVER_IP}/24", f"{CLIENT_IP}/24")
    discoveryd.configure([link.server])
    discoveryd.restart()
    wait_for(
        lambda: netbios_addresses(link, CLIENT_IP) == {SERVER_IP},
        f"{NETBIOS_NAME} to be answered",
    )
    return discoveryd


class TestNotifyReload:
    def test_start_reports_ready(self, serving: Discoveryd):
        props = unit_properties(
            "Type", "ActiveState", "SubState", "NRestarts",
        )
        assert props == {
            "Type": "notify-reload",
            "ActiveState": "active",
            "SubState": "running",
            "NRestarts": "0",
        }

    def test_reload_returns_when_done(self, serving: Discoveryd):
        since = time.time()
        result = serving.reload()
        assert result.returncode == 0, result.stderr
        journal = serving.journal_since(since)
        # A SIGHUP that arrives during an interface update is held
        # until the update finishes; systemctl reload returns once the
        # reload itself has, either way.
        assert (
            "Received SIGHUP, scheduling reload" in journal
            or "Received SIGHUP during an interface update" in journal
        ), journal
        assert unit_properties("ActiveState", "SubState") == {
            "ActiveState": "active", "SubState": "running",
        }

    def test_back_to_back_reloads_both_complete(self, serving: Discoveryd):
        for _ in range(2):
            result = serving.reload()
            assert result.returncode == 0, result.stderr
        assert unit_properties("ActiveState")["ActiveState"] == "active"

    def test_reload_requested_during_startup_waits_for_it(
        self, links: LinkFactory, discoveryd: Discoveryd,
    ):
        """``systemctl start`` returns at ``READY=1``, before names are
        registered; a reload sent right then is held until startup
        finishes, and ``systemctl reload`` still returns success."""
        link = links(0)
        link.add_ipv4(f"{SERVER_IP}/24", f"{CLIENT_IP}/24")
        discoveryd.configure([link.server])
        since = time.time()
        discoveryd.restart()
        result = discoveryd.reload()
        assert result.returncode == 0, result.stderr
        journal = discoveryd.journal_since(since)
        assert "Received SIGHUP during startup" in journal
        assert unit_properties("ActiveState")["ActiveState"] == "active"
        assert netbios_addresses(link, CLIENT_IP) == {SERVER_IP}

    def test_stop_is_clean(self, serving: Discoveryd):
        result = serving.stop()
        assert result.returncode == 0, result.stderr
        assert unit_properties("ActiveState", "Result") == {
            "ActiveState": "inactive", "Result": "success",
        }
