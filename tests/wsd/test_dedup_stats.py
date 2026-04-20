"""Tests for MessageDedup.stats() — SIGUSR1 status dump contents."""
from __future__ import annotations

from truenas_pywsd.server.core.dedup import MessageDedup


def test_empty_dedup_stats():
    d = MessageDedup(max_entries=10, ttl=8.0)
    s = d.stats()
    assert s == {
        "tracked_ids": 0,
        "max_capacity": 10,
        "ttl_seconds": 8.0,
    }


def test_tracked_ids_reflects_recent_inserts():
    d = MessageDedup(max_entries=10, ttl=8.0)
    d.is_duplicate("urn:uuid:1")
    d.is_duplicate("urn:uuid:2")
    d.is_duplicate("urn:uuid:3")
    assert d.stats()["tracked_ids"] == 3


def test_tracked_ids_capped_by_max_capacity():
    d = MessageDedup(max_entries=3, ttl=8.0)
    for i in range(10):
        d.is_duplicate(f"urn:uuid:{i}")
    s = d.stats()
    assert s["tracked_ids"] == 3
    assert s["max_capacity"] == 3


def test_default_capacity_from_constants():
    from truenas_pywsd.protocol.constants import WSD_MAX_KNOWN_MESSAGES
    d = MessageDedup()
    assert d.stats()["max_capacity"] == WSD_MAX_KNOWN_MESSAGES
