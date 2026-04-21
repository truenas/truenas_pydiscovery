"""Tests for WSD message deduplication."""
from __future__ import annotations

from truenas_pywsd.server.core.dedup import MessageDedup


class TestMessageDedup:
    def test_first_message_not_duplicate(self):
        d = MessageDedup()
        assert d.is_duplicate("msg-1") is False

    def test_same_message_is_duplicate(self):
        d = MessageDedup()
        d.is_duplicate("msg-1")
        assert d.is_duplicate("msg-1") is True

    def test_different_message_not_duplicate(self):
        d = MessageDedup()
        d.is_duplicate("msg-1")
        assert d.is_duplicate("msg-2") is False

    def test_max_entries_eviction(self):
        d = MessageDedup(max_entries=3)
        d.is_duplicate("msg-1")
        d.is_duplicate("msg-2")
        d.is_duplicate("msg-3")
        d.is_duplicate("msg-4")  # evicts msg-1
        # msg-1 should no longer be tracked
        assert d.is_duplicate("msg-1") is False
        # msg-4 should still be tracked
        assert d.is_duplicate("msg-4") is True
