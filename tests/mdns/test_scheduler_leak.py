"""QueryScheduler._seen_questions is pruned by a periodic sweep
driven from ``MDNSServer._maintenance_loop`` (1 Hz).  The old
64-entry size gate is gone: growth is bounded by time, not count,
because ``sweep(now)`` drops anything older than the 2 s prune
grace (the in-code suppression window is 1 s).
"""
from __future__ import annotations

import time

from truenas_pymdns.server.core.cache import RecordCache
from truenas_pymdns.server.query.scheduler import QueryScheduler


def _s() -> QueryScheduler:
    return QueryScheduler(lambda msg: None, RecordCache())


def test_sweep_drops_entries_older_than_two_seconds():
    sch = _s()
    now = time.monotonic()
    sch._seen_questions["stale.local|1"] = now - 5.0
    sch._seen_questions["recent.local|1"] = now - 0.5
    sch._seen_questions["fresh.local|1"] = now

    sch.sweep(now)

    assert "stale.local|1" not in sch._seen_questions
    assert "recent.local|1" in sch._seen_questions
    assert "fresh.local|1" in sch._seen_questions


def test_sweep_is_idempotent_on_empty_dict():
    sch = _s()
    sch.sweep(time.monotonic())
    assert sch._seen_questions == {}


def test_sweep_noop_when_all_entries_fresh():
    sch = _s()
    now = time.monotonic()
    for i in range(200):
        sch._seen_questions[f"host-{i}.local|1"] = now - 0.1
    sch.sweep(now)
    assert len(sch._seen_questions) == 200
