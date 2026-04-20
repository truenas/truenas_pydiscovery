"""Tests for RecordCache.stats() — SIGUSR1 status dump contents."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.records import (
    AAAARecordData,
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)
from truenas_pymdns.server.core.cache import RecordCache


def _a(name: str, addr: str, cache_flush: bool = False) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=cache_flush,
    )


def _aaaa(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.AAAA),
        ttl=120,
        data=AAAARecordData(IPv6Address(addr)),
    )


def _ptr(service_type: str, target: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(service_type, QType.PTR),
        ttl=4500,
        data=PTRRecordData(target),
    )


def _srv(name: str, port: int, target: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.SRV),
        ttl=120,
        data=SRVRecordData(0, 0, port, target),
        cache_flush=True,
    )


def _txt(name: str, *entries: bytes) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.TXT),
        ttl=4500,
        data=TXTRecordData(entries=entries),
    )


def test_empty_cache_reports_zeros():
    cache = RecordCache()
    s = cache.stats()
    assert s["total_entries"] == 0
    assert s["by_type"] == {}
    assert s["service_types"] == {}
    assert s["poof_tracked"] == 0
    assert s["poof_candidates"] == 0


def test_by_type_breakdown():
    cache = RecordCache()
    cache.add(_a("host.local", "10.0.0.1"), 1000.0)
    cache.add(_aaaa("host.local", "fe80::1"), 1000.0)
    cache.add(_ptr("_smb._tcp.local", "truenas._smb._tcp.local"), 1000.0)
    cache.add(_srv("truenas._smb._tcp.local", 445, "host.local"), 1000.0)
    cache.add(_txt("truenas._smb._tcp.local", b"model=TN"), 1000.0)

    s = cache.stats()
    assert s["total_entries"] == 5
    assert s["by_type"] == {
        "A": 1, "AAAA": 1, "PTR": 1, "SRV": 1, "TXT": 1,
    }


def test_service_type_grouping():
    cache = RecordCache()
    cache.add(_ptr("_smb._tcp.local", "a._smb._tcp.local"), 1000.0)
    cache.add(_ptr("_smb._tcp.local", "b._smb._tcp.local"), 1000.0)
    cache.add(_ptr("_http._tcp.local", "a._http._tcp.local"), 1000.0)
    # A records with the same name as a PTR shouldn't contaminate
    # service_types — only PTR-type entries are grouped.
    cache.add(_a("_smb._tcp.local", "10.0.0.1"), 1000.0)

    s = cache.stats()
    assert s["service_types"] == {
        "_smb._tcp.local": 2,
        "_http._tcp.local": 1,
    }
    assert "A" in s["by_type"]


def test_poof_fields_track_counters():
    cache = RecordCache()
    key = MDNSRecordKey("h.local", QType.A)
    cache.add(_a("h.local", "10.0.0.1"), 1000.0)
    # On this branch record_poof() takes one arg and thresholds at
    # POOF_THRESHOLD=2 (M1 fix is on a separate branch).
    cache.record_poof(key)
    s = cache.stats()
    assert s["poof_tracked"] == 1
    assert s["poof_candidates"] == 0
    cache.record_poof(key)
    s = cache.stats()
    assert s["poof_candidates"] == 1


def test_multiple_records_under_one_key():
    """Cache can hold multiple PTR targets under the same key."""
    cache = RecordCache()
    cache.add(_ptr("_smb._tcp.local", "a._smb._tcp.local"), 1000.0)
    cache.add(_ptr("_smb._tcp.local", "b._smb._tcp.local"), 1000.0)
    s = cache.stats()
    assert s["total_entries"] == 2
    assert s["by_type"]["PTR"] == 2
    assert s["service_types"]["_smb._tcp.local"] == 2
