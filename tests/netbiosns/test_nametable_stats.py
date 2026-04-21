"""Tests for NameTable.stats() — SIGUSR1 status dump contents."""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import NBFlag
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.core.nametable import NameTable


def _name(name: str, name_type: int) -> NetBIOSName:
    return NetBIOSName(name=name, name_type=name_type, scope="")


def test_empty_table_reports_zeros():
    s = NameTable().stats()
    assert s == {
        "total": 0,
        "registered": 0,
        "pending": 0,
        "unique": 0,
        "group": 0,
        "by_type": {},
    }


def test_registered_vs_pending():
    t = NameTable()
    t.add(_name("TRUENAS", 0x20), IPv4Address("10.0.0.1"))
    t.add(_name("TRUENAS", 0x00), IPv4Address("10.0.0.1"))
    t.mark_registered(_name("TRUENAS", 0x20))

    s = t.stats()
    assert s["total"] == 2
    assert s["registered"] == 1
    assert s["pending"] == 1


def test_unique_vs_group():
    t = NameTable()
    t.add(_name("TRUENAS", 0x20), IPv4Address("10.0.0.1"))
    t.add(
        _name("WORKGROUP", 0x00),
        IPv4Address("10.0.0.1"),
        nb_flags=NBFlag.GROUP,
    )

    s = t.stats()
    assert s["unique"] == 1
    assert s["group"] == 1


def test_by_type_hex_keys():
    t = NameTable()
    t.add(_name("TRUENAS", 0x00), IPv4Address("10.0.0.1"))
    t.add(_name("TRUENAS", 0x03), IPv4Address("10.0.0.1"))
    t.add(_name("TRUENAS", 0x20), IPv4Address("10.0.0.1"))

    s = t.stats()
    assert s["by_type"] == {"0x00": 1, "0x03": 1, "0x20": 1}


def test_pending_is_total_minus_registered():
    t = NameTable()
    for name_type in (0x00, 0x03, 0x20):
        t.add(_name("TRUENAS", name_type), IPv4Address("10.0.0.1"))
    t.mark_registered(_name("TRUENAS", 0x20))

    s = t.stats()
    assert s["total"] == 3
    assert s["registered"] == 1
    assert s["pending"] == 2
