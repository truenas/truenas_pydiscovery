"""release_all_names: send RELEASE packets with TTL=0 for every
registered name (RFC 1002 s4.2.3 — analogous to mDNS goodbye).
"""
from __future__ import annotations

import struct
from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import NBFlag, Opcode
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.core.nametable import NameTable
from truenas_pynetbiosns.server.core.release import release_all_names


_LOCAL_IP = IPv4Address("10.0.0.1")


def _seed(table: NameTable, name: str, *, registered: bool,
          group: bool = False) -> None:
    nb = NetBIOSName(name, 0x20)
    flags = NBFlag.GROUP if group else NBFlag(0)
    table.add(nb, _LOCAL_IP, flags)
    if registered:
        table.mark_registered(nb)


class TestReleaseAll:
    def test_empty_table_is_noop(self):
        sent: list[NBNSMessage] = []
        release_all_names(sent.append, NameTable(), _LOCAL_IP)
        assert sent == []

    def test_sends_one_release_per_registered_name(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed(table, "HOSTA", registered=True)
        _seed(table, "HOSTB", registered=True)

        release_all_names(sent.append, table, _LOCAL_IP)
        assert len(sent) == 2
        names = {m.questions[0].name.name for m in sent}
        assert names == {"HOSTA", "HOSTB"}

    def test_pending_entries_not_released(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed(table, "DONE", registered=True)
        _seed(table, "PENDING", registered=False)

        release_all_names(sent.append, table, _LOCAL_IP)
        assert len(sent) == 1
        assert sent[0].questions[0].name.name == "DONE"

    def test_wire_ttl_is_zero(self):
        """Round-trip every emitted release through the wire format
        and confirm the peer sees TTL=0 in the RR."""
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed(table, "GOODBYE", registered=True)

        release_all_names(sent.append, table, _LOCAL_IP)
        assert sent
        wire = sent[0].to_wire()
        decoded = NBNSMessage.from_wire(wire)
        assert decoded.opcode == Opcode.RELEASE
        assert decoded.additionals
        assert decoded.additionals[0].ttl == 0

    def test_group_flag_preserved(self):
        """Release for a group name must keep the GROUP bit in the
        flags word of the NB rdata."""
        sent: list[NBNSMessage] = []
        table = NameTable()
        _seed(table, "GROUPR", registered=True, group=True)

        release_all_names(sent.append, table, _LOCAL_IP)
        assert sent
        rr = sent[0].additionals[0]
        flags_val, = struct.unpack("!H", rr.rdata[:2])
        assert flags_val & NBFlag.GROUP
