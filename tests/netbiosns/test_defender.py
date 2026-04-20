"""Defender: RFC 1002 s5.1.1.5 name-conflict defense.  When another
node tries to register a name we already own, we respond with ACT_ERR
to keep the name.
"""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pynetbiosns.protocol.constants import (
    NBFlag, Opcode, Rcode,
)
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.core.defender import Defender
from truenas_pynetbiosns.server.core.nametable import NameTable


_SRC: tuple[str, int] = ("10.0.0.99", 137)


def _new() -> tuple[list[tuple[NBNSMessage, tuple[str, int]]], NameTable, Defender]:
    sent: list[tuple[NBNSMessage, tuple[str, int]]] = []
    table = NameTable()

    def send(msg: NBNSMessage, dest: tuple[str, int]) -> None:
        sent.append((msg, dest))

    return sent, table, Defender(send, table)


def _reg_msg(name: str, name_type: int = 0x20) -> NBNSMessage:
    return NBNSMessage.build_registration(
        name, name_type, IPv4Address("10.0.0.99"),
    )


def _seed(table: NameTable, name: str, *,
          registered: bool, group: bool = False) -> None:
    nb = NetBIOSName(name, 0x20)
    table.add(nb, IPv4Address("10.0.0.1"),
              NBFlag.GROUP if group else NBFlag(0))
    if registered:
        table.mark_registered(nb)


class TestDefendOwnedUniqueName:
    def test_registered_unique_name_defended_with_act_err(self):
        sent, table, defender = _new()
        _seed(table, "HOSTA", registered=True)

        defended = defender.handle_registration(_reg_msg("HOSTA"), _SRC)
        assert defended is True
        assert len(sent) == 1
        msg, dest = sent[0]
        assert dest == _SRC
        assert msg.rcode == Rcode.ACT_ERR
        assert msg.opcode == Opcode.REGISTRATION
        assert msg.answers
        assert msg.answers[0].name == NetBIOSName("HOSTA", 0x20)

    def test_defense_unicast_to_source_not_broadcast(self):
        """RFC 1002 s5.1.1.5: defensive responses go back to the
        requesting node as unicast, not broadcast."""
        sent, table, defender = _new()
        _seed(table, "HOSTU", registered=True)

        defender.handle_registration(_reg_msg("HOSTU"), _SRC)
        _, dest = sent[0]
        assert dest == _SRC


class TestDefenseExclusions:
    def test_unregistered_name_not_defended(self):
        """A name that's still in the pending-registration window
        must not be defended — we don't own it yet, so the incoming
        registration might be our own loopback."""
        sent, table, defender = _new()
        _seed(table, "HOSTP", registered=False)

        defended = defender.handle_registration(_reg_msg("HOSTP"), _SRC)
        assert defended is False
        assert sent == []

    def test_group_names_never_defended(self):
        """Group names are shared by definition — multiple owners
        are expected, so we do not send ACT_ERR for them."""
        sent, table, defender = _new()
        _seed(table, "GROUPA", registered=True, group=True)

        defended = defender.handle_registration(_reg_msg("GROUPA"), _SRC)
        assert defended is False
        assert sent == []

    def test_unknown_name_not_defended(self):
        sent, _, defender = _new()
        defended = defender.handle_registration(_reg_msg("UNKNOWN"), _SRC)
        assert defended is False
        assert sent == []


class TestNonRegistrationOpcodesIgnored:
    def test_query_opcode_is_ignored(self):
        sent, table, defender = _new()
        _seed(table, "HOSTQ", registered=True)
        query = NBNSMessage.build_name_query("HOSTQ", 0x20)

        defended = defender.handle_registration(query, _SRC)
        assert defended is False
        assert sent == []

    def test_refresh_opcode_triggers_defense(self):
        """RFC 1002 s4.2.4: a REFRESH with a name we own is also a
        conflict — defender.py treats REFRESH the same as REGISTRATION."""
        sent, table, defender = _new()
        _seed(table, "HOSTR", registered=True)
        refresh = NBNSMessage.build_refresh(
            "HOSTR", 0x20, IPv4Address("10.0.0.99"),
        )

        defended = defender.handle_registration(refresh, _SRC)
        assert defended is True
        assert len(sent) == 1
        assert sent[0][0].rcode == Rcode.ACT_ERR
