"""SIGHUP live-update reload: name-set and browse-announcer deltas.

The live-update path lets middleware edits like "change server
comment" or "add an alias" reconcile without releasing every
registered name on the network.  These tests cover the name-diff
helper, the ``release_names`` subset primitive, and the dispatcher
that picks between full rebuild and live update.

No real transports are involved — we drive ``NBNSServer`` with
``interfaces=[]`` so ``_subnets`` stays empty and we only exercise
the diff logic and browse-announcer setters directly.  Wire-level
behaviour is in ``tests/integration/``.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Address
from pathlib import Path

from truenas_pynetbiosns.protocol.constants import NameType, Opcode
from truenas_pynetbiosns.protocol.message import NBNSMessage
from truenas_pynetbiosns.protocol.name import NetBIOSName
from truenas_pynetbiosns.server.browse.announcer import (
    BrowseAnnouncer,
    build_host_announcement,
)
from truenas_pynetbiosns.server.config import (
    DaemonConfig,
    ServerConfig,
)
from truenas_pynetbiosns.server.core.nametable import NameTable
from truenas_pynetbiosns.server.core.release import (
    release_names,
)
from truenas_pynetbiosns.server.server import (
    NBNSServer,
    _expected_name_records,
)


_LOCAL_IP = IPv4Address("10.0.0.1")


def _make_server(tmp_path: Path, **server_kwargs) -> NBNSServer:
    return NBNSServer(DaemonConfig(
        server=ServerConfig(**server_kwargs),
        rundir=tmp_path,
    ))


class TestExpectedNameRecords:
    """``_expected_name_records`` must enumerate exactly what
    ``_register_names`` would register, so the diff is accurate."""

    def test_primary_registers_three_types_plus_workgroup(self):
        cfg = ServerConfig(netbios_name="HOST", workgroup="WG")
        names = _expected_name_records(cfg, "HOST", "WG")
        assert names == {
            ("HOST", NameType.WORKSTATION, False),
            ("HOST", NameType.MESSENGER, False),
            ("HOST", NameType.SERVER, False),
            ("WG", NameType.WORKSTATION, True),
        }

    def test_aliases_expand_into_additional_triplets(self):
        cfg = ServerConfig(
            netbios_name="HOST",
            netbios_aliases=["ALIAS1", "ALIAS2"],
            workgroup="WG",
        )
        names = _expected_name_records(cfg, "HOST", "WG")
        # 3 (primary) + 3*2 (aliases) + 1 (workgroup) = 10.
        assert len(names) == 10
        for n in ("HOST", "ALIAS1", "ALIAS2"):
            for nt in (
                NameType.WORKSTATION,
                NameType.MESSENGER,
                NameType.SERVER,
            ):
                assert (n, nt, False) in names
        assert ("WG", NameType.WORKSTATION, True) in names

    def test_workgroup_always_group_flagged(self):
        # The diff subtracts (name, type, is_group) tuples; getting
        # the group flag wrong on the workgroup would mean we'd
        # release a unique record when the workgroup changes.
        cfg = ServerConfig(netbios_name="HOST", workgroup="WG")
        names = _expected_name_records(cfg, "HOST", "WG")
        wg_entries = [n for n in names if n[0] == "WG"]
        assert len(wg_entries) == 1
        assert wg_entries[0][2] is True


class TestReleaseNames:
    """``release_names`` must release only the requested subset and
    prune each released entry from the table so subsequent refreshes
    and responses stop touching it."""

    def _seed(self, table: NameTable, name: str, name_type: int,
              group: bool = False) -> None:
        from truenas_pynetbiosns.protocol.constants import NBFlag
        flags = NBFlag.GROUP if group else NBFlag(0)
        nb = NetBIOSName(name, name_type)
        table.add(nb, _LOCAL_IP, flags)
        table.mark_registered(nb)

    def test_empty_subset_is_noop(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        self._seed(table, "HOST", NameType.WORKSTATION)
        release_names(sent.append, table, _LOCAL_IP, set())
        assert sent == []
        # Table untouched.
        assert len(table.all_registered()) == 1

    def test_releases_only_listed_tuples(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        self._seed(table, "HOST", NameType.WORKSTATION)
        self._seed(table, "HOST", NameType.SERVER)
        self._seed(table, "WG", NameType.WORKSTATION, group=True)

        release_names(
            sent.append, table, _LOCAL_IP,
            {("HOST", NameType.WORKSTATION, False)},
        )

        assert len(sent) == 1
        assert sent[0].questions[0].name.name == "HOST"
        assert sent[0].opcode == Opcode.RELEASE
        # HOST/WORKSTATION is gone from the table; the other two
        # stay.
        remaining = {
            (e.name.name, e.name.name_type, e.is_group)
            for e in table.all_registered()
        }
        assert remaining == {
            ("HOST", NameType.SERVER, False),
            ("WG", NameType.WORKSTATION, True),
        }

    def test_group_flag_honored_in_diff_match(self):
        # "WG" registered as group and as unique are different
        # tuples and must be distinguished.
        sent: list[NBNSMessage] = []
        table = NameTable()
        self._seed(table, "WG", NameType.WORKSTATION, group=True)
        self._seed(table, "WG", NameType.SERVER)  # unique

        release_names(
            sent.append, table, _LOCAL_IP,
            {("WG", NameType.WORKSTATION, True)},
        )

        assert len(sent) == 1
        remaining = {
            (e.name.name, e.name.name_type, e.is_group)
            for e in table.all_registered()
        }
        assert ("WG", NameType.SERVER, False) in remaining
        assert ("WG", NameType.WORKSTATION, True) not in remaining

    def test_missing_tuple_is_silently_skipped(self):
        sent: list[NBNSMessage] = []
        table = NameTable()
        self._seed(table, "HOST", NameType.WORKSTATION)

        release_names(
            sent.append, table, _LOCAL_IP,
            {("GHOST", NameType.WORKSTATION, False)},
        )

        assert sent == []
        # HOST still registered.
        assert len(table.all_registered()) == 1


class TestReloadDispatch:
    """Dispatcher picks full-rebuild vs. live-update path."""

    def test_first_reload_is_full_rebuild(self, tmp_path):
        server = _make_server(tmp_path, netbios_name="HOST", workgroup="WG")
        assert server._prev_config is None
        asyncio.run(server._reload())
        # No subnets (interfaces=[]), but the path completed
        # without raising.
        assert server._subnets == []

    def test_interface_change_forces_full_rebuild(self, tmp_path):
        server = _make_server(tmp_path, netbios_name="HOST", workgroup="WG")
        asyncio.run(server._reload())

        new_cfg = DaemonConfig(
            server=ServerConfig(
                netbios_name="HOST", workgroup="WG",
                interfaces=["nonexistent-iface"],
            ),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        # Full rebuild path runs resolve_subnets on the new list.
        # With no matching interface, it raises ValueError which the
        # server catches and returns — _subnets stays empty.
        asyncio.run(server._reload())
        assert server._subnets == []

    def test_no_config_change_is_noop(self, tmp_path, caplog):
        import logging
        server = _make_server(tmp_path, netbios_name="HOST", workgroup="WG")
        asyncio.run(server._reload())

        server.apply_config(server._config)
        with caplog.at_level(logging.INFO):
            asyncio.run(server._reload())

        # Dispatcher logged the no-op branch.
        assert any(
            "no config changes" in r.message.lower()
            for r in caplog.records
        )

    def test_server_string_change_takes_live_update_path(
        self, tmp_path, caplog,
    ):
        # server_string is used only in the browse announcement
        # payload; no name release is needed on change.  The
        # dispatcher should pick the live-update branch.
        import logging
        server = _make_server(
            tmp_path, netbios_name="HOST", workgroup="WG",
            server_string="old comment",
        )
        asyncio.run(server._reload())

        new_cfg = DaemonConfig(
            server=ServerConfig(
                netbios_name="HOST", workgroup="WG",
                server_string="new comment",
            ),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        with caplog.at_level(logging.INFO):
            asyncio.run(server._reload())
        # Live update path logs this exact prefix.
        assert any(
            "live update complete" in r.message.lower()
            for r in caplog.records
        )


class TestBrowseAnnouncerSetters:
    """Live-update modifies the announcer's cached hostname /
    workgroup / server_string in place so the next iteration carries
    the new payload without resetting the announce cadence."""

    def test_set_server_string_changes_future_announcement_payload(self):
        sent: list[bytes] = []
        ann = BrowseAnnouncer(
            send_fn=sent.append,
            hostname="HOST",
            workgroup="WG",
            server_string="old",
        )
        # Manually run one send, change, send again — we don't want
        # to race the real _loop() timer.
        from truenas_pynetbiosns.protocol.constants import ServerType
        st = ServerType.WORKSTATION | ServerType.SERVER
        ann._send_announcement(st, interval_s=60)
        ann.set_server_string("new")
        ann._send_announcement(st, interval_s=60)
        assert len(sent) == 2
        # The payload bytes for the comment field differ.
        expected_old = build_host_announcement(
            hostname="HOST", workgroup="WG",
            server_string="old", server_type=st,
            announce_interval_ms=60000,
        )
        expected_new = build_host_announcement(
            hostname="HOST", workgroup="WG",
            server_string="new", server_type=st,
            announce_interval_ms=60000,
        )
        assert sent[0] == expected_old
        assert sent[1] == expected_new

    def test_set_hostname_changes_future_announcement_payload(self):
        sent: list[bytes] = []
        ann = BrowseAnnouncer(
            send_fn=sent.append, hostname="OLD", workgroup="WG",
        )
        from truenas_pynetbiosns.protocol.constants import ServerType
        st = ServerType.WORKSTATION | ServerType.SERVER
        ann.set_hostname("NEW")
        ann._send_announcement(st, interval_s=60)
        assert len(sent) == 1
        expected = build_host_announcement(
            hostname="NEW", workgroup="WG",
            server_type=st, announce_interval_ms=60000,
        )
        assert sent[0] == expected
