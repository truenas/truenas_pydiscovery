"""Status dump includes TXT record contents per SRV instance.

Middleware integration tests assert on ``status.children.mdns.
services_registered[].txt`` to verify Time-Machine / Device-Info TXT
keys flow from ``smb.update`` through the services.d rendering into
the running daemon.  That needs the daemon's status dump to carry
the TXT contents alongside the SRV metadata."""
from __future__ import annotations

import json
from pathlib import Path

from truenas_pymdns.server.config import (
    DaemonConfig,
    ServerConfig,
    ServiceConfig,
)
from truenas_pymdns.server.server import MDNSServer
from truenas_pymdns.server.service.file_loader import service_to_entry_group


def _make_server(tmp_path: Path, hostname: str = "host") -> MDNSServer:
    service_dir = tmp_path / "services.d"
    service_dir.mkdir()
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    return MDNSServer(DaemonConfig(
        server=ServerConfig(
            host_name=hostname,
            interfaces=[],
        ),
        service_dir=service_dir,
        rundir=rundir,
    ))


def _read_status(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "rundir" / "status.json").read_text())


class TestServicesRegisteredTxt:
    def test_txt_dict_included_per_service(self, tmp_path):
        server = _make_server(tmp_path)
        svc = ServiceConfig(
            service_type="_adisk._tcp",
            port=0,
            instance_name="testshare",
            txt={
                "dk0": "adVN=TestShare,adVF=0x82,adVU=deadbeef",
                "sys": "waMA=00:00:00:00:00:00,adVF=0x100",
            },
        )
        server._entry_groups.append(
            service_to_entry_group(svc, "host", "host.local"),
        )

        server._write_status()

        status = _read_status(tmp_path)
        registered = status["services_registered"]
        adisk = [s for s in registered if s["instance"].startswith("testshare")]
        assert len(adisk) == 1, registered
        entry = adisk[0]
        assert entry["txt"] == {
            "dk0": "adVN=TestShare,adVF=0x82,adVU=deadbeef",
            "sys": "waMA=00:00:00:00:00:00,adVF=0x100",
        }

    def test_service_with_no_txt_gets_empty_dict(self, tmp_path):
        server = _make_server(tmp_path)
        svc = ServiceConfig(
            service_type="_http._tcp",
            port=80,
            instance_name="web",
        )
        server._entry_groups.append(
            service_to_entry_group(svc, "host", "host.local"),
        )

        server._write_status()

        registered = _read_status(tmp_path)["services_registered"]
        web = [s for s in registered if s["instance"].startswith("web")]
        assert len(web) == 1
        assert web[0]["txt"] == {}

    def test_boolean_txt_entry_has_empty_value(self, tmp_path):
        # RFC 6763 §6.4 lets a bare ``key`` (no ``=``) stand as a
        # boolean flag; ``TXTRecordData.from_dict`` emits ``"key="``
        # so the raw wire form is ``key=``, but we still normalise
        # in ``_decode_txt`` so consumers get ``{"key": ""}``.
        server = _make_server(tmp_path)
        svc = ServiceConfig(
            service_type="_test._tcp",
            port=1234,
            instance_name="bool",
            txt={"flag_a": "", "flag_b": "val"},
        )
        server._entry_groups.append(
            service_to_entry_group(svc, "host", "host.local"),
        )

        server._write_status()

        registered = _read_status(tmp_path)["services_registered"]
        entry = next(s for s in registered if s["instance"].startswith("bool"))
        assert entry["txt"] == {"flag_a": "", "flag_b": "val"}

    def test_multiple_services_get_independent_txt(self, tmp_path):
        server = _make_server(tmp_path)
        smb = ServiceConfig(
            service_type="_smb._tcp",
            port=445,
            instance_name="smb-inst",
            txt={"foo": "bar"},
        )
        http = ServiceConfig(
            service_type="_http._tcp",
            port=80,
            instance_name="http-inst",
            txt={"path": "/"},
        )
        server._entry_groups.append(
            service_to_entry_group(smb, "host", "host.local"),
        )
        server._entry_groups.append(
            service_to_entry_group(http, "host", "host.local"),
        )

        server._write_status()

        registered = _read_status(tmp_path)["services_registered"]
        by_type = {s["instance"]: s for s in registered}
        smb_entry = next(s for k, s in by_type.items() if k.startswith("smb-inst"))
        http_entry = next(s for k, s in by_type.items() if k.startswith("http-inst"))
        assert smb_entry["txt"] == {"foo": "bar"}
        assert http_entry["txt"] == {"path": "/"}
