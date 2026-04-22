"""SIGHUP metadata live-update reload path.

Workgroup/domain changes for WSD are published in the HTTP
metadata Get response and in the ``<wsd:MetadataVersion>`` element
of Hello / ProbeMatch / ResolveMatch (WSD 1.1 §4.1).  The
live-update path updates each per-interface ``MetadataHandler`` in
place so future Get responses carry the new workgroup, and bumps
the server's ``_metadata_version`` counter so clients tracking
MetadataVersion know to re-acquire metadata.
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from truenas_pywsd.protocol.constants import Action, WellKnownURI
from truenas_pywsd.protocol.soap import build_envelope
from truenas_pywsd.server.config import DaemonConfig, ServerConfig
from truenas_pywsd.server.core.metadata import MetadataHandler
from truenas_pywsd.server.net.interface import InterfaceInfo
from truenas_pywsd.server.server import PerInterfaceState, WSDServer


def _make_server(tmp_path: Path, **server_kwargs) -> WSDServer:
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    return WSDServer(DaemonConfig(
        server=ServerConfig(**server_kwargs),
        rundir=rundir,
    ))


def _seed_interface(
    server: WSDServer, iface_name: str = "lo", index: int = 1,
) -> PerInterfaceState:
    """Attach a minimal ``PerInterfaceState`` with just a
    ``MetadataHandler`` to *server* so live-update reload has
    something to iterate.  We skip transports/http servers since
    this test only cares about in-memory handler state."""
    iface = InterfaceInfo(name=iface_name, index=index)
    ifstate = PerInterfaceState(iface)
    cur = server._config.server
    is_domain = bool(cur.domain)
    wg_or_domain = cur.domain if is_domain else cur.workgroup
    ifstate.meta_handler = MetadataHandler(
        endpoint_uuid=server._endpoint_uuid,
        hostname=server._hostname,
        workgroup_or_domain=wg_or_domain,
        is_domain=is_domain,
    )
    server._interfaces[index] = ifstate
    return ifstate


def _extract_workgroup_from_response(body: bytes) -> tuple[str, bool]:
    """Pull the workgroup/domain text out of a Get response body.

    ``build_get_response`` emits ``<pub:Computer>hostname/Workgroup:WG
    </pub:Computer>`` or ``.../Domain:DOMAIN</pub:Computer>`` — we
    use the label to decide is_domain and return the value after the
    colon as the workgroup or domain string.
    """
    text = body.decode("utf-8")
    start = text.find("<pub:Computer>")
    end = text.find("</pub:Computer>")
    assert start >= 0 and end > start, (
        f"no <pub:Computer> in response: {text!r}"
    )
    payload = text[start + len("<pub:Computer>"):end]
    # payload is "hostname/Workgroup:VALUE" or "hostname/Domain:VALUE".
    _, _, after_slash = payload.partition("/")
    label, _, value = after_slash.partition(":")
    return value, label == "Domain"


class TestMetadataHandlerUpdate:
    """The public setter the live-update path calls."""

    def test_update_changes_future_get_response(self):
        handler = MetadataHandler(
            endpoint_uuid=str(uuid.uuid4()),
            hostname="host",
            workgroup_or_domain="OLDWG",
            is_domain=False,
        )

        # Build a Get request to feed into handle_request.
        get_body = build_envelope(
            Action.GET,
            to=WellKnownURI.WSA_ANONYMOUS,
            message_id="urn:uuid:test-1",
        )
        resp_before = handler.handle_request(get_body)
        wg_before, is_domain_before = _extract_workgroup_from_response(
            resp_before,
        )
        assert wg_before == "OLDWG"
        assert is_domain_before is False

        handler.update_workgroup("NEWDOMAIN", is_domain=True)

        get_body2 = build_envelope(
            Action.GET,
            to=WellKnownURI.WSA_ANONYMOUS,
            message_id="urn:uuid:test-2",
        )
        resp_after = handler.handle_request(get_body2)
        wg_after, is_domain_after = _extract_workgroup_from_response(
            resp_after,
        )
        assert wg_after == "NEWDOMAIN"
        assert is_domain_after is True


class TestReloadDispatch:
    def test_first_reload_is_full_rebuild(self, tmp_path):
        server = _make_server(
            tmp_path, hostname="host", workgroup="WG",
        )
        assert server._prev_config is None
        asyncio.run(server._reload())
        # interfaces=[] → full rebuild path loops over zero
        # interfaces and returns cleanly.
        assert server._interfaces == {}

    def test_hostname_change_takes_full_rebuild(self, tmp_path):
        # Hostname drives endpoint UUID; a change is a device
        # replacement from a WSD client's perspective, so the full
        # rebuild (with Bye old UUID + Hello new UUID) is correct.
        server = _make_server(
            tmp_path, hostname="oldhost", workgroup="WG",
        )
        asyncio.run(server._reload())
        # Simulate some accumulated metadata_version (it's per-
        # endpoint; the new endpoint gets a fresh counter).
        server._metadata_version = 5
        old_uuid = server._endpoint_uuid

        new_cfg = DaemonConfig(
            server=ServerConfig(hostname="newhost", workgroup="WG"),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        # Full rebuild re-derives the endpoint UUID from the new
        # hostname.
        assert server._hostname == "newhost"
        assert server._endpoint_uuid != old_uuid
        # Per WSD 1.1 §4.1, new endpoint = MetadataVersion resets
        # to the initial value of 1.
        assert server._metadata_version == 1

    def test_workgroup_change_takes_metadata_live_update(self, tmp_path):
        server = _make_server(
            tmp_path, hostname="host", workgroup="OLDWG",
        )
        asyncio.run(server._reload())
        # Pre-populate an interface with a handler so the live-
        # update path has something to iterate.
        ifstate = _seed_interface(server)
        instance_before = server._instance_id
        metadata_version_before = server._metadata_version
        uuid_before = server._endpoint_uuid

        new_cfg = DaemonConfig(
            server=ServerConfig(hostname="host", workgroup="NEWWG"),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        # Endpoint UUID unchanged — no Bye/Hello needed.
        assert server._endpoint_uuid == uuid_before
        # InstanceId MUST NOT change on config reload (WSD 1.1
        # §4.2.1 says it identifies the app's instance, which
        # hasn't restarted).
        assert server._instance_id == instance_before
        # MetadataVersion MUST bump so clients re-fetch metadata
        # (WSD 1.1 §4.1).
        assert server._metadata_version == metadata_version_before + 1
        # The per-interface metadata handler has the new workgroup.
        handler = ifstate.meta_handler
        assert handler is not None
        get_body = build_envelope(
            Action.GET,
            to=WellKnownURI.WSA_ANONYMOUS,
            message_id="urn:uuid:t1",
        )
        resp = handler.handle_request(get_body)
        wg, is_domain = _extract_workgroup_from_response(resp)
        assert wg == "NEWWG"
        assert is_domain is False

    def test_domain_change_flips_is_domain_flag(self, tmp_path):
        # Switching from workgroup to domain changes both the
        # string and the kind marker in ``pub:Computer``.
        server = _make_server(
            tmp_path, hostname="host", workgroup="WG",
        )
        asyncio.run(server._reload())
        ifstate = _seed_interface(server)

        new_cfg = DaemonConfig(
            server=ServerConfig(
                hostname="host", workgroup="WG", domain="AD.EXAMPLE",
            ),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        handler = ifstate.meta_handler
        assert handler is not None
        resp = handler.handle_request(
            build_envelope(
                Action.GET,
                to=WellKnownURI.WSA_ANONYMOUS,
                message_id="urn:uuid:t2",
            ),
        )
        wg, is_domain = _extract_workgroup_from_response(resp)
        assert wg == "AD.EXAMPLE"
        assert is_domain is True

    def test_interface_change_forces_full_rebuild(self, tmp_path):
        # Interfaces + IPv4/IPv6 toggles mean sockets must rebind.
        # Metadata-live-update would leave stale transports in
        # place, so the dispatcher must pick full rebuild.
        server = _make_server(
            tmp_path, hostname="host", workgroup="WG",
        )
        asyncio.run(server._reload())

        new_cfg = DaemonConfig(
            server=ServerConfig(
                hostname="host", workgroup="WG",
                interfaces=["nonexistent-iface"],
            ),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        # Full rebuild path runs resolve_interface on the new list;
        # with no match it logs a warning and _interfaces stays
        # empty.  The point is that we went through _full_rebuild
        # (not the metadata path that would have touched handlers).
        asyncio.run(server._reload())
        assert server._interfaces == {}

    def test_ipv6_toggle_forces_full_rebuild(self, tmp_path):
        server = _make_server(
            tmp_path, hostname="host", workgroup="WG",
            use_ipv4=True, use_ipv6=True,
        )
        asyncio.run(server._reload())
        ifstate_before = _seed_interface(server)
        instance_before = server._instance_id
        metadata_version_before = server._metadata_version

        # Toggle IPv6 off — that's a transport-family change.
        new_cfg = DaemonConfig(
            server=ServerConfig(
                hostname="host", workgroup="WG",
                use_ipv4=True, use_ipv6=False,
            ),
            rundir=server._config.rundir,
        )
        server.apply_config(new_cfg)
        asyncio.run(server._reload())

        # Full rebuild clears _interfaces — ifstate_before is no
        # longer registered.
        assert ifstate_before not in server._interfaces.values()
        # InstanceId doesn't bump on config reload (WSD §4.2.1).
        assert server._instance_id == instance_before
        # Endpoint UUID unchanged (hostname unchanged), so the
        # MetadataVersion counter for THIS endpoint carries over
        # rather than resetting to 1.  Metadata itself didn't
        # change either, so the version also doesn't bump — just
        # a fresh XAddrs via new ResolveMatches.
        assert server._metadata_version == metadata_version_before

    def test_responder_probe_match_uses_live_metadata_version(
        self, tmp_path,
    ):
        # The responder is constructed once per interface and lives
        # across reloads; WSD 1.1 §5.3 requires each ProbeMatch to
        # carry the *current* MetadataVersion.  That only works if
        # the responder reads the counter at response-build time,
        # not at construction time.  Drive a real responder
        # through two ``_respond_probe`` calls with a bump in
        # between and assert the serialised element tracks the
        # live value.
        from ipaddress import IPv4Interface

        from truenas_pywsd.server.core.dedup import MessageDedup
        from truenas_pywsd.server.core.responder import WSDResponder

        server = _make_server(
            tmp_path, hostname="host", workgroup="WG",
        )
        asyncio.run(server._reload())
        # Attach a per-interface handler so the live-update path
        # has a MetadataHandler to touch (it iterates
        # ``self._interfaces``).
        _seed_interface(server)

        captured: list[bytes] = []
        responder = WSDResponder(
            send_unicast_fn=lambda data, addr: captured.append(data),
            endpoint_uuid=server._endpoint_uuid,
            xaddrs="http://1.2.3.4:5357/x",
            dedup=MessageDedup(),
            addrs_v4=[IPv4Interface("1.2.3.4/24")],
            addrs_v6=[],
            metadata_version=lambda: server._metadata_version,
        )

        asyncio.run(responder._respond_probe(
            "urn:uuid:probe-1", ("1.2.3.5", 3702),
        ))
        assert captured, "responder produced no ProbeMatch bytes"
        assert (
            b"<wsd:MetadataVersion>1</wsd:MetadataVersion>"
            in captured[0]
        )

        # Bump the live counter via the reload path.
        server.apply_config(DaemonConfig(
            server=ServerConfig(hostname="host", workgroup="NEW"),
            rundir=server._config.rundir,
        ))
        asyncio.run(server._reload())
        assert server._metadata_version == 2

        captured.clear()
        asyncio.run(responder._respond_probe(
            "urn:uuid:probe-2", ("1.2.3.5", 3702),
        ))
        assert captured
        assert (
            b"<wsd:MetadataVersion>2</wsd:MetadataVersion>"
            in captured[0]
        )

    def test_unchanged_config_is_noop(self, tmp_path, caplog):
        import logging
        server = _make_server(
            tmp_path, hostname="host", workgroup="WG",
        )
        asyncio.run(server._reload())

        server.apply_config(server._config)
        with caplog.at_level(logging.INFO):
            asyncio.run(server._reload())

        assert any(
            "no config changes" in r.message.lower()
            for r in caplog.records
        )
