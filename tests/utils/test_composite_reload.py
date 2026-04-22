"""Tests for the unified-config reload path on SIGHUP.

``CompositeDaemon`` (in ``truenas_pydiscovery_utils.composite``)
re-reads its config file on SIGHUP when the ``config_reloader`` +
``config_dispatch`` pair is wired up by
``build_composite_daemon`` — it hands the fresh per-protocol
sub-config to each child before delegating to the normal SIGHUP
fan-out.  Without that pair, children keep the ``self._config`` they
captured at startup and SIGHUP only picks up changes the children
re-read directly from disk (mDNS's services.d directory), missing
hostname / netbios-name / workgroup / interface changes written to
``truenas-discoveryd.conf``.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from truenas_pydiscovery.composite import (
    ChildName,
    _dispatch_unified_config,
    build_composite_daemon,
)
from truenas_pydiscovery.config import UnifiedConfig, load_unified_config
from truenas_pydiscovery_utils.composite import CompositeDaemon
from truenas_pymdns.server.config import (
    DaemonConfig as MdnsConfig,
    ServerConfig as MdnsServerConfig,
)
from truenas_pymdns.server.server import MDNSServer
from truenas_pynetbiosns.server.config import (
    DaemonConfig as NbnsConfig,
    ServerConfig as NbnsServerConfig,
)
from truenas_pynetbiosns.server.server import NBNSServer
from truenas_pywsd.server.config import (
    DaemonConfig as WsdConfig,
    ServerConfig as WsdServerConfig,
)
from truenas_pywsd.server.server import WSDServer


# No running daemon interacts with the network during these tests:
# every config uses ``interfaces=[]`` so ``_reload()`` walks zero
# subnets / interfaces and touches no sockets.


def _build_real_children(tmp_path: Path, *, hostname: str, netbios: str):
    rundir = tmp_path / "rundir"
    rundir.mkdir()
    mdns = MDNSServer(MdnsConfig(
        server=MdnsServerConfig(host_name=hostname),
        service_dir=tmp_path / "no-services",
        rundir=rundir,
    ))
    nbns = NBNSServer(NbnsConfig(
        server=NbnsServerConfig(netbios_name=netbios, workgroup="WG"),
        rundir=rundir,
    ))
    wsd = WSDServer(WsdConfig(
        server=WsdServerConfig(hostname=hostname, workgroup="WG"),
        rundir=rundir,
    ))
    return mdns, nbns, wsd


def _unified(mdns_cfg=None, nbns_cfg=None, wsd_cfg=None) -> UnifiedConfig:
    return UnifiedConfig(mdns=mdns_cfg, netbiosns=nbns_cfg, wsd=wsd_cfg)


def _logger() -> logging.Logger:
    return logging.getLogger("test.composite.reload")


def _composite(children, reloader, dispatch=_dispatch_unified_config):
    return CompositeDaemon(
        _logger(), children,
        config_reloader=reloader,
        config_dispatch=dispatch,
    )


class TestApplyConfig:
    """Per-child ``apply_config`` swaps ``self._config`` and any attrs
    derived from it, so the subsequent ``_reload()`` sees the new
    values."""

    def test_mdns_apply_config_replaces_config_and_rederives_hostname(
        self, tmp_path,
    ):
        server = MDNSServer(MdnsConfig(
            server=MdnsServerConfig(host_name="old-host"),
            service_dir=tmp_path / "no-services",
            rundir=tmp_path,
        ))
        assert server._hostname == "old-host"
        assert server._fqdn == "old-host.local"

        new_cfg = MdnsConfig(
            server=MdnsServerConfig(
                host_name="new-host", domain_name="lan",
            ),
            service_dir=tmp_path / "still-none",
            rundir=tmp_path,
        )
        server.apply_config(new_cfg)

        assert server._config is new_cfg
        assert server._hostname == "new-host"
        assert server._fqdn == "new-host.lan"

    def test_netbiosns_apply_config_replaces_config(self, tmp_path):
        server = NBNSServer(NbnsConfig(
            server=NbnsServerConfig(netbios_name="OLDNAME", workgroup="WG"),
            rundir=tmp_path,
        ))
        assert server._config.server.netbios_name == "OLDNAME"

        new_cfg = NbnsConfig(
            server=NbnsServerConfig(netbios_name="NEWNAME", workgroup="WG"),
            rundir=tmp_path,
        )
        server.apply_config(new_cfg)

        # ``_reload()`` re-derives ``_netbios_name`` from the stored
        # config; ``apply_config`` only needs to swap the reference.
        assert server._config is new_cfg

    def test_wsd_apply_config_replaces_config(self, tmp_path):
        server = WSDServer(WsdConfig(
            server=WsdServerConfig(hostname="old-host", workgroup="WG"),
            rundir=tmp_path,
        ))
        assert server._config.server.hostname == "old-host"

        new_cfg = WsdConfig(
            server=WsdServerConfig(hostname="new-host", workgroup="WG"),
            rundir=tmp_path,
        )
        server.apply_config(new_cfg)

        # WSD's ``_reload()`` re-derives ``_hostname`` and
        # ``_endpoint_uuid`` from the stored config.
        assert server._config is new_cfg


class TestReloadDispatch:
    """The composite's ``_reload()`` should re-read the config file,
    push the fresh per-protocol sub-configs into the children via
    ``apply_config``, then fan the SIGHUP out."""

    def test_reload_pushes_fresh_subconfigs_to_children(self, tmp_path):
        mdns, nbns, wsd = _build_real_children(
            tmp_path, hostname="old-host", netbios="OLDNAME",
        )
        new_mdns = MdnsConfig(
            server=MdnsServerConfig(host_name="new-host"),
            service_dir=tmp_path / "no-services",
            rundir=tmp_path,
        )
        new_nbns = NbnsConfig(
            server=NbnsServerConfig(netbios_name="NEWNAME", workgroup="WG"),
            rundir=tmp_path,
        )
        new_wsd = WsdConfig(
            server=WsdServerConfig(hostname="new-host", workgroup="WG"),
            rundir=tmp_path,
        )
        composite = _composite(
            [
                (ChildName.MDNS.value, mdns),
                (ChildName.NETBIOSNS.value, nbns),
                (ChildName.WSD.value, wsd),
            ],
            reloader=lambda: _unified(new_mdns, new_nbns, new_wsd),
        )

        asyncio.run(composite._reload())

        assert mdns._config is new_mdns
        assert mdns._hostname == "new-host"
        assert nbns._config is new_nbns
        assert wsd._config is new_wsd

    def test_reloader_failure_leaves_children_with_previous_config(
        self, tmp_path, caplog,
    ):
        mdns, nbns, wsd = _build_real_children(
            tmp_path, hostname="old-host", netbios="OLDNAME",
        )
        orig_mdns_cfg = mdns._config
        orig_nbns_cfg = nbns._config
        orig_wsd_cfg = wsd._config

        def boom() -> UnifiedConfig:
            raise RuntimeError("disk read failed")

        composite = _composite(
            [
                (ChildName.MDNS.value, mdns),
                (ChildName.NETBIOSNS.value, nbns),
                (ChildName.WSD.value, wsd),
            ],
            reloader=boom,
        )

        with caplog.at_level(
            logging.ERROR, logger="test.composite.reload",
        ):
            asyncio.run(composite._reload())

        # Reload carried on with stale config (fan-out still happened
        # — children's ``_reload()`` can run safely against whatever
        # config they have).
        assert mdns._config is orig_mdns_cfg
        assert nbns._config is orig_nbns_cfg
        assert wsd._config is orig_wsd_cfg
        assert any(
            "failed to re-read" in r.message.lower()
            for r in caplog.records
        )

    def test_protocol_disabled_in_new_config_keeps_previous_child_config(
        self, tmp_path, caplog,
    ):
        mdns, nbns, wsd = _build_real_children(
            tmp_path, hostname="old-host", netbios="OLDNAME",
        )
        orig_nbns_cfg = nbns._config
        new_mdns = MdnsConfig(
            server=MdnsServerConfig(host_name="new-host"),
            service_dir=tmp_path / "no-services",
            rundir=tmp_path,
        )
        new_wsd = WsdConfig(
            server=WsdServerConfig(hostname="new-host", workgroup="WG"),
            rundir=tmp_path,
        )
        composite = _composite(
            [
                (ChildName.MDNS.value, mdns),
                (ChildName.NETBIOSNS.value, nbns),
                (ChildName.WSD.value, wsd),
            ],
            reloader=lambda: _unified(new_mdns, None, new_wsd),
        )

        with caplog.at_level(
            logging.WARNING, logger="truenas_pydiscovery.composite",
        ):
            asyncio.run(composite._reload())

        # Enabled children got the new config; the disabled one kept
        # its previous config (changing the enabled set of protocols
        # requires restarting the unit, not a SIGHUP).
        assert mdns._config is new_mdns
        assert wsd._config is new_wsd
        assert nbns._config is orig_nbns_cfg
        assert any(
            f"{ChildName.NETBIOSNS.value} disabled" in r.message
            for r in caplog.records
        )


class TestBuildFactory:
    def test_factory_no_reloader_means_no_config_refresh(self, tmp_path):
        conf = tmp_path / "u.conf"
        conf.write_text("""
[discovery]
interfaces = eth0

[mdns]
""")
        cfg = load_unified_config(conf)
        composite = build_composite_daemon(cfg)
        assert composite._config_reloader is None
        assert composite._config_dispatch is None

    def test_factory_wires_reloader_and_dispatch(self, tmp_path):
        conf = tmp_path / "u.conf"
        conf.write_text("""
[discovery]
interfaces = eth0

[mdns]
""")
        cfg = load_unified_config(conf)
        composite = build_composite_daemon(
            cfg, config_reloader=lambda: cfg,
        )
        assert composite._config_reloader is not None
        assert composite._config_dispatch is _dispatch_unified_config
