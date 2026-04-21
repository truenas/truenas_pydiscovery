"""Entry point for ``truenas-discoveryd``.

Hosts mDNS, NetBIOS Name Service, and WS-Discovery in one process.
"""
from __future__ import annotations

import logging
import sys

from truenas_pydiscovery_utils.entry_point import run_daemon

from truenas_pydiscovery.composite import build_composite_daemon
from truenas_pydiscovery.config import (
    DEFAULT_CONFIG_PATH,
    NoProtocolsEnabledError,
    load_unified_config,
)


def main() -> None:
    try:
        run_daemon(
            name="truenas-discoveryd",
            description=(
                "TrueNAS unified discovery daemon "
                "(mDNS + NetBIOS NS + WS-Discovery)"
            ),
            config_loader=load_unified_config,
            server_class=build_composite_daemon,
            default_config=DEFAULT_CONFIG_PATH,
            logger_name="truenas_pydiscovery",
        )
    except NoProtocolsEnabledError as exc:
        # Operator has disabled every protocol.  run_daemon() already
        # configured syslog (or console if -v), so emit one line and
        # exit 0 — systemd's Restart=on-failure won't restart a clean
        # exit, which stops the journal-spam restart loop.
        logging.getLogger("truenas_pydiscovery").warning("%s", exc)
        sys.exit(0)


if __name__ == "__main__":
    main()
