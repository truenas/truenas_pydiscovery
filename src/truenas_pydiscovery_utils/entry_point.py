"""Common daemon CLI entry point boilerplate.

Every discovery daemon uses the same ``-c/--config`` and ``-v/--verbose``
flags and the same startup sequence: parse args, configure logging, load
config, instantiate server, run event loop.  ``run_daemon`` wires this
up so each daemon's ``__main__.py`` is a one-liner.
"""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any, Callable

from .logger import setup_console, setup_syslog


def run_daemon(
    name: str,
    description: str,
    config_loader: Callable[[Path], Any],
    server_class: Callable[..., Any],
    default_config: Path,
    *,
    logger_name: str | None = None,
) -> None:
    """Parse CLI flags, set up logging, load config, and run *server_class*.

    *config_loader* is called with the config file path and must return
    a config object accepted by ``server_class(config, reloader)``.

    *server_class* is any callable that takes ``(config, reloader)`` and
    returns a daemon exposing ``async run()`` — typically a
    ``BaseDaemon`` subclass, but can be a factory function for
    composite daemons.  ``reloader`` is a zero-argument callable that
    re-invokes ``config_loader`` on the same path, so the server can
    pick up on-disk config changes on SIGHUP without re-parsing CLI
    args.  A server that doesn't support live reload may ignore it.

    *logger_name* is the top-level logger for this daemon's package
    (e.g. ``"truenas_pymdns"``).  If not given, *name* is used.

    Logging: ``-v`` enables console (stderr) logging for interactive
    debugging.  Without ``-v``, logging goes to syslog via non-blocking
    queue handler.
    """
    if logger_name is None:
        logger_name = name

    parser = argparse.ArgumentParser(prog=name, description=description)
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=default_config,
        help="Path to configuration file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug)",
    )
    args = parser.parse_args()

    if args.verbose:
        setup_console(args.verbose)
    else:
        setup_syslog(logger_name, ident=f"{name}: ")

    config_path: Path = args.config

    def reloader() -> Any:
        return config_loader(config_path)

    config = reloader()
    server = server_class(config, reloader)
    asyncio.run(server.run())
