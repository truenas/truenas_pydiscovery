"""CLI dispatcher for python -m truenas_pymdns.client."""
from __future__ import annotations

import sys

from .cli.browse import main as browse_main
from .cli.lookup import main as lookup_main
from .cli.resolve import main as resolve_main


def main() -> None:
    """Dispatch to browse, resolve, or lookup subcommand."""
    if len(sys.argv) < 2:
        print(
            "Usage: python -m truenas_pymdns.client"
            " {browse|resolve|lookup}",
            file=sys.stderr,
        )
        sys.exit(1)

    cmd = sys.argv[1]
    sys.argv = sys.argv[1:]

    commands = {
        "browse": browse_main,
        "resolve": resolve_main,
        "lookup": lookup_main,
    }
    fn = commands.get(cmd)
    if fn is None:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)
    fn()


if __name__ == "__main__":
    main()
