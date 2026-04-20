"""wsd-info: fetch metadata from a WSD device."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from ..query import fetch_metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wsd-info",
        description="Fetch metadata from a WSD device endpoint",
    )
    parser.add_argument(
        "url",
        help="Device metadata URL (e.g. http://192.168.1.100:5357/uuid)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0,
        help="Request timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON",
    )
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    try:
        info = await fetch_metadata(args.url, timeout=args.timeout)
    except (OSError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not info:
        print("No metadata returned", file=sys.stderr)
        return 1

    if args.json_output:
        print(json.dumps(info))
    else:
        for key, value in info.items():
            label = key.replace("_", " ").title()
            print(f"  {label}: {value}")

    return 0


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
