"""wsd-discover: discover WSD devices on the network."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from ..query import discover_devices, extract_endpoint, extract_xaddrs, fetch_metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wsd-discover",
        description="Discover WSD devices on the local network",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=4.0,
        help="Discovery timeout in seconds (default: 4.0)",
    )
    parser.add_argument(
        "-r", "--resolve", action="store_true",
        help="Fetch metadata for each discovered device",
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Interface IPv4 address to send from",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSONL (one JSON object per line)",
    )
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    responses = await discover_devices(
        timeout=args.timeout, interface_addr=args.interface,
    )

    if not responses:
        print("No WSD devices found", file=sys.stderr)
        return 1

    seen: set[str] = set()
    for env in responses:
        endpoint = extract_endpoint(env)
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)

        xaddrs = extract_xaddrs(env)
        data: dict = {"endpoint": endpoint}
        if xaddrs:
            data["xaddrs"] = xaddrs

        if args.resolve and xaddrs:
            try:
                info = await fetch_metadata(xaddrs, timeout=args.timeout)
                data.update(info)
            except (OSError, TimeoutError):
                data["metadata_error"] = "fetch failed"

        if args.json_output:
            print(json.dumps(data), flush=True)
        else:
            print(f"  {endpoint}")
            if xaddrs:
                print(f"    XAddrs: {xaddrs}")
            if data.get("friendly_name"):
                print(f"    FriendlyName: {data['friendly_name']}")
            if data.get("computer"):
                print(f"    Computer: {data['computer']}")
            if data.get("manufacturer"):
                print(f"    Manufacturer: {data['manufacturer']}")
            if data.get("metadata_error"):
                print("    (metadata fetch failed)")

    return 0


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
