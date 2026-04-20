"""mdns-lookup: look up a named service instance (like dns-sd -L)."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from truenas_pymdns.protocol.constants import QType
from ..query import (
    extract_addresses,
    extract_service_info,
    one_shot_query,
    qu_question,
)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the lookup tool."""
    parser = argparse.ArgumentParser(
        prog="mdns-lookup",
        description=(
            "Look up and display the information necessary to contact "
            "a named mDNS service instance"
        ),
    )
    parser.add_argument(
        "name",
        help="Service instance name (e.g. TN26NEW)",
    )
    parser.add_argument(
        "service_type",
        help="Service type (e.g. _http._tcp)",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default="local",
        help="Domain (default: local)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=3.0,
        help="Query timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Interface IPv4 address to send queries from",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON",
    )
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    """Look up a named service instance."""
    fqdn = f"{args.name}.{args.service_type}.{args.domain}"

    try:
        records = await one_shot_query(
            [
                qu_question(fqdn, QType.SRV),
                qu_question(fqdn, QType.TXT),
            ],
            timeout=args.timeout,
            interface_addr=args.interface,
        )
        info = extract_service_info(
            records, args.name, args.service_type, args.domain,
        )

        if info.host and not info.addresses:
            addr_records = await one_shot_query(
                [
                    qu_question(info.host, QType.A),
                    qu_question(info.host, QType.AAAA),
                ],
                timeout=args.timeout,
                interface_addr=args.interface,
            )
            info.addresses = extract_addresses(addr_records, info.host)

        if not info.host:
            print(
                f"No SRV record found for {fqdn}",
                file=sys.stderr,
            )
            return 1

        if args.json_output:
            print(json.dumps({
                "fqdn": fqdn,
                "host": info.host,
                "port": info.port,
                "addresses": info.addresses,
                "txt": info.txt,
            }))
        else:
            print(
                f"{fqdn}. can be reached at "
                f"{info.host}:{info.port}"
            )
            if info.txt:
                txt_parts = [
                    f"{k}={v}" if v else k for k, v in info.txt.items()
                ]
                print(f" {' '.join(txt_parts)}")

    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


def main() -> None:
    """Entry point for the mdns-lookup CLI."""
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
