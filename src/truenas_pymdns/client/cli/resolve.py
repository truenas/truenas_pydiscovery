"""mdns-resolve: resolve mDNS names via direct multicast queries."""
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
    """Parse command-line arguments for the resolve tool."""
    parser = argparse.ArgumentParser(
        prog="mdns-resolve",
        description="Resolve mDNS names",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-n", "--name",
        help="Hostname to resolve (e.g. myhost.local)",
    )
    group.add_argument(
        "-s", "--service",
        nargs=2,
        metavar=("NAME", "TYPE"),
        help="Service to resolve (e.g. 'My NAS' _smb._tcp)",
    )
    parser.add_argument(
        "-d", "--domain",
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
        help="Output as JSONL (one JSON object per line)",
    )
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    """Dispatch to the appropriate resolve function."""
    try:
        if args.name:
            records = await one_shot_query(
                [
                    qu_question(args.name, QType.A),
                    qu_question(args.name, QType.AAAA),
                ],
                timeout=args.timeout,
                interface_addr=args.interface,
            )
            addresses = extract_addresses(records, args.name)
            if not addresses:
                print(
                    f"No addresses found for {args.name}",
                    file=sys.stderr,
                )
                return 1
            if args.json_output:
                print(json.dumps({
                    "name": args.name, "addresses": addresses,
                }))
            else:
                for addr in addresses:
                    print(f"{args.name}\t{addr}")

        elif args.service:
            name, svc_type = args.service
            fqdn = f"{name}.{svc_type}.{args.domain}"

            records = await one_shot_query(
                [
                    qu_question(fqdn, QType.SRV),
                    qu_question(fqdn, QType.TXT),
                ],
                timeout=args.timeout,
                interface_addr=args.interface,
            )
            info = extract_service_info(
                records, name, svc_type, args.domain,
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
                info.addresses = extract_addresses(
                    addr_records, info.host,
                )

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
                print(f"  {fqdn}")
                print(f"  hostname = [{info.host}]")
                for addr in info.addresses:
                    print(f"  address = [{addr}]")
                print(f"  port = [{info.port}]")
                for k, v in info.txt.items():
                    print(f'  txt = ["{k}={v}"]')

    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


def main() -> None:
    """Entry point for the mdns-resolve CLI."""
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
