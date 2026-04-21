"""mdns-browse: browse for mDNS/DNS-SD services via direct multicast queries."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from truenas_pymdns.protocol.constants import QType
from ..query import (
    collect_responses,
    create_query_socket,
    extract_ptr_targets,
    extract_service_info,
    one_shot_query,
    qu_question,
    send_query,
)
from truenas_pymdns.protocol.records import MDNSRecord  # noqa: F401 (used in type hint)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the browse tool."""
    parser = argparse.ArgumentParser(
        prog="mdns-browse",
        description="Browse for mDNS/DNS-SD services",
    )
    parser.add_argument(
        "service_type",
        nargs="?",
        default=None,
        help="Service type to browse (e.g. _http._tcp)",
    )
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Show all service types",
    )
    parser.add_argument(
        "-r", "--resolve",
        action="store_true",
        help="Resolve discovered services",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=None,
        help="Total browse duration in seconds (default: until Ctrl+C)",
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


def _emit(args: argparse.Namespace, data: dict) -> None:
    if args.json_output:
        print(json.dumps(data), flush=True)
    else:
        target = data.get("target", "")
        print(f"+  {target}")
        if "host" in data:
            print(f"   hostname = [{data['host']}]")
            for addr in data.get("addresses", []):
                print(f"   address = [{addr}]")
            print(f"   port = [{data.get('port', 0)}]")
            for k, v in data.get("txt", {}).items():
                print(f'   txt = ["{k}={v}"]')


async def async_main(args: argparse.Namespace) -> int:
    """Browse for mDNS services via direct multicast queries."""
    if args.all:
        svc_type = "_services._dns-sd._udp"
        domain = "local"
    elif args.service_type:
        svc_type = args.service_type
        domain = "local"
    else:
        print("Specify a service type or use --all", file=sys.stderr)
        return 1

    browse_name = f"{svc_type}.{domain}"
    seen: set[str] = set()
    sock = create_query_socket(args.interface)

    try:
        delay = 1.0
        max_delay = 20.0
        loop = asyncio.get_running_loop()
        deadline = (
            loop.time() + args.timeout if args.timeout else None
        )

        while True:
            if deadline is not None:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                wait = min(delay, remaining)
            else:
                wait = delay

            questions = [qu_question(browse_name, QType.PTR)]
            send_query(sock, questions)

            records: list[MDNSRecord] = []
            await collect_responses(sock, wait, records)

            targets = extract_ptr_targets(records, browse_name)
            for target in targets:
                if target in seen:
                    continue
                seen.add(target)

                suffix = f".{browse_name}"
                if target.lower().endswith(suffix.lower()):
                    instance = target[:-len(suffix)]
                else:
                    instance = target

                data: dict = {"target": target, "instance": instance}

                if args.resolve and instance:
                    info = extract_service_info(
                        records, instance, svc_type, domain,
                    )
                    if not info.host:
                        fqdn = f"{instance}.{svc_type}.{domain}"
                        extra = await one_shot_query([
                            qu_question(fqdn, QType.SRV),
                            qu_question(fqdn, QType.TXT),
                        ], timeout=2.0, interface_addr=args.interface)
                        info = extract_service_info(
                            records + extra, instance, svc_type, domain,
                        )
                    if info.host:
                        data["host"] = info.host
                        data["port"] = info.port
                        data["addresses"] = info.addresses
                        data["txt"] = info.txt

                _emit(args, data)

            delay = min(delay * 2, max_delay)

    finally:
        sock.close()

    return 0


def main() -> None:
    """Entry point for the mdns-browse CLI."""
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
