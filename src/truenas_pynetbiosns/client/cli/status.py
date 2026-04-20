"""nbt-status: query node status (registered names) of a NetBIOS host."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from truenas_pynetbiosns.protocol.constants import NETBIOS_NAME_LENGTH, NBFlag, RRType
from truenas_pynetbiosns.protocol.message import NBNSMessage
from ..query import one_shot_query


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nbt-status",
        description="Query registered names on a NetBIOS host",
    )
    parser.add_argument("host", help="IP address of the host to query")
    parser.add_argument(
        "-t", "--timeout", type=float, default=2.0,
        help="Query timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSONL (one JSON object per line)",
    )
    return parser.parse_args()


def _parse_nbstat_rdata(rdata: bytes) -> list[tuple[str, int, int]]:
    """Parse NBSTAT rdata into (name, type, flags) tuples."""
    if len(rdata) < 1:
        return []
    count = rdata[0]
    names: list[tuple[str, int, int]] = []
    offset = 1
    for _ in range(count):
        if offset + 18 > len(rdata):
            break
        raw_name = rdata[offset:offset + NETBIOS_NAME_LENGTH]
        name = raw_name.decode("ascii", errors="replace").rstrip()
        name_type = rdata[offset + NETBIOS_NAME_LENGTH]
        flags = int.from_bytes(rdata[offset + 16:offset + 18], "big")
        names.append((name, name_type, flags))
        offset += 18
    return names


async def async_main(args: argparse.Namespace) -> int:
    msg = NBNSMessage.build_node_status_query()
    responses = await one_shot_query(
        msg, timeout=args.timeout, dest=args.host,
    )

    found = False
    for resp in responses:
        for rr in resp.answers:
            if rr.rr_type == RRType.NBSTAT:
                names = _parse_nbstat_rdata(rr.rdata)
                if not names:
                    continue
                found = True
                if args.json_output:
                    for name, ntype, flags in names:
                        print(json.dumps({
                            "name": name,
                            "type": f"0x{ntype:02x}",
                            "group": bool(flags & NBFlag.GROUP.value),
                            "active": bool(flags & 0x0400),
                        }), flush=True)
                else:
                    print(f"{'Name':<16} {'Type':<6} {'Flags'}")
                    print("-" * 36)
                    for name, ntype, flags in names:
                        group = "GROUP" if flags & NBFlag.GROUP.value else "UNIQUE"
                        active = "ACTIVE" if flags & 0x0400 else ""
                        print(
                            f"{name:<16} <{ntype:02x}>  "
                            f"{group:<7} {active}"
                        )

    if not found:
        print(f"No response from {args.host}", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
