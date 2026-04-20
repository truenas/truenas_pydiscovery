"""nbt-lookup: resolve a NetBIOS name to IP addresses."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from truenas_pynetbiosns.protocol.constants import NameType, RRType
from truenas_pynetbiosns.protocol.message import NBNSMessage, parse_nb_rdata
from ..query import one_shot_query


def _parse_name_type(val: str) -> int:
    """Accept a ``NameType`` enum name (case-insensitive) or an integer.

    Named values cover the well-known suffixes from RFC 1001/1002 and
    MS-BRWS.  An integer literal (``0x41``, ``65``, ``0o101``) is still
    accepted so unusual name types can be queried without extending the
    enum.
    """
    key = val.strip().upper()
    if key in NameType.__members__:
        return NameType[key].value
    try:
        return int(val, 0)
    except ValueError:
        choices = ", ".join(t.name for t in NameType)
        raise argparse.ArgumentTypeError(
            f"invalid name type {val!r}: expected one of {{{choices}}} "
            f"or an integer literal (e.g. 0x20)",
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nbt-lookup",
        description="Resolve a NetBIOS name to IP addresses",
    )
    parser.add_argument("name", help="NetBIOS name to look up")
    type_names = ", ".join(t.name for t in NameType)
    parser.add_argument(
        "--type", type=_parse_name_type, default=NameType.SERVER.value,
        metavar="TYPE",
        help=(
            f"Name type suffix: one of {{{type_names}}} "
            f"(case-insensitive), or an integer literal like 0x41. "
            f"Default: SERVER (0x20)."
        ),
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=2.0,
        help="Query timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Interface IP address to send from",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSONL (one JSON object per line)",
    )
    return parser.parse_args()


async def async_main(args: argparse.Namespace) -> int:
    msg = NBNSMessage.build_name_query(args.name, args.type)
    responses = await one_shot_query(
        msg, timeout=args.timeout, interface_addr=args.interface,
    )

    found = False
    for resp in responses:
        for rr in resp.answers:
            if rr.rr_type == RRType.NB:
                entries = parse_nb_rdata(rr.rdata)
                for flags, ip in entries:
                    if args.json_output:
                        print(json.dumps({
                            "name": str(rr.name),
                            "ip": str(ip),
                        }), flush=True)
                    else:
                        print(f"{rr.name}\t{ip}")
                    found = True

    if not found:
        print(
            f"No response for {args.name}<{args.type:02x}>",
            file=sys.stderr,
        )
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
