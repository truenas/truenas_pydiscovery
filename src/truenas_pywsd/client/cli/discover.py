"""wsd-discover: discover WSD devices on the network."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from ..query import (
    discover_devices,
    extract_endpoint,
    extract_xaddrs,
    fetch_metadata,
    resolve_endpoint,
)


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


async def _process_endpoint(
    endpoint: str,
    xaddrs: str,
    args: argparse.Namespace,
) -> dict:
    """Resolve XAddrs (if absent) and fetch metadata for *endpoint*.

    Runs per-endpoint Resolve and Get concurrently with other
    endpoints so an unresponsive host doesn't stall the rest of
    the discovery — a slow Resolve on host A used to burn the full
    ``args.timeout`` before host B's metadata fetch even started.
    """
    data: dict = {"endpoint": endpoint}

    # Windows hosts omit XAddrs from ProbeMatches by default for
    # privacy; when the caller asked to resolve and we don't have
    # XAddrs yet, send a unicast Resolve to extract them from the
    # target's ResolveMatches.
    if args.resolve and not xaddrs:
        xaddrs = await resolve_endpoint(
            endpoint,
            timeout=args.timeout,
            interface_addr=args.interface,
        )

    if xaddrs:
        data["xaddrs"] = xaddrs

    if args.resolve and xaddrs:
        try:
            info = await fetch_metadata(
                xaddrs,
                timeout=args.timeout,
                # We already know the endpoint URN from the
                # Probe/Resolve exchange — pass it through so
                # Windows accepts the Get.  Without this, WSDAPI
                # dispatches on wsa:To and faults with
                # wsa:DestinationUnreachable.
                endpoint=endpoint,
            )
            data.update(info)
        except (OSError, TimeoutError):
            data["metadata_error"] = "fetch failed"

    return data


def _emit(data: dict, args: argparse.Namespace) -> None:
    if args.json_output:
        print(json.dumps(data), flush=True)
        return
    print(f"  {data['endpoint']}")
    if data.get("xaddrs"):
        print(f"    XAddrs: {data['xaddrs']}")
    if data.get("friendly_name"):
        print(f"    FriendlyName: {data['friendly_name']}")
    if data.get("computer"):
        print(f"    Computer: {data['computer']}")
    if data.get("manufacturer"):
        print(f"    Manufacturer: {data['manufacturer']}")
    if data.get("fault"):
        print(f"    Fault: {data['fault']}")
        if data.get("fault_reason"):
            print(f"      Reason: {data['fault_reason']}")
    if data.get("metadata_error"):
        print("    (metadata fetch failed)")


async def async_main(args: argparse.Namespace) -> int:
    responses = await discover_devices(
        timeout=args.timeout, interface_addr=args.interface,
    )

    if not responses:
        print("No WSD devices found", file=sys.stderr)
        return 1

    # Dedupe by endpoint URN (a single host emits 1-4 ProbeMatches
    # retransmissions per SOAP-over-UDP §3.4).  Preserve ProbeMatch
    # arrival order so human-friendly output stays stable between
    # runs when the same hosts respond.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for env in responses:
        endpoint = extract_endpoint(env)
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)
        unique.append((endpoint, extract_xaddrs(env)))

    # Run per-endpoint Resolve + Get concurrently.  Serial
    # processing multiplied the per-host timeout by the number of
    # endpoints and made "which hosts we see" depend on how many
    # slow responders preceded them in the ProbeMatch queue.
    results = await asyncio.gather(
        *(_process_endpoint(ep, xa, args) for ep, xa in unique),
        return_exceptions=True,
    )

    for data in results:
        if isinstance(data, BaseException):
            continue
        _emit(data, args)

    return 0


def main() -> None:
    args = parse_args()
    try:
        sys.exit(asyncio.run(async_main(args)))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
