"""truenas-discovery-status: dump truenas-discoveryd runtime state as JSON.

Reads the daemon's pidfile, sends SIGUSR1 to trigger a fresh status
dump from each child daemon, waits for the per-protocol ``status.json``
files to refresh, then merges them into a single JSON object on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

DEFAULT_RUNDIR = Path("/run/truenas-discovery")
PIDFILE_NAME = "truenas-discoveryd.pid"
CHILD_NAMES = ("mdns", "netbiosns", "wsd")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="truenas-discovery-status",
        description=(
            "Dump truenas-discoveryd runtime state as a single JSON "
            "object.  Sends SIGUSR1 to the daemon to refresh its "
            "status files, then merges them."
        ),
    )
    parser.add_argument(
        "--rundir",
        type=Path,
        default=DEFAULT_RUNDIR,
        help=(
            "Daemon runtime directory containing the pidfile and per-"
            f"protocol status.json files (default: {DEFAULT_RUNDIR})"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help=(
            "Seconds to wait for the daemon to refresh status files "
            "(default: 5.0).  Use 0 to skip waiting."
        ),
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON output with indentation.",
    )
    return parser.parse_args(argv)


def _read_pid(pidfile: Path) -> int | None:
    try:
        text = pidfile.read_text().strip()
    except FileNotFoundError:
        print(
            f"truenas-discovery-status: daemon not running "
            f"(pidfile {pidfile} missing)",
            file=sys.stderr,
        )
        return None
    except OSError as e:
        print(
            f"truenas-discovery-status: cannot read {pidfile}: {e}",
            file=sys.stderr,
        )
        return None
    try:
        return int(text)
    except ValueError:
        print(
            f"truenas-discovery-status: pidfile {pidfile} contains "
            f"invalid pid: {text!r}",
            file=sys.stderr,
        )
        return None


def _send_sigusr1(pid: int) -> bool:
    try:
        os.kill(pid, signal.SIGUSR1)
    except ProcessLookupError:
        print(
            f"truenas-discovery-status: pid {pid} not running "
            f"(stale pidfile?)",
            file=sys.stderr,
        )
        return False
    except PermissionError:
        print(
            "truenas-discovery-status: no permission to signal pid "
            f"{pid}; run as root or the truenas-discovery user",
            file=sys.stderr,
        )
        return False
    return True


def _wait_for_refresh(
    before: dict[Path, int], deadline: float,
) -> bool:
    """Block until every path's st_mtime_ns advances past its snapshot.

    Returns True if every path refreshed in time, False on timeout."""
    pending = dict(before)
    while pending:
        if time.monotonic() >= deadline:
            return False
        for p in list(pending):
            try:
                now = p.stat().st_mtime_ns
            except FileNotFoundError:
                continue
            if now > pending[p]:
                pending.pop(p)
        if pending:
            time.sleep(0.05)
    return True


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        print(
            f"truenas-discovery-status: failed to read {path}: {e}",
            file=sys.stderr,
        )
        return None


def _run(args: argparse.Namespace) -> int:
    rundir: Path = args.rundir
    pidfile = rundir / PIDFILE_NAME
    pid = _read_pid(pidfile)
    if pid is None:
        return 1

    child_paths = [
        (name, rundir / name / "status.json") for name in CHILD_NAMES
    ]
    existing_before = {
        p: p.stat().st_mtime_ns for _, p in child_paths if p.exists()
    }

    if not _send_sigusr1(pid):
        return 1

    if existing_before and args.timeout > 0:
        deadline = time.monotonic() + args.timeout
        if not _wait_for_refresh(existing_before, deadline):
            print(
                f"truenas-discovery-status: timed out after "
                f"{args.timeout}s waiting for status refresh; "
                f"printing last sampled data",
                file=sys.stderr,
            )

    children: dict[str, dict] = {}
    for name, path in child_paths:
        body = _read_json(path)
        if body is not None:
            children[name] = body

    output = {"pid": pid, "children": children}
    indent = 2 if args.pretty else None
    print(json.dumps(output, indent=indent))
    return 0


def main() -> None:
    """Entry point for the truenas-discovery-status CLI."""
    sys.exit(_run(parse_args()))


if __name__ == "__main__":
    main()
