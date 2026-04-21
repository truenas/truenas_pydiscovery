"""Programmatic continuous service-discovery Browser.

Analogous to Avahi's ``AvahiServiceBrowser`` and Bonjour's
``DNSServiceBrowse``: clients subscribe to a service type and
receive ``BrowserEvent.NEW`` / ``BrowserEvent.REMOVE`` /
``BrowserEvent.ALL_FOR_NOW`` events as an async iterator.  The
lower-level one-shot API in ``client/query.py`` stays available for
callers that just want a single lookup.

Sends QU PTR queries at RFC 6762 §5.2 doubling intervals (1 s, 2 s,
4 s, ...) capped at ``_MAX_QUERY_INTERVAL``.  Tracks seen targets
and emits NEW on first sight.  REMOVE is emitted when a peer sends
a TTL=0 goodbye for a previously-seen target.  ALL_FOR_NOW fires
after the first pass of responses settles.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import AsyncIterator

from truenas_pymdns.protocol.constants import (
    BrowserEvent,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    MDNSRecord,
    PTRRecordData,
)
from .query import (
    collect_responses,
    create_query_socket,
    extract_ptr_targets,
    extract_service_info,
    qu_question,
    send_query,
)

# RFC 6762 s5.2: continuous-query backoff cap.
_MAX_QUERY_INTERVAL = 3600.0

# First-pass window: how long after the initial query we wait before
# emitting ALL_FOR_NOW.  Mirrors avahi's browser.c ALL_FOR_NOW delay.
_ALL_FOR_NOW_WINDOW = 2.0


@dataclass(slots=True)
class BrowserResult:
    """A single event from the Browser async iterator."""
    event: BrowserEvent
    target: str = ""
    instance: str = ""
    host: str = ""
    port: int = 0
    addresses: tuple[str, ...] = ()
    txt: dict[str, str] | None = None


class Browser:
    """Continuous mDNS/DNS-SD service browser.

    Usage::

        async with Browser("_smb._tcp") as b:
            async for ev in b:
                if ev.event == BrowserEvent.NEW:
                    print("Found", ev.target)

    The browser keeps re-querying at exponential-backoff intervals
    and yields events as they arrive.  Close the context manager to
    stop querying and release the socket.
    """

    def __init__(
        self,
        service_type: str,
        *,
        domain: str = "local",
        interface_addr: str | None = None,
        resolve: bool = False,
    ) -> None:
        self._service_type = service_type
        self._domain = domain
        self._browse_name = f"{service_type}.{domain}"
        self._interface_addr = interface_addr
        self._resolve = resolve
        self._sock: socket.socket | None = None
        self._seen: dict[str, BrowserResult] = {}
        self._queue: asyncio.Queue[BrowserResult] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def __aenter__(self) -> "Browser":
        self._sock = create_query_socket(self._interface_addr)
        self._task = asyncio.create_task(self._run())
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __aiter__(self) -> AsyncIterator[BrowserResult]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[BrowserResult]:
        while not self._stop.is_set():
            getter = asyncio.create_task(self._queue.get())
            stopper = asyncio.create_task(self._stop.wait())
            done, pending = await asyncio.wait(
                {getter, stopper},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for p in pending:
                p.cancel()
            if stopper in done and getter not in done:
                return
            yield getter.result()

    async def _run(self) -> None:
        assert self._sock is not None
        interval = 1.0
        all_for_now_emitted = False
        while not self._stop.is_set():
            send_query(
                self._sock,
                [qu_question(self._browse_name, QType.PTR)],
            )

            records: list[MDNSRecord] = []
            collect = asyncio.create_task(
                collect_responses(self._sock, interval, records),
            )
            try:
                await collect
            except asyncio.CancelledError:
                return

            self._process_batch(records)

            if (not all_for_now_emitted
                    and interval >= _ALL_FOR_NOW_WINDOW):
                await self._queue.put(
                    BrowserResult(event=BrowserEvent.ALL_FOR_NOW),
                )
                all_for_now_emitted = True

            interval = min(interval * 2, _MAX_QUERY_INTERVAL)

    def _process_batch(self, records: list[MDNSRecord]) -> None:
        targets = extract_ptr_targets(records, self._browse_name)
        for target in targets:
            # Detect goodbye (TTL=0) PTRs for known targets.
            goodbye = self._is_goodbye_for(target, records)
            if goodbye and target in self._seen:
                prior = self._seen.pop(target)
                removed = BrowserResult(
                    event=BrowserEvent.REMOVE,
                    target=target,
                    instance=prior.instance,
                )
                self._queue.put_nowait(removed)
                continue

            if target in self._seen:
                continue

            instance = self._instance_label(target)
            result = BrowserResult(
                event=BrowserEvent.NEW,
                target=target,
                instance=instance,
            )
            if self._resolve and instance:
                info = extract_service_info(
                    records, instance, self._service_type, self._domain,
                )
                if info.host:
                    result.host = info.host
                    result.port = info.port
                    result.addresses = tuple(info.addresses)
                    result.txt = dict(info.txt)

            self._seen[target] = result
            self._queue.put_nowait(result)

    def _instance_label(self, target: str) -> str:
        suffix = f".{self._browse_name}"
        lowered = target.lower()
        if lowered.endswith(suffix.lower()):
            return target[:-len(suffix)]
        return target

    def _is_goodbye_for(
        self, target: str, records: list[MDNSRecord],
    ) -> bool:
        target_lower = target.lower()
        for rr in records:
            if (rr.key.name == self._browse_name.lower()
                    and rr.key.rtype == QType.PTR
                    and isinstance(rr.data, PTRRecordData)
                    and rr.data.target.lower() == target_lower
                    and rr.ttl == 0):
                return True
        return False


# Silence unused-import warnings for symbols re-exported by name only.
_UNUSED = MDNSMessage
