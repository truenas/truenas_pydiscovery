"""Tests for the programmatic ``Browser`` class (continuous discovery).

The Browser sends repeated PTR queries via ``create_query_socket``
and emits ``BrowserResult`` events on an async-iterator interface.
We drive it with a local UDP sender that replies on the socket's
ephemeral port, and verify NEW / REMOVE / ALL_FOR_NOW events.
"""
from __future__ import annotations

import asyncio
import socket
from ipaddress import IPv4Address

from truenas_pymdns.client.browser import Browser, BrowserResult
from truenas_pymdns.protocol.constants import (
    BrowserEvent,
    MDNSFlags,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
)


def _ptr(owner: str, target: str, ttl: int = 4500) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(owner, QType.PTR),
        ttl=ttl,
        data=PTRRecordData(target),
    )


def _srv(fqdn: str, port: int, host: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(fqdn, QType.SRV),
        ttl=1800,
        data=SRVRecordData(0, 0, port, host),
        cache_flush=True,
    )


def _a(host: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(host, QType.A),
        ttl=1800,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


async def _send_response(
    target_port: int, records: list[MDNSRecord],
) -> None:
    """Send a fabricated mDNS response to the Browser's ephemeral port."""
    msg = MDNSMessage(
        flags=MDNSFlags.QR.value | MDNSFlags.AA.value,
        answers=records,
    )
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(msg.to_wire(), ("127.0.0.1", target_port))
    finally:
        sender.close()


async def _collect_events(
    browser: Browser,
    *,
    count: int,
    timeout: float = 5.0,
) -> list[BrowserResult]:
    """Drain *count* events from the Browser or time out."""
    events: list[BrowserResult] = []

    async def drain() -> None:
        async for ev in browser:
            events.append(ev)
            if len(events) >= count:
                return

    try:
        await asyncio.wait_for(drain(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    return events


class TestBrowserNewEvents:
    def test_first_sighting_emits_new(self):
        async def drive() -> list[BrowserResult]:
            async with Browser(
                "_smb._tcp", interface_addr="127.0.0.1",
            ) as b:
                assert b._sock is not None
                port = b._sock.getsockname()[1]
                # Give Browser a moment to send its first query before
                # we respond — respond a touch later.
                await asyncio.sleep(0.1)
                await _send_response(port, [
                    _ptr("_smb._tcp.local", "nas._smb._tcp.local"),
                ])
                events = await _collect_events(b, count=1, timeout=3.0)
                return events

        events = asyncio.run(drive())
        assert any(
            ev.event == BrowserEvent.NEW
            and ev.target == "nas._smb._tcp.local"
            and ev.instance == "nas"
            for ev in events
        )

    def test_duplicate_target_does_not_emit_again(self):
        async def drive() -> list[BrowserResult]:
            async with Browser(
                "_smb._tcp", interface_addr="127.0.0.1",
            ) as b:
                port = b._sock.getsockname()[1]
                await asyncio.sleep(0.1)
                await _send_response(port, [
                    _ptr("_smb._tcp.local", "nas._smb._tcp.local"),
                ])
                events = await _collect_events(b, count=1, timeout=2.0)
                # Second response with same target — no new event.
                await _send_response(port, [
                    _ptr("_smb._tcp.local", "nas._smb._tcp.local"),
                ])
                # Briefly let the Browser process before collecting.
                extra = await _collect_events(b, count=1, timeout=0.5)
                events.extend(extra)
                return events

        events = asyncio.run(drive())
        new_events = [e for e in events if e.event == BrowserEvent.NEW]
        assert len(new_events) == 1


class TestBrowserRemoveEvents:
    def test_goodbye_ttl_zero_emits_remove(self):
        async def drive() -> list[BrowserResult]:
            async with Browser(
                "_smb._tcp", interface_addr="127.0.0.1",
            ) as b:
                port = b._sock.getsockname()[1]
                await asyncio.sleep(0.1)
                await _send_response(port, [
                    _ptr("_smb._tcp.local", "nas._smb._tcp.local"),
                ])
                new_events = await _collect_events(
                    b, count=1, timeout=2.0,
                )
                await _send_response(port, [
                    _ptr("_smb._tcp.local", "nas._smb._tcp.local", ttl=0),
                ])
                remove_events = await _collect_events(
                    b, count=1, timeout=3.0,
                )
                return new_events + remove_events

        events = asyncio.run(drive())
        assert any(e.event == BrowserEvent.REMOVE for e in events)


class TestBrowserResolveMode:
    def test_resolve_attaches_host_port_and_addresses(self):
        async def drive() -> BrowserResult:
            async with Browser(
                "_smb._tcp", interface_addr="127.0.0.1", resolve=True,
            ) as b:
                port = b._sock.getsockname()[1]
                await asyncio.sleep(0.1)
                await _send_response(port, [
                    _ptr("_smb._tcp.local", "nas._smb._tcp.local"),
                    _srv(
                        "nas._smb._tcp.local", 445, "host.local",
                    ),
                    _a("host.local", "10.0.0.1"),
                ])
                evs = await _collect_events(b, count=1, timeout=3.0)
                assert evs
                return evs[0]

        ev = asyncio.run(drive())
        assert ev.event == BrowserEvent.NEW
        assert ev.host == "host.local"
        assert ev.port == 445
        assert "10.0.0.1" in ev.addresses


class TestBrowserAllForNow:
    def test_all_for_now_fires_after_initial_window(self):
        """After the initial query window expires without new events,
        the Browser must emit ``ALL_FOR_NOW`` so callers can stop
        spinning."""
        async def drive() -> list[BrowserResult]:
            async with Browser(
                "_smb._tcp", interface_addr="127.0.0.1",
            ) as b:
                # No responses at all — just wait for the sentinel.
                return await _collect_events(b, count=1, timeout=4.5)

        events = asyncio.run(drive())
        assert any(
            e.event == BrowserEvent.ALL_FOR_NOW for e in events
        )


class TestBrowserClose:
    def test_close_stops_iteration(self):
        async def drive() -> list[BrowserResult]:
            b = Browser(
                "_smb._tcp", interface_addr="127.0.0.1",
            )
            await b.__aenter__()
            port = b._sock.getsockname()[1]
            await asyncio.sleep(0.05)
            await _send_response(port, [
                _ptr("_smb._tcp.local", "close._smb._tcp.local"),
            ])
            evs = await _collect_events(b, count=1, timeout=2.0)
            await b.close()
            # After close, the async iterator must exit promptly.
            more = await _collect_events(b, count=1, timeout=0.5)
            return evs + more

        events = asyncio.run(drive())
        # At most one NEW before close.  No panic after close.
        assert sum(
            1 for e in events if e.event == BrowserEvent.NEW
        ) == 1
