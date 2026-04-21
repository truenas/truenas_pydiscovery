"""Self-echo of a multi-rdata RRSET must not trigger conflicts.

A host with multiple IPv6 addresses on one interface owns several
AAAA records for the same hostname.  ``IP_MULTICAST_LOOP=1``
(``multicast.py:40``, intentional for own-probe detection in
RFC 6762 §8.2) delivers our announcement back to us, so we see
every AAAA record in the RRSET arrive as a "peer" record.

The conflict detector must recognise each arriving record as part
of our own RRSET — i.e. a conflict only when the peer's rdata
matches NONE of our owned records for that (name, type).  An older
form of the loop broke on the first owned record whose rdata
differed from the peer's, which flagged AAAA-#2 as conflicting
with owned-AAAA-#1 even though AAAA-#2 was in our own RRSET.

The bug symptom on deployment:

    RFC 6762 §9: peer rdata conflict from 192.168.1.102
        on ['tnnew26.local'] — resetting group to probing state
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

from truenas_pymdns.protocol.constants import (
    MDNSFlags,
    QType,
)
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    AAAARecordData,
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
)
from truenas_pymdns.server.core.entry_group import EntryGroup


class _FakeAnnouncer:
    def __init__(self) -> None:
        self.scheduled: list[list[MDNSRecord]] = []

    def schedule_announce(
        self, records: list[MDNSRecord], count: int = 1,
    ) -> None:
        self.scheduled.append(list(records))


class _FakeIfState:
    def __init__(self, iface_name: str, iface_index: int) -> None:
        from truenas_pymdns.server.net.interface import InterfaceInfo
        self.iface = InterfaceInfo(name=iface_name, index=iface_index)
        self.announcer = _FakeAnnouncer()


def _aaaa(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.AAAA),
        ttl=120,
        data=AAAARecordData(IPv6Address(addr)),
        cache_flush=True,
    )


def _a(name: str, addr: str) -> MDNSRecord:
    return MDNSRecord(
        key=MDNSRecordKey(name, QType.A),
        ttl=120,
        data=ARecordData(IPv4Address(addr)),
        cache_flush=True,
    )


def _server_with_rrset(
    aaaa_addrs: list[str], v4_addrs: list[str] | None = None,
) -> tuple[object, _FakeIfState]:
    from truenas_pymdns.server.server import MDNSServer
    from truenas_pymdns.server.service.registry import ServiceRegistry

    state = _FakeIfState("eno4", 3)
    server = MDNSServer.__new__(MDNSServer)
    server._interfaces = {3: state}
    server._registry = ServiceRegistry()
    server._entry_groups = []
    server._conflict_tasks = []

    class _NoopStatus:
        def inc(self, *_a, **_kw) -> None:
            pass
    server._status = _NoopStatus()

    group = EntryGroup()
    for v4 in v4_addrs or []:
        group.add_record(_a("tnnew26.local", v4))
    for v6 in aaaa_addrs:
        group.add_record(_aaaa("tnnew26.local", v6))
    from truenas_pymdns.protocol.constants import EntryGroupState
    group.set_state(EntryGroupState.ESTABLISHED)
    server._entry_groups.append(group)
    server._registry.add_group(group)
    return server, state


def _response_with(records: list[MDNSRecord]) -> MDNSMessage:
    return MDNSMessage(
        flags=MDNSFlags.QR.value | MDNSFlags.AA.value,
        answers=records,
    )


def _run(coro) -> None:
    import asyncio
    asyncio.run(coro)


class TestSelfEchoMultipleAAAA:
    def test_echo_of_each_aaaa_is_not_a_conflict(self):
        """Every AAAA in our RRSET, echoed back individually, must
        match *some* owned record and not trigger a reprobe."""
        async def drive() -> None:
            server, _state = _server_with_rrset(
                aaaa_addrs=[
                    "2606:ce40:70:3bb3::819",
                    "2606:ce40:70:3bb3:ae1f:6bff:feb4:194b",
                ],
                v4_addrs=["192.168.1.102"],
            )
            for addr in (
                "2606:ce40:70:3bb3::819",
                "2606:ce40:70:3bb3:ae1f:6bff:feb4:194b",
            ):
                echo = _response_with([_aaaa("tnnew26.local", addr)])
                server._check_established_conflicts(
                    echo, 3, source=(addr, 5353),
                )
            assert server._conflict_tasks == []

        _run(drive())

    def test_echo_of_entire_rrset_in_one_packet_is_not_a_conflict(
        self,
    ):
        """The ``IP_MULTICAST_LOOP`` echo typically delivers the
        whole announcement back in a single packet — all AAAA and
        the A record together.  None should trigger a reprobe."""
        async def drive() -> None:
            server, _state = _server_with_rrset(
                aaaa_addrs=[
                    "2606:ce40:70:3bb3::819",
                    "2606:ce40:70:3bb3:ae1f:6bff:feb4:194b",
                ],
                v4_addrs=["192.168.1.102"],
            )
            echo = _response_with([
                _a("tnnew26.local", "192.168.1.102"),
                _aaaa("tnnew26.local", "2606:ce40:70:3bb3::819"),
                _aaaa(
                    "tnnew26.local",
                    "2606:ce40:70:3bb3:ae1f:6bff:feb4:194b",
                ),
            ])
            server._check_established_conflicts(
                echo, 3, source=("192.168.1.102", 5353),
            )
            assert server._conflict_tasks == []

        _run(drive())

    def test_foreign_aaaa_is_still_flagged(self):
        """Positive control: a peer with a truly different AAAA
        address for our name must still trigger a conflict."""
        async def drive() -> None:
            server, _state = _server_with_rrset(
                aaaa_addrs=["2606:ce40:70:3bb3::819"],
            )
            foreign = _response_with([
                _aaaa("tnnew26.local", "2001:db8::1"),
            ])
            server._check_established_conflicts(
                foreign, 3, source=("2001:db8::1", 5353),
            )
            assert len(server._conflict_tasks) == 1

        _run(drive())


class TestSelfEchoMultipleA:
    """Same guard on the IPv4 side — a host with two IPv4 addresses
    on one interface owns two A records for the same hostname."""

    def test_echo_of_each_a_is_not_a_conflict(self):
        async def drive() -> None:
            server, _state = _server_with_rrset(
                aaaa_addrs=[],
                v4_addrs=["192.168.1.102", "10.0.0.5"],
            )
            for addr in ("192.168.1.102", "10.0.0.5"):
                echo = _response_with([_a("tnnew26.local", addr)])
                server._check_established_conflicts(
                    echo, 3, source=(addr, 5353),
                )
            assert server._conflict_tasks == []

        _run(drive())
