"""Atomic service registration with entry group state machine."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Callable

from truenas_pymdns.protocol.constants import (
    DEFAULT_TTL_HOST_RECORD,
    DEFAULT_TTL_OTHER_RECORD,
    EntryGroupState,
    QType,
)
from truenas_pymdns.protocol.records import (
    ARecordData,
    AAAARecordData,
    MDNSRecord,
    PTRRecordData,
    MDNSRecordKey,
    SRVRecordData,
    TXTRecordData,
)


@dataclass(slots=True)
class OwnedRecord:
    """Server-side wrapper around an authoritative MDNSRecord.

    Carries mutable per-record scheduling state — the RFC 6762 s6
    multicast rate-limit timestamp and the s7.4 peer-answer
    suppression timestamp — so those values track the record's
    lifecycle naturally instead of living in a side dict keyed by
    name|rtype.

    Analogous to mDNSResponder's AuthRecord.LastMCTime /
    LastMCInterface fields (mDNSCore/mDNS.c).
    """
    record: MDNSRecord
    last_multicast: float = 0.0
    last_peer_answer: float = 0.0


class EntryGroup:
    """Atomic set of DNS records to register on the network.

    State machine: UNCOMMITTED -> REGISTERING -> ESTABLISHED | COLLISION
    """

    def __init__(
        self,
        on_state_change: Callable[[EntryGroupState], None] | None = None,
    ):
        self.state = EntryGroupState.UNCOMMITTED
        self._records: list[OwnedRecord] = []
        self._on_state_change = on_state_change
        self.interfaces: list[int] | None = None  # None = all interfaces

    @property
    def records(self) -> list[MDNSRecord]:
        """Return a copy of all records (unwrapped to wire form)."""
        return [ow.record for ow in self._records]

    @property
    def owned_records(self) -> list[OwnedRecord]:
        """Return a copy of the OwnedRecord wrappers (for registry lookup)."""
        return list(self._records)

    def add_record(self, record: MDNSRecord) -> None:
        """Append a record to this group; only allowed in UNCOMMITTED state."""
        if self.state != EntryGroupState.UNCOMMITTED:
            raise RuntimeError("Cannot add records after commit")
        self._records.append(OwnedRecord(record))

    def add_service(
        self,
        instance: str,
        service_type: str,
        domain: str,
        host: str,
        port: int,
        txt: dict[str, str] | None = None,
        priority: int = 0,
        weight: int = 0,
        subtypes: list[str] | None = None,
    ) -> None:
        """Add a complete DNS-SD service (RFC 6763 s4).

        Creates: meta-PTR, service PTR, SRV, TXT, and optional
        subtype PTR records (RFC 6763 s7.1).
        """
        fqdn = f"{instance}.{service_type}.{domain}"
        svc_name = f"{service_type}.{domain}"

        # RFC 6763 s9: service type enumeration meta-PTR
        # _services._dns-sd._udp.<domain> -> _type._proto.<domain>
        meta_name = f"_services._dns-sd._udp.{domain}"
        self.add_record(MDNSRecord(
            key=MDNSRecordKey(meta_name, QType.PTR),
            ttl=DEFAULT_TTL_OTHER_RECORD,
            data=PTRRecordData(svc_name),
        ))

        # RFC 6763 s4.1: service PTR
        # _type._proto.<domain> -> <instance>._type._proto.<domain>
        self.add_record(MDNSRecord(
            key=MDNSRecordKey(svc_name, QType.PTR),
            ttl=DEFAULT_TTL_OTHER_RECORD,
            data=PTRRecordData(fqdn),
        ))

        # RFC 2782: SRV record
        # <instance>._type._proto.<domain> -> host:port
        self.add_record(MDNSRecord(
            key=MDNSRecordKey(fqdn, QType.SRV),
            ttl=DEFAULT_TTL_HOST_RECORD,
            data=SRVRecordData(priority, weight, port, host),
            cache_flush=True,
        ))

        # RFC 6763 s6: TXT record (MUST exist, even if empty)
        txt_data = (TXTRecordData.from_dict(txt)
                    if txt else TXTRecordData(entries=()))
        self.add_record(MDNSRecord(
            key=MDNSRecordKey(fqdn, QType.TXT),
            ttl=DEFAULT_TTL_OTHER_RECORD,
            data=txt_data,
            cache_flush=True,
        ))

        # RFC 6763 s7.1: subtype PTR records
        # _subtype._sub._type._proto.<domain> -> <instance>._type._proto.<domain>
        for subtype in (subtypes or []):
            sub_name = f"{subtype}._sub.{svc_name}"
            self.add_record(MDNSRecord(
                key=MDNSRecordKey(sub_name, QType.PTR),
                ttl=DEFAULT_TTL_OTHER_RECORD,
                data=PTRRecordData(fqdn),
            ))

    def add_address(self, hostname: str, address: str) -> None:
        """Add an A or AAAA record for a hostname plus reverse PTR."""
        addr = ip_address(address)
        if isinstance(addr, IPv4Address):
            self.add_record(MDNSRecord(
                key=MDNSRecordKey(hostname, QType.A),
                ttl=DEFAULT_TTL_HOST_RECORD,
                data=ARecordData(addr),
                cache_flush=True,
            ))
            # Reverse PTR
            rev = addr.reverse_pointer
            self.add_record(MDNSRecord(
                key=MDNSRecordKey(rev, QType.PTR),
                ttl=DEFAULT_TTL_HOST_RECORD,
                data=PTRRecordData(hostname),
                cache_flush=True,
            ))
        elif isinstance(addr, IPv6Address):
            self.add_record(MDNSRecord(
                key=MDNSRecordKey(hostname, QType.AAAA),
                ttl=DEFAULT_TTL_HOST_RECORD,
                data=AAAARecordData(addr),
                cache_flush=True,
            ))
            rev = addr.reverse_pointer
            self.add_record(MDNSRecord(
                key=MDNSRecordKey(rev, QType.PTR),
                ttl=DEFAULT_TTL_HOST_RECORD,
                data=PTRRecordData(hostname),
                cache_flush=True,
            ))

    def set_state(self, state: EntryGroupState) -> None:
        """Transition to a new state and invoke the state-change callback."""
        if self.state != state:
            self.state = state
            if self._on_state_change:
                self._on_state_change(state)

    def get_unique_records(self) -> list[MDNSRecord]:
        """Return records that should be probed (unique records)."""
        return [ow.record for ow in self._records if ow.record.cache_flush]
