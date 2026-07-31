"""Atomic service registration with entry group state machine."""
from __future__ import annotations

from dataclasses import dataclass, field
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

    ``last_multicast`` / ``last_peer_answer`` map an interface index to
    the monotonic time this record was last multicast / last seen
    answered by a peer ON THAT INTERFACE.  Both the §6 1-second
    multicast rate limit and §7.4 duplicate-answer suppression are
    per-interface (§6: "... on that particular interface"); one
    ServiceRegistry shares these OwnedRecord objects across every
    per-interface Responder, so the timestamps MUST be keyed by
    interface or one link's traffic would rate-limit or suppress
    another's.

    Analogous to mDNSResponder's AuthRecord.LastMCTime /
    LastMCInterface pair (``ProcessQuery`` in mDNSCore/mDNS.c).

    ``should_probe`` separates "unique" from "unique and claimed by
    probing".  A record can carry the cache-flush bit — asserting it
    owns its whole RRSet — without the responder needing to verify
    that ownership first, when the name cannot collide by
    construction.  RFC 6762 §8.1: "If a responder knows by other
    means that its unique resource record set name, rrtype, and
    rrclass cannot already be in use by any other responder on the
    network, then it SHOULD skip the probing step for that resource
    record set."

    Both reference implementations model the same split — Apple as
    ``kDNSRecordTypeKnownUnique`` ("mDNS can assume name is unique
    without checking", which ``DefaultProbeCountForRecordType`` turns
    into zero probes), avahi as ``AVAHI_PUBLISH_NO_PROBE`` ("though
    the RRset is intended to be unique no probes shall be sent").
    Only Apple applies it to the reverse address PTR
    (``AdvertiseInterface``); avahi probes its reverse PTRs and
    reserves the flag for its localhost entries, so the precedent
    followed here is RFC 6762 §8.1 plus Apple.
    """
    record: MDNSRecord
    last_multicast: dict[int, float] = field(default_factory=dict)
    last_peer_answer: dict[int, float] = field(default_factory=dict)
    should_probe: bool = True


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

    def add_record(
        self, record: MDNSRecord, should_probe: bool = True,
    ) -> None:
        """Append a record to this group; only allowed in UNCOMMITTED state.

        *should_probe* is False for a unique record whose name cannot
        collide by construction — see ``OwnedRecord.should_probe``.
        """
        if self.state != EntryGroupState.UNCOMMITTED:
            raise RuntimeError("Cannot add records after commit")
        self._records.append(
            OwnedRecord(record, should_probe=should_probe),
        )

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
        """Add an A or AAAA record for a hostname plus reverse PTR.

        The address record is probed; the reverse PTR is not.  RFC 6762
        §8.1 names this exact case as the example of a record set to
        skip probing for: "when creating the reverse address mapping
        PTR records, the host can reasonably assume that no other host
        will be trying to create those same PTR records, since that
        would imply that the two hosts were trying to use the same IP
        address, and if that were the case, the two hosts would be
        suffering communication problems beyond the scope of what
        Multicast DNS is designed to solve."

        Probing it is not merely wasteful, it cannot converge.  The
        PTR's name is derived from the address, so renaming the host
        rewrites the record's rdata but never its name — two responders
        sharing an address would conflict, rename, and conflict again
        forever.  Apple registers this record as
        ``kDNSRecordTypeKnownUnique`` in ``AdvertiseInterface`` for the
        same reason, and gives it no conflict callback at all.
        """
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
            ), should_probe=False)
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
            ), should_probe=False)

    def remove_record(self, ow: OwnedRecord) -> bool:
        """Withdraw *ow* from this group; True if it was a member.

        Matched by object identity, not equality: ``OwnedRecord`` is a
        dataclass whose generated ``==`` is field-wise, so an
        equal-valued wrapper in another group must not be mistaken for
        this one.  Used for conflict withdrawal of an established
        record (RFC 6762 §9), so unlike ``add_record`` it carries no
        state restriction.
        """
        for i, cand in enumerate(self._records):
            if cand is ow:
                del self._records[i]
                return True
        return False

    def set_state(self, state: EntryGroupState) -> None:
        """Transition to a new state and invoke the state-change callback."""
        if self.state != state:
            self.state = state
            if self._on_state_change:
                self._on_state_change(state)

    def get_unique_records(self) -> list[MDNSRecord]:
        """Return the records to probe for.

        Unique (cache-flush) records, minus those whose uniqueness is
        known a priori and so skip probing per RFC 6762 §8.1 — see
        ``OwnedRecord.should_probe``.  They are still announced with
        the cache-flush bit; only the ownership claim is skipped.
        """
        return [
            ow.record for ow in self._records
            if ow.record.cache_flush and ow.should_probe
        ]
