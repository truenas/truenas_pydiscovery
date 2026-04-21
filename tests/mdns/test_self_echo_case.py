"""Self-echo via IP_MULTICAST_LOOP must not trigger false conflicts.

Reproduces the deployed bug: a host whose hostname preserves
uppercase (e.g. ``TNNEW26``) registers ``TNNEW26.local A ...`` and
``<reverse>.in-addr.arpa PTR TNNEW26.local`` — both with
cache-flush.  On announcement, DNS name compression has the PTR
rdata point back at the A record's name bytes, which
``MDNSRecordKey`` stored lowercased, so the compressed pointer
resolves to ``tnnew26.local`` on the receiver side.  When the
multicast echoes back via ``IP_MULTICAST_LOOP=1`` and
``_check_established_conflicts`` compares wire bytes, the stored
``TNNEW26.local`` target and parsed ``tnnew26.local`` disagree at
the byte level — a false conflict.

RFC 6762 §16 is explicit: domain names MUST be compared
case-insensitively.  Using ``RecordData.__eq__`` (which folds via
``_identity``) suppresses the false positive while still catching
real rdata differences.
"""
from __future__ import annotations

from ipaddress import IPv4Address

from truenas_pymdns.protocol.constants import QType
from truenas_pymdns.protocol.message import MDNSMessage
from truenas_pymdns.protocol.records import (
    ARecordData,
    MDNSRecord,
    MDNSRecordKey,
    PTRRecordData,
    SRVRecordData,
    TXTRecordData,
)
from truenas_pymdns.server.core.entry_group import EntryGroup


def _build_self_announcement_wire(hostname: str, addr: str) -> bytes:
    """Build the wire-form announcement a host sends for itself — A
    plus reverse PTR — using the real ``EntryGroup.add_address``
    path so name compression is applied exactly as the daemon
    would on the wire."""
    group = EntryGroup()
    group.add_address(hostname, addr)
    msg = MDNSMessage.build_response(group.records)
    return msg.to_wire()


class TestSelfEchoPTRCompression:
    def test_ptr_rdata_case_folds_on_roundtrip(self):
        """Wire round-trip preserves PTR target only up to case — the
        parsed target's bytes may differ from our stored bytes once
        compression aliases the A record's lowercased name."""
        wire = _build_self_announcement_wire("TNNEW26.local", "192.168.1.102")
        parsed = MDNSMessage.from_wire(wire)

        # Find the PTR record.
        ptr_parsed = next(
            rr for rr in parsed.answers
            if rr.key.rtype == QType.PTR
        )
        # Build our in-memory stored record.
        stored_ptr = MDNSRecord(
            key=MDNSRecordKey(
                IPv4Address("192.168.1.102").reverse_pointer, QType.PTR,
            ),
            ttl=120,
            data=PTRRecordData("TNNEW26.local"),
            cache_flush=True,
        )

        # Wire bytes differ (case).
        assert stored_ptr.rdata_wire() != ptr_parsed.rdata_wire(), (
            "this test only makes sense if the bytes differ — if "
            "they start matching, the compression behaviour has "
            "changed and the regression guard below is no longer "
            "exercising the originally broken path."
        )
        # But the data objects compare equal per RFC 6762 §16.
        assert stored_ptr.data == ptr_parsed.data, (
            "PTR data must compare case-insensitively — the fix is "
            "to use ``.data ==`` instead of ``rdata_wire() ==``"
        )


class TestSelfEchoARecord:
    """A record rdata is the packed IP address — no case concern,
    equality works trivially.  Test here just to confirm the
    ``data ==`` path handles it."""

    def test_a_record_matches_on_selfecho(self):
        stored = MDNSRecord(
            key=MDNSRecordKey("TNNEW26.local", QType.A),
            ttl=120,
            data=ARecordData(IPv4Address("192.168.1.102")),
            cache_flush=True,
        )
        other = MDNSRecord(
            key=MDNSRecordKey("tnnew26.local", QType.A),
            ttl=120,
            data=ARecordData(IPv4Address("192.168.1.102")),
            cache_flush=True,
        )
        assert stored.data == other.data


class TestSelfEchoSRV:
    """SRV rdata target is a domain name — same case-folded equality
    rule as PTR."""

    def test_srv_target_case_roundtrip_equal(self):
        stored = SRVRecordData(0, 0, 443, "TNNEW26.local")
        parsed_back_lowercase = SRVRecordData(0, 0, 443, "tnnew26.local")
        assert stored == parsed_back_lowercase


class TestSelfEchoEmptyTXT:
    """Empty TXT records serialise to a single ``\\x00`` byte and
    ``from_wire`` parses that back as ``(b"",)``.  Without
    canonicalisation in ``__post_init__``, a registered
    ``TXTRecordData(entries=())`` would not compare equal to its
    own wire round-trip and every self-echo of a service without
    TXT entries would trip the conflict detector."""

    def test_empty_entries_round_trip_equal(self):
        stored = TXTRecordData(entries=())
        wire_parsed = TXTRecordData.from_wire(stored.to_wire())
        assert stored == wire_parsed
        assert stored.entries == wire_parsed.entries == (b"",)

    def test_empty_record_wire_form_unchanged(self):
        """Canonicalisation must not change the wire bytes we emit
        (RFC 6763 §6: single zero-length string)."""
        assert TXTRecordData(entries=()).to_wire() == b"\x00"
        assert TXTRecordData(entries=(b"",)).to_wire() == b"\x00"
