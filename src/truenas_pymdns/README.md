# truenas_pymdns

Pure-Python mDNS/DNS-SD implementation for TrueNAS. This package is a
**library** — the server is launched via the unified
`truenas-discoveryd` daemon (see the top-level `README.md`), not
independently.

## Protocol Specifications

| Spec | Title | What we use it for |
|------|-------|--------------------|
| [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) | Multicast DNS | Core protocol: packet format, probing, announcing, conflict resolution, cache flush, goodbye, TTL=255 validation, known-answer suppression, response timing/jitter |
| [RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763) | DNS-Based Service Discovery | Service naming (`Instance.Service.Domain`), PTR/SRV/TXT record relationships, `_services._dns-sd._udp` meta-query, subtype browsing (`_sub`), TXT key=value format, additional record generation |
| [RFC 6760](https://datatracker.ietf.org/doc/html/rfc6760) | Requirements for a Protocol to Replace AppleTalk NBP | Requirements that mDNS/DNS-SD fulfills: zeroconf operation, UTF-8 names, conflict detection, late binding, network browsing |
| [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) | Domain Names - Implementation and Specification | Wire format: message header, name encoding with label compression, resource record layout |
| [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782) | DNS SRV Records | SRV rdata format: priority, weight, port, target (no name compression per RFC 6762 s18.14) |
| [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596) | DNS Extensions to Support IPv6 | AAAA record type (28) for IPv6 addresses |

## Code References

The following open-source projects were used as implementation references:

| Project | License | What we referenced |
|---------|---------|-------------------|
| [avahi/avahi](https://github.com/avahi/avahi) tag [`v0.8`](https://github.com/avahi/avahi/releases/tag/v0.8) (`avahi-core/`) | LGPL-2.1 | Goodbye packet sending (`avahi_goodbye_entry` at `announce.c:512`), response scheduler force-flush (`avahi_response_scheduler_force` at `response-sched.c:505`), cache-flush semantics, probing/announcing state machines, conflict resolution logic |
| [Apple mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder) tag [`mDNSResponder-2881.0.25`](https://github.com/apple-oss-distributions/mDNSResponder/releases/tag/mDNSResponder-2881.0.25) (`mDNSCore/`, `mDNSPosix/`) | Apache-2.0 | Timing constant tuning (`mDNS.c`: goodbye count, host record TTL, `MAX_PROBE_RESTARTS`), simultaneous-probe tiebreak + 1 s defer (`ResolveSimultaneousProbe` at `mDNS.c:8053`), stale-packet tolerance (`kMaxAllowedMCastProbingConflicts` at `mDNS.c:929`), §9 same-name re-probe on established conflict (`mDNSCoreReceiveResponse` at `mDNS.c:10315`), shared-record goodbye on conflict rename (`mDNS_Deregister_internal` at `mDNS.c:2230`), unique-without-probing for reverse address mapping PTRs and their discard-on-conflict (`kDNSRecordTypeKnownUnique` in `AdvertiseInterface` and `mDNSCoreReceiveResponse`), netlink link-state monitor + flap-delay/reduced-announce semantics (`OpenIfNotifySocket` at `mDNSPosix/mDNSPosix.c:1620`, `mDNS_RegisterInterface` at `mDNS.c:14174` and `mDNS.c:14262`) |

## Subpackages

- [protocol/](protocol/README.md) — wire protocol: packet parsing/building, record dataclasses, traffic flow diagrams
- [server/](server/README.md) — server module: config, probing, announcing, response scheduling. Hosted inside `truenas-discoveryd`.
- [client/](client/README.md) — standalone CLI tools (`mdns-browse`, `mdns-resolve`, `mdns-lookup`)
