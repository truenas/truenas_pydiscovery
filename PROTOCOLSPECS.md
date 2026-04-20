# Protocol Specifications

Normative references for the three protocols implemented by
`truenas-pydiscoveryd`. Each entry links to the canonical public
specification; where the repo carries a local archival copy under
`docs/specs/`, the filename is noted in the **Local copy** column.

Per-protocol usage notes (which clauses of each spec we actually
implement) live in the per-package READMEs:
[`src/truenas_pymdns/README.md`](src/truenas_pymdns/README.md),
[`src/truenas_pynetbiosns/README.md`](src/truenas_pynetbiosns/README.md),
[`src/truenas_pywsd/README.md`](src/truenas_pywsd/README.md).

## mDNS / DNS-SD (`truenas_pymdns`)

| Spec | Title | Publisher | Local copy |
|------|-------|-----------|------------|
| [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762) | Multicast DNS | IETF | [`docs/specs/rfc6762.txt`](docs/specs/rfc6762.txt) |
| [RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763) | DNS-Based Service Discovery | IETF | [`docs/specs/rfc6763.txt`](docs/specs/rfc6763.txt) |
| [RFC 6760](https://datatracker.ietf.org/doc/html/rfc6760) | Requirements for a Protocol to Replace AppleTalk NBP | IETF | — |
| [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) | Domain Names — Implementation and Specification | IETF | — |
| [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782) | DNS SRV Records | IETF | — |
| [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596) | DNS Extensions to Support IPv6 (AAAA) | IETF | — |

## NetBIOS Name Service + Browser (`truenas_pynetbiosns`)

| Spec | Title | Publisher | Local copy |
|------|-------|-----------|------------|
| [RFC 1001](https://datatracker.ietf.org/doc/html/rfc1001) | NetBIOS Service on TCP/UDP: Concepts and Methods | IETF | [`docs/specs/rfc1001.txt`](docs/specs/rfc1001.txt) |
| [RFC 1002](https://datatracker.ietf.org/doc/html/rfc1002) | NetBIOS Service on TCP/UDP: Detailed Specifications | IETF | [`docs/specs/rfc1002.txt`](docs/specs/rfc1002.txt) |
| [MS-BRWS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/) | Common Internet File System (CIFS) Browser Protocol | Microsoft | [`docs/specs/ms-brws.pdf`](docs/specs/ms-brws.pdf) |

## Web Services Discovery (`truenas_pywsd`)

| Spec | Title | Publisher | Local copy |
|------|-------|-----------|------------|
| [WS-Discovery 1.1](http://docs.oasis-open.org/ws-dd/discovery/1.1/os/wsdd-discovery-1.1-spec-os.html) | Web Services Dynamic Discovery | OASIS | [`docs/specs/wsdd-discovery-1.1-spec-os.pdf`](docs/specs/wsdd-discovery-1.1-spec-os.pdf) |
| [SOAP-over-UDP 1.1](http://docs.oasis-open.org/ws-dd/soapoverudp/1.1/os/wsdd-soapoverudp-1.1-spec-os.html) | SOAP-over-UDP | OASIS | [`docs/specs/wsdd-soapoverudp-1.1-spec-os.pdf`](docs/specs/wsdd-soapoverudp-1.1-spec-os.pdf) |
| [DPWS 1.1](http://docs.oasis-open.org/ws-dd/dpws/1.1/os/wsdd-dpws-1.1-spec-os.html) | Devices Profile for Web Services | OASIS | [`docs/specs/wsdd-dpws-1.1-spec-os.pdf`](docs/specs/wsdd-dpws-1.1-spec-os.pdf) |
| [WS-Addressing 1.0 — Core](https://www.w3.org/TR/2006/REC-ws-addr-core-20060509/) | Web Services Addressing (Core) | W3C | [`docs/specs/ws-addr-core.html`](docs/specs/ws-addr-core.html) |
| [WS-Addressing 1.0 — SOAP Binding](https://www.w3.org/TR/2006/REC-ws-addr-soap-20060509/) | Web Services Addressing (SOAP Binding) | W3C | [`docs/specs/ws-addr-soap.html`](docs/specs/ws-addr-soap.html) |
| [WS-MetadataExchange](http://specs.xmlsoap.org/ws/2004/09/mex/WS-MetadataExchange.pdf) | Web Services Metadata Exchange | xmlsoap.org | — |
| [MS-PBSD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pbsd/) | Publication Services Data Structure (defines `pub:Computer`) | Microsoft | [`docs/specs/ms-pbsd.pdf`](docs/specs/ms-pbsd.pdf) |
| [MS-DPWSSN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dpwssn/) | Devices Profile for Web Services (DPWS): Size Negotiation Extension | Microsoft | [`docs/specs/ms-dpwssn.pdf`](docs/specs/ms-dpwssn.pdf) |
| [WSDAPI Compliance (index)](https://learn.microsoft.com/en-us/windows/win32/wsdapi/wsdapi-specification-compliance) | Microsoft WSDAPI Specification Compliance | Microsoft | — |
| [WSDAPI: WS-Discovery Compliance](https://learn.microsoft.com/en-us/windows/win32/wsdapi/ws-discovery-specification-compliance) | Microsoft WSDAPI: per-clause MUST/SHOULD/MAY profile for WS-Discovery 1.1 | Microsoft | — |
| [WSDAPI: DPWS Compliance](https://learn.microsoft.com/en-us/windows/win32/wsdapi/dpws-specification-compliance) | Microsoft WSDAPI: per-clause MUST/SHOULD/MAY profile for DPWS 1.1 | Microsoft | — |

---

## Related / Non-Normative References

Documents cited indirectly or useful for context.  These are not the
primary specs we implement against, but they define data formats,
registries, or transport layers that our normative references build
on.  Listed here so future reviewers don't have to rediscover them.

### mDNS / DNS-SD

| Spec | Title | Publisher | Notes |
|------|-------|-----------|-------|
| [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034) | Domain Names — Concepts and Facilities | IETF | Paired with RFC 1035; defines the DNS data model mDNS records inherit (class, type, TTL semantics). |
| [RFC 6335](https://datatracker.ietf.org/doc/html/rfc6335) | IANA Procedures for the Service Name and Port Number Registry | IETF | Governs the consolidated registry where DNS-SD service-type labels (`_smb._tcp`, etc.) are registered alongside port numbers. |
| [RFC 8553](https://datatracker.ietf.org/doc/html/rfc8553) | DNS AttrLeaf Changes | IETF | Establishes an IANA registry for underscore-prefixed DNS labels (e.g. `_smb`, `_tcp`, `_sub`) that DNS-SD relies on. |
| [RFC 8766](https://datatracker.ietf.org/doc/html/rfc8766) | Discovery Proxy for Multicast DNS-Based Service Discovery | IETF | Bridges mDNS into wide-area DNS so off-link clients can browse local services.  Not implemented — link kept for future scope. |
| [RFC 9665](https://datatracker.ietf.org/doc/html/rfc9665) | Service Registration Protocol (SRP) for DNS-Based Service Discovery | IETF | DNS-SD extension for authenticated unicast registrations (replaces draft-ietf-dnssd-srp).  Not implemented. |
| [IANA Service Name & Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) | Service Name + DNS-SD Types + Port Numbers | IANA | Canonical registry for service-type labels like `_smb._tcp`; merged from Stuart Cheshire's private list per RFC 6335. |
| [dns-sd.org](http://www.dns-sd.org/ServiceTypes.html) | Community Service Types List | Stuart Cheshire | Larger de-facto registry maintained alongside IANA; referenced by Apple and Avahi. |
| [Apple Bonjour Conformance Test](https://developer.apple.com/bonjour/) | Conformance Test Overview | Apple | Informative — the de-facto test suite Apple runs against third-party mDNS stacks. |

### NetBIOS Name Service + Browser

| Spec | Title | Publisher | Notes |
|------|-------|-----------|-------|
| [MS-NBTE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbte/) | NetBIOS over TCP (NBT) Extensions | Microsoft | Microsoft's clarifications and extensions to RFC 1001/1002; consult when Windows peers interoperate oddly.  Contains the canonical table of 16th-byte name-type suffixes (0x00, 0x03, 0x20, etc.) that our `NameType` enum encodes. |
| [MS-CIFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/) | Common Internet File System (CIFS) Protocol | Microsoft | Transport for the browser protocol; context for MS-BRWS. |
| [MS-WPO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wpo/) | Windows Protocols Overview | Microsoft | Top-level navigator for all MS-* protocols; useful cross-reference index. |

### Web Services Discovery

| Spec | Title | Publisher | Notes |
|------|-------|-----------|-------|
| [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122) | UUID URN Namespace | IETF | Format for the `urn:uuid:…` values we use in MessageID, RelatesTo, and EndpointReference. |
| [SOAP 1.2 Part 1](https://www.w3.org/TR/soap12-part1/) | SOAP Messaging Framework | W3C | Envelope/Header/Body structure our `build_envelope` produces. |
| [SOAP 1.2 Part 2](https://www.w3.org/TR/soap12-part2/) | SOAP Adjuncts | W3C | Fault codes and encoding rules. |
| [XML 1.0 (5th Edition)](https://www.w3.org/TR/xml/) | Extensible Markup Language | W3C | Base syntax for all our SOAP/WSD messages. |
| [Namespaces in XML 1.0](https://www.w3.org/TR/xml-names/) | XML Namespaces | W3C | Namespace resolution used throughout the protocol constants. |
| [WS-Transfer (2006)](https://www.w3.org/Submission/WS-Transfer/) | WS-Transfer | W3C Submission | The Get/Put actions WS-MetadataExchange builds on; our HTTP metadata route uses the WS-Transfer `Get` action. |
| [RFC 9110](https://datatracker.ietf.org/doc/html/rfc9110) + [RFC 9112](https://datatracker.ietf.org/doc/html/rfc9112) | HTTP Semantics / HTTP/1.1 | IETF | Transport for the metadata endpoint on port 5357. |
| [IANA Service Name & Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) | Registered service names/ports | IANA | Port 3702 (`ws-discovery`) and 5357 (`wsdapi`) are registered there. |

---

## Conformance Testing

Only one of the three protocols we implement has a published
conformance test suite.  This is a useful context when reviewing
test strategy: for NetBIOS-NS and WSD the project's own unit +
integration tests plus cross-validation against the listed
reference implementations are the bar, because nothing higher
exists publicly.

| Protocol | Official conformance test | Notes / de-facto reference |
|----------|---------------------------|----------------------------|
| mDNS / DNS-SD | **[Bonjour Conformance Test](https://developer.apple.com/bonjour/) (Apple)** — downloadable harness + guideline PDF on the Apple Developer site. | Checks wire-format, probing, conflict handling, and §10 goodbye against Apple's reference behaviour.  Not an IETF document but the accepted bar for mDNS interoperability. |
| NetBIOS-NS | **None.** Neither IETF (RFC 1001/1002) nor Microsoft (MS-BRWS, MS-NBTE, MS-CIFS) publishes a test suite.  Microsoft's [Windows Protocol Test Suites](https://github.com/microsoft/WindowsProtocolTestSuites) repo covers SMB2 / DFS / Kerberos / RDP but **does not include NetBIOS**. | De-facto reference: Samba's `source4/torture/nbt/` (register.c, query.c, wins.c, dgram.c) — self-tests of the Samba NBT stack.  The `truenas_pynetbiosns` README cites the specific test files we mirror. |
| WSD | **None.**  OASIS's WS-DD Technical Committee (WS-Discovery 1.1, DPWS 1.1, SOAP-over-UDP 1.1) never published a conformance harness and was closed in 2016. | Closest equivalent: Microsoft's [WSDAPI Specification Compliance](https://learn.microsoft.com/en-us/windows/win32/wsdapi/wsdapi-specification-compliance) — a written MUST/SHOULD/MAY profile (already cited in the normative section).  Interop with Windows Explorer's Network view is the practical acceptance bar. |

---

## Reference Implementations

For behaviours that are under-specified by the RFCs (probe-conflict
backoff, flap handling, stale-packet tolerance, etc.) we pin a
specific version of each reference implementation so that citations
in code comments stay stable.  Upgrade paths: bump the tag here,
re-check the cited lines, update comment references in the same
commit.

| Protocol | Reference | Pinned version | Notes |
|----------|-----------|----------------|-------|
| mDNS / DNS-SD | [apple-oss-distributions/mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder) | [`mDNSResponder-2881.0.25`](https://github.com/apple-oss-distributions/mDNSResponder/releases/tag/mDNSResponder-2881.0.25) | Line numbers cited in our code comments (`mDNSCore/mDNS.c:*`, `mDNSPosix/mDNSPosix.c:*`) are against this tag.  Re-verify if bumped. |
| mDNS / DNS-SD | [avahi/avahi](https://github.com/avahi/avahi) | master (no stable tag pinned) | avahi has not cut a release since 0.8 (2020); we cross-reference `avahi-core/probe-sched.c`, `response-sched.c`, `announce.c`. |
| NetBIOS-NS | [samba-team/samba](https://gitlab.com/samba-team/samba) `source4/torture/nbt/` | master | NBT self-tests (`register.c`, `query.c`, `wins.c`, `dgram.c`) used as behavioural reference — we match their expected packet shapes. |
| WSD | *(none pinned)* | — | OASIS did not publish a reference; we rely on the normative specs + Microsoft's WSDAPI compliance page. |
