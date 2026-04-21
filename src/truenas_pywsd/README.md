# truenas_pywsd

Pure-Python Web Services Discovery (WSD) implementation for TrueNAS.
This package is a **library** — the server is launched via the unified
`truenas-discoveryd` daemon (see the top-level `README.md`), not
independently.

## Protocol Specifications

| Spec | Title | What we use it for |
|------|-------|--------------------|
| [WS-Discovery 1.1](http://docs.oasis-open.org/ws-dd/discovery/1.1/os/wsdd-discovery-1.1-spec-os.html) | Web Services Dynamic Discovery (OASIS) | Core protocol: Hello, Bye, Probe, ProbeMatch, Resolve, ResolveMatch, SOAP-over-UDP multicast, message retransmission rules |
| [SOAP-over-UDP 1.1](http://docs.oasis-open.org/ws-dd/soapoverudp/1.1/os/wsdd-soapoverudp-1.1-spec-os.html) | SOAP-over-UDP (OASIS) | Multicast/unicast message delivery, retransmission with exponential backoff, duplicate detection via MessageID |
| [WS-Addressing 1.0](https://www.w3.org/TR/2006/REC-ws-addr-core-20060509/) | Web Services Addressing (W3C) | SOAP header: To, Action, MessageID, RelatesTo, EndpointReference |
| [WS-MetadataExchange](http://specs.xmlsoap.org/ws/2004/09/mex/WS-MetadataExchange.pdf) | Web Services Metadata Exchange | HTTP Get/GetResponse for device metadata retrieval on port 5357 |
| [WSDP](http://specs.xmlsoap.org/ws/2006/02/devprof/devicesprofile.pdf) | Devices Profile for Web Services | Device types (wsdp:Device), ThisDevice/ThisModel metadata, host relationship |
| [MS-PBSD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pbsd/) | Pub/Sub Device Protocol | `pub:Computer` type, hostname/workgroup/domain advertisement format |
| [WSDAPI Compliance](https://learn.microsoft.com/en-us/windows/win32/wsdapi/wsdapi-specification-compliance) | Microsoft WSDAPI Specification Compliance | DPWS compliance requirements, AppSequence validation rules, Hello message format, scope matching rules |

## Code References

The following open-source projects were used as implementation references:

| Project | License | What we referenced |
|---------|---------|-------------------|
| [christgau/wsdd](https://github.com/christgau/wsdd) | MIT | Primary reference: overall architecture, SOAP envelope structure, Hello/Bye/Probe/ProbeMatch message format, HTTP metadata exchange, AppSequence handling, multicast socket setup, `pub:Computer` field format, IP_MULTICAST_ALL Linux tuning |
| [gershnik/wsdd-native](https://github.com/gershnik/wsdd-native) | BSD-3-Clause | AppSequence with SequenceId, metadata template approach, ProbeMatch/ResolveMatch response format |
| [KoynovStas/wsdd](https://github.com/KoynovStas/wsdd) | GPL-2.0 | C implementation: multicast TTL/loop settings, HTTP Content-Type handling |

## Subpackages

- [protocol/](protocol/README.md) — SOAP/XML message building and parsing with defusedxml
- [server/](server/README.md) — server module: config, discovery, metadata exchange. Hosted inside `truenas-discoveryd`.
- [client/](client/README.md) — CLI tools (`wsd-discover`, `wsd-info`)

## Limitations

- **Server mode only.** The daemon responds to Probes and serves metadata but does not actively discover other devices.
- **No Netlink interface monitoring.** Interface changes require SIGHUP reload.
