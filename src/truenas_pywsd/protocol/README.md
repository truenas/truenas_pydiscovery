# truenas_pywsd.protocol

SOAP/XML message building and parsing for WS-Discovery.

## Modules

- `constants.py` — ports (3702/5357), multicast addresses, XML namespace URIs, action URIs, timing constants, device types, metadata dialects
- `namespaces.py` — namespace prefix map, `qname()` helper for Clark notation, auto-registers prefixes with ElementTree
- `soap.py` — `build_envelope()` / `parse_envelope()` for SOAP 1.2 with WS-Addressing headers (To, Action, MessageID, RelatesTo, AppSequence). Uses `defusedxml` for all parsing.
- `messages.py` — high-level message builders: `build_hello`,
  `build_bye`, `build_probe_match`, `build_resolve_match`,
  `build_get_response` (all share a private
  `_append_endpoint_reference` helper that emits the WS-Addressing
  EPR subtree).  Parsers: `parse_probe_types`,
  `parse_probe_scopes`, `parse_resolve_endpoint`.  RFC 3986
  scope-matching helper `scope_matches` (WS-Discovery 1.1 §5.1) is
  also here.

## WSD Traffic Flow

Discovery uses SOAP 1.2 over UDP multicast on 239.255.255.250:3702 (IPv4) or
[ff02::c]:3702 (IPv6).  Metadata exchange uses HTTP POST on port 5357.
Multicast messages are repeated 4x with 50-250ms jitter (SOAP-over-UDP 1.1 s3).

### Daemon Startup — Hello (WS-Discovery s4.1)

When the daemon starts, it announces itself to the network:

```
  truenas                                         239.255.255.250:3702
       |                                               |
       |  HELLO (x4, 50-250ms jitter)                  |
       |  Action: .../discovery/Hello                  |
       |  EndpointReference: urn:uuid:{uuid}           |
       |  Types: wsdp:Device pub:Computer              |
       |  XAddrs: http://192.168.1.100:5357/{uuid}     |
       |  MetadataVersion: 1                           |
       |---------------------------------------------->|
```

### Device Discovery — Probe / ProbeMatch (WS-Discovery s5)

A Windows client searches for devices on the network:

```
  Windows client           truenas                  239.255.255.250:3702
       |                      |                          |
       |  PROBE (multicast)   |                          |
       |  Action: .../Probe   |                          |
       |  Types: wsdp:Device  |                          |
       |--------------------->|------------------------->|
       |                      |                          |
       |                      |  (0-500ms random delay)  |
       |                      |                          |
       |  PROBE MATCH (unicast, x2)                      |
       |  Action: .../ProbeMatches                       |
       |  RelatesTo: {probe msg id}                      |
       |  EndpointReference: urn:uuid:{uuid}             |
       |  Types: wsdp:Device pub:Computer                |
       |  XAddrs: http://...:5357/{uuid}                 |
       |  MetadataVersion: N                             |
       |<---------------------|                          |
```

### Directed Resolution — Resolve / ResolveMatch (WS-Discovery s6)

Client resolves a specific device to get its metadata endpoint:

```
  Windows client                              truenas
       |                                         |
       |  RESOLVE (multicast)                    |
       |  Action: .../Resolve                    |
       |  EndpointReference: urn:uuid:{uuid}     |
       |---------------------------------------->|
       |                                         |
       |  RESOLVE MATCH (unicast, x2)            |
       |  Action: .../ResolveMatches             |
       |  RelatesTo: {resolve msg id}            |
       |  EndpointReference: urn:uuid:{uuid}     |
       |  Types: wsdp:Device pub:Computer        |
       |  XAddrs: http://...:5357/{uuid}         |
       |  MetadataVersion: 1                     |
       |<----------------------------------------|
```

### Metadata Exchange — Get / GetResponse (WS-Transfer via HTTP)

Client retrieves device details for Network Neighborhood display:

```
  Windows client                                 truenas:5357
       |                                              |
       |  HTTP POST /xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxx  |
       |  Content-Type: application/soap+xml          |
       |  SOAP Body:                                  |
       |    Action: .../transfer/Get                  |
       |    To: urn:uuid:{uuid}                       |
       |--------------------------------------------->|
       |                                              |
       |  HTTP 200 OK                                 |
       |  Content-Type: application/soap+xml          |
       |  SOAP Body:                                  |
       |    Action: .../transfer/GetResponse          |
       |    Metadata:                                 |
       |      ThisDevice:                             |
       |        FriendlyName: "WSD Device TRUENAS"    |
       |      ThisModel:                              |
       |        Manufacturer: "TrueNAS"               |
       |        DeviceCategory: "Computers"           |
       |      Relationship (host):                    |
       |        pub:Computer:                         |
       |          "TRUENAS/Workgroup:WORKGROUP"       |
       |<---------------------------------------------|
```

### Daemon Shutdown — Bye (WS-Discovery s4.2)

When the daemon stops, it announces departure:

```
  truenas                                         239.255.255.250:3702
       |                                               |
       |  BYE (x4, 50-250ms jitter)                    |
       |  Action: .../discovery/Bye                    |
       |  EndpointReference: urn:uuid:{uuid}           |
       |---------------------------------------------->|
```

### Full Discovery Sequence (typical Windows client)

```
  Windows 10 client        truenas                 239.255.255.250:3702
       |                      |                            |
       |  1. PROBE            |                            |
       |  Types: wsdp:Device  |                            |
       |--------------------->|--------------------------->|
       |                      |                            |
       |  2. PROBE MATCH      |                            |
       |  (unicast to client) |                            |
       |<---------------------|                            |
       |                      |                            |
       |  3. RESOLVE          |                            |
       |  urn:uuid:{uuid}     |                            |
       |--------------------->|                            |
       |                      |                            |
       |  4. RESOLVE MATCH    |                            |
       |  XAddrs: http://...:5357/{uuid}                   |
       |<---------------------|                            |
       |                      |                            |
       |  5. HTTP GET (TCP :5357)                          |
       |  Action: .../transfer/Get                         |
       |--------------------->|                            |
       |                      |                            |
       |  6. HTTP GET RESPONSE|                            |
       |  FriendlyName, Computer, Workgroup                |
       |<---------------------|                            |
       |                      |                            |
       | (client shows "TRUENAS" in Network Neighborhood)  |
```

### SOAP Envelope Structure

All messages use this wrapper:

```xml
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>{action URI}</wsa:Action>
    <wsa:MessageID>urn:uuid:{random}</wsa:MessageID>
    <!-- Optional: -->
    <wsa:RelatesTo>{original message ID}</wsa:RelatesTo>
    <wsd:AppSequence InstanceId="N" SequenceId="urn:uuid:{uuid}" MessageNumber="M"/>
  </soap:Header>
  <soap:Body>
    <!-- Message-specific content -->
  </soap:Body>
</soap:Envelope>
```
