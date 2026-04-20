# truenas_pymdns.protocol

Wire protocol: parsing and building mDNS packets per RFC 6762 / RFC 6763.

## Modules

- `constants.py` — port, multicast addresses, record type/class enums, timing values, TTLs
- `name.py` — DNS name encoding/decoding with pointer compression
- `records.py` — `MDNSRecordKey`, `MDNSRecord`, and per-type rdata dataclasses (`ARecordData`, `AAAARecordData`, `PTRRecordData`, `SRVRecordData`, `TXTRecordData`). Each has `to_wire()`/`from_wire()`.
- `message.py` — `MDNSQuestion` and `MDNSMessage` with full packet serialization and convenience builders (`build_query`, `build_response`, `build_probe`, `build_goodbye`)

## mDNS Traffic Flow

All traffic uses multicast UDP on 224.0.0.251:5353 (IPv4) or ff02::fb:5353 (IPv6).
IP TTL must be 255 on all packets (RFC 6762 s11).

### Service Registration (RFC 6762 s8)

When the daemon starts and wants to announce `_smb._tcp` on port 445:

```
  truenas.local                          224.0.0.251:5353
       |                                       |
       |  PROBE (x3 at 250ms intervals)        |
       |  QD: myhost.local. ANY? (QU)          |
       |  NS: myhost.local. A 192.168.1.100    |
       |-------------------------------------->|
       |                                       |
       |          (no conflict response)       |
       |                                       |
       |  ANNOUNCE (x3 at 1s, 2s, 4s)          |
       |  AN: _smb._tcp.local. PTR             |
       |        truenas._smb._tcp.local.       |
       |  AN: truenas._smb._tcp.local. SRV     |
       |        0 0 445 truenas.local.         |
       |  AN: truenas._smb._tcp.local. TXT     |
       |        "model=MacPro7,1"              |
       |  AN: truenas.local. A                 |
       |        192.168.1.100                  |
       |  (all with cache-flush bit set)       |
       |-------------------------------------->|
```

### Service Browsing (RFC 6763 s4)

A macOS client wants to find SMB shares:

```
  macOS client                truenas.local              224.0.0.251:5353
       |                            |                           |
       |  QUERY                     |                           |
       |  QD: _smb._tcp.local. PTR? |                           |
       |--------------------------->|-------------------------->|
       |                            |                           |
       |                            |  RESPONSE (20-120ms delay)|
       |                            |  AN: _smb._tcp.local. PTR |
       |                            |    truenas._smb._tcp.local|
       |                            |  AR: truenas._smb._tcp.   |
       |                            |    local. SRV 0 0 445     |
       |                            |    truenas.local.         |
       |                            |  AR: truenas._smb._tcp.   |
       |                            |    local. TXT "model=..." |
       |                            |  AR: truenas.local. A     |
       |                            |    192.168.1.100          |
       |<---------------------------|-------------------------->|
```

The additional records (AR) in the response are per RFC 6763 s12:
PTR answers include SRV+TXT+A/AAAA in the additionals section.

### Service Type Enumeration (RFC 6763 s9)

Discovering what service types exist on the network:

```
  client                                 224.0.0.251:5353
       |                                       |
       |  QUERY                                |
       |  QD: _services._dns-sd._udp.local.    |
       |       PTR?                            |
       |-------------------------------------->|
       |                                       |
       |  RESPONSE                             |
       |  AN: _services._dns-sd._udp.local.    |
       |       PTR _smb._tcp.local.            |
       |  AN: _services._dns-sd._udp.local.    |
       |       PTR _http._tcp.local.           |
       |  AN: _services._dns-sd._udp.local.    |
       |       PTR _device-info._tcp.local.    |
       |<--------------------------------------|
```

### Known-Answer Suppression (RFC 6762 s7.1)

Client already has a cached PTR and includes it in the query so
the responder doesn't repeat it:

```
  client                     truenas.local
       |                            |
       |  QUERY                     |
       |  QD: _smb._tcp.local. PTR? |
       |  AN: _smb._tcp.local. PTR  |  (known answer, TTL >= 50%)
       |    truenas._smb._tcp.local.|
       |--------------------------->|
       |                            |
       |       (suppressed — truenas already knows client has it)
```

### Conflict Detection (RFC 6762 s8.2)

Two hosts probe for the same name simultaneously:

```
  host-A                     host-B                  224.0.0.251:5353
       |                        |                           |
       |  PROBE                 |                           |
       |  QD: myhost.local. ANY?|                           |
       |  NS: myhost.local.     |                           |
       |      A 192.168.1.10    |                           |
       |----------------------->|-------------------------->|
       |                        |                           |
       |                        |  PROBE                    |
       |                        |  QD: myhost.local. ANY?   |
       |                        |  NS: myhost.local.        |
       |                        |      A 192.168.1.20       |
       |<-----------------------|-------------------------->|
       |                        |                           |
       | (lexicographic compare: 192.168.1.20 > 192.168.1.10)
       | (host-A loses, must pick new name)                 |
       |                        |                           |
       |  PROBE (retry)         |                           |
       |  QD: myhost-2.local.   |                           |
       |       ANY?             |                           |
       |  NS: myhost-2.local.   |                           |
       |      A 192.168.1.10    |                           |
       |----------------------->|-------------------------->|
```

### Goodbye (RFC 6762 s10.1)

Daemon shutting down — sends all records with TTL=0:

```
  truenas.local                          224.0.0.251:5353
       |                                       |
       |  RESPONSE (goodbye)                   |
       |  AN: _smb._tcp.local. PTR TTL=0       |
       |    truenas._smb._tcp.local.           |
       |  AN: truenas._smb._tcp.local.         |
       |       SRV TTL=0                       |
       |  AN: truenas._smb._tcp.local.         |
       |       TXT TTL=0                       |
       |  AN: truenas.local. A TTL=0           |
       |-------------------------------------->|
       |                                       |
       | (remote caches set TTL=1, expire 1s later per s10.1)
```

### Hostname Resolution (RFC 6762 s3)

Simple A/AAAA query for a .local name:

```
  client                     truenas.local
       |                            |
       |  QUERY                     |
       |  QD: truenas.local. A?     |
       |  QD: truenas.local. AAAA?  |
       |--------------------------->|
       |                            |
       |  RESPONSE                  |
       |  AN: truenas.local. A      |
       |      192.168.1.100         |
       |  AN: truenas.local. AAAA   |
       |      fe80::1               |
       |<---------------------------|
```

### TrueNAS Typical Records

A TrueNAS box announcing its services registers these record sets:

```
Service: SMB (_smb._tcp, port 445)
  _services._dns-sd._udp.local.  PTR  _smb._tcp.local.
  _smb._tcp.local.               PTR  truenas._smb._tcp.local.
  truenas._smb._tcp.local.       SRV  0 0 445 truenas.local.
  truenas._smb._tcp.local.       TXT  (empty)

Service: Time Machine (_adisk._tcp, port 9)
  _services._dns-sd._udp.local.  PTR  _adisk._tcp.local.
  _adisk._tcp.local.             PTR  truenas._adisk._tcp.local.
  truenas._adisk._tcp.local.     SRV  0 0 9 truenas.local.
  truenas._adisk._tcp.local.     TXT  "sys=waMa=0,adVF=0x100"
                                       "dk0=adVN=TMBackup,adVF=0x82,adVU=..."

Service: Device Info (_device-info._tcp, port 9)
  _services._dns-sd._udp.local.  PTR  _device-info._tcp.local.
  _device-info._tcp.local.       PTR  truenas._device-info._tcp.local.
  truenas._device-info._tcp.local. SRV  0 0 9 truenas.local.
  truenas._device-info._tcp.local. TXT  "model=MacPro7,1@ECOLOR=226,226,224"

Service: Web UI (_http._tcp, port 443)
  _services._dns-sd._udp.local.  PTR  _http._tcp.local.
  _http._tcp.local.              PTR  truenas._http._tcp.local.
  truenas._http._tcp.local.      SRV  0 0 443 truenas.local.
  truenas._http._tcp.local.      TXT  (empty)

Host address records:
  truenas.local.                  A     192.168.1.100
  truenas.local.                  AAAA  fe80::aabb:ccdd:eeff
  100.1.168.192.in-addr.arpa.    PTR   truenas.local.
```
