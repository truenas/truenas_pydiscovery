# truenas_pynetbiosns.protocol

Wire protocol: parsing and building NetBIOS Name Service packets per RFC 1002.

## Modules

- `constants.py` — ports (137/138), opcodes, name types (0x00 workstation, 0x03 messenger, 0x20 server), header flags, NB rdata flags, timing values, browse opcodes, server type flags
- `name.py` — `NetBIOSName` dataclass, first-level (half-ASCII) encoding/decoding. 15-char names are space-padded and uppercased, the 16th byte is the service type suffix, each byte becomes two wire bytes via nibble-split + 0x41. Optional scope encoded as DNS-style labels.
- `message.py` — `NBNSMessage`, `NBQuestion`, `NBResourceRecord` with full packet serialization and convenience builders (`build_name_query`, `build_registration`, `build_release`, `build_refresh`, `build_positive_response`, `build_negative_response`, `build_node_status_query`, `build_node_status_response`)

## NetBIOS Name Wire Encoding

```
Name "TRUENAS" type 0x20:
  Pad to 16 bytes: T R U E N A S _ _ _ _ _ _ _ _ \x20
  Half-ASCII each byte: T=0x54 → 0x46('F') 0x45('E'), ...
  Wire: 0x20 <32 encoded bytes> [<scope>] 0x00
```

## Packet Format (RFC 1002 s4.2)

```
Header (12 bytes):
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |              NAME_TRN_ID (16 bits)            |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |R | OPCODE  |AA|TC|RD|RA| 0| 0| B|    RCODE    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |         QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

NB Resource Record RDATA (6 bytes per address):
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  | G |  ONT  |         RESERVED                  |  2 bytes flags
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                 IP ADDRESS                    |  4 bytes
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

## NetBIOS NS Traffic Flow

All name service traffic uses UDP broadcast on port 137.
Browse announcements use UDP broadcast on port 138 via mailslots.

### Name Registration (RFC 1002 s4.2.2)

Daemon registers HOSTNAME<0x20> (file server) on startup:

```
  truenas                                     broadcast:137
       |                                           |
       |  REGISTRATION (x3 at 250ms intervals)     |
       |  Opcode: REGISTRATION (5)                 |
       |  QD: TRUENAS<20> NB?                      |
       |  AR: TRUENAS<20> NB 192.168.1.100         |
       |  Flags: RD, BROADCAST                     |
       |------------------------------------------>|
       |                                           |
       |          (no negative response)           |
       |                                           |
       | → name registered in local table          |
```

### Name Defense (RFC 1002 s4.2.5)

Another node tries to register our name — we defend it:

```
  other-host              truenas                   broadcast:137
       |                     |                           |
       |  REGISTRATION       |                           |
       |  QD: TRUENAS<20>    |                           |
       |  AR: 10.0.0.99      |                           |
       |-------------------->|-------------------------->|
       |                     |                           |
       |  NEGATIVE RESPONSE (unicast)                    |
       |  Opcode: REGISTRATION                           |
       |  RCODE: ACT_ERR (6)                             |
       |  (name already active)                          |
       |<--------------------|                           |
```

### Name Query (RFC 1002 s4.2.12)

A Windows client resolves a NetBIOS name:

```
  Windows client             truenas                 broadcast:137
       |                        |                         |
       |  NAME QUERY            |                         |
       |  Opcode: QUERY (0)     |                         |
       |  QD: TRUENAS<20> NB?   |                         |
       |  Flags: RD, BROADCAST  |                         |
       |----------------------->|------------------------>|
       |                        |                         |
       |  POSITIVE RESPONSE (unicast)                     |
       |  Opcode: QUERY (0)                               |
       |  RCODE: OK (0)                                   |
       |  AN: TRUENAS<20> NB 192.168.1.100                |
       |  Flags: RESPONSE, AA, RD                         |
       |<-----------------------|                         |
```

### Node Status (RFC 1002 s4.2.17)

`nbtstat -a TRUENAS` queries all registered names:

```
  client                       truenas
       |                          |
       |  NODE STATUS QUERY       |
       |  QD: *<00> NBSTAT?       |
       |------------------------->|
       |                          |
       |  NODE STATUS RESPONSE    |
       |  AN: *<00> NBSTAT        |
       |    TRUENAS<00>  ACTIVE   |
       |    TRUENAS<03>  ACTIVE   |
       |    TRUENAS<20>  ACTIVE   |
       |    WORKGROUP<00> GROUP   |
       |<-------------------------|
```

### Name Release (RFC 1002 s4.2.10)

Daemon releases names on shutdown:

```
  truenas                                     broadcast:137
       |                                           |
       |  RELEASE (for each registered name)       |
       |  Opcode: RELEASE (6)                      |
       |  QD: TRUENAS<20> NB?                      |
       |  AR: TRUENAS<20> NB TTL=0                 |
       |      192.168.1.100                        |
       |------------------------------------------>|
```

### Host Announcement (MS-BRWS via port 138)

Periodic server announcement to browse list:

```
  truenas                                        broadcast:138
       |                                              |
       |  DATAGRAM (mailslot \MAILSLOT\BROWSE)        |
       |  Opcode: HOST_ANNOUNCEMENT (0x01)            |
       |  ServerName: TRUENAS                         |
       |  ServerType: WORKSTATION | SERVER            |
       |  Comment: "TrueNAS Server"                   |
       |  (intervals: 1m, 2m, 4m... cap 12m)          |
       |--------------------------------------------->|
```
