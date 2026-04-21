# truenas_pynetbiosns

Pure-Python NetBIOS Name Service implementation for TrueNAS. This
package is a **library** — the server is launched via the unified
`truenas-discoveryd` daemon (see the top-level `README.md`), not
independently.

## Protocol Specifications

| Spec | Title | What we use it for |
|------|-------|--------------------|
| [RFC 1001](https://datatracker.ietf.org/doc/html/rfc1001) | NetBIOS Service on TCP/UDP: Concepts and Methods | Architecture: B/P/M/H node types, name registration and defense model, browse service concepts |
| [RFC 1002](https://datatracker.ietf.org/doc/html/rfc1002) | NetBIOS Service on TCP/UDP: Detailed Specifications | Core protocol: packet format, name encoding (half-ASCII first-level encoding), opcodes, name registration/query/release/refresh, node status, resource record format, timing constants |
| [MS-BRWS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/) | Common Internet File System (CIFS) Browser Protocol | Host announcements, browser elections, server type flags, announcement intervals, mailslot message format |

## Code References

The following open-source projects were used as implementation references:

| Project | License | What we referenced |
|---------|---------|-------------------|
| [samba-team/samba](https://gitlab.com/samba-team/samba) (`source3/nmbd/`) | GPL-3.0 | Name registration flow (`nmbd_nameregister.c`), name defense (`nmbd_incomingrequests.c`), election mechanics (`nmbd_elections.c`, `nmbd_become_lmb.c`), host announcements (`nmbd_sendannounce.c`), per-interface subnet architecture (`nmbd_subnetdb.c`), name encoding and packet format (`libsmb/nmblib.c`) |
| [samba-team/samba](https://gitlab.com/samba-team/samba) (`source4/torture/nbt/`) | GPL-3.0 | Test patterns for name defense (`register.c`), WINS lifecycle (`wins.c`), scope boundary testing, case sensitivity, special character handling |
| [truenas/middleware](https://github.com/truenas/middleware) (`middlewared/utils/netbios.py`) | — | NetBIOS name validation rules, reserved word list, SMB config parameter mapping (`plugins/smb_/util_smbconf.py`) |

## Subpackages

- [protocol/](protocol/README.md) — wire protocol: packet parsing/building, name encoding, constants
- [server/](server/README.md) — server module: config, name registration, query response, browse announcements. Hosted inside `truenas-discoveryd`.
- [client/](client/README.md) — CLI tools (`nbt-lookup`, `nbt-status`)

## Registered Names

The 16th byte of a NetBIOS name is the **suffix** that identifies the service
(MS-NBTE §2.1.1.2).  For a non-browser file server the required set is small.
This is what `nbt-status -A <our-ip>` shows when queried against a host running
`truenas-discoveryd`:

| Suffix | Scope  | Name                | Meaning                    |
|--------|--------|---------------------|----------------------------|
| `<00>` | unique | `<hostname>`        | Workstation service        |
| `<03>` | unique | `<hostname>`        | Messenger service          |
| `<20>` | unique | `<hostname>`        | File server service        |
| `<00>` | group  | `<workgroup>`       | Workgroup membership       |

This is the minimum set RFC 1001 §17.4.1 describes for a host that offers file
services and participates in a workgroup.  Direct SMB access
(`\\<hostname>`, `\\<ip>`) works off these names alone — the `<20>` unique
advertises our SMB listener, and workgroup membership is announced via the
workgroup `<00>` group.

### Names we deliberately DON'T register

Samba's `nmbd` additionally registers names for the **CIFS browser protocol**
(MS-BRWS), the mechanism legacy Windows "Network Neighborhood" uses to
enumerate hosts.  Those names are:

| Suffix | Scope  | Name                  | Role                                             |
|--------|--------|-----------------------|--------------------------------------------------|
| `<1e>` | group  | `<workgroup>`         | Browser election candidate                       |
| `<1d>` | unique | `<workgroup>`         | Local Master Browser (held while elected)        |
| `<01>` | group  | `..__MSBROWSE__.`     | Master-Browser announcements                     |
| `<1c>` | group  | `<domain>`            | Domain Controller / Domain browser list (AD-only) |
| `<1b>` | unique | `<domain>`            | Domain Master Browser (forest-wide, AD-only)     |

We do not register any of these.  Rationale, per-name:

- **`<1e>` browser election candidate.**  Participating in the election opens
  the door to being elected Local Master Browser.  The LMB role requires
  collecting host announcements on the wire, maintaining a browse-list,
  serving `GetBackupListReq` / `BecomeBackup`, and responding to
  `NodeStatusRequest` with a specific suffix set — a substantial state machine
  (see Samba's `nmbd_elections.c`, `nmbd_become_lmb.c`, `nmbd_browserdb.c`).
  A non-browser daemon that registers `<1e>` but doesn't implement the role
  would win elections on subnets where no real browser exists and then break
  Network Neighborhood for every client.  See [RFC 1002 §A] and [MS-BRWS §3].
- **`<1d>` Local Master Browser**, **`<01>` `..__MSBROWSE__.`** — only
  registered by a node that has actually won the election.  Not applicable.
- **`<1c>` / `<1b>`** — Active Directory roles that belong on domain
  controllers, not file servers.

Modern Windows (10/11) discovers hosts via **WS-Discovery** (handled by our
`truenas_pywsd` sibling), not via NetBIOS browse.  Legacy SMB1 browse should
be provided by a domain controller or a dedicated Samba peer on the network;
TrueNAS explicitly does not want that responsibility.  TrueNAS middleware
reflects this by defaulting `local master = no` and forcing it off in Active
Directory mode — this daemon mirrors that policy.

## Limitations

- **No Local Master Browser role.** See "Names we deliberately DON'T register"
  above for the full rationale.  In short: participating in browser elections
  without implementing the LMB role would break Network Neighborhood.
- **No WINS server or client.** Only B-node (broadcast) name resolution is
  supported.  P-node (unicast to WINS) and H-node (hybrid) are not implemented.
- **No Domain Master Browser.** Cross-subnet browse list synchronization is
  not supported.
- **IPv4 only.** NetBIOS over TCP/IP (RFC 1001/1002) has no IPv6 extension.
