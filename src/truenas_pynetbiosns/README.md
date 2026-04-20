# truenas_pynetbiosns

Pure-Python NetBIOS Name Service implementation for TrueNAS. This
package is a **library** — the server is launched via the unified
`truenas-pydiscoveryd` daemon (see the top-level `README.md`), not
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
- [server/](server/README.md) — server module: config, name registration, query response, browse announcements. Hosted inside `truenas-pydiscoveryd`.
- [client/](client/README.md) — CLI tools (`nbt-lookup`, `nbt-status`)

## Limitations

- **No Local Master Browser role.** This daemon does not participate in browser elections and will not become a Local Master Browser. Winning an election without properly implementing the LMB role (collecting host announcements, serving browse lists, responding to GetBackupListReq) would break Network Neighborhood for all clients on the subnet. Since TrueNAS middleware defaults `local master = no` and forces it off in Active Directory mode, this is not needed for the target use case.
- **No WINS server or client.** Only B-node (broadcast) name resolution is supported. P-node (unicast to WINS) and H-node (hybrid) are not implemented.
- **No Domain Master Browser.** Cross-subnet browse list synchronization is not supported.
- **IPv4 only.** NetBIOS over TCP/IP (RFC 1001/1002) has no IPv6 extension.
