# truenas_pynetbiosns.server

NetBIOS Name Service + Browser server module — runs as a child of the
unified `truenas-discoveryd` daemon.

## Modules

- `server.py` — top-level orchestrator (`NBNSServer(BaseDaemon)`). Manages per-interface state, registers names on startup, defends names, handles SIGHUP reload and SIGUSR1 status dump through the `BaseDaemon` contract.
- `config.py` — `DaemonConfig` dataclass. The unified loader in `truenas_pydiscovery.config` reads the `[netbiosns]` section into this dataclass.

## Standard Paths

| Path | Purpose |
|------|---------|
| `/etc/truenas-discovery/truenas-discoveryd.conf` | Unified daemon config (`[netbiosns]` section) |
| `/run/truenas-discovery/netbiosns/status.json` | Runtime status (written on SIGUSR1) |

## NetBIOS configuration

The `[netbiosns]` section in `/etc/truenas-discovery/truenas-discoveryd.conf`:

```ini
[netbiosns]
enabled = yes
netbios-name = TRUENAS
netbios-aliases = NAS1, NAS2
workgroup = WORKGROUP
server-string = TrueNAS Server
```

All keys are optional. `netbios-name` falls back to the shared
`[discovery].hostname` and then the system hostname (uppercased,
truncated to 15 chars). `interfaces` / `workgroup` can be set per
section to override the shared `[discovery]` values.

## Name Registration

On startup, for each configured name (primary + aliases), the daemon registers:

- `HOSTNAME<0x00>` — workstation service (unique)
- `HOSTNAME<0x03>` — messenger service (unique)
- `HOSTNAME<0x20>` — file server service (unique)
- `WORKGROUP<0x00>` — workgroup name (group)

Registration uses B-node broadcast: one registration request, sent on port 137 and resent 3 times, each transmission followed by a 1 s wait, as Samba nmbd times a broadcast registration (RFC 1002 §6 has 3 transmissions 250 ms apart). The first negative response carrying the request's NAME_TRN_ID ends the claim; if none has arrived by the end of the last wait, the name is considered registered.

Every name on every subnet is claimed at the same time, each with its own request, as Samba nmbd queues one registration per name (`register_my_workgroup_one_subnet`). Registering all names therefore takes one claim's 4 s however many names and subnets there are. A name listed more than once is claimed once.

## Subpackages

- [core/](core/README.md) — name table, registration, defense, release
- [net/](net/README.md) — broadcast UDP sockets, interface resolution
- [query/](query/README.md) — name query and node status response
- [browse/](browse/README.md) — host announcements
