# truenas_pynetbiosns.server

NetBIOS Name Service + Browser server module — runs as a child of the
unified `truenas-pydiscoveryd` daemon.

## Modules

- `server.py` — top-level orchestrator (`NBNSServer(BaseDaemon)`). Manages per-interface state, registers names on startup, defends names, handles SIGHUP reload and SIGUSR1 status dump through the `BaseDaemon` contract.
- `config.py` — `DaemonConfig` dataclass. The unified loader in `truenas_pydiscovery.config` reads the `[netbiosns]` section into this dataclass.

## Standard Paths

| Path | Purpose |
|------|---------|
| `/etc/truenas-pydiscovery/truenas-pydiscoveryd.conf` | Unified daemon config (`[netbiosns]` section) |
| `/run/truenas-pydiscovery/netbiosns/status.json` | Runtime status (written on SIGUSR1) |

## NetBIOS configuration

The `[netbiosns]` section in `/etc/truenas-pydiscovery/truenas-pydiscoveryd.conf`:

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

Registration uses B-node broadcast: 3 packets at 250ms intervals on port 137. If no negative response is received, the name is considered registered.

## Subpackages

- [core/](core/README.md) — name table, registration, defense, refresh, release
- [net/](net/README.md) — broadcast UDP sockets, interface resolution
- [query/](query/README.md) — name query and node status response
- [browse/](browse/README.md) — host announcements
