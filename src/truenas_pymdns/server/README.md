# truenas_pymdns.server

mDNS/DNS-SD server module — runs as a child of the unified
`truenas-pydiscoveryd` daemon.

## Modules

- `server.py` — top-level orchestrator. Manages per-interface state (transport, cache, schedulers), loads service files, handles probing/announcing, runs maintenance loop. Drives SIGTERM/SIGINT shutdown, SIGHUP reload, SIGUSR1 status dump via the `BaseDaemon` contract; signals are received by the parent composite.
- `config.py` — `DaemonConfig` dataclass + helpers. The unified loader in `truenas_pydiscovery.config` reads the `[mdns]` section into this dataclass.
- `status.py` — writes `status.json` atomically to rundir on demand.

Wire protocol types (`MDNSMessage`, `MDNSRecord`, etc.) live in the shared [`truenas_pymdns.protocol`](../protocol/README.md) package.

## Standard Paths

| Path | Purpose |
|------|---------|
| `/etc/truenas-pydiscovery/truenas-pydiscoveryd.conf` | Unified daemon config (`[mdns]` section) |
| `/etc/truenas-pydiscovery/services.d/*.conf` | Service definitions (one file per service) |
| `/run/truenas-pydiscovery/mdns/status.json` | Runtime status (written on SIGUSR1) |

## mDNS configuration

The `[mdns]` section in `/etc/truenas-pydiscovery/truenas-pydiscoveryd.conf`:

```ini
[mdns]
enabled = yes
host-name = truenas
domain-name = local
use-ipv4 = yes
use-ipv6 = yes
cache-entries-max = 4096
ratelimit-interval-usec = 1000000
ratelimit-burst = 1000
service-dir = /etc/truenas-pydiscovery/services.d
```

All keys are optional. `host-name` falls back to the shared
`[discovery].hostname` and then the system hostname. `interfaces`
may be set per-section to override the shared `[discovery].interfaces`.

## Service Config

Each `.conf` file in the service directory defines one mDNS service. Middleware writes these; the daemon reads them on startup and SIGHUP reload.

Only `type` and `port` are required. `name` defaults to `%h` (replaced with the configured hostname at registration time). `domain` defaults to `local`. `host` defaults to the daemon's FQDN. `interfaces` limits which interfaces advertise this service. `[txt]` entries are optional key=value pairs included in the TXT record.

### SMB (`/etc/truenas-pydiscovery/services.d/SMB.conf`)

```ini
[service]
type = _smb._tcp
port = 445
```

### Device Info (`/etc/truenas-pydiscovery/services.d/DEV_INFO.conf`)

```ini
[service]
type = _device-info._tcp
port = 9

[txt]
model = MacPro7,1@ECOLOR=226,226,224
```

### Time Machine (`/etc/truenas-pydiscovery/services.d/ADISK.conf`)

```ini
[service]
type = _adisk._tcp
port = 9

[txt]
sys = waMa=0,adVF=0x100
dk0 = adVN=TMBackup,adVF=0x82,adVU=aabb-ccdd-eeff
```

### Web UI with interface binding (`/etc/truenas-pydiscovery/services.d/HTTP.conf`)

```ini
[service]
type = _http._tcp
port = 443
interfaces = eth0
```

## Subpackages

- [core/](core/README.md) — protocol state machines: cache, probing, announcing, conflict resolution
- [net/](net/README.md) — multicast sockets, interface resolution, asyncio transport
- [query/](query/README.md) — query batching and response scheduling
- [service/](service/README.md) — service file loading and authoritative record registry
