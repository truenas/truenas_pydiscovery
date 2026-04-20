# truenas_pywsd.server

Web Services Discovery server module — runs as a child of the unified
`truenas-pydiscoveryd` daemon.

## Modules

- `server.py` — top-level orchestrator (`WSDServer(BaseDaemon)`). Manages per-interface state, sends Hello/Bye, handles Probe/Resolve, serves HTTP metadata. SIGHUP reload and SIGUSR1 status dump flow through the `BaseDaemon` contract.
- `config.py` — `DaemonConfig` dataclass. The unified loader in `truenas_pydiscovery.config` reads the `[wsd]` section into this dataclass.

## Standard Paths

| Path | Purpose |
|------|---------|
| `/etc/truenas-pydiscovery/truenas-pydiscoveryd.conf` | Unified daemon config (`[wsd]` section) |
| `/run/truenas-pydiscovery/wsd/status.json` | Runtime status (written on SIGUSR1) |

## WSD configuration

The `[wsd]` section in `/etc/truenas-pydiscovery/truenas-pydiscoveryd.conf`:

```ini
[wsd]
enabled = yes
hostname = truenas
workgroup = WORKGROUP
domain =
use-ipv4 = yes
use-ipv6 = yes
```

All keys are optional. `hostname` / `workgroup` fall back to the
shared `[discovery]` values. If `domain` is set, the device
advertises as a domain member instead of workgroup member.

## Subpackages

- [core/](core/README.md) — Hello/Bye announcer, Probe/Resolve responder, metadata handler, message dedup
- [net/](net/README.md) — UDP multicast transport (port 3702), HTTP metadata server (port 5357), interface resolution
