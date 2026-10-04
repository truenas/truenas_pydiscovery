# truenas-pydiscovery

Pure-Python network service discovery for TrueNAS. A single
`truenas-discoveryd` daemon hosts mDNS/DNS-SD, NetBIOS Name Service,
and Web Services Discovery in one process; per-protocol CLI query
tools ship alongside it for development and debugging — they send
queries directly on the network without the daemon, but are not
full-featured browsing clients (see [Client Tools](#client-tools)
below).

## Layout

| Package | Purpose | Role | Client Tools |
|---------|---------|------|--------------|
| `truenas_pydiscovery` | Unified daemon orchestrator | Entry point (`truenas-discoveryd`) | `truenas-discovery-status` |
| `truenas_pymdns` | mDNS/DNS-SD (RFC 6762/6763) | Library module | `mdns-browse`, `mdns-resolve`, `mdns-lookup` |
| `truenas_pynetbiosns` | NetBIOS NS + Browser (RFC 1001/1002, MS-BRWS) | Library module | `nbt-lookup`, `nbt-status` |
| `truenas_pywsd` | Web Services Discovery (WS-Discovery 1.1, DPWS) | Library module | `wsd-discover`, `wsd-info` |
| `truenas_pydiscovery_utils` | Shared infra: BaseDaemon, composite, logging, status | — | — |

### Dependencies

- Python >= 3.11, stdlib only — except `defusedxml` for WSD XML parsing (XXE prevention)
- No runtime dependency on Avahi, Samba, or D-Bus

## Source Layout

```
src/
  truenas_pydiscovery/          # Unified daemon orchestrator
    server/__main__.py          # truenas-discoveryd entry point
    config.py                   # Unified INI loader ([discovery] + per-protocol)
    composite.py                # Builds CompositeDaemon from enabled sections
    cli/status.py               # truenas-discovery-status: dump unified state as JSON

  truenas_pymdns/               # mDNS/DNS-SD
    protocol/                   # Wire protocol (RFC 6762/6763)
    server/                     # Probing, announcing, responding, caching
    client/                     # CLI tools: browse, resolve, lookup

  truenas_pynetbiosns/          # NetBIOS Name Service + Browser
    protocol/                   # Wire protocol (RFC 1001/1002)
    server/                     # Registration, defense, refresh, browse announcements
    client/                     # CLI tools: lookup, status

  truenas_pywsd/                # Web Services Discovery
    protocol/                   # SOAP/XML messages (WS-Discovery 1.1, DPWS)
    server/                     # Hello/Bye, Probe/Resolve, HTTP metadata
    client/                     # CLI tools: discover, info

  truenas_pydiscovery_utils/    # Shared infrastructure
    daemon.py                   # BaseDaemon: async lifecycle, signal handling
    composite.py                # CompositeDaemon: fan out lifecycle to children
    interface_monitor.py        # Netlink link/address monitor driving reconciles
    netlink_addr.py             # Netlink address enumeration
    interface_tokens.py         # Interface token classification and validation
    sd_notify.py                # systemd notifications (READY/RELOADING)
    logger.py                   # Non-blocking syslog via QueueHandler/QueueListener
    status.py                   # Atomic JSON status writer
    entry_point.py              # Common CLI boilerplate (-c/-v flags)
```

## Build & Install

```bash
dpkg-buildpackage -us -uc -b
dpkg -i ../python3-truenas-pydiscovery_*.deb
```

## Daemon

One unified daemon.  `-c CONFIG` for config file, `-v` for
verbosity (syslog by default, stderr with `-v`).  Signals:
`SIGHUP` reloads every enabled protocol, `SIGUSR1` writes
per-protocol status JSONs, `SIGTERM` / `SIGINT` for graceful
shutdown (each protocol emits its own goodbye / bye / release
frames before closing sockets).

Interface and address changes need no reload.  The daemon follows the
kernel's netlink notifications (`truenas_pydiscovery_utils.interface_monitor`)
and, once they have been quiet for a second (at most five seconds after
the first), reads the interfaces again.  If anything differs, each
protocol updates the interfaces whose addresses changed: NetBIOS NS
rebuilds their subnets, mDNS says goodbye for addresses it no longer
publishes and probes and announces again, WS-Discovery serves the new
addresses and sends Hello.  An interface configured before it exists,
or before it has an address, is served once it has one.  See
`truenas-discoveryd(8)`, INTERFACE CHANGES.

```bash
truenas-discoveryd -c /etc/truenas-discovery/truenas-discoveryd.conf
```

Man page: [`truenas-discoveryd(8)`](debian/man/truenas-discoveryd.8).

### systemd

The Debian package installs a systemd unit at
`/lib/systemd/system/truenas-discoveryd.service` (source:
[`debian/python3-truenas-pydiscovery.truenas-discoveryd.service`](debian/python3-truenas-pydiscovery.truenas-discoveryd.service)).
Production deployments should manage the daemon via systemd rather
than the bare binary:

```bash
systemctl enable --now truenas-discoveryd      # start on boot + now
systemctl reload truenas-discoveryd            # SIGHUP (rereads config + services.d/)
systemctl kill -s SIGUSR1 truenas-discoveryd   # dump per-protocol status JSONs
truenas-discovery-status                       # fetch + merge the status JSONs
journalctl -u truenas-discoveryd -f            # follow stderr → journal
```

The daemon writes a pidfile at `<rundir>/truenas-discoveryd.pid`
(default `/run/truenas-discovery/truenas-discoveryd.pid`) on startup.
`truenas-discovery-status` reads it, sends SIGUSR1, waits for each
protocol's `status.json` to refresh, then prints one merged JSON object
on stdout.  See [`truenas-discovery-status(1)`](debian/man/truenas-discovery-status.1).

Unit highlights: runs as the unprivileged `truenas-discovery`
system user (group `daemon`, created in `postinst`), with
`AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW` so it can
still bind 137/138/3702/5353/5357 and send raw frames. Also:
`After=network-online.target`, `Restart=on-failure`,
`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`.

`Type=notify-reload`: the daemon sends `READY=1` as soon as its signal
handlers are installed, before the protocols probe and register names,
so systemd's start timeout does not cover that work; a stop request
abandons whatever startup has left.  It brackets each SIGHUP reload
with `RELOADING=1` / `READY=1`, so `systemctl reload` waits for the
reload to finish.  A SIGHUP that arrives during startup or during
another reload is held and served by one more reload once that
finishes.  systemd applies the start timeout to reloads too, so the
unit sets `TimeoutStartSec=300` to cover a reload that first waits for
startup to finish.  Startup ends with one reload pass, which applies
configuration written before `READY=1` (systemd does not signal a
reload requested before then).  `RestartForceExitStatus=SIGHUP`
restarts the unit if a SIGHUP ever arrives before the handlers are
installed.  Requires systemd 253 or later; the package `Breaks:` older
versions.

### Configuration

One INI file, one `[discovery]` section for shared fields, and one
section per protocol. Any protocol can be disabled with
`enabled = false`; missing sections are treated as disabled. At least
one protocol must be enabled or the daemon refuses to start.

```ini
[discovery]
interfaces = eth0 eth1
hostname = TRUENAS
workgroup = WORKGROUP

[mdns]
enabled = true
domain-name = local
service-dir = /etc/truenas-discovery/services.d

[netbiosns]
enabled = true
server-string = TrueNAS Server

[wsd]
enabled = true
use-ipv4 = yes
use-ipv6 = yes
```

Man page: [`truenas-discoveryd.conf(5)`](debian/man/truenas-discoveryd.conf.5) — complete field reference for every key in every section.

### mDNS service files

Individual mDNS service definitions live in the service directory
(default `/etc/truenas-discovery/services.d/`), one `.conf` per
service:

```ini
[service]
type = _smb._tcp
port = 445
```

Man page: [`truenas-discoveryd-service.conf(5)`](debian/man/truenas-discoveryd-service.conf.5) — full per-file key reference and TXT-record examples.

### Protocol scope notes

- **mDNS** announces services and responds to queries per RFC 6762/6763.
- **NetBIOS NS** registers hostname at name types `0x00`, `0x03`, `0x20`
  and sends browse announcements; does not participate in browser
  elections. See [`src/truenas_pynetbiosns/README.md`](src/truenas_pynetbiosns/README.md#limitations).
- **WSD** announces as `wsdp:Device pub:Computer` via SOAP-over-UDP
  multicast and serves metadata via HTTP on port 5357 so Windows 10+
  clients discover the NAS without NetBIOS.

## Client Tools

All client tools query the network directly — no daemon required.
All support `--json` for machine-readable JSONL output.  Each tool
ships a section-1 man page; run `man <tool>` after install or view
the source under `debian/man/`.

### Scope: development and debugging only

These tools are provided to inspect what peers advertise on the
wire, verify the daemon's own announcements, and debug interop
problems — not to act as production-quality browsing clients.
They lack the persistent-cache and passive-listener machinery that
a continuously-updating "network browser" UI expects.  Pointers to
the spec sections that define the missing behaviour:

- **mDNS.**  The CLI tools (`mdns-browse`, `mdns-resolve`,
  `mdns-lookup`) issue one-shot / short-lived QU queries and print
  whatever unicast responses arrive inside the timeout window.
  They do not maintain an mDNS record cache across invocations,
  which is the foundation RFC 6762 builds its cache-coherency
  mechanisms on: Known-Answer Suppression on continuous queries
  (§7.1, a MUST for §5.2 continuous queriers), TTL-driven re-query
  at 80/85/90/95% of record lifetime (§5.2, §10), Passive
  Observation Of Failures (§10.5), and the one-second deferred
  delete on TTL=0 goodbye packets (§10.1).  `mdns-browse` in
  particular just tracks a per-invocation "seen" set and never
  emits removes.
- **WSD.**  `wsd-discover` sends a Probe and consumes whatever
  ProbeMatches / Hellos happen to arrive inside the timeout window.
  It does not join the 3702 multicast group as a long-lived
  listener — an Ad hoc Client SHOULD listen for Hello messages to
  populate its cache and Bye messages to invalidate it
  (WS-Discovery 1.1 §4.1.2, §4.2.2).
- **NetBIOS.**  `nbt-lookup` and `nbt-status` implement the B-node
  one-shot broadcast query (RFC 1002 §5.1.1.3), which the spec
  does not pair with a client-side name cache — so there is less
  gap here — but the tools still only do per-invocation lookups,
  not continuous browsing.

Turning any of these into a general-purpose browsing client would
mean building the missing cache and listener machinery first.

### mDNS

```bash
mdns-browse _http._tcp                    # Discover HTTP services
mdns-browse --all --resolve --json        # All types, resolved, JSONL
mdns-resolve -n truenas.local             # Resolve hostname to IP
mdns-resolve -s "TrueNAS" _smb._tcp       # Resolve service instance
mdns-lookup TN26NEW _http._tcp            # Look up service (like dns-sd -L)
```

Man pages:
[`mdns-browse(1)`](debian/man/mdns-browse.1),
[`mdns-resolve(1)`](debian/man/mdns-resolve.1),
[`mdns-lookup(1)`](debian/man/mdns-lookup.1).

### NetBIOS NS

```bash
nbt-lookup TRUENAS                        # Resolve NetBIOS name to IP
nbt-lookup MYHOST --type WORKSTATION      # Query workstation name type
nbt-status 192.168.1.100                  # List all registered names on host
nbt-status 10.0.0.5 --json                # JSONL output
```

Man pages:
[`nbt-lookup(1)`](debian/man/nbt-lookup.1),
[`nbt-status(1)`](debian/man/nbt-status.1).

### WSD

```bash
wsd-discover                              # Find WSD devices on network
wsd-discover --resolve --json             # With metadata, JSONL output
wsd-info http://192.168.1.100:5357/uuid   # Fetch device metadata
```

Man pages:
[`wsd-discover(1)`](debian/man/wsd-discover.1),
[`wsd-info(1)`](debian/man/wsd-info.1).

## Testing

```bash
# Run all tests
PYTHONPATH=src python3 -m pytest tests/ -v

# With coverage
PYTHONPATH=src python3 -m pytest tests/ --cov=truenas_pymdns --cov=truenas_pynetbiosns --cov=truenas_pywsd --cov-report=term-missing -v

# Lint and type check
flake8 --max-line-length=110 src/
mypy src/

# Functional tests (see below)
sudo TRUENAS_PYDISCOVERY_FUNCTIONAL=1 python3 -m pytest tests/functional -v
```

### Functional tests

`tests/functional/` exercises the installed daemon the way the network
sees it.  Each test writes a configuration for the `truenas-discoveryd`
unit, starts, reloads or stops it with `systemctl`, and queries it with
the shipped client tools (`nbt-lookup`, `mdns-resolve`, `wsd-discover`)
from network namespaces joined to the host by veth links.  They need
root, systemd as init and the package installed, and run only when
`TRUENAS_PYDISCOVERY_FUNCTIONAL=1` is set: they reconfigure the host's
network and its `truenas-discoveryd` service, so use a disposable host.
CI runs them in a Debian Trixie VM.

## Continuous integration and releases

`.github/workflows/build-test.yml` runs on pushes and pull requests to
`master` and `stable/*`:

- **build-test**: in a `debian:trixie` container, flake8, mypy, the
  Debian package build, and the unit and integration tests against the
  installed package.
- **qemu-test**: boots a Debian Trixie cloud image under QEMU/KVM
  (UEFI) on the runner, builds and installs the package in it, and
  runs the whole suite as root, functional tests included.  The VM's
  serial console and journal go into the job's `test-logs-debian-trixie`
  artifact.
- **publish**: on a push to a branch listed in `.github/trains.json`
  (`master` as train `master`, `stable/27` as train `27`), once both
  test jobs have passed, replaces the rolling `<train>-nightly` GitHub
  prerelease with the package built by build-test, `SHA256SUMS`, and a
  `manifest.json` naming the branch, commit, build, package version and
  files.  Fetch `manifest.json` first and verify downloads against
  `SHA256SUMS`; every publish replaces all assets.

## Contributing

### Test coverage

All bugfixes and significant functional changes must include test coverage. Tests live in `tests/` mirroring the source package layout (`tests/mdns/`, `tests/netbiosns/`, `tests/wsd/`, `tests/utils/`).

### Man pages

All changes to CLI tool flags, arguments, or behavior must include corresponding updates to the man pages in `debian/man/`. New tools must have a man page added and listed in `debian/python3-truenas-pydiscovery.manpages`.

### Code conventions

- Code must pass `flake8` and `mypy` type checking
- Prefer Python `enum` types where possible
- `ctypes` usage is not accepted
- **No third-party Python packages.** The runtime depends on the
  Python standard library only — the single exception is
  `defusedxml`, retained for XXE prevention in WSD XML parsing.
  Do not introduce new PyPI dependencies; if you reach for one,
  reconsider the design or vendor the minimum code you need.
- README.md files in each subpackage must stay in sync with actual code
