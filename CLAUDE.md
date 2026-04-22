# CLAUDE.md

## Build & Install

```bash
dpkg-buildpackage -us -uc -b
dpkg -i ../python3-truenas-pydiscovery_*.deb
```

## Lint & Type Check

```bash
flake8 --max-line-length=110 src/
mypy src/
```

## Tests

```bash
PYTHONPATH=src python3 -m pytest tests/ -v
```

## Testing Policy

- All bugfixes and significant functional changes must include test coverage
- Tests live in `tests/` mirroring the source layout (`tests/mdns/`, `tests/netbiosns/`, `tests/wsd/`, `tests/utils/`)
- Run with coverage: `PYTHONPATH=src python3 -m pytest tests/ --cov=truenas_pymdns --cov=truenas_pynetbiosns --cov=truenas_pywsd --cov-report=term-missing -v`
- **No mocks.** Never use `unittest.mock.MagicMock`, `Mock`, or `patch`. Build real dependencies — a real `ServiceRegistry` with a real `EntryGroup`, a real `RecordCache`, a real `QueryScheduler` with a lambda send-fn, a real `asyncio.new_event_loop()` — or delete the test.
- **Hand-rolled fakes count as mocks.** A `class _FakeSock: def sendto(self, ...)` that records arguments is morally the same as `MagicMock`: it duck-types a real object without exercising real behaviour. Same rule — build the real dep (e.g. a loopback socket pair) or delete the test.
- `lambda *a, **kw: None` as a callback is fine. It's an intentional no-op sink, not a mock of an object's behaviour.

## Protocol Specs

- Before making any protocol-related change (wire format, state machine,
  timing constants, message handling), consult the relevant specification
  under `docs/specs/`. `PROTOCOLSPECS.md` is the index mapping each
  protocol to its normative references and local copies.
- If a spec referenced in `PROTOCOLSPECS.md` is not yet in `docs/specs/`,
  download it there first (as `.txt`/`.pdf`/`.html` matching the canonical
  form), read it, then proceed with the change. Add the local-copy link to
  `PROTOCOLSPECS.md` in the same commit.
- Do not rely on memory or secondhand summaries for protocol behavior —
  quote the spec section you are implementing.

## Man Pages

- All changes to CLI tool flags, arguments, or behavior must include corresponding updates to man pages in `debian/man/`
- New tools must have a man page added and listed in `debian/python3-truenas-pydiscovery.manpages`
- Daemon man pages are section 8, client tools are section 1

## Project Conventions

- Pure Python, stdlib only -- except `defusedxml` for WSD XML parsing (XXE prevention)
- Python >= 3.11
- Source layout: `src/` with five packages (`truenas_pydiscovery`, `truenas_pymdns`, `truenas_pynetbiosns`, `truenas_pywsd`, `truenas_pydiscovery_utils`). The mDNS/NetBIOS/WSD packages are libraries; the server is the single `truenas-discoveryd` entry point in `truenas_pydiscovery.server.__main__:main`.
- `ctypes` usage is not accepted
- Prefer Python `enum` types where possible
- `from __future__ import annotations` in every module
- All imports at top of file, never inline
- Frozen/slotted dataclasses for protocol types and config
- Prefer `.value` on IntEnum/IntFlag/StrEnum for performance in hot paths (not `int()`)
- Max line length: 110 characters
- README.md files in each subpackage must stay in sync with actual code (module lists, CLI flags, architecture descriptions)
- Debian packaging source files: `debian/changelog`, `debian/control`, `debian/rules`, `debian/man/`, `debian/python3-truenas-pydiscovery.manpages`. Everything else under `debian/` is build artifacts.
- No private network identifiers in source/tests/comments. User-supplied pcaps, debug sessions, and live captures routinely expose real IPs, MACs, endpoint UUIDs, and hostnames; never paste those verbatim into code, docstrings, tests, or commit messages. Use documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849: `2001:db8::/32`), RFC 4122 documentation UUIDs (or obvious placeholders like `00000000-0000-0000-0000-000000000001`), and generic hostnames (`host1`, `OLDHOST`, `NAS01`) instead. The "obvious illustrative" IPs already scattered through existing docs (`192.168.1.100`, `10.0.0.5`) are grandfathered and fine to keep using, but don't import real addresses from captures.
