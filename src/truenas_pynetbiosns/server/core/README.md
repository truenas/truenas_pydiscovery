# core/

NetBIOS name lifecycle state machines and local name registry.

- `nametable.py` — local name registry mapping `NetBIOSName` to IP addresses, NB flags, TTL, and registration state. Case-insensitive lookup via `NetBIOSName.__eq__`.
- `registrar.py` — name registration via broadcast. Broadcasts one registration request up to 3 times, each followed by a 250ms wait (RFC 1002 §5.1.1.1), and stops at the first negative response whose NAME_TRN_ID matches the request's; other responses are ignored.
- `defender.py` — name defense: when another node attempts to register or refresh a name we own, responds with `RCODE_ACT` (active error). Mirrors Samba's `nbt_register_own` / `nbt_refresh_own` behavior.
- `refresher.py` — periodic name refresh loop. Re-sends registration packets for all registered names at a fixed interval (default 15 minutes) to maintain network presence.
- `release.py` — clean name release. `release_all_names()` sends release packets (TTL=0) for every registered name on shutdown. `release_names()` takes a subset (set of `(name, name_type, is_group)` tuples) and releases only matching entries, pulling them from the name table so the refresher and responder stop touching them — used by the SIGHUP live-update reload to surrender only aliases that actually went away (primary name change, alias removal) without disturbing names we're keeping.
