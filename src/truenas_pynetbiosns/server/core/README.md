# core/

NetBIOS name lifecycle state machines and local name registry.

- `nametable.py` — local name registry mapping `NetBIOSName` to IP addresses, NB flags, TTL, and registration state. Case-insensitive lookup via `NetBIOSName.__eq__`.
- `registrar.py` — name registration via broadcast. Broadcasts one registration request and resends it 3 times, each transmission followed by a 1 s wait, as Samba nmbd does (`make_response_record`, `register_name_timeout_response`), and stops at the first negative response whose NAME_TRN_ID matches the request's; other responses are ignored.
- `defender.py` — name defense: when another node attempts to register or refresh a name we own, responds with `RCODE_ACT` (active error). Mirrors Samba's `nbt_register_own` / `nbt_refresh_own` behavior.
- `release.py` — name release for names given up while running. `release_names()` takes a set of `(name, name_type, is_group)` tuples and releases only matching entries (TTL=0 broadcast), pulling them from the name table so the responder stops answering for them — used by the SIGHUP live-update reload to surrender only names that actually went away (primary name change, alias removal) without disturbing names we're keeping. Nothing is released at shutdown: Samba nmbd's `terminate` releases only names registered with a WINS server.

Names are not refreshed: nmbd refreshes only names registered with a WINS server (`refresh_my_names`), and RFC 1001 §15.5.1 leaves refresh to P and M nodes.
