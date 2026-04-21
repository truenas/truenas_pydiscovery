# core/

NetBIOS name lifecycle state machines and local name registry.

- `nametable.py` — local name registry mapping `NetBIOSName` to IP addresses, NB flags, TTL, and registration state. Case-insensitive lookup via `NetBIOSName.__eq__`.
- `registrar.py` — name registration via broadcast. Sends 3 registration packets at 250ms intervals (RFC 1002). Tracks conflicts from negative responses.
- `defender.py` — name defense: when another node attempts to register or refresh a name we own, responds with `RCODE_ACT` (active error). Mirrors Samba's `nbt_register_own` / `nbt_refresh_own` behavior.
- `refresher.py` — periodic name refresh loop. Re-sends registration packets for all registered names at a fixed interval (default 15 minutes) to maintain network presence.
- `release.py` — clean name release on shutdown. Sends release packets (TTL=0) for all registered names so other nodes know we have left.
