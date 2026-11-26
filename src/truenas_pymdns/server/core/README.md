# core/

mDNS protocol state machines and record management.

- `entry_group.py` — atomic service registration. Creates PTR+SRV+TXT+meta-PTR records for a service. State machine: UNCOMMITTED → REGISTERING → ESTABLISHED | COLLISION.
- `prober.py` — probing state machine per RFC 6762 s8. Sends 3 probes at 250ms intervals. A response naming a probed name, once the first probe is out, is a conflict whatever its rdata (s8.1); a simultaneous probe for the name is settled by lexicographic tiebreak (s8.2); records the host publishes itself, on any interface, never count (s9, s14).
- `announcer.py` — sends 3 announcements at doubling intervals (1s, 2s, 4s) with cache-flush bit set
- `conflict.py` — lexicographic record comparison for probe tiebreaking (RFC 6762 s8.2) and alternative name generation
- `goodbye.py` — sends TTL=0 records on shutdown so remote caches expire immediately
