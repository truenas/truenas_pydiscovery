# core/

mDNS protocol state machines and record management.

- `cache.py` — per-interface record cache with TTL expiry, cache-flush bit handling (RFC 6762 s10.2), POOF tracking, and known-answer suppression support
- `entry_group.py` — atomic service registration. Creates PTR+SRV+TXT+meta-PTR records for a service. State machine: UNCOMMITTED → REGISTERING → ESTABLISHED | COLLISION.
- `prober.py` — probing state machine per RFC 6762 s8. Sends 3 probes at 250ms intervals, handles conflict detection via lexicographic comparison.
- `announcer.py` — sends 3 announcements at doubling intervals (1s, 2s, 4s) with cache-flush bit set
- `conflict.py` — lexicographic record comparison for probe tiebreaking (RFC 6762 s8.2) and alternative name generation
- `goodbye.py` — sends TTL=0 records on shutdown so remote caches expire immediately
