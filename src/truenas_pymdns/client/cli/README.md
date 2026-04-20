# cli/

mDNS client CLI tools. Send queries directly on the network -- no daemon required.

- `browse.py` — `mdns-browse`: discover services by type. `-a/--all` for all types, `-r/--resolve` to auto-resolve each result, `-t/--timeout` for duration, `-i/--interface` for source interface.
- `resolve.py` — `mdns-resolve`: `-n/--name hostname.local` for A/AAAA lookup, `-s/--service "Name" _type._tcp` for full service resolution (SRV+TXT+addresses), `-d/--domain` to override domain.
- `lookup.py` — `mdns-lookup NAME TYPE [DOMAIN]`: look up a named service instance (like `dns-sd -L`). Shows hostname:port and TXT records.
