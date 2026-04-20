# truenas_pynetbiosns.client

NetBIOS Name Service client tools. Send queries directly via UDP broadcast -- no daemon required.

- `query.py` — query engine: ephemeral broadcast socket, send/receive NBT messages
- `cli/lookup.py` — `nbt-lookup NAME`: resolve a NetBIOS name to IP addresses (like `nmblookup`)
- `cli/status.py` — `nbt-status HOST`: query node status, list all registered names (like `nbtstat -a`)
