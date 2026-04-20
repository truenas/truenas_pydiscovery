# service/

Service definition loading and authoritative record storage.

- `file_loader.py` — loads `.conf` files from the service directory. One file per service. Format:
  ```ini
  [service]
  type = _smb._tcp
  port = 445
  interfaces = eth0, eth1

  [txt]
  key = value
  ```
  Middleware writes these files; daemon reads them on startup and SIGHUP.

- `registry.py` — stores all entry groups the server is authoritative for. Handles lookup by name/type, ANY queries, and `_services._dns-sd._udp.local` meta-queries. Filters by interface when entry groups are interface-bound.
