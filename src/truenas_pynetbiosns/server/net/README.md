# net/

Network layer: broadcast UDP sockets and subnet resolution.

- `subnet.py` — `NbnsSubnet` dataclass plus `resolve_subnets`,
  which walks the configured ``interfaces`` tokens (names, bare
  IPv4 addresses, or CIDR blocks) and expands each to one
  concrete subnet record (interface name, local IPv4, netmask,
  broadcast).  Mirrors Samba's `source3/nmbd/nmbd_subnetdb.c`
  model so a single interface with two configured addresses
  yields two ``NbnsSubnet`` instances sharing one underlying
  ``NBNSTransport``.  IPv4 only; IPv6 isn't defined for NetBIOS
  over TCP/IP (RFC 1001/1002).
- `transport.py` — `NBNSTransport`: per-interface asyncio
  integration using `loop.add_reader()`.  Creates UDP sockets on
  port 137 (name service) and port 138 (datagram/browse).  Uses
  `SO_BROADCAST` for subnet broadcast instead of multicast.
  Provides `send_broadcast()`, `send_unicast()`, and
  `send_dgram_broadcast()` (the port-138 path consumed by
  `BrowseAnnouncer`).
