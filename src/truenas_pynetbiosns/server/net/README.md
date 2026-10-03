# net/

Network layer: broadcast UDP sockets and subnet resolution.

- `subnet.py` — `NbnsSubnet` dataclass plus `resolve_subnets`,
  which walks the configured ``interfaces`` tokens (names, bare
  IPv4 addresses, or CIDR blocks) and expands each to one
  concrete subnet record (interface name, local IPv4, netmask,
  broadcast).  Mirrors Samba's `source3/nmbd/nmbd_subnetdb.c`
  model so a single interface with two configured addresses
  yields two ``NbnsSubnet`` instances sharing one underlying
  ``NBNSTransport``.  A token that matches no local IPv4 address
  is skipped with a warning, as Samba's ``interpret_interface``
  skips it; the server resolves the tokens again on every reload.
  IPv4 only; IPv6 isn't defined for NetBIOS over TCP/IP
  (RFC 1001/1002).
- `transport.py` — `NBNSTransport`: per-interface asyncio
  integration using `loop.add_reader()`.  Creates UDP sockets on
  port 137 (name service) and port 138 (datagram/browse).  Uses
  `SO_BROADCAST` for subnet broadcast instead of multicast.
  Provides `send_broadcast()`, `send_unicast()`, and
  `send_dgram()` (the port-138 path consumed by `BrowseAnnouncer`).
  Every subnet on an interface shares its transport, so the server
  addresses each subnet's broadcasts to that subnet's broadcast
  address.
- `global_receiver.py` — `NBNSGlobalReceiver`: the daemon-wide
  ``0.0.0.0`` socket on port 137 (Samba's ``ClientNMB``), dispatching
  by source subnet.  The port-138 socket (``ClientDGRAM``) opens only
  when a datagram handler is passed, and `NBNSServer` passes none.
- `dedup.py` — `PacketDedup`: a subnet broadcast reaches both the
  subnet's broadcast socket and the global receiver; the dispatcher
  drops the second copy, as Samba's ``is_processed_packet`` does.
