# net/

Network layer: multicast sockets, interface resolution, asyncio transport.

- `multicast.py` — socket factory functions for IPv4/IPv6 mDNS. Sets `IP_MULTICAST_TTL=255`, `SO_BINDTODEVICE`, `IP_RECVTTL`; `SO_REUSEADDR`/`SO_REUSEPORT` only when `disallow-other-stacks` is off (default is an exclusive 5353 bind, the inverse of avahi's default). Join/leave group helpers.
- `interface.py` — `resolve_interface(name)`: resolves an interface name to its OS index via `socket.if_nametoindex()` and its addresses through `truenas_pydiscovery_utils.netlink_addr.enumerate_addresses`. Interface and address changes are watched by the composite daemon's `InterfaceMonitor` (`truenas_pydiscovery_utils.interface_monitor`), which calls `MDNSServer._on_link_up` and `_reconcile_interfaces`.
- `transport.py` — `MDNSTransport`: per-interface asyncio integration using `loop.add_reader()` + `sock.recvmsg()` (not `create_datagram_endpoint`) because we need ancillary data for TTL=255 validation per RFC 6762 s11. Datagrams whose OPCODE or RCODE is non-zero are ignored on reception (RFC 6762 §18.3 / §18.11) before the query/response split.
