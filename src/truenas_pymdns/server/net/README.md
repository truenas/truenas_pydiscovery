# net/

Network layer: multicast sockets, interface resolution, asyncio transport.

- `multicast.py` — socket factory functions for IPv4/IPv6 mDNS. Sets `SO_REUSEADDR`, `IP_MULTICAST_TTL=255`, `SO_BINDTODEVICE`, `IP_RECVTTL`. Join/leave group helpers.
- `interface.py` — `resolve_interface(name)`: resolves an interface name to its OS index via `socket.if_nametoindex()`, gets IPv4 address via ioctl, gets IPv6 addresses from `/proc/net/if_inet6`. No monitoring, no classes.
- `transport.py` — `MDNSTransport`: per-interface asyncio integration using `loop.add_reader()` + `sock.recvmsg()` (not `create_datagram_endpoint`) because we need ancillary data for TTL=255 validation per RFC 6762 s11.
- `link_monitor.py` — `LinkMonitor`: opens an `AF_NETLINK` / `NETLINK_ROUTE` socket bound to `RTMGRP_LINK`, parses `RTM_NEWLINK`/`RTM_DELLINK` frames, fires an async callback on DOWN→UP transitions. Drives re-probing on cable replug (RFC 6762 §8.3 / §13, BCT II.17). Mirrors Apple mDNSResponder tag `mDNSResponder-2881.0.25` Linux netlink subscription at `mDNSPosix/mDNSPosix.c:1620`.
