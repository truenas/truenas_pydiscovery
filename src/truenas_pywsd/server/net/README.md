# net/

Network layer: multicast UDP transport and HTTP metadata server.

- `interface.py` — `resolve_interface(name)`: resolves interface name to OS index, IPv4 addresses (via ioctl), and link-local IPv6 addresses (from `/proc/net/if_inet6`). WSD uses both IPv4 and IPv6.
- `transport.py` — `WSDTransport`: per-interface multicast UDP sockets on port 3702. IPv4 joins 239.255.255.250, IPv6 joins ff02::c. Multicast TTL/hops = 1 (link-local scope). Uses `loop.add_reader()` for async receive.
- `http.py` — `WSDHttpServer`: async TCP server on port 5357 for WS-MetadataExchange. Uses `asyncio.start_server()`. Handles HTTP POST with SOAP body, routes to metadata handler, returns GetResponse. `server.py` binds one listener per advertised address — every IPv4 address and every link-local IPv6 address (the v6 bind carries the interface zone; the advertised XAddr stays zone-less) — so a peer that found us over IPv4 or over `ff02::c` can POST its Get to a reachable v4 / `[v6]` endpoint.
