# truenas_pywsd.client

WSD client tools. Send discovery queries directly via UDP multicast -- no daemon required.

- `query.py` — query engine:
  - `discover_devices()` — multicast Probe on UDP 3702, collects ProbeMatch / ResolveMatch / Hello responses for a timeout window.
  - `resolve_endpoint(uuid)` — multicast Resolve targeting a specific endpoint; used when a peer's ProbeMatch omits `<wsd:XAddrs>` so the client still ends up with a transport URL.
  - `fetch_metadata(url, endpoint=...)` — HTTP POST of WS-Transfer Get on TCP 5357; parses Content-Length + reads the body exactly, surfaces SOAP faults as `fault` / `fault_reason` keys in the returned dict. Sends `wsa:ReplyTo = anonymous` (Windows WSDAPI rejects Gets without it) and uses the endpoint URN for `wsa:To` (auto-derived from the XAddrs URL when not supplied; Windows dispatches on that header).
  - `endpoint_urn_from_xaddrs(url)` — helper that derives `urn:uuid:UUID` from a DPWS XAddrs URL, or returns the URL unchanged when the path isn't a UUID.
- `cli/discover.py` — `wsd-discover`: probe for WSD devices, list endpoints and XAddrs. `-r` resolves missing XAddrs via Resolve and auto-fetches metadata.
- `cli/info.py` — `wsd-info URL`: fetch device metadata (FriendlyName, Manufacturer, Computer/Workgroup) via HTTP Get
