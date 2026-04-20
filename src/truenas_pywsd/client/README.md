# truenas_pywsd.client

WSD client tools. Send discovery queries directly via UDP multicast -- no daemon required.

- `query.py` — query engine: Probe via multicast, collect ProbeMatch responses, HTTP metadata fetch
- `cli/discover.py` — `wsd-discover`: probe for WSD devices, list endpoints and XAddrs. `-r` to auto-fetch metadata.
- `cli/info.py` — `wsd-info URL`: fetch device metadata (FriendlyName, Manufacturer, Computer/Workgroup) via HTTP Get
