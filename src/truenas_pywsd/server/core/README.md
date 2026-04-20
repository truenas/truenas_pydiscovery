# core/

WSD protocol state machines and request handlers.

- `announcer.py` — sends Hello (startup) and Bye (shutdown) with SOAP-over-UDP retransmission: 4 repeats with 50-250ms jitter, doubling to 500ms max.
- `responder.py` — handles incoming Probe and Resolve messages. Responds with ProbeMatch (no XAddrs, client must Resolve) or ResolveMatch (with XAddrs for metadata endpoint). Random 0-500ms delay before responding per SOAP-over-UDP collision avoidance.
- `metadata.py` — handles HTTP Get requests on port 5357. Returns GetResponse with ThisDevice (FriendlyName), ThisModel (manufacturer, DeviceCategory), and Relationship (pub:Computer with hostname/workgroup or domain).
- `dedup.py` — message ID duplicate detection. Tracks last 10 MessageIDs to prevent processing retransmitted Probes multiple times.
