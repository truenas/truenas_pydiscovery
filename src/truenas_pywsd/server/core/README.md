# core/

WSD protocol state machines and request handlers.

- `announcer.py` — sends Hello (startup) and Bye (shutdown) with SOAP-over-UDP retransmission: 4 repeats with 50-250ms jitter, doubling to 500ms max.
- `responder.py` — handles incoming Probe and Resolve messages. ProbeMatch and ResolveMatch both carry XAddrs inline (matches Windows WSDAPI so peers POST the metadata Get without a follow-up Resolve round-trip). `<wsa:To>` on the unicast response is the anonymous URI per WS-Addressing 1.0 §3.1. MetadataVersion is read from a server-provided callable at response-build time so SIGHUP-driven metadata bumps propagate without rebuilding the responder. Random 0-500ms delay before responding per SOAP-over-UDP collision avoidance.
- `metadata.py` — handles HTTP Get requests on port 5357. Returns GetResponse with ThisDevice (FriendlyName), ThisModel (manufacturer, DeviceCategory), and Relationship (pub:Computer with hostname/workgroup or domain). `MetadataHandler.update_workgroup(workgroup_or_domain, is_domain)` swaps the published workgroup/domain in place so the WSD live-update reload path doesn't have to rebuild the handler.
- `dedup.py` — message ID duplicate detection. Tracks last 10 MessageIDs to prevent processing retransmitted Probes multiple times.
