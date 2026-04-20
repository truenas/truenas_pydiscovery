# truenas_pymdns.client

mDNS client tools that send queries directly on the network using
QU (unicast-response) on an ephemeral port.  No daemon required.

- `__main__.py` — dispatcher for `python -m truenas_pymdns.client {browse|resolve|lookup}`
- `query.py` — one-shot multicast query engine.  Creates UDP
  sockets, sends QU queries, collects unicast responses.  Provides
  `create_query_socket`, `send_query`, `collect_responses`,
  `one_shot_query`, and extract helpers (`extract_ptr_targets`,
  `extract_service_info`, `extract_addresses`).  `ServiceInfo.txt`
  keys are normalised to lowercase (RFC 6763 §6.6).
- `browser.py` — programmatic continuous-discovery `Browser`
  class.  Async context manager whose iterator yields
  `BrowserEvent.NEW` / `REMOVE` / `ALL_FOR_NOW` `BrowserResult`
  objects; analogous to Avahi's `AvahiServiceBrowser` / Bonjour's
  `DNSServiceBrowse`.  Higher-level API for apps that want to
  subscribe rather than poll.

## Subpackages

- [cli/](cli/README.md) — `mdns-browse`, `mdns-resolve`, and
  `mdns-lookup` commands
