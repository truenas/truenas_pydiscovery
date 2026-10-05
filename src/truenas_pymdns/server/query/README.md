# query/

Incoming query handling and response scheduling.

- `responder.py` — handles incoming queries: looks up matching records in the registry, applies known-answer suppression, sends QU queries as immediate unicast, defers multicast responses by 20-120ms with jitter, suppresses if a peer already answered
