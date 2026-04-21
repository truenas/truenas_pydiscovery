# query/

Query and response scheduling.

- `scheduler.py` — batches outgoing queries with ~100ms deferral, attaches known-answer records from cache for suppression, deduplicates repeated questions
- `responder.py` — handles incoming queries: looks up matching records in the registry, applies known-answer suppression, sends QU queries as immediate unicast, defers multicast responses by 20-120ms with jitter, suppresses if a peer already answered
