# query/

Name query and node status response handling.

- `responder.py` — answers incoming name queries (NB type) by looking up the name table and sending a positive response with our IP address. Group names respond with 255.255.255.255 per RFC 1002. Also handles NBSTAT (node status) queries by returning all registered names with their flags.
