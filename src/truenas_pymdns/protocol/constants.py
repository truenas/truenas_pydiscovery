"""mDNS protocol constants per RFC 6762 and RFC 6763.

References:
    RFC 6762 - Multicast DNS
    RFC 6763 - DNS-Based Service Discovery
    RFC 6760 - Requirements for a Protocol to Replace AppleTalk NBP
"""
from __future__ import annotations

from enum import IntEnum, IntFlag

# ---------------------------------------------------------------------------
# mDNS multicast addresses and port (RFC 6762 s3)
# ---------------------------------------------------------------------------

MDNS_PORT = 5353
MDNS_IPV4_GROUP = "224.0.0.251"
MDNS_IPV6_GROUP = "ff02::fb"
MDNS_IPV4_ADDR = (MDNS_IPV4_GROUP, MDNS_PORT)
MDNS_IPV6_ADDR = (MDNS_IPV6_GROUP, MDNS_PORT, 0, 0)

# ---------------------------------------------------------------------------
# DNS message header layout (RFC 1035 s4.1.1, used by RFC 6762)
#
#                                  1  1  1  1  1  1
#    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                      ID                       |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                    QDCOUNT                    |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                    ANCOUNT                    |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                    NSCOUNT                    |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                    ARCOUNT                    |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
# For mDNS (RFC 6762 s18.1):
#   - ID MUST be zero for multicast responses
#   - QR=0 for queries, QR=1 for responses
#   - AA MUST be set in responses
# ---------------------------------------------------------------------------

DNS_HEADER_SIZE = 12
DNS_MAX_NAME_LENGTH = 253
DNS_MAX_LABEL_LENGTH = 63
DNS_MAX_UDP_PAYLOAD = 9000

# ---------------------------------------------------------------------------
# Cache-flush bit (RFC 6762 s10.2)
#
# In mDNS responses, the top bit of the rrclass field is repurposed:
#   bit 15 = cache-flush (1 = flush stale records with same name+class)
#   bits 14-0 = actual rrclass value
#
# In queries, the top bit of the qclass field is the QU bit (RFC 6762 s5.4):
#   bit 15 = unicast-response requested
# ---------------------------------------------------------------------------

CLASS_CACHE_FLUSH = 0x8000

# ---------------------------------------------------------------------------
# TTL values (RFC 6762 s11)
#
# Records relating to hostnames (A, AAAA, SRV, reverse-PTR):
#   RFC recommends 120s; Apple mDNSResponder moved to 4500s to reduce
#   refresh chatter.  We use 1800s (30 min) as a middle ground — stale
#   entries clear reasonably fast while avoiding excessive queries.
#   The daemon sends goodbye + re-announce on SIGHUP, so stale entries
#   only matter on unclean shutdown.
# Other records (service PTR, TXT):
#   SHOULD use 75 minutes (4500s) since they change less frequently.
# ---------------------------------------------------------------------------

DEFAULT_TTL_HOST_RECORD = 1800   # A, AAAA, SRV, reverse PTR (30 min)
DEFAULT_TTL_OTHER_RECORD = 4500  # service PTR, TXT (75 minutes)

# ---------------------------------------------------------------------------
# Timing constants (RFC 6762 s5.2, s6, s8.1, s8.3)
# ---------------------------------------------------------------------------

# Probing (RFC 6762 s8.1): 3 probes, 250ms apart, random 0-250ms initial
PROBE_INTERVAL = 0.250
PROBE_COUNT = 3
PROBE_INITIAL_RANDOM_MAX = 0.250

# Simultaneous-probe defer (RFC 6762 s8.2): after losing a probe
# tiebreak, wait one second before re-probing the same name.  Gives a
# real competing peer time to finish its probing and answer back;
# stale echoed probes (from WiFi APs or Ethernet switches) go
# unanswered and the re-probe succeeds.  Matches Apple mDNSResponder's
# `m->SuppressProbes = timenow + mDNSPlatformOneSecond` in
# `ResolveSimultaneousProbe` (mDNSCore/mDNS.c).
SIMULTANEOUS_PROBE_DEFER = 1.0

# Stale-packet tolerance (RFC 6762 s8.2): on the first N probe
# conflicts for a given session, wait SIMULTANEOUS_PROBE_DEFER and
# retry with the same name.  Only on the (N+1)th conflict do we
# treat it as a real peer and rename per s9.  Matches Apple
# mDNSResponder's `kMaxAllowedMCastProbingConflicts` (mDNSCore/mDNS.c).
MAX_PROBING_CONFLICT_RETRIES = 1

# Announcing (RFC 6762 s8.3): at least 2 announcements, 1s apart, doubling
ANNOUNCE_INTERVAL_INITIAL = 1.0
ANNOUNCE_COUNT = 3

# Link-flap detection / throttling.  Mirrors Apple mDNSResponder's
# ``mDNS_RegisterInterface`` (mDNSCore/mDNS.c:14262-14273) which uses
# a longer probe delay and reduced announcement count for a flapping
# interface: *"In the case of a flapping interface, we pause for
# five seconds, and reduce the announcement count to one packet."*
LINK_FLAP_WINDOW = 10.0             # re-up within this = flap
LINK_FLAP_PROBE_DELAY = 5.0         # extended defer on flap
LINK_NORMAL_PROBE_DELAY = 0.5       # normal (mDNSPlatformOneSecond/2)
LINK_FLAP_ANNOUNCE_COUNT = 1        # single announcement on flap

# Goodbye (RFC 6762 s10.1): repeat for reliability against packet loss
# Apple mDNSResponder uses GoodbyeCount=3.
GOODBYE_COUNT = 3

# Maximum probe restarts before giving up (Apple: MAX_PROBE_RESTARTS=20)
MAX_PROBE_RESTARTS = 20

# Query deferral (RFC 6762 s5.2): 20-120ms random initial delay
QUERY_DEFER_MIN = 0.020
QUERY_DEFER_MAX = 0.120

# Response timing (RFC 6762 s6): 20-120ms for shared, up to 500ms aggregation
RESPONSE_DEFER_MIN = 0.020
RESPONSE_DEFER_MAX = 0.120
RESPONSE_AGGREGATION_MAX = 0.500

# Multicast rate limit (RFC 6762 s6): >= 1s between identical multicasts
MULTICAST_RATE_LIMIT = 1.0

# TC bit response delay (RFC 6762 s7.2): 400-500ms when TC set
TC_DEFER_MIN = 0.400
TC_DEFER_MAX = 0.500

# Conflict rate limiting (RFC 6762 s8.1):
#   If 15 conflicts in 10 seconds, wait 5 seconds before next probe
CONFLICT_RATE_WINDOW = 10.0
CONFLICT_RATE_MAX = 15
CONFLICT_RATE_BACKOFF = 5.0

# Legacy response TTL cap (RFC 6762 s6.7)
LEGACY_RESPONSE_TTL_CAP = 10

# Typical Ethernet MTU minus IP+UDP headers
MDNS_MAX_PACKET_SIZE = 1460

# RFC 6762 s11: multicast packets MUST have IP TTL / hop limit of 255
MDNS_TTL = 255

# Max TXT entry length (RFC 6763 s6.2): single length-prefixed string
TXT_MAX_ENTRY_LENGTH = 255

# Default maximum cache entries per interface
DEFAULT_CACHE_MAX_ENTRIES = 4096

# DNS name compression: max pointer offset is 14 bits (RFC 1035 s4.1.4)
DNS_COMPRESSION_MAX_OFFSET = 0x3FFF

# UDP receive buffer size for mDNS packets
MDNS_RECV_BUFSIZE = 9000

# recvmsg ancillary data buffer size (cmsg)
CMSG_BUFSIZE = 256

# Max valid port / SRV priority / SRV weight (16-bit unsigned)
MAX_UINT16 = 65535


# ---------------------------------------------------------------------------
# Record types (RFC 1035 s3.2.2, extensions)
# ---------------------------------------------------------------------------

class QType(IntEnum):
    """DNS record type codes."""
    A = 1        # IPv4 address (RFC 1035)
    NS = 2       # nameserver (RFC 1035)
    CNAME = 5    # canonical name (RFC 1035)
    SOA = 6      # start of authority (RFC 1035)
    PTR = 12     # domain name pointer (RFC 1035)
    HINFO = 13   # host information (RFC 1035)
    TXT = 16     # text strings (RFC 1035)
    AAAA = 28    # IPv6 address (RFC 3596)
    SRV = 33     # service locator (RFC 2782)
    NSEC = 47    # next secure (RFC 4034, used for negative responses)
    ANY = 255    # wildcard match (RFC 1035)


class QClass(IntEnum):
    """DNS record class codes."""
    IN = 1
    ANY = 255


class MDNSFlags(IntFlag):
    """Bitmask flags in the DNS message header (RFC 1035 s4.1.1)."""
    QR = 0x8000           # Query/Response
    OPCODE_MASK = 0x7800  # Opcode (4 bits)
    AA = 0x0400           # Authoritative Answer
    TC = 0x0200           # Truncated
    RD = 0x0100           # Recursion Desired
    RA = 0x0080           # Recursion Available
    Z = 0x0040            # Reserved
    AD = 0x0020           # Authentic Data
    CD = 0x0010           # Checking Disabled
    RCODE_MASK = 0x000F   # Response code (4 bits)


class EntryGroupState(IntEnum):
    """Lifecycle state of an entry group registration (RFC 6762 s8)."""
    UNCOMMITTED = 0
    REGISTERING = 1   # probing phase (s8.1)
    ESTABLISHED = 2   # probing succeeded, announced (s8.3)
    COLLISION = 3     # name conflict detected (s9)


class BrowserEvent(IntEnum):
    """Events emitted by a service browser."""
    NEW = 0
    REMOVE = 1
    CACHE_EXHAUSTED = 2
    ALL_FOR_NOW = 3
