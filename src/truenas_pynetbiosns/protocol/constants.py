"""NetBIOS Name Service protocol constants per RFC 1002.

References:
    RFC 1001 - Protocol Standard for a NetBIOS Service on a TCP/UDP Transport:
               Concepts and Methods
    RFC 1002 - Protocol Standard for a NetBIOS Service on a TCP/UDP Transport:
               Detailed Specifications
"""
from __future__ import annotations

from enum import IntEnum, IntFlag

# ---------------------------------------------------------------------------
# Ports (RFC 1002 s4.2)
# ---------------------------------------------------------------------------

NBNS_PORT = 137     # Name Service
DGRAM_PORT = 138    # Datagram Service

# ---------------------------------------------------------------------------
# Packet header (RFC 1002 s4.2.1)
#
#                                  1  1  1  1  1  1
#    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                 NAME_TRN_ID                   |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |R |  OPCODE   |AA|TC|RD|RA| 0| 0|B |   RCODE   |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                   QDCOUNT                     |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                   ANCOUNT                     |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                   NSCOUNT                     |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#  |                   ARCOUNT                     |
#  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# ---------------------------------------------------------------------------

NB_HEADER_SIZE = 12

# Header second-word bit layout (RFC 1002 s4.2.1.1):
#   R(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) 00 B(1) RCODE(4)
OPCODE_SHIFT = 11
OPCODE_MASK = 0x0F
RCODE_MASK = 0x0F
FLAGS_MASK = 0xFFF0       # Bits that are pure flags (R, AA, TC, RD, RA, B)
OPCODE_FIELD_MASK = OPCODE_MASK << OPCODE_SHIFT  # Opcode bits within flags word


# ---------------------------------------------------------------------------
# Opcodes (RFC 1002 s4.2.1.1)
# ---------------------------------------------------------------------------

class Opcode(IntEnum):
    """NetBIOS Name Service opcodes."""
    QUERY = 0               # Name query
    REGISTRATION = 5        # Name registration
    RELEASE = 6             # Name release
    WACK = 7                # Wait for acknowledgement
    REFRESH = 8             # Name refresh
    MULTIHOMED_REG = 15     # Multi-homed name registration


# ---------------------------------------------------------------------------
# Header flags (RFC 1002 s4.2.1.1)
# ---------------------------------------------------------------------------

class HeaderFlags(IntFlag):
    """Bitmask flags in the NB header second 16-bit word."""
    RESPONSE = 0x8000       # R: 1=response, 0=request
    AA = 0x0400             # Authoritative Answer
    TC = 0x0200             # Truncation
    RD = 0x0100             # Recursion Desired
    RA = 0x0080             # Recursion Available
    BROADCAST = 0x0010      # B: 1=broadcast, 0=unicast


# ---------------------------------------------------------------------------
# Response codes (RFC 1002 s4.2.6)
# ---------------------------------------------------------------------------

class Rcode(IntEnum):
    """Response codes in name service packets."""
    OK = 0x0
    FMT_ERR = 0x1       # Format error
    SRV_ERR = 0x2       # Server failure
    NAM_ERR = 0x3       # Name not found
    IMP_ERR = 0x4       # Unsupported request
    RFS_ERR = 0x5       # Refused
    ACT_ERR = 0x6       # Active error (name owned by another)
    CFT_ERR = 0x7       # Name in conflict


# ---------------------------------------------------------------------------
# Resource record types (RFC 1002 s4.2.1.2)
# ---------------------------------------------------------------------------

class RRType(IntEnum):
    """Resource record types."""
    A = 0x0001       # IP address (not typically used in NBNS)
    NS = 0x0002      # Name server
    NB = 0x0020      # NetBIOS general name service
    NBSTAT = 0x0021  # NetBIOS node status


class RRClass(IntEnum):
    """Resource record classes."""
    IN = 0x0001


# ---------------------------------------------------------------------------
# NB resource record flags (RFC 1002 s4.2.1.3)
#
# RDATA for NB records: 2-byte flags + 4-byte IP address
#
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |  G  |  ONT  |           RESERVED              |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   G = 1: group name, 0: unique name
#   ONT: owner node type (00=B, 01=P, 10=M, 11=reserved)
# ---------------------------------------------------------------------------

class NBFlag(IntFlag):
    """Flags in NB resource record rdata."""
    GROUP = 0x8000           # Group name (vs unique)
    ONT_P = 0x2000           # P-node
    ONT_M = 0x4000           # M-node
    ACTIVE = 0x0400          # Name is active


# ---------------------------------------------------------------------------
# NetBIOS name types (suffix byte)
#
# The 16th byte of a NetBIOS name indicates the service type.
# ---------------------------------------------------------------------------

class NameType(IntEnum):
    """Well-known NetBIOS name type suffixes."""
    WORKSTATION = 0x00       # Workstation service
    MESSENGER = 0x03         # Messenger service
    SERVER = 0x20            # File server service
    DOMAIN_MASTER = 0x1B     # Domain Master Browser
    DOMAIN_CONTROLLER = 0x1C  # Domain controller (group)
    LOCAL_MASTER = 0x1D      # Local Master Browser
    BROWSER_ELECTION = 0x1E  # Browser election (group)
    MASTER_BROWSER = 0x01    # Master Browser (__MSBROWSE__)


# ---------------------------------------------------------------------------
# NetBIOS name encoding constants (RFC 1002 s4.1)
# ---------------------------------------------------------------------------

NETBIOS_NAME_LENGTH = 15     # Max printable name length (padded with spaces)
NETBIOS_ENCODED_LENGTH = 32  # Half-ASCII encoded length (15+1 type) * 2
NETBIOS_LABEL_LENGTH = 0x20  # Length prefix byte for encoded name

# RFC 1002 §4.1 half-ASCII (first-level) encoding:
#   each source byte is split into two 4-bit nibbles and each nibble
#   is offset by 'A' (0x41) before being written.  Decoding subtracts
#   the same base.  NIBBLE_MASK isolates the low 4 bits.
NETBIOS_HALF_ASCII_BASE = 0x41
NETBIOS_NIBBLE_MASK = 0x0F

# DNS scope-label length limit (RFC 1035 §2.3.4) — NetBIOS scope
# labels are DNS-style; this is re-asserted here so name.py doesn't
# reach into the mDNS constants module.
DNS_MAX_LABEL_LENGTH = 63

# ---------------------------------------------------------------------------
# Timing constants (RFC 1002 s6 — DEFINED CONSTANTS)
# ---------------------------------------------------------------------------

# Name registration (RFC 1002 s6: BCAST_REQ_RETRY_COUNT, BCAST_REQ_RETRY_TIMEOUT)
REGISTRATION_RETRY_COUNT = 3
REGISTRATION_RETRY_INTERVAL = 0.250   # 250ms between retries

# Name refresh (RFC 1002 s6)
REFRESH_INTERVAL = 900                # 15 minutes (Samba default)
MAX_REFRESH_TIME = 3600               # 1 hour max TTL

# Name release
RELEASE_RETRY_COUNT = 1               # Single release packet

# Host announcements (port 138, MS-BRWS s3.2.6)
ANNOUNCE_INTERVAL_INITIAL = 60        # 1 minute
ANNOUNCE_INTERVAL_MAX = 720           # 12 minutes
ANNOUNCE_COUNT_STARTUP = 3            # Send 3 at startup

# Browser elections
ELECTION_DELAY = 0.100                # 100ms before responding

# Default TTL for broadcast registrations
DEFAULT_TTL = 0                       # 0 = permanent (B-node broadcast)

# Max UDP packet size for name service (RFC 1002 s6: MAX_DATAGRAM_LENGTH)
NBNS_MAX_PACKET_SIZE = 576

# ---------------------------------------------------------------------------
# Browse announcement types (port 138 mailslot payloads)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MS-BRWS mailslot payload layout (§2.2.1 / §2.2.3 / §2.2.6 / §2.2.19)
#
# Fixed on-wire values that appear in every browser announcement /
# election packet.  Collected here so the builders in
# server/browse/announcer.py don't carry magic numbers.
# ---------------------------------------------------------------------------

# §2.2.1: 16-bit little-endian sentinel at the fixed offset inside
# HostAnnouncement/DomainAnnouncement/LocalMasterAnnouncement payloads
# that Windows browsers validate.
BROWSE_SIGNATURE = 0xAA55

# §2.2.1: comment/server-string field is a null-terminated ASCII
# string with an implementation-defined cap; Windows uses 43 bytes
# of payload + 1 null terminator.
BROWSE_COMMENT_MAX = 43

# §2.2.1: browser protocol version carried in every announcement.
# We advertise 15.1 to match modern Windows behaviour (CIFS era).
BROWSER_VERSION_MAJOR = 15
BROWSER_VERSION_MINOR = 1

# §2.2.1: operating-system identification bytes.  We impersonate
# Windows XP (5.1) since that's the baseline most browser peers
# still recognise.
BROWSE_OS_MAJOR = 5
BROWSE_OS_MINOR = 1

# §2.2.6: default HostAnnouncement / LocalMasterAnnouncement
# periodicity after the startup burst — 12 minutes in milliseconds.
BROWSE_ANNOUNCE_PERIODICITY_DEFAULT_MS = ANNOUNCE_INTERVAL_MAX * 1000

# §2.2.19 ElectionRequest "Criteria" bitfield default.  We claim a
# middling role (Windows-Server revision | NT-Server | Potential
# Browser) so we lose elections to real Master Browsers but still
# beat workstations; see the docstring on ``build_election_request``.
BROWSE_ELECTION_CRITERIA_DEFAULT = 0x20010F03


class BrowseOpcode(IntEnum):
    """Opcodes in browse mailslot messages."""
    HOST_ANNOUNCEMENT = 0x01
    ANNOUNCEMENT_REQUEST = 0x02
    ELECTION_REQUEST = 0x08
    GETBACKUP_LIST_REQ = 0x09
    GETBACKUP_LIST_RESP = 0x0A
    BECOME_BACKUP = 0x0B
    DOMAIN_ANNOUNCEMENT = 0x0C
    MASTER_ANNOUNCEMENT = 0x0D
    LOCAL_MASTER_ANNOUNCEMENT = 0x0F


# ---------------------------------------------------------------------------
# Server type flags (used in browse announcements)
# ---------------------------------------------------------------------------

class ServerType(IntFlag):
    """Server type flags in host announcements."""
    WORKSTATION = 0x00000001
    SERVER = 0x00000002
    SQLSERVER = 0x00000004
    DOMAIN_CTRL = 0x00000008
    DOMAIN_BAKCTRL = 0x00000010
    TIME_SOURCE = 0x00000020
    AFP = 0x00000040
    NOVELL = 0x00000080
    DOMAIN_MEMBER = 0x00000100
    PRINT_QUEUE = 0x00000200
    DIALIN_SERVER = 0x00000400
    XENIX_SERVER = 0x00000800
    NT = 0x00001000
    WFW = 0x00002000
    POTENTIAL_BROWSER = 0x00010000
    BACKUP_BROWSER = 0x00020000
    MASTER_BROWSER = 0x00040000
    DOMAIN_MASTER = 0x00080000
    LOCAL_LIST_ONLY = 0x40000000
    DOMAIN_ENUM = 0x80000000
