"""WS-Discovery protocol constants.

References:
    WS-Discovery 1.1 (OASIS)
    SOAP-over-UDP 1.1 (OASIS)
    WS-Addressing 1.0 (W3C)
    Devices Profile for Web Services (WSDP)
    MS-PBSD — Pub/Sub Device Protocol
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

# ---------------------------------------------------------------------------
# Ports and multicast addresses (WS-Discovery 1.1 s3.1.1)
# ---------------------------------------------------------------------------

WSD_UDP_PORT = 3702
WSD_HTTP_PORT = 5357

WSD_MCAST_V4 = "239.255.255.250"
WSD_MCAST_V6 = "ff02::c"

WSD_MCAST_V4_ADDR = (WSD_MCAST_V4, WSD_UDP_PORT)
WSD_MCAST_V6_ADDR = (WSD_MCAST_V6, WSD_UDP_PORT, 0, 0)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

WSD_MAX_LEN = 32767
WSD_MAX_KNOWN_MESSAGES = 10

# ---------------------------------------------------------------------------
# SOAP-over-UDP retransmission (OASIS SOAP-over-UDP 1.1 s3.4 + Appendix A)
# ---------------------------------------------------------------------------

# Total sends (initial + retransmissions).  Spec Appendix A defaults
# are 2/1 retransmissions (3/2 total) but those are non-normative;
# we send one extra multicast for reliability on busy networks.
MULTICAST_UDP_REPEAT = 4    # spec default: 3 total
UNICAST_UDP_REPEAT = 2      # spec default: 2 total
UDP_MIN_DELAY = 0.050       # 50ms
UDP_MAX_DELAY = 0.250       # 250ms
UDP_UPPER_DELAY = 0.500     # 500ms max backoff

# ---------------------------------------------------------------------------
# WS-Discovery timing (WS-Discovery 1.1 s5)
# ---------------------------------------------------------------------------

PROBE_TIMEOUT = 4.0
MAX_STARTUP_PROBE_DELAY = 3.0

# HTTP read deadline for the metadata exchange endpoint (port 5357).
# RFC 9110 / RFC 9112 don't mandate a specific timeout; 10 seconds is
# long enough for healthy peers to post a SOAP Get over a slow LAN
# and short enough that a silent peer is reaped quickly.
HTTP_REQUEST_TIMEOUT_S = 10.0

# ---------------------------------------------------------------------------
# XML Namespaces
# ---------------------------------------------------------------------------


class Namespace(StrEnum):
    """XML namespace URIs used in WSD SOAP messages."""
    SOAP = "http://www.w3.org/2003/05/soap-envelope"
    WSA = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
    WSD = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
    WSX = "http://schemas.xmlsoap.org/ws/2004/09/mex"
    WSDP = "http://schemas.xmlsoap.org/ws/2006/02/devprof"
    PUB = "http://schemas.microsoft.com/windows/pub/2005/07"
    PNPX = "http://schemas.microsoft.com/windows/pnpx/2005/10"


class Prefix(StrEnum):
    """XML namespace prefixes."""
    SOAP = "soap"
    WSA = "wsa"
    WSD = "wsd"
    WSX = "wsx"
    WSDP = "wsdp"
    PUB = "pub"
    PNPX = "pnpx"


# Namespace prefix map (for ElementTree serialization)
NS_MAP: Mapping[str, str] = MappingProxyType({
    Prefix.SOAP: Namespace.SOAP,
    Prefix.WSA: Namespace.WSA,
    Prefix.WSD: Namespace.WSD,
    Prefix.WSX: Namespace.WSX,
    Prefix.WSDP: Namespace.WSDP,
    Prefix.PUB: Namespace.PUB,
    Prefix.PNPX: Namespace.PNPX,
})

# ---------------------------------------------------------------------------
# WS-Addressing well-known URIs
# ---------------------------------------------------------------------------


class WellKnownURI(StrEnum):
    """WS-Addressing and WS-Discovery well-known URIs."""
    WSA_ANONYMOUS = (
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
    )
    WSA_DISCOVERY = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"


# URN prefix for endpoint references
URN_PREFIX = "urn:uuid:"


def urn_uuid(endpoint_uuid: str) -> str:
    """Format an endpoint UUID as a URN."""
    return f"{URN_PREFIX}{endpoint_uuid}"


# ---------------------------------------------------------------------------
# WS-Discovery action URIs
# ---------------------------------------------------------------------------


class Action(StrEnum):
    """SOAP Action URIs for WS-Discovery and WS-Transfer messages."""
    HELLO = f"{Namespace.WSD}/Hello"
    BYE = f"{Namespace.WSD}/Bye"
    PROBE = f"{Namespace.WSD}/Probe"
    PROBE_MATCHES = f"{Namespace.WSD}/ProbeMatches"
    RESOLVE = f"{Namespace.WSD}/Resolve"
    RESOLVE_MATCHES = f"{Namespace.WSD}/ResolveMatches"
    GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
    GET_RESPONSE = (
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
    )
    # WS-Addressing 1.0 §6.5 fault action — peers emit this when
    # rejecting a request (e.g. WSDAPI returns
    # ``wsa:DestinationUnreachable`` with this action if
    # ``<wsa:To>`` doesn't match any registered endpoint).
    FAULT = f"{Namespace.WSA}/fault"


# ---------------------------------------------------------------------------
# Device types
# ---------------------------------------------------------------------------


class DeviceType(StrEnum):
    """WSD device type identifiers."""
    DEVICE = "wsdp:Device"
    COMPUTER = "pub:Computer"


WSD_DEVICE_TYPES = f"{DeviceType.DEVICE} {DeviceType.COMPUTER}"

# ---------------------------------------------------------------------------
# Metadata dialects (WSDP)
# ---------------------------------------------------------------------------


class MetadataDialect(StrEnum):
    """WSDP metadata section dialect URIs."""
    THIS_DEVICE = f"{Namespace.WSDP}/ThisDevice"
    THIS_MODEL = f"{Namespace.WSDP}/ThisModel"
    RELATIONSHIP = f"{Namespace.WSDP}/Relationship"


RELATIONSHIP_HOST = f"{Namespace.WSDP}/host"

# ---------------------------------------------------------------------------
# XML element local names (used with qname())
# ---------------------------------------------------------------------------


class Element(StrEnum):
    """Local names for XML elements used in WSD messages."""
    # SOAP
    ENVELOPE = "Envelope"
    HEADER = "Header"
    BODY = "Body"
    # WS-Addressing
    TO = "To"
    ACTION = "Action"
    MESSAGE_ID = "MessageID"
    RELATES_TO = "RelatesTo"
    ADDRESS = "Address"
    ENDPOINT_REFERENCE = "EndpointReference"
    REPLY_TO = "ReplyTo"
    FROM = "From"
    # WS-Discovery
    HELLO = "Hello"
    BYE = "Bye"
    PROBE = "Probe"
    PROBE_MATCHES = "ProbeMatches"
    PROBE_MATCH = "ProbeMatch"
    RESOLVE = "Resolve"
    RESOLVE_MATCHES = "ResolveMatches"
    RESOLVE_MATCH = "ResolveMatch"
    TYPES = "Types"
    XADDRS = "XAddrs"
    METADATA_VERSION = "MetadataVersion"
    APP_SEQUENCE = "AppSequence"
    # WS-MetadataExchange
    METADATA = "Metadata"
    METADATA_SECTION = "MetadataSection"
    # WSDP
    THIS_DEVICE = "ThisDevice"
    THIS_MODEL = "ThisModel"
    FRIENDLY_NAME = "FriendlyName"
    FIRMWARE_VERSION = "FirmwareVersion"
    SERIAL_NUMBER = "SerialNumber"
    MANUFACTURER = "Manufacturer"
    MODEL_NAME = "ModelName"
    RELATIONSHIP = "Relationship"
    HOST = "Host"
    SERVICE_ID = "ServiceId"
    SCOPES = "Scopes"
    # PNPX
    DEVICE_CATEGORY = "DeviceCategory"
    # PUB
    COMPUTER = "Computer"
    # SOAP Fault (both SOAP 1.1 and 1.2 share these local names
    # for Code/Subcode Value and Reason Text)
    FAULT = "Fault"
    CODE = "Code"
    SUBCODE = "Subcode"
    VALUE = "Value"
    REASON = "Reason"
    TEXT = "Text"


class Attribute(StrEnum):
    """XML attribute names used in WSD messages."""
    DIALECT = "Dialect"
    TYPE = "Type"
    INSTANCE_ID = "InstanceId"
    SEQUENCE_ID = "SequenceId"
    MESSAGE_NUMBER = "MessageNumber"


class MembershipLabel(StrEnum):
    """Labels for pub:Computer membership advertisement."""
    DOMAIN = "Domain"
    WORKGROUP = "Workgroup"


# ---------------------------------------------------------------------------
# Device metadata defaults
# ---------------------------------------------------------------------------


class DeviceMetadata(StrEnum):
    """Default values for device metadata fields."""
    MANUFACTURER = "TrueNAS"
    MODEL_NAME = "TrueNAS"
    DEVICE_CATEGORY = "Computers"
    FIRMWARE_VERSION = "1.0"
    SERIAL_NUMBER = "1"
    FRIENDLY_NAME_PREFIX = "WSD Device"
