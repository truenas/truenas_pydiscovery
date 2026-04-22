"""WS-Discovery message builders and parsers.

Builds the body elements for Hello, Bye, Probe, ProbeMatch,
Resolve, ResolveMatch, and the HTTP Get/GetResponse metadata.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit

from .constants import (
    Action,
    Attribute,
    DeviceMetadata,
    DeviceType,
    Element,
    MembershipLabel,
    MetadataDialect,
    Namespace,
    Prefix,
    RELATIONSHIP_HOST,
    WSD_DEVICE_TYPES,
    WellKnownURI,
    urn_uuid,
)
from .namespaces import qname, qname_ns
from .soap import build_envelope


def _append_endpoint_reference(
    parent: ET.Element, endpoint_uuid: str,
) -> None:
    """Append a ``<wsa:EndpointReference>`` subtree to *parent*.

    WS-Addressing 1.0 §2.1 defines the EndpointReferenceType as an
    XML element containing a child ``<wsa:Address>`` URI.  Every
    WS-Discovery announcement and match message carries an EPR for
    the target service using the ``urn:uuid:…`` scheme (RFC 4122).
    Four WSD builders need this exact shape (Hello §4.1, Bye §4.2,
    ProbeMatch §5.3, ResolveMatch §6.3) — centralising the
    construction here keeps them in lock-step if the EPR format
    ever grows additional optional fields (ReferenceParameters,
    Metadata, etc.) that WS-Addressing allows.
    """
    epr = ET.SubElement(
        parent, qname(Prefix.WSA, Element.ENDPOINT_REFERENCE),
    )
    ET.SubElement(epr, qname(Prefix.WSA, Element.ADDRESS)).text = (
        urn_uuid(endpoint_uuid)
    )


# ---------------------------------------------------------------------------
# Hello / Bye
# ---------------------------------------------------------------------------

def build_hello(
    endpoint_uuid: str,
    xaddrs: str,
    metadata_version: int = 1,
    app_sequence: int = 0,
    message_number: int = 1,
) -> bytes:
    """Build a Hello announcement message (WS-Discovery 1.1 s4.1)."""
    hello = ET.Element(qname(Prefix.WSD, Element.HELLO))
    _append_endpoint_reference(hello, endpoint_uuid)
    ET.SubElement(hello, qname(Prefix.WSD, Element.TYPES)).text = WSD_DEVICE_TYPES
    ET.SubElement(hello, qname(Prefix.WSD, Element.XADDRS)).text = xaddrs
    ET.SubElement(hello, qname(Prefix.WSD, Element.METADATA_VERSION)).text = (
        str(metadata_version)
    )
    return build_envelope(
        Action.HELLO, hello,
        app_sequence=app_sequence, message_number=message_number,
    )


def build_bye(
    endpoint_uuid: str,
    app_sequence: int = 0,
    message_number: int = 1,
) -> bytes:
    """Build a Bye announcement message (WS-Discovery 1.1 s4.2)."""
    bye = ET.Element(qname(Prefix.WSD, Element.BYE))
    _append_endpoint_reference(bye, endpoint_uuid)
    return build_envelope(
        Action.BYE, bye,
        app_sequence=app_sequence, message_number=message_number,
    )


# ---------------------------------------------------------------------------
# ProbeMatch / ResolveMatch
# ---------------------------------------------------------------------------

def build_probe_match(
    endpoint_uuid: str,
    relates_to: str,
    xaddrs: str = "",
    metadata_version: int = 1,
) -> bytes:
    """Build a ProbeMatches response (WS-Discovery 1.1 s5.3).

    Sent unicast to the Probe originator.  ``<wsa:To>`` is the
    anonymous URI — WS-Addressing 1.0 §3.1 says a reply uses the
    request's ``ReplyTo`` (or anonymous if omitted), and the
    multicast-group URN (``WSA_DISCOVERY``) is only appropriate
    for messages actually addressed to the group.

    *xaddrs* is the transport URL set; when non-empty, emitted as
    ``<wsd:XAddrs>``.  WS-Discovery §5.3 permits XAddrs in a
    ProbeMatch as a SHOULD, and Windows WSDAPI includes it so peers
    can POST the metadata Get without a follow-up multicast
    Resolve — one round-trip per discovery instead of two."""
    matches = ET.Element(qname(Prefix.WSD, Element.PROBE_MATCHES))
    match = ET.SubElement(matches, qname(Prefix.WSD, Element.PROBE_MATCH))
    _append_endpoint_reference(match, endpoint_uuid)
    ET.SubElement(match, qname(Prefix.WSD, Element.TYPES)).text = WSD_DEVICE_TYPES
    if xaddrs:
        ET.SubElement(match, qname(Prefix.WSD, Element.XADDRS)).text = xaddrs
    ET.SubElement(match, qname(Prefix.WSD, Element.METADATA_VERSION)).text = (
        str(metadata_version)
    )
    return build_envelope(
        Action.PROBE_MATCHES, matches, relates_to=relates_to,
        to=WellKnownURI.WSA_ANONYMOUS,
    )


def build_resolve_match(
    endpoint_uuid: str,
    xaddrs: str,
    relates_to: str,
    metadata_version: int = 1,
) -> bytes:
    """Build a ResolveMatches response (WS-Discovery 1.1 s6.3).

    Sent unicast to the Resolve originator; ``<wsa:To>`` uses the
    anonymous URI for the same reason as ``build_probe_match``."""
    matches = ET.Element(qname(Prefix.WSD, Element.RESOLVE_MATCHES))
    match = ET.SubElement(matches, qname(Prefix.WSD, Element.RESOLVE_MATCH))
    _append_endpoint_reference(match, endpoint_uuid)
    ET.SubElement(match, qname(Prefix.WSD, Element.TYPES)).text = WSD_DEVICE_TYPES
    ET.SubElement(match, qname(Prefix.WSD, Element.XADDRS)).text = xaddrs
    ET.SubElement(match, qname(Prefix.WSD, Element.METADATA_VERSION)).text = (
        str(metadata_version)
    )
    return build_envelope(
        Action.RESOLVE_MATCHES, matches, relates_to=relates_to,
        to=WellKnownURI.WSA_ANONYMOUS,
    )


# ---------------------------------------------------------------------------
# Probe / Resolve parsing
# ---------------------------------------------------------------------------

def parse_probe_types(body: ET.Element | None) -> list[str]:
    """Extract the Types list from a Probe body element (WS-Discovery 1.1 s5.1)."""
    if body is None:
        return []
    probe = body.find(qname(Prefix.WSD, Element.PROBE))
    if probe is None:
        return []
    types_el = probe.find(qname(Prefix.WSD, Element.TYPES))
    if types_el is None or not types_el.text:
        return []
    return types_el.text.split()


def parse_probe_scopes(body: ET.Element | None) -> list[str]:
    """Extract the Scopes list from a Probe body element.

    WS-Discovery 1.1 §5.1: a Probe MAY include a ``<wsd:Scopes>``
    element containing zero or more whitespace-separated URIs that
    the sender wants the responder's scopes to match.  Returns the
    list of scope URIs (empty list if none were specified).
    """
    if body is None:
        return []
    probe = body.find(qname(Prefix.WSD, Element.PROBE))
    if probe is None:
        return []
    scopes_el = probe.find(qname(Prefix.WSD, Element.SCOPES))
    if scopes_el is None or not scopes_el.text:
        return []
    return scopes_el.text.split()


def scope_matches(
    probe_scopes: list[str], target_scopes: list[str],
) -> bool:
    """RFC 3986 / WS-Discovery 1.1 §5.1 RFC3986 matching rule.

    The default MatchBy is the RFC3986 string-prefix rule: every
    scope URI in the probe must be a prefix of some scope URI in
    the target, where the comparison is the canonicalised RFC 3986
    URI form (scheme lower-cased, path segments compared exactly).

    Implemented pragmatically: lower-case the scheme/authority and
    require exact string-prefix match on the full canonical URI.
    Returns True if every ``probe_scopes`` entry prefix-matches at
    least one ``target_scopes`` entry.  An empty ``probe_scopes``
    list is treated as "match everything" per the spec.
    """
    if not probe_scopes:
        return True
    targets = [_canonicalise_uri(t) for t in target_scopes]
    for p in probe_scopes:
        pc = _canonicalise_uri(p)
        if not any(t == pc or t.startswith(pc + "/") for t in targets):
            return False
    return True


def _canonicalise_uri(uri: str) -> str:
    """Lower-case scheme+authority and strip trailing slashes.

    This is a simplified RFC 3986 canonical form good enough for
    prefix matching of typical WSD scope URIs like
    ``http://example.com/...`` or ``urn:...`` tags."""
    parts = urlsplit(uri)
    if parts.scheme and parts.netloc:
        canon = urlunsplit((
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path.rstrip("/"),
            parts.query,
            parts.fragment,
        ))
    else:
        # URN or other opaque — lowercase the scheme portion only.
        canon = uri
        if ":" in canon:
            scheme, rest = canon.split(":", 1)
            canon = f"{scheme.lower()}:{rest}"
    return canon


def parse_resolve_endpoint(body: ET.Element | None) -> str:
    """Extract the endpoint address from a Resolve body element (WS-Discovery 1.1 s6.1)."""
    if body is None:
        return ""
    resolve = body.find(qname(Prefix.WSD, Element.RESOLVE))
    if resolve is None:
        return ""
    epr = resolve.find(qname(Prefix.WSA, Element.ENDPOINT_REFERENCE))
    if epr is None:
        return ""
    addr = epr.find(qname(Prefix.WSA, Element.ADDRESS))
    if addr is None or not addr.text:
        return ""
    return addr.text


# ---------------------------------------------------------------------------
# GetResponse metadata (served over HTTP)
# ---------------------------------------------------------------------------

def build_get_response(
    endpoint_uuid: str,
    hostname: str,
    workgroup_or_domain: str,
    is_domain: bool = False,
    relates_to: str = "",
) -> bytes:
    """Build a GetResponse with device metadata (WSDP / WS-MetadataExchange).

    Contains ThisDevice, ThisModel, and Relationship sections.
    """
    metadata = ET.Element(qname(Prefix.WSX, Element.METADATA))

    # ThisDevice
    section_dev = ET.SubElement(
        metadata, qname(Prefix.WSX, Element.METADATA_SECTION),
        attrib={Attribute.DIALECT: MetadataDialect.THIS_DEVICE},
    )
    this_device = ET.SubElement(
        section_dev, qname(Prefix.WSDP, Element.THIS_DEVICE),
    )
    ET.SubElement(
        this_device, qname(Prefix.WSDP, Element.FRIENDLY_NAME),
    ).text = f"{DeviceMetadata.FRIENDLY_NAME_PREFIX} {hostname}"
    ET.SubElement(
        this_device, qname(Prefix.WSDP, Element.FIRMWARE_VERSION),
    ).text = DeviceMetadata.FIRMWARE_VERSION
    ET.SubElement(
        this_device, qname(Prefix.WSDP, Element.SERIAL_NUMBER),
    ).text = DeviceMetadata.SERIAL_NUMBER

    # ThisModel
    section_model = ET.SubElement(
        metadata, qname(Prefix.WSX, Element.METADATA_SECTION),
        attrib={Attribute.DIALECT: MetadataDialect.THIS_MODEL},
    )
    this_model = ET.SubElement(
        section_model, qname(Prefix.WSDP, Element.THIS_MODEL),
    )
    ET.SubElement(
        this_model, qname(Prefix.WSDP, Element.MANUFACTURER),
    ).text = DeviceMetadata.MANUFACTURER
    ET.SubElement(
        this_model, qname(Prefix.WSDP, Element.MODEL_NAME),
    ).text = DeviceMetadata.MODEL_NAME
    ET.SubElement(
        this_model, qname_ns(Namespace.PNPX, Element.DEVICE_CATEGORY),
    ).text = DeviceMetadata.DEVICE_CATEGORY

    # Relationship (host)
    section_rel = ET.SubElement(
        metadata, qname(Prefix.WSX, Element.METADATA_SECTION),
        attrib={Attribute.DIALECT: MetadataDialect.RELATIONSHIP},
    )
    relationship = ET.SubElement(
        section_rel, qname(Prefix.WSDP, Element.RELATIONSHIP),
        attrib={Attribute.TYPE: RELATIONSHIP_HOST},
    )
    host = ET.SubElement(relationship, qname(Prefix.WSDP, Element.HOST))
    host_epr = ET.SubElement(
        host, qname(Prefix.WSA, Element.ENDPOINT_REFERENCE),
    )
    ET.SubElement(
        host_epr, qname(Prefix.WSA, Element.ADDRESS),
    ).text = urn_uuid(endpoint_uuid)
    ET.SubElement(
        host, qname(Prefix.WSDP, Element.TYPES),
    ).text = DeviceType.COMPUTER
    ET.SubElement(
        host, qname(Prefix.WSDP, Element.SERVICE_ID),
    ).text = urn_uuid(endpoint_uuid)

    label = (
        MembershipLabel.DOMAIN if is_domain
        else MembershipLabel.WORKGROUP
    )
    ET.SubElement(
        host, qname_ns(Namespace.PUB, Element.COMPUTER),
    ).text = f"{hostname}/{label}:{workgroup_or_domain}"

    # HTTP unicast response to the Get request; WS-Addressing 1.0
    # §3.1 specifies anonymous (or echo ReplyTo) for the reply's
    # <wsa:To>, not the multicast-group URN.  Confirmed against
    # Windows WSDAPI wire — its ProbeMatches also uses anonymous.
    return build_envelope(
        Action.GET_RESPONSE, metadata, relates_to=relates_to,
        to=WellKnownURI.WSA_ANONYMOUS,
    )
