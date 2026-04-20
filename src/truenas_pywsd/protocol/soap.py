"""SOAP 1.2 envelope building and parsing for WS-Discovery.

References:
    SOAP 1.2 (W3C)
    WS-Addressing 1.0 (W3C)

All XML parsing uses ``defusedxml`` to prevent XXE and entity
expansion attacks.
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import defusedxml.ElementTree as SafeET  # type: ignore[import-untyped]

from .constants import Attribute, Element, Prefix, URN_PREFIX, WellKnownURI
from .namespaces import qname


def _message_id() -> str:
    """Generate a unique WS-Addressing MessageID."""
    return f"{URN_PREFIX}{uuid.uuid4()}"


@dataclass(slots=True)
class SOAPEnvelope:
    """Parsed SOAP envelope with WS-Addressing headers."""
    action: str = ""
    message_id: str = ""
    relates_to: str = ""
    to: str = ""
    endpoint: str = ""
    body: ET.Element | None = None


def build_envelope(
    action: str,
    body_element: ET.Element | None = None,
    *,
    relates_to: str = "",
    to: str = WellKnownURI.WSA_DISCOVERY,
    endpoint: str = "",
    message_id: str = "",
    app_sequence: int | None = None,
    message_number: int = 1,
) -> bytes:
    """Build a SOAP 1.2 envelope with WS-Addressing headers.

    Includes AppSequence element when provided (WS-Discovery 1.1 s7).

    *app_sequence* is the InstanceId (fixed per daemon lifetime).
    *message_number* increments globally across all sent messages.

    Returns UTF-8 encoded XML bytes.
    """
    envelope = ET.Element(qname(Prefix.SOAP, Element.ENVELOPE))
    header = ET.SubElement(envelope, qname(Prefix.SOAP, Element.HEADER))

    ET.SubElement(header, qname(Prefix.WSA, Element.TO)).text = to
    ET.SubElement(header, qname(Prefix.WSA, Element.ACTION)).text = action

    if not message_id:
        message_id = _message_id()
    ET.SubElement(header, qname(Prefix.WSA, Element.MESSAGE_ID)).text = message_id

    if relates_to:
        ET.SubElement(
            header, qname(Prefix.WSA, Element.RELATES_TO),
        ).text = relates_to

    if app_sequence is not None:
        ET.SubElement(
            header, qname(Prefix.WSD, Element.APP_SEQUENCE),
            attrib={
                Attribute.INSTANCE_ID: str(app_sequence),
                Attribute.SEQUENCE_ID: f"{URN_PREFIX}{uuid.uuid4()}",
                Attribute.MESSAGE_NUMBER: str(message_number),
            },
        )

    body = ET.SubElement(envelope, qname(Prefix.SOAP, Element.BODY))
    if body_element is not None:
        body.append(body_element)

    tree = ET.ElementTree(envelope)
    ET.indent(tree, space="")
    return ET.tostring(
        envelope, encoding="utf-8", xml_declaration=True,
    )


def parse_envelope(data: bytes) -> SOAPEnvelope:
    """Parse a SOAP envelope from wire bytes.

    Uses defusedxml for safe XML parsing.
    Raises ValueError on malformed input.
    """
    try:
        root = SafeET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"XML parse error: {e}") from e

    if root.tag != qname(Prefix.SOAP, Element.ENVELOPE):
        raise ValueError(f"Expected SOAP Envelope, got {root.tag}")

    header = root.find(qname(Prefix.SOAP, Element.HEADER))
    body = root.find(qname(Prefix.SOAP, Element.BODY))

    result = SOAPEnvelope()
    result.body = body

    if header is not None:
        action_el = header.find(qname(Prefix.WSA, Element.ACTION))
        if action_el is not None and action_el.text:
            result.action = action_el.text

        msgid_el = header.find(qname(Prefix.WSA, Element.MESSAGE_ID))
        if msgid_el is not None and msgid_el.text:
            result.message_id = msgid_el.text

        relates_el = header.find(qname(Prefix.WSA, Element.RELATES_TO))
        if relates_el is not None and relates_el.text:
            result.relates_to = relates_el.text

        to_el = header.find(qname(Prefix.WSA, Element.TO))
        if to_el is not None and to_el.text:
            result.to = to_el.text

    return result
