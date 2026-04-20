"""XML namespace helpers for WS-Discovery SOAP messages.

Registers namespace prefixes with ElementTree so serialized XML
uses readable prefixes (``wsd:``, ``soap:``) instead of ``ns0:``.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .constants import NS_MAP, Namespace


def qname(ns_prefix: str, local: str) -> str:
    """Build a Clark-notation QName: ``{namespace_uri}local``.

    Example: ``qname('wsd', 'Hello')`` → ``'{http://...}/Hello'``
    """
    uri = NS_MAP[ns_prefix]
    return f"{{{uri}}}{local}"


def qname_ns(ns: Namespace, local: str) -> str:
    """Build a Clark-notation QName from a Namespace enum."""
    return f"{{{ns}}}{local}"


def register_namespaces() -> None:
    """Register all WSD namespace prefixes with ElementTree.

    Must be called before serializing XML to get clean prefixes.
    """
    for prefix, uri in NS_MAP.items():
        ET.register_namespace(prefix, uri)


# Register on import so all serialization gets clean prefixes.
register_namespaces()
