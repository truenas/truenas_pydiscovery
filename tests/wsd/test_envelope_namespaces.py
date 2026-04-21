"""Every emitted envelope must declare the namespaces its QNames reference.

The bug: ``<wsd:Types>wsdp:Device pub:Computer</wsd:Types>`` stores
``wsdp:`` and ``pub:`` only in text content, so ``ElementTree``'s
automatic prefix-binding (which tracks tag and attribute names) did
not emit ``xmlns:wsdp`` or ``xmlns:pub`` on the envelope root.
Windows's WSD parser rejects envelopes with unbound prefixes in QName
text and the device never appears in Explorer's Network view.

The fix (``soap.py::_declare_text_only_namespaces``) adds ``xmlns:``
attrs on the envelope root for every ``NS_MAP`` prefix whose URI
isn't already used as an element tag — mirroring what
``christgau/wsdd`` does unconditionally at ``wsdd.py:506-507``.
"""
from __future__ import annotations

import re
import uuid

from truenas_pywsd.protocol.messages import (
    build_bye,
    build_get_response,
    build_hello,
    build_probe_match,
    build_resolve_match,
)


_REQUIRED_PREFIXES_IN_HELLO = {
    # ET auto-declares these because they appear as tag names:
    "soap", "wsa", "wsd",
    # Needed for <wsd:Types>wsdp:Device pub:Computer</wsd:Types>:
    "wsdp", "pub",
}

_XMLNS_RE = re.compile(rb' xmlns:([A-Za-z0-9]+)="([^"]+)"')


def _xmlns_decls_on_root(wire: bytes) -> list[tuple[bytes, bytes]]:
    """Return ``(prefix, uri)`` pairs from the *root* element's
    ``xmlns:`` attrs, preserving declaration order."""
    # Skip the ``<?xml ... ?>`` declaration, then scan the root
    # element's open tag (up to its first ``>``).
    root_start = wire.index(b"<soap:Envelope")
    root_end = wire.index(b">", root_start)
    root_attrs = wire[root_start:root_end]
    return _XMLNS_RE.findall(root_attrs)


class TestEnvelopeNamespaces:
    def test_hello_declares_wsdp_and_pub(self):
        wire = build_hello(
            str(uuid.uuid4()),
            "http://192.168.1.10:5357/abc",
            app_sequence=1, message_number=1,
        )
        prefixes = {p.decode() for p, _uri in _xmlns_decls_on_root(wire)}
        assert _REQUIRED_PREFIXES_IN_HELLO <= prefixes, (
            f"Hello must declare at least "
            f"{_REQUIRED_PREFIXES_IN_HELLO}; got {prefixes}"
        )

    def test_probematch_declares_wsdp_and_pub(self):
        wire = build_probe_match(
            str(uuid.uuid4()),
            relates_to=f"urn:uuid:{uuid.uuid4()}",
        )
        prefixes = {p.decode() for p, _uri in _xmlns_decls_on_root(wire)}
        assert {"wsdp", "pub"} <= prefixes

    def test_resolvematch_declares_wsdp_and_pub(self):
        wire = build_resolve_match(
            str(uuid.uuid4()),
            xaddrs="http://192.168.1.10:5357/abc",
            relates_to=f"urn:uuid:{uuid.uuid4()}",
        )
        prefixes = {p.decode() for p, _uri in _xmlns_decls_on_root(wire)}
        assert {"wsdp", "pub"} <= prefixes

    def test_bye_does_not_need_text_only_prefixes(self):
        """Bye has no QName-valued text content — only wsa/wsd/soap
        are strictly required, though declaring the rest on the root
        is harmless."""
        wire = build_bye(str(uuid.uuid4()))
        prefixes = {p.decode() for p, _uri in _xmlns_decls_on_root(wire)}
        # Tag-bound prefixes must be there.
        assert {"soap", "wsa", "wsd"} <= prefixes


class TestNoDuplicateNamespaceDeclarations:
    """Strict XML parsers (defusedxml, libxml2 with a strict flag,
    Windows's own MSXML-derived WSD parser under some modes) reject
    envelopes that declare the same ``xmlns:`` attribute twice on a
    single element.  Prior to the fix, the explicit-declaration path
    and ElementTree's auto-declaration both emitted ``xmlns:wsx``
    etc. on ``GetResponse`` envelopes, producing a duplicate the
    test suite's own ``parse_envelope`` round-trip rejected."""

    def _assert_no_duplicates(self, wire: bytes) -> None:
        decls = _xmlns_decls_on_root(wire)
        prefixes = [p for p, _uri in decls]
        assert len(prefixes) == len(set(prefixes)), (
            f"Duplicate xmlns prefix in envelope root: {decls}"
        )

    def test_hello_has_no_duplicate_namespaces(self):
        self._assert_no_duplicates(build_hello(
            str(uuid.uuid4()),
            "http://192.168.1.10:5357/abc",
            app_sequence=1, message_number=1,
        ))

    def test_probematch_has_no_duplicate_namespaces(self):
        self._assert_no_duplicates(build_probe_match(
            str(uuid.uuid4()),
            relates_to=f"urn:uuid:{uuid.uuid4()}",
        ))

    def test_resolvematch_has_no_duplicate_namespaces(self):
        self._assert_no_duplicates(build_resolve_match(
            str(uuid.uuid4()),
            xaddrs="http://192.168.1.10:5357/abc",
            relates_to=f"urn:uuid:{uuid.uuid4()}",
        ))

    def test_getresponse_workgroup_has_no_duplicate_namespaces(self):
        self._assert_no_duplicates(build_get_response(
            "abc123", "TRUENAS", "WORKGROUP", is_domain=False,
        ))

    def test_getresponse_domain_has_no_duplicate_namespaces(self):
        self._assert_no_duplicates(build_get_response(
            "abc123", "TRUENAS", "CORP.EXAMPLE", is_domain=True,
        ))
