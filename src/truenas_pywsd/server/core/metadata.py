"""HTTP metadata request handler (WSDP / WS-MetadataExchange).

Handles Get requests on port 5357 and returns GetResponse
with device metadata (ThisDevice, ThisModel, Relationship).
"""
from __future__ import annotations

import logging

from truenas_pywsd.protocol.constants import Action
from truenas_pywsd.protocol.messages import build_get_response
from truenas_pywsd.protocol.soap import parse_envelope

logger = logging.getLogger(__name__)


class MetadataHandler:
    """Handles WS-MetadataExchange Get requests."""

    def __init__(
        self,
        endpoint_uuid: str,
        hostname: str,
        workgroup_or_domain: str,
        is_domain: bool = False,
    ) -> None:
        self._endpoint_uuid = endpoint_uuid
        self._hostname = hostname
        self._workgroup_or_domain = workgroup_or_domain
        self._is_domain = is_domain

    def update_workgroup(
        self, workgroup_or_domain: str, is_domain: bool,
    ) -> None:
        """Swap workgroup/domain for subsequent Get responses.

        Used by the WSD SIGHUP live-update path so a middleware
        workgroup edit doesn't need a Bye+Hello storm — clients that
        re-Probe or re-Get after this call see the new value."""
        self._workgroup_or_domain = workgroup_or_domain
        self._is_domain = is_domain

    def handle_request(self, body: bytes) -> bytes:
        """Process an HTTP SOAP request and return response bytes.

        Raises ValueError on malformed input.
        """
        envelope = parse_envelope(body)

        if envelope.action != Action.GET:
            raise ValueError(
                f"Unexpected action: {envelope.action!r}"
            )

        logger.debug("Get request, relates_to=%s", envelope.message_id)

        return build_get_response(
            endpoint_uuid=self._endpoint_uuid,
            hostname=self._hostname,
            workgroup_or_domain=self._workgroup_or_domain,
            is_domain=self._is_domain,
            relates_to=envelope.message_id,
        )
