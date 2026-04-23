"""Interface-token classification and validation.

The ``interfaces = ...`` config key appears in both the shared
``[discovery]`` section of ``truenas-discoveryd.conf`` and in each
protocol's own section.  Tokens can be:

- **NAME** — a Linux interface name (``eth0``, ``enp3s0``), accepted
  by every protocol.
- **IPV4** — a bare IPv4 address (``192.168.1.5``), meaningful only
  to NBNS's ``resolve_subnets`` where it selects one specific
  local address.
- **CIDR** — an IPv4 network (``192.168.1.0/24``), meaningful only
  to NBNS where it defines an explicit subnet with the given
  prefix overriding the kernel netmask.

mDNS and WSD only accept NAME tokens; silently-dropping non-name
tokens was a long-standing source of operator confusion.  Consolidating
the classifier here lets each protocol's ``ServerConfig.__post_init__``
enforce its own policy at dataclass construction — mDNS/WSD raise on
IP/CIDR, NBNS accepts all three kinds.  The shared ``[discovery]``
section also uses ``require_names_only`` so operators who want
NBNS-specific richness must put it in ``[netbiosns] interfaces``.
"""
from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network


class TokenKind(StrEnum):
    """Category of an interface-list token."""
    NAME = "name"
    IPV4 = "ipv4"
    CIDR = "cidr"


def classify_token(tok: str) -> TokenKind:
    """Return the ``TokenKind`` for a single interface-list token.

    Raises ``ValueError`` for empty or whitespace-only tokens and for
    strings that look like a CIDR but don't parse as an IPv4 network.
    Strings containing no ``/`` that don't parse as an IPv4 address
    fall back to ``NAME`` — we don't validate against Linux's
    interface-name rules here (those vary by kernel version; the
    resolver that actually uses the name will fail loudly enough
    when the interface isn't found)."""
    tok = tok.strip()
    if not tok:
        raise ValueError("empty interface token")
    if "/" in tok:
        # Raises ValueError itself on malformed CIDR — let it
        # propagate with its own clearer message.
        IPv4Network(tok, strict=False)
        return TokenKind.CIDR
    try:
        IPv4Address(tok)
        return TokenKind.IPV4
    except ValueError:
        return TokenKind.NAME


def require_names_only(tokens: list[str]) -> list[str]:
    """Validate that every token in *tokens* is an interface NAME.

    Returns the list unchanged on success so callers can inline the
    call in ``__post_init__`` or a builder.  Raises ``ValueError``
    on the first non-name token with a message identifying the
    offender — used by mDNS and WSD ``ServerConfig.__post_init__``
    (protocols that only understand interface names) and by the
    unified loader for ``[discovery] interfaces`` (so shared
    configuration is protocol-portable)."""
    for tok in tokens:
        kind = classify_token(tok)
        if kind is not TokenKind.NAME:
            raise ValueError(
                f"interface token {tok!r} is a {kind.value} — "
                "only interface names are accepted here (IP and "
                "CIDR forms are NBNS-specific; put them in "
                "[netbiosns] interfaces)"
            )
    return tokens
