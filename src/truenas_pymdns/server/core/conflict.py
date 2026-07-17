"""mDNS conflict detection and resolution per RFC 6762 s8.2."""
from __future__ import annotations

import re

from truenas_pymdns.protocol.records import MDNSRecord


def lexicographic_compare(
    ours: list[MDNSRecord], theirs: list[MDNSRecord]
) -> int:
    """Compare record sets per RFC 6762 §8.2.1 for probe tiebreaking.

    Returns the sign of ``ours - theirs`` after sorting both sides into
    the §8.2 lexicographical order and comparing element-by-element;
    ties fall through to ``len(ours) - len(theirs)`` (the set that runs
    out of records first loses, docs/specs/rfc6762.txt:1631-1638).

    Both the sort key and the per-record comparison use the raw,
    uncompressed rdata wire bytes (``MDNSRecord.lexicographic_cmp``),
    matching the §8.2 byte comparison and Apple mDNSResponder.  The
    per-record compare still ties case-variant-identical rdata (RFC
    6762 §16), so BCT guideline §820 case flips on tiebreak replies do
    not provoke a rename.

    Callers apply the RFC: the record set with the lexicographically
    GREATER concatenation wins.  So:

        > 0: ours is greater → we win, continue probing.
        = 0: identical → cooperating responder, continue probing.
        < 0: ours is smaller → we lose, must rename.
    """
    def sort_key(r: MDNSRecord) -> tuple:
        return (r.key.rclass.value, r.key.rtype.value, r.rdata_wire())

    sorted_ours = sorted(ours, key=sort_key)
    sorted_theirs = sorted(theirs, key=sort_key)

    for a, b in zip(sorted_ours, sorted_theirs):
        cmp = a.lexicographic_cmp(b)
        if cmp != 0:
            return cmp

    # If all compared elements are equal, the longer set wins
    return len(sorted_ours) - len(sorted_theirs)


_TRAILING_NUM = re.compile(r"^(.*?)(?:\s*[#-](\d+))?$")


def generate_alternative_name(name: str, attempt: int = 0) -> str:
    """Generate an alternative name after a conflict.

    Hostnames:  "myhost"     -> "myhost-2" -> "myhost-3"
    Instances:  "My Service" -> "My Service #2" -> "My Service #3"
    """
    m = _TRAILING_NUM.match(name)
    base = m.group(1) if m else name
    current_num = int(m.group(2)) if m and m.group(2) else 1

    if attempt > 0:
        next_num = current_num + attempt
    else:
        next_num = current_num + 1

    # Use hyphen for hostnames (no spaces), hash for instance names
    if " " in base:
        return f"{base} #{next_num}"
    return f"{base}-{next_num}"
