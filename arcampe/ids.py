"""Control ID helpers. CMS writes AC-02(03); NIST OSCAL writes ac-2.3."""
from __future__ import annotations

import re

_ID = re.compile(r"^\s*([A-Za-z]{2})-(\d+)\s*(?:\((\d+)\))?\s*$")


def canonical(cid: str) -> str:
    """Return the zero-padded CMS form, e.g. 'ac-2(3)' -> 'AC-02(03)'."""
    m = _ID.match(cid)
    if not m:
        raise ValueError(f"not a control id: {cid!r}")
    out = f"{m[1].upper()}-{int(m[2]):02d}"
    return out + (f"({int(m[3]):02d})" if m[3] else "")


def to_oscal(cid: str) -> str:
    c = canonical(cid)
    fam, rest = c.split("-", 1)
    num = int(rest[:2])
    enh = f".{int(rest[3:5])}" if "(" in rest else ""
    return f"{fam.lower()}-{num}{enh}"


def family(cid: str) -> str:
    return canonical(cid)[:2]


def base_of(cid: str) -> str:
    return canonical(cid)[:5]
