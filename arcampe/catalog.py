"""The 402-control ARC-AMPE AE catalog with DEE flags, NIST titles and automation labels."""
from __future__ import annotations

import functools
import json
from collections import Counter
from dataclasses import dataclass

from . import DATA

FAMILY_ORDER = ["AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP",
                "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR"]


@dataclass(frozen=True)
class Control:
    id: str
    oscal_id: str
    family: str
    family_name: str
    title: str
    enhancement: bool
    ae: bool
    dee: bool
    nist_low: bool
    nist_moderate: bool
    nist_high: bool
    nist_privacy: bool
    label: str = ""


@functools.lru_cache(maxsize=1)
def raw() -> dict:
    return json.loads((DATA / "catalog" / "catalog.json").read_text())


@functools.lru_cache(maxsize=1)
def load() -> tuple[Control, ...]:
    from .labels import label_for

    out = []
    for row in raw()["controls"]:
        c = Control(**row)
        out.append(Control(**{**row, "label": label_for(c.id)}))
    return tuple(out)


def by_id() -> dict[str, Control]:
    return {c.id: c for c in load()}


def baseline(name: str) -> list[Control]:
    if name not in ("ae", "dee"):
        raise ValueError("baseline must be 'ae' or 'dee'")
    return [c for c in load() if getattr(c, name)]


def counts(name: str = "ae") -> dict:
    ctrls = baseline(name)
    fam = Counter(c.family for c in ctrls)
    lab = Counter(c.label for c in ctrls)
    by = {f: Counter(c.label for c in ctrls if c.family == f) for f in FAMILY_ORDER}
    return {"total": len(ctrls), "families": len(fam), "by_family": dict(fam),
            "by_label": dict(lab), "by_family_label": {f: dict(v) for f, v in by.items()},
            "enhancements": sum(c.enhancement for c in ctrls)}


def table(name: str = "ae") -> str:
    c = counts(name)
    lines = ["| Family | Name | Controls | Automated | Hybrid | Attestation |", "|---|---|---:|---:|---:|---:|"]
    names = {x.family: x.family_name for x in load()}
    for f in FAMILY_ORDER:
        d = c["by_family_label"][f]
        lines.append(f"| {f} | {names[f]} | {c['by_family'].get(f, 0)} | {d.get('automated', 0)} | "
                     f"{d.get('hybrid', 0)} | {d.get('attestation', 0)} |")
    lb = c["by_label"]
    lines.append(f"| **All** | {c['families']} families | **{c['total']}** | **{lb.get('automated', 0)}** | "
                 f"**{lb.get('hybrid', 0)}** | **{lb.get('attestation', 0)}** |")
    return "\n".join(lines)
