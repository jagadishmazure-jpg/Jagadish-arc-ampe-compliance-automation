"""Regulatory change management: watch a feed, analyze impact on controls, open remediation tasks.

The feed here is a synthetic list of changes. In production it would be a reviewed subscription
(for example CMS guidance pages or the Federal Register) read by an analyst, not scraped blindly.
"""
from __future__ import annotations

from . import catalog
from .crosswalk import reverse

FEED = [  # synthetic regulatory changes
    {"id": "RC-01", "source": "CMS (example)", "title": "Shorter incident reporting window proposed",
     "affects": {"ARC-AMPE": ["IR-06"]}, "effective": "2027-03-01", "type": "proposed"},
    {"id": "RC-02", "source": "State law (fictional)", "title": "Lakehaven consumer data rights act",
     "affects": {"CCPA": ["1798.100", "1798.105"]}, "effective": "2027-01-01", "type": "final"},
    {"id": "RC-03", "source": "HHS (example)", "title": "Security Rule update: encryption and MFA expectations",
     "affects": {"HIPAA": ["164.312(a)(1)", "164.312(d)"]}, "effective": "2027-06-30", "type": "proposed"},
]


def impact(change: dict) -> dict:
    ids = catalog.by_id()
    controls: set[str] = set()
    for fw, refs in change["affects"].items():
        if fw == "ARC-AMPE":
            controls.update(r for r in refs if r in ids)
        else:
            rev = reverse(fw)
            for r in refs:
                controls.update(rev.get(r, []))
    labels: dict[str, int] = {}
    for c in controls:
        labels[ids[c].label] = labels.get(ids[c].label, 0) + 1
    return {"change": change["id"], "title": change["title"], "controls": sorted(controls),
            "count": len(controls), "by_label": labels,
            "tasks": [f"Review {c} implementation statement and checks" for c in sorted(controls)[:10]]}


def run() -> list[dict]:
    return [impact(c) for c in FEED]
