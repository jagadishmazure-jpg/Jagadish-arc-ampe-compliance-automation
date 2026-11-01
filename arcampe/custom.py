"""Custom controls, hybrid frameworks and custom scoring.

An organization can define its own controls in YAML, link each to catalog controls, and pick a
scoring rule. A hybrid framework is then scored from the same assessment run as ARC-AMPE.
"""
from __future__ import annotations

import yaml

from . import catalog

EXAMPLE = """
name: lakehaven-board-dashboard
scoring: weighted        # weighted | strict (all linked controls must pass)
controls:
  - id: LHX-01
    title: Members' data never leaves the U.S.
    links: [SA-09(05), SC-07]
    weight: 3
  - id: LHX-02
    title: Every admin uses phishing-resistant MFA
    links: [IA-02(06), AC-02(07)]
    weight: 3
  - id: LHX-03
    title: Backups restore within the RTO
    links: [CP-09, CP-09(01), CP-10]
    weight: 2
  - id: LHX-04
    title: Vendors with PII are assessed yearly
    links: [SR-03, SR-08]
    weight: 1
"""


def load(text: str = EXAMPLE) -> dict:
    fw = yaml.safe_load(text)
    ids = catalog.by_id()
    bad = [lk for c in fw["controls"] for lk in c["links"] if lk not in ids]
    if bad:
        raise ValueError(f"unknown linked controls: {bad}")
    if fw.get("scoring") not in ("weighted", "strict"):
        raise ValueError("scoring must be weighted or strict")
    return fw


def score(fw: dict, by_control: dict) -> dict:
    rows, total, got = [], 0, 0.0
    for c in fw["controls"]:
        res = [by_control.get(lk, {"status": "not_tested"})["status"] for lk in c["links"]]
        tested = [r for r in res if r != "not_tested"]
        if fw["scoring"] == "strict":
            s = 1.0 if tested and all(r == "pass" for r in tested) else 0.0
        else:
            s = sum(r == "pass" for r in tested) / len(tested) if tested else 0.0
        total += c["weight"]
        got += s * c["weight"]
        rows.append({"id": c["id"], "title": c["title"], "links": c["links"], "results": res, "score": round(s, 2)})
    return {"framework": fw["name"], "score_pct": round(100 * got / total, 1), "controls": rows}
