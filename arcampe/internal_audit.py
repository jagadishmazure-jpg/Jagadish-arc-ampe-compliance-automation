"""Internal audit and financial controls: control self-assessment, test of design and effectiveness,
sample sizes, and key control indicators (KCIs). COSO components are recorded per control.
"""
from __future__ import annotations

import random

COSO = ("control environment", "risk assessment", "control activities", "information and communication",
        "monitoring activities")
# Common attribute-sampling guide by control frequency (author-chosen demo values).
SAMPLE_SIZE = {"annual": 1, "quarterly": 2, "monthly": 2, "weekly": 5, "daily": 25, "recurring": 40}

CONTROLS = [  # synthetic financial / IT general controls for the exchange's premium aggregation
    {"id": "FC-01", "title": "Premium payment reconciliation", "frequency": "monthly", "coso": "control activities",
     "key": True, "owner": "finance"},
    {"id": "FC-02", "title": "Access to payment system reviewed", "frequency": "quarterly",
     "coso": "control activities", "key": True, "owner": "it"},
    {"id": "FC-03", "title": "Change to payment interface approved", "frequency": "recurring",
     "coso": "control activities", "key": True, "owner": "it"},
    {"id": "FC-04", "title": "Journal entries over threshold approved", "frequency": "daily",
     "coso": "control activities", "key": False, "owner": "finance"},
    {"id": "FC-05", "title": "Audit committee reviews control deficiencies", "frequency": "quarterly",
     "coso": "monitoring activities", "key": True, "owner": "cfo"},
    {"id": "FC-06", "title": "Staff acknowledge code of conduct", "frequency": "annual",
     "coso": "control environment", "key": True, "owner": "hr"},
    {"id": "FC-07", "title": "Annual fraud and financial reporting risk assessment", "frequency": "annual",
     "coso": "risk assessment", "key": True, "owner": "cfo"},
    {"id": "FC-08", "title": "Monthly finance reporting package reviewed by management", "frequency": "monthly",
     "coso": "information and communication", "key": False, "owner": "finance"},
]


def test_effectiveness(control: dict, population: list[bool], seed: int = 7) -> dict:
    """Draw a seeded sample from the population of control instances (True = performed correctly)."""
    n = min(SAMPLE_SIZE[control["frequency"]], len(population))
    rng = random.Random(f"{seed}:{control['id']}")
    sample = rng.sample(population, n)
    exceptions = sum(not x for x in sample)
    return {"control": control["id"], "sample": n, "exceptions": exceptions,
            "conclusion": "effective" if exceptions == 0 else "deficiency"}


def self_assessment(answers: dict[str, dict]) -> list[dict]:
    """Control owners answer: designed? operating? evidence attached? Gaps become audit focus areas."""
    out = []
    for c in CONTROLS:
        a = answers.get(c["id"], {})
        gaps = [k for k in ("designed", "operating", "evidence") if not a.get(k)]
        out.append({"control": c["id"], "owner": c["owner"], "gaps": gaps, "focus": bool(gaps) and c["key"]})
    return out


def kcis(results: list[dict]) -> dict:
    key = {c["id"] for c in CONTROLS if c["key"]}
    tested_key = [r for r in results if r["control"] in key]
    return {"key_controls": len(key), "tested": len(tested_key),
            "effective_pct": round(100 * sum(r["conclusion"] == "effective" for r in tested_key) /
                                   max(1, len(tested_key)), 1),
            "coso_coverage": sorted({c["coso"] for c in CONTROLS})}
