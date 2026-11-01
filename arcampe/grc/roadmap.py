"""Post-SOC 2 roadmap helper (A13): "which framework next?"

Inputs: the buyer type you sell to and this repo's measured readiness per framework. Each candidate gets a score =
buyer fit (author table, 0-3) x 30 + current readiness % x 0.4 + family overlap with SOC 2 % x 0.3. Higher means
more buyer pull and less new work. The output is a suggestion for a person to decide, never a commitment.
"""
from __future__ import annotations

from . import frameworks

BUYER_FIT = {  # author judgement: how often each buyer type asks for the framework (0 none .. 3 usually)
    "defense": {"CMMC_L2": 3, "NIST_800_171": 3, "FEDRAMP_PROXY": 2, "ISO27001": 1, "HIPAA": 0, "HITRUST": 0,
                "ISO42001": 1, "PCI_DSS": 0, "NIS2": 0, "EU_AI_ACT": 0},
    "health": {"HIPAA": 3, "HITRUST": 3, "ISO27001": 1, "ISO42001": 1, "CMMC_L2": 0, "NIST_800_171": 0,
               "FEDRAMP_PROXY": 0, "PCI_DSS": 1, "NIS2": 0, "EU_AI_ACT": 1},
    "regulated_eu": {"ISO27001": 3, "NIS2": 3, "EU_AI_ACT": 2, "ISO42001": 2, "DORA": 2, "HIPAA": 0,
                     "HITRUST": 0, "CMMC_L2": 0, "NIST_800_171": 0, "PCI_DSS": 1},
    "ai_vendor": {"ISO42001": 3, "AIUC_1": 3, "EU_AI_ACT": 2, "NIST_AI_RMF": 2, "ISO27001": 2, "HIPAA": 0,
                  "CMMC_L2": 0, "NIST_800_171": 0, "PCI_DSS": 0, "HITRUST": 0},
}


class RoadmapError(ValueError):
    pass


def _families(fw: str) -> set[str]:
    return {c[:2] for c in frameworks.mapped_controls(fw)}


def soc2_family_overlap(fw: str) -> float:
    soc = _families("SOC2")
    f = _families(fw)
    return round(100 * len(f & soc) / len(f), 1) if f else 0.0


def recommend(buyer: str, top: int = 3, by_control=None) -> list[dict]:
    if buyer not in BUYER_FIT:
        raise RoadmapError(f"unknown buyer type {buyer}; choose from {sorted(BUYER_FIT)}")
    known = set(frameworks.ALL_MAPPED)
    cands = [f for f in BUYER_FIT[buyer] if f in known]
    ready = {r["framework"]: r["ready_pct"] for r in frameworks.readiness(by_control, frameworks=cands)}
    rows = []
    for f in cands:
        fit = BUYER_FIT[buyer][f]
        ov = soc2_family_overlap(f)
        rows.append({"framework": f, "buyer_fit": fit, "ready_pct": ready[f], "soc2_overlap_pct": ov,
                     "score": round(fit * 30 + ready[f] * 0.4 + ov * 0.3, 1)})
    rows.sort(key=lambda r: (-r["score"], r["framework"]))
    return [{**r, "rank": i + 1, "decision": "suggestion for a person to decide"} for i, r in enumerate(rows[:top])]


