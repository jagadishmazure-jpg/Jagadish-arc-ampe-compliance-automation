"""SR family and third-party risk: vendor register, tiering, questionnaires, scoring, monitoring.

Scores are transparent sums of named factors so a reviewer can see why a vendor is high risk.
"""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field

from . import DATA, TODAY

QUESTIONS = {  # id -> (text, weight). A "no" adds the weight to inherent risk.
    "Q1": ("Do you hold a current independent security assessment (for example SOC 2 Type II or FedRAMP)?", 3),
    "Q2": ("Is all PII stored and processed in the United States?", 4),
    "Q3": ("Do you enforce MFA for all staff with access to our data?", 3),
    "Q4": ("Will you notify us of a suspected breach within one hour?", 3),
    "Q5": ("Do you provide a software bill of materials (SBOM) for delivered software?", 2),
    "Q6": ("Do you flow down 45 CFR 155.260 privacy and security terms to subcontractors?", 3),
    "Q7": ("Do you encrypt our data at rest and in transit with FIPS-validated modules?", 3),
}


@dataclass
class Vendor:
    id: str
    name: str
    service: str
    pii_access: bool
    annual_spend: int
    data_location: str
    answers: dict
    last_assessed: str | None
    open_issues: list = field(default_factory=list)
    rating_history: list = field(default_factory=list)   # external security rating, oldest first
    contract: dict = field(default_factory=dict)

    def tier(self) -> str:
        if self.pii_access and self.annual_spend >= 250_000:
            return "critical"
        if self.pii_access:
            return "high"
        return "moderate" if self.annual_spend >= 100_000 else "low"


def load(path=None) -> list[Vendor]:
    return [Vendor(**v) for v in json.loads((path or DATA / "vendors.json").read_text())]


def questionnaire_gaps(v: Vendor) -> list[str]:
    return [q for q in QUESTIONS if v.answers.get(q) is not True]


def score(v: Vendor, today: str = TODAY) -> dict:
    """0-100 risk score: inherent (tier + questionnaire gaps) plus monitoring signals."""
    factors: dict[str, int] = {}
    factors["tier"] = {"critical": 30, "high": 20, "moderate": 10, "low": 0}[v.tier()]
    factors["questionnaire_gaps"] = sum(QUESTIONS[q][1] for q in questionnaire_gaps(v)) * 2
    if v.data_location != "US":
        factors["offshore_data"] = 15
    age = None if not v.last_assessed else (dt.date.fromisoformat(today) - dt.date.fromisoformat(v.last_assessed)).days
    if age is None or age > 365:
        factors["assessment_stale"] = 10
    if len(v.rating_history) >= 2 and v.rating_history[-1] < v.rating_history[0] - 50:
        factors["rating_drop"] = 8
    factors["open_issues"] = min(10, 3 * len(v.open_issues))
    total = min(100, sum(factors.values()))
    band = "high" if total >= 60 else "moderate" if total >= 35 else "low"
    return {"vendor": v.id, "name": v.name, "tier": v.tier(), "score": total, "band": band, "factors": factors,
            "assessment_age_days": age}


def findings(vendors: list[Vendor], today: str = TODAY) -> list[dict]:
    """SR / SA findings that feed the POA&M."""
    out = []
    for v in vendors:
        if not v.pii_access:
            continue
        s = score(v, today)
        out.append({"id": "SR-ASSESS", "control": "SR-03", "subject": v.id,
                     "passed": "assessment_stale" not in s["factors"],
                     "detail": f"{v.name}: last assessed {s['assessment_age_days']} days ago"})
        out.append({"id": "SR-LOC", "control": "SA-09(05)", "subject": v.id, "passed": v.data_location == "US",
                     "detail": f"{v.name}: data in {v.data_location}"})
        out.append({"id": "SR-FLOW", "control": "SR-03", "subject": v.id,
                     "passed": bool(v.contract.get("flowdown_45cfr155260")),
                     "detail": f"{v.name}: flow-down clause={v.contract.get('flowdown_45cfr155260')}"})
    return out


def register_table(vendors: list[Vendor]) -> str:
    rows = ["| Vendor | Tier | Score | Band | Top factors |", "|---|---|---:|---|---|"]
    for v in sorted(vendors, key=lambda x: -score(x)["score"]):
        s = score(v)
        top = ", ".join(f"{k} {n}" for k, n in sorted(s["factors"].items(), key=lambda kv: -kv[1])[:3] if n)
        rows.append(f"| {v.name} | {s['tier']} | {s['score']} | {s['band']} | {top} |")
    return "\n".join(rows)
