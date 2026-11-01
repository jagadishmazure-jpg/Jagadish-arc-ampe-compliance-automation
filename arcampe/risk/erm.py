"""Enterprise and operational risk: register, KRIs with thresholds, program maturity, leadership view."""
from __future__ import annotations

from ..challenges.scoring import band

REGISTER = [  # synthetic enterprise risks: (id, title, owner, likelihood, impact, category)
    ("E01", "Open-enrollment surge exceeds call center capacity", "operations", 4, 3, "operational"),
    ("E02", "Federal data services hub outage blocks eligibility checks", "it-ops", 2, 5, "operational"),
    ("E03", "Loss of PII leads to CMS corrective action", "ciso", 3, 5, "compliance"),
    ("E04", "Key vendor exit (call center)", "procurement", 2, 4, "third-party"),
    ("E05", "Budget cut delays POA&M remediation", "cfo", 3, 3, "financial"),
    ("E06", "Staff turnover in security team", "ciso", 3, 3, "people"),
]
KRIS = [  # (id, name, value, amber, red, higher_is_worse) - values come from this repo's run or are synthetic
    ("K1", "POA&M items overdue (%)", None, 10, 25, True),
    ("K2", "Attestations current (%)", None, 90, 80, False),
    ("K3", "Critical vulnerabilities open > 15 days", None, 1, 3, True),
    ("K4", "Restore tests within 12 months (%)", None, 90, 75, False),
    ("K5", "Vendors with PII and stale assessment", None, 1, 2, True),
]
MATURITY_LEVELS = ("initial", "managed", "defined", "quantitatively managed", "optimizing")


def kri_status(value: float, amber: float, red: float, higher_is_worse: bool) -> str:
    if higher_is_worse:
        return "red" if value >= red else "amber" if value >= amber else "green"
    return "red" if value <= red else "amber" if value <= amber else "green"


def kri_values(poam_items, attest_summary: dict, evidence, vendor_findings) -> dict[str, float]:
    overdue = 100 * sum(i.sla_status == "overdue" for i in poam_items) / max(1, len(poam_items))
    att = 100 * (attest_summary["current"] + attest_summary["due_soon"]) / max(1, attest_summary["total"])
    crit = sum(1 for i in poam_items if i.severity == "critical" and i.days_open > 15)
    restore = [e for e in evidence if e.kind == "backup_job"]
    targets = {e.subject for e in restore}
    tested = {e.subject for e in restore if e.attributes["restore_tested_on"]
              and e.attributes["restore_tested_on"] >= "2025-10-31"}
    stale = sum(1 for f in vendor_findings if f["id"] == "SR-ASSESS" and not f["passed"])
    return {"K1": round(overdue, 1), "K2": round(att, 1), "K3": crit,
            "K4": round(100 * len(tested) / max(1, len(targets)), 1), "K5": stale}


def kri_table(values: dict[str, float]) -> list[dict]:
    return [{"id": k, "name": n, "value": values[k], "status": kri_status(values[k], a, r, w),
             "amber": a, "red": r} for k, n, _, a, r, w in KRIS]


def maturity(evidence_coverage_pct: float, automated_pct: float, poam_within_sla_pct: float) -> dict:
    """A simple, explainable maturity level (1-5) from three measured inputs."""
    pts = (evidence_coverage_pct >= 40) + (evidence_coverage_pct >= 75) + (automated_pct >= 15) \
        + (poam_within_sla_pct >= 90)
    level = 1 + int(pts)
    return {"level": level, "name": MATURITY_LEVELS[level - 1],
            "inputs": {"evidence_coverage_pct": evidence_coverage_pct, "automated_pct": automated_pct,
                       "poam_within_sla_pct": poam_within_sla_pct}}


def register() -> list[dict]:
    return [{"id": i, "title": t, "owner": o, "likelihood": lk, "impact": im, "score": lk * im,
             "band": band(lk * im / 2.5), "category": c} for i, t, o, lk, im, c in REGISTER]
