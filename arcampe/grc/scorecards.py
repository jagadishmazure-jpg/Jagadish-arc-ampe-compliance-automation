"""Three leadership scorecards (Efficiency, Risk, Trust) with FAIR loss ranges, plus the daily operational deltas.

Every row carries its basis: "measured, synthetic" (computed from this repo's synthetic data), "SIMULATED"
(an invented business number, e.g. audit-prep hours) or "author judgement". Vendor marketing figures are never
used here. The board view shows loss ranges as P50 / P90 / P95 with no red/amber/green colors.
"""
from __future__ import annotations

from .. import TODAY

MANUAL_SOURCES = {"docs_library"}  # uploaded documents; everything else is collected by a connector
AUDIT_PREP_HOURS = {"baseline (2025 cycle)": 120, "current (2026 cycle)": 74}  # SIMULATED
AUDIT_FINDINGS = {"2025": 14, "2026 H1": 11, "2026 H2": 9}  # SIMULATED exceptions per cycle
QUESTIONNAIRE_SLA_DAYS = 5


def _ms(v) -> tuple:
    return (v, "measured, synthetic")


def build(m: dict | None = None, today: str = TODAY) -> dict:
    from ..integrations.connectors import collect_all
    from . import ai_frameworks, ai_tests, audit_hub, insights, recurring, reporting, risk_program
    m = reporting.metrics(today) if m is None else m
    ev = collect_all()
    auto = sum(e.source not in MANUAL_SOURCES for e in ev)
    ins = insights.summary(today=today)
    sla = risk_program.sla(today=today)
    fair = risk_program.fair()
    reqs = audit_hub.request_summary()
    at = ai_tests.summary()
    cra = ai_frameworks.cra_summary()
    c = m["controls"]
    high_risks = sum(d["high"] for d in m["risk"]["registers"].values())
    gov = {k["kpi"]: k["value"] for k in m["ai_governance"]}
    q = m["questionnaires"]
    t = m["trust_to_revenue"]
    eff = [
        ("Audit prep hours per cycle", " -> ".join(f"{k}: {v}" for k, v in AUDIT_PREP_HOURS.items()), "SIMULATED"),
        ("Evidence automation rate", f"{round(100 * auto / len(ev), 1)}% ({auto} / {len(ev)})", "measured, synthetic"),
        ("Auditor requests (PBC) this cycle", f"{reqs['requests']} ({reqs['ready']} ready)", "measured, synthetic"),
        ("Audit findings trend", " -> ".join(f"{k}: {v}" for k, v in AUDIT_FINDINGS.items()), "SIMULATED"),
        ("MTTR for failed tests", f"{ins['mttr_hours']} h", "measured on synthetic history"),
        ("Tests flipped pass->fail in 24h / 7d / 14d",
         " / ".join(str(ins["flipped"][w]) for w in ("24h", "7d", "14d")), "measured on synthetic history"),
        ("Recurring reviews on time", f"{recurring.on_time_rate(today)}%", "measured, synthetic"),
    ]
    risk = [
        ("Open high residual risks", str(high_risks), "measured, synthetic"),
        ("Critical + high findings open",
         str(m["vulnerabilities"]["critical"]["open"] + m["vulnerabilities"]["high"]["open"]), "measured, synthetic"),
        ("Control effectiveness (passing / tested)", f"{round(100 * c['passing'] / c['tested'], 1)}%",
         "measured, synthetic"),
        ("Risk SLA adherence", f"{sla['adherence_pct']}% ({sla['breaches']} breaches)", "measured, synthetic"),
        ("Invalid risk acceptances (no owner or expired)", str(len(sla["invalid_acceptances"])),
         "measured, synthetic"),
        ("AI inventory coverage", f"{m['ai_register']['inventory_coverage_pct']}%", "measured, synthetic"),
        ("Risky AI actions blocked", str(gov.get("Agent legal-risk incidents blocked", "n/a")), "measured, synthetic"),
    ]
    for rid, x in fair.items():
        risk.append((f"FAIR annual loss {rid} (P50 / P90 / P95)",
                     f"${x['p50']:,} / ${x['p90']:,} / ${x['p95']:,}", "SIMULATED (FAIR-style Monte Carlo)"))
    trust = [
        ("Questionnaire turnaround", f"{q['avg_days_to_decision']} days avg vs {QUESTIONNAIRE_SLA_DAYS}-day target",
         "measured, synthetic"),
        ("Questionnaire SLA breaches", str(q["sla_breaches"]), "measured, synthetic"),
        ("AI evidence-mapping precision", str(m["agents"]["mapper_precision"]), "measured on labeled set"),
        ("AI-generated tests accepted by reviewers", f"{at['acceptance_pct']}% ({at['live']} live)",
         "measured on synthetic requests"),
        ("EU CRA reporting clocks met", f"{cra['met']} of {cra['met'] + cra['late'] + cra['overdue']}",
         "measured, synthetic events"),
        ("Value waiting on security review", f"${t['value_waiting']:,}", "SIMULATED"),
    ]
    return {"efficiency": eff, "risk": risk, "trust": trust,
            "fair_sentences": {rid: x["sentence"] for rid, x in fair.items()}}


def daily_deltas(today: str = TODAY) -> list[tuple]:
    from . import insights
    ins = insights.summary(today=today)
    return [("Tests flipped pass->fail in last 24h", str(ins["flipped"]["24h"]), "measured on synthetic history"),
            ("Failing tests now", str(ins["failing_now"]), "measured, synthetic"),
            ("MTTR for failed tests", f"{ins['mttr_hours']} h", "measured on synthetic history")]
