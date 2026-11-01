"""Resilience and business continuity: BIA, RTO/RPO coverage, plan tests, supply-chain dependencies."""
from __future__ import annotations

import datetime as dt

from . import TODAY

BIA = [  # synthetic business impact analysis for the fictional exchange
    {"process": "eligibility determination", "system": "sql-lhx-elig", "mtd_hours": 24, "rto_hours": 8, "rpo_hours": 4,
     "depends_on": ["Federal data services hub", "Harbor Identity Proofing"]},
    {"process": "plan enrollment", "system": "sql-lhx-enroll", "mtd_hours": 48, "rto_hours": 12, "rpo_hours": 24,
     "depends_on": ["Bluequill Print and Mail"]},
    {"process": "consumer portal sessions", "system": "cosmos-lhx-session", "mtd_hours": 24, "rto_hours": 4,
     "rpo_hours": 1, "depends_on": []},
    {"process": "call center case notes", "system": "vm-lhx-app04", "mtd_hours": 72, "rto_hours": 24,
     "rpo_hours": 24, "depends_on": ["Northmere Call Center Services"]},
]
EXERCISES = [  # tabletop and functional exercises (synthetic)
    {"id": "TT-2026-1", "type": "tabletop", "scenario": "ransomware on enrollment", "date": "2026-04-14",
     "findings": 4, "closed": 3},
    {"id": "FX-2025-2", "type": "functional failover", "scenario": "region loss", "date": "2025-09-10",
     "findings": 2, "closed": 2},
]


def coverage(evidence, today: str = TODAY) -> list[dict]:
    """Compare each BIA RPO and restore-test date with backup evidence."""
    t = dt.date.fromisoformat(today)
    jobs: dict[str, list] = {}
    for e in evidence:
        if e.kind == "backup_job":
            jobs.setdefault(e.subject, []).append(e)
    out = []
    for b in BIA:
        js = [j for j in jobs.get(b["system"], []) if j.attributes["ok"]]
        newest = max((dt.date.fromisoformat(j.observed_at[:10]) for j in js), default=None)
        gap_h = None if newest is None else (t - newest).days * 24   # backup dates are day-level
        if gap_h is None or gap_h > max(b["rpo_hours"], 24):
            rpo = "missed"
        elif b["rpo_hours"] < 24:
            rpo = "unproven (day-level data cannot show an RPO under 24h)"
        else:
            rpo = "met"
        tests = [j.attributes["restore_tested_on"] for j in jobs.get(b["system"], []) if j.attributes["restore_tested_on"]]
        last_test = max(tests, default=None)
        out.append({"process": b["process"], "system": b["system"], "rpo_hours": b["rpo_hours"],
                    "hours_since_good_backup": gap_h,
                    "rpo_status": rpo,
                    "last_restore_test": last_test,
                    "restore_test_current": last_test is not None
                    and (dt.date.fromisoformat(today) - dt.date.fromisoformat(last_test)).days <= 365,
                    "dependencies": b["depends_on"]})
    return out


def exercise_status(today: str = TODAY) -> dict:
    last = max(EXERCISES, key=lambda x: x["date"])
    age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(last["date"])).days
    return {"last": last["id"], "age_days": age, "cp04_met": age <= 365,
            "open_findings": sum(x["findings"] - x["closed"] for x in EXERCISES)}


def dependency_concentration() -> dict[str, int]:
    out: dict[str, int] = {}
    for b in BIA:
        for d in b["depends_on"]:
            out[d] = out.get(d, 0) + 1
    return out
