"""Evidence statuses with freshness: Needs Artifact, Needs Renewal, Upcoming Renewal, Ready, Error.

Each evidence kind has a renewal window in days (author's defaults; a team can change them).
* Error: the record fails its hash/lineage check.
* Needs Renewal: older than its window.
* Upcoming Renewal: inside the last 15 days of its window.
* Ready: fresh and intact.
* Needs Artifact: a control in scope has no evidence record at all.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter

from .. import TODAY
from ..integrations import schema

STATUSES = ("Needs Artifact", "Needs Renewal", "Upcoming Renewal", "Ready", "Error")
WINDOW_DAYS = {"account": 30, "access_review": 90, "backup_job": 7, "change": 30, "pull_request": 30,
               "log_review": 7, "training": 365, "policy_doc": 365, "vendor": 365, "vuln_scan": 30,
               "vuln_host": 30, "incident": 365, "hr_event": 90, "posture_finding": 30, "risk_snapshot": 31,
               "flaw_remediation": 365}
DEFAULT_WINDOW = 90
UPCOMING_DAYS = 15


def classify(e, today: str = TODAY) -> dict:
    window = WINDOW_DAYS.get(e.kind, DEFAULT_WINDOW)
    try:
        age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(e.observed_at[:10])).days
    except ValueError:
        return {"id": e.evidence_id, "kind": e.kind, "status": "Error", "age": None, "window": window,
                "why": "bad date"}
    if not schema.verify(e):
        st, why = "Error", "hash or lineage check failed"
    elif age > window:
        st, why = "Needs Renewal", f"{age} days old, window {window}"
    elif age > window - UPCOMING_DAYS:
        st, why = "Upcoming Renewal", f"renew within {window - age} days"
    else:
        st, why = "Ready", f"{age} days old"
    return {"id": e.evidence_id, "kind": e.kind, "status": st, "age": age, "window": window,
            "renew_by": (dt.date.fromisoformat(e.observed_at[:10]) + dt.timedelta(days=window)).isoformat(),
            "why": why, "controls": list(e.control_hints)}


def needs_artifact(evidence, controls) -> list[str]:
    have = {c for e in evidence for c in e.control_hints}
    return sorted(c for c in controls if c not in have)


def summary(evidence=None, controls=None, today: str = TODAY) -> dict:
    if evidence is None:
        from ..integrations.connectors import collect_all
        evidence = collect_all()
    rows = [classify(e, today) for e in evidence]
    c = Counter(r["status"] for r in rows)
    missing = needs_artifact(evidence, controls or [])
    c["Needs Artifact"] = len(missing)
    fresh = sum(r["status"] in ("Ready", "Upcoming Renewal") for r in rows)
    return {"counts": {s: c.get(s, 0) for s in STATUSES}, "records": len(rows),
            "fresh_pct": round(100 * fresh / len(rows), 1) if rows else 0.0, "missing": missing, "rows": rows}
