"""Audited and tested: tracking vulnerability assessments, pen tests and control assessments.

Vulnerability assessment (VA): broad, automated, finds known weaknesses, no exploitation. RA-05.
Penetration test (PT): narrow, human-led, tries to exploit and chain weaknesses under signed rules
of engagement, then retests fixes. CA-08. A scan report labelled "pen test" is flagged.
Control assessment: independent check that controls work as written. CA-02, CA-02(01).
"""
from __future__ import annotations

import datetime as dt
import json

from .. import DATA, TODAY
from ..params import PARAMS

CADENCE = {  # type -> (every_days, control, also_when)
    "vulnerability_assessment": (PARAMS["RA-05"]["scan_every_days"], "RA-05", "new critical CVE or major change"),
    "penetration_test": (PARAMS["CA-08"]["pentest_every_days"], "CA-08", "major release or architecture change"),
    "control_assessment": (365, "CA-02", "significant change or new ATO"),
}
REQUIRED = {
    "penetration_test": {"exploitation": True, "rules_of_engagement": True},
    "vulnerability_assessment": {"exploitation": False},
}


def load(path=None) -> list[dict]:
    return json.loads((path or DATA / "platform" / "assurance.json").read_text())["records"]


def classify(rec: dict) -> str:
    """What the evidence actually is, from its properties, regardless of its label."""
    if rec["exploitation"] and rec["rules_of_engagement"]:
        return "penetration_test"
    if rec["type"] == "control_assessment":
        return "control_assessment"
    return "vulnerability_assessment"


def validate(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        actual = classify(r)
        issues = []
        if actual != r["type"]:
            issues.append(f"labelled {r['type']} but evidence shows {actual}")
        if actual == "penetration_test" and r["findings"].get("high", 0) + r["findings"].get("critical", 0) \
                and not r["retest_date"]:
            issues.append("no retest of high/critical findings")
        if r["type"] in ("penetration_test", "control_assessment") and r["performer"] != "independent":
            issues.append("not performed by an independent assessor")
        out.append({"id": r["id"], "claimed": r["type"], "actual": actual, "ok": not issues, "issues": issues})
    return out


def cadence_status(records: list[dict], today: str = TODAY) -> list[dict]:
    t = dt.date.fromisoformat(today)
    out = []
    for typ, (every, control, trigger) in CADENCE.items():
        valid = [r for r in records if classify(r) == typ]
        last = max((r["date"] for r in valid), default=None)
        age = None if last is None else (t - dt.date.fromisoformat(last)).days
        out.append({"type": typ, "control": control, "every_days": every, "also_when": trigger, "last": last,
                    "age_days": age, "ok": age is not None and age <= every,
                    "next_due": None if last is None else
                    (dt.date.fromisoformat(last) + dt.timedelta(days=every)).isoformat()})
    return out
