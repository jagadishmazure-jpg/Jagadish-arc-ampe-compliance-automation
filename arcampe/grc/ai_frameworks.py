"""AI framework views (A12): ISO 42001, NIST AI RMF, EU AI Act article map, AIUC-1 domains, and EU Cyber
Resilience Act reporting clocks. All crosswalks are author-built and APPROXIMATE.

`overlap()` counts, over an author-judged list of 25 ISO 42001 Annex A topics, how many already get reusable
evidence from a SOC 2 / ISO 27001 program. It is the author's judgement, shown with its inputs, not a fact.

EU CRA clocks (Art. 14, as summarized in public guidance; confirm against the regulation text): for an actively
exploited vulnerability an early warning within 24 hours, a notification within 72 hours and a final report
within 14 days after a corrective measure is available; for a severe incident the final report is due within one
month of the notification. Drafts are previews; submission needs a named human approver.
"""
from __future__ import annotations

import datetime as dt

from .. import catalog
from . import frameworks

AI_FRAMEWORKS = ("ISO42001", "NIST_AI_RMF", "EU_AI_ACT", "AIUC_1")
AIUC_DOMAINS = ("A Data & Privacy", "B Security", "C Safety", "D Reliability", "E Accountability", "F Society")
CRA_CLOCKS = {"early_warning": dt.timedelta(hours=24), "notification": dt.timedelta(hours=72)}
CRA_FINAL = {"vulnerability": dt.timedelta(days=14), "incident": dt.timedelta(days=30)}


class CraError(ValueError):
    pass


def readiness(by_control=None) -> list[dict]:
    return frameworks.readiness(by_control, frameworks=list(AI_FRAMEWORKS))


def _cids() -> list[str]:
    return [c.id for c in catalog.baseline("ae")]


def aiuc_domains(by_control=None) -> list[dict]:
    from .. import assess
    by = assess.by_control() if by_control is None else by_control
    rows = []
    for d in AIUC_DOMAINS:
        ids = [c for c in _cids() if d in frameworks.map_control(c).get("AIUC_1", ())]
        st = [by.get(c, {}).get("status", "not_tested") for c in ids]
        rows.append({"domain": d, "controls": len(ids), "pass": st.count("pass"), "fail": st.count("fail"),
                     "untested": len(ids) - st.count("pass") - st.count("fail")})
    return rows


def eu_ai_act_articles() -> dict[str, list[str]]:
    out: dict[str, set] = {}
    for fam, arts in frameworks.EXT_MAP["EU_AI_ACT"].items():
        for a in arts:
            out.setdefault(a, set()).add(fam)
    return {a: sorted(v) for a, v in sorted(out.items(), key=lambda x: int(x[0].split(".")[1]))}


# Author-judged topic list for ISO 42001 Annex A (paraphrased topic names, not the standard's text). The third
# field says whether a SOC 2 / ISO 27001 program usually already produces reusable evidence for the topic.
ISO42001_TOPICS = (
    ("A.2", "AI policy", "partial"), ("A.2", "Alignment with other policies", "yes"),
    ("A.2", "Review of the AI policy", "yes"), ("A.3", "AI roles and responsibilities", "partial"),
    ("A.3", "Reporting of concerns", "yes"), ("A.4", "Resources for AI systems", "partial"),
    ("A.4", "Competence of AI staff", "yes"), ("A.5", "AI system impact assessment process", "no"),
    ("A.5", "Impact on individuals and groups", "no"), ("A.5", "Societal impact assessment", "no"),
    ("A.6", "Objectives for responsible AI development", "no"), ("A.6", "AI system requirements", "partial"),
    ("A.6", "Design and development records", "yes"), ("A.6", "Verification and validation", "partial"),
    ("A.6", "Deployment", "yes"), ("A.6", "Operation and monitoring", "yes"),
    ("A.6", "Technical documentation", "partial"), ("A.6", "Event logs", "yes"),
    ("A.7", "Data for AI systems", "partial"), ("A.7", "Data quality", "no"), ("A.7", "Data provenance", "no"),
    ("A.8", "Information for users", "partial"), ("A.8", "Incident communication", "yes"),
    ("A.9", "Intended use of AI", "no"), ("A.10", "Suppliers and customers", "yes"),
)


def overlap() -> dict:
    """Share of ISO 42001 topics where existing SOC 2 / ISO 27001 evidence is reusable (author judgement)."""
    n = len(ISO42001_TOPICS)
    yes = sum(t[2] == "yes" for t in ISO42001_TOPICS)
    part = sum(t[2] == "partial" for t in ISO42001_TOPICS)
    return {"topics": n, "reusable": yes, "partial": part, "ai_specific": n - yes - part,
            "overlap_pct": round(100 * (yes + 0.5 * part) / n, 1),
            "ai_specific_topics": [t[1] for t in ISO42001_TOPICS if t[2] == "no"],
            "label": "author judgement over 25 topics (partial counts half)"}


# ------------------------------------------------------------------ EU CRA clocks
SAMPLE_EVENTS = (
    {"id": "CRA-1", "type": "vulnerability", "product": "Member portal app", "aware": "2026-10-02T09:00",
     "early_warning": "2026-10-02T20:00", "notification": "2026-10-04T15:00", "fix_available": "2026-10-10T12:00",
     "final": "2026-10-20T10:00"},
    {"id": "CRA-2", "type": "vulnerability", "product": "Enrollment API SDK", "aware": "2026-10-20T08:00",
     "early_warning": "2026-10-21T11:00", "notification": "", "fix_available": "", "final": ""},
    {"id": "CRA-3", "type": "incident", "product": "Broker desktop app", "aware": "2026-09-01T07:00",
     "early_warning": "2026-09-01T18:00", "notification": "2026-09-03T06:00", "fix_available": "",
     "final": "2026-09-25T12:00"},
)


def _t(s: str) -> dt.datetime | None:
    return dt.datetime.fromisoformat(s) if s else None


def clocks(ev: dict, now: str = "2026-10-31T09:00") -> dict:
    aware, n = _t(ev["aware"]), _t(now)
    out = {}
    for k, limit in CRA_CLOCKS.items():
        due, done = aware + limit, _t(ev[k])
        out[k] = {"due": due.isoformat(timespec="minutes"),
                  "status": ("met" if done <= due else "late") if done else ("overdue" if n > due else "open")}
    base = _t(ev["fix_available"]) if ev["type"] == "vulnerability" else _t(ev["notification"])
    if base is None:
        out["final"] = {"due": None, "status": "waiting for " + ("a fix" if ev["type"] == "vulnerability"
                                                                 else "the notification")}
    else:
        due, done = base + CRA_FINAL[ev["type"]], _t(ev["final"])
        out["final"] = {"due": due.isoformat(timespec="minutes"),
                        "status": ("met" if done <= due else "late") if done else ("overdue" if n > due else "open")}
    return {"id": ev["id"], "type": ev["type"], "product": ev["product"], **out}


def cra_summary(now: str = "2026-10-31T09:00") -> dict:
    rows = [clocks(e, now) for e in SAMPLE_EVENTS]
    st = [r[k]["status"] for r in rows for k in ("early_warning", "notification", "final")]
    return {"events": len(rows), "met": st.count("met"), "late": st.count("late"), "overdue": st.count("overdue"),
            "rows": rows, "label": "synthetic events"}


def draft_cra_report(ev: dict, stage: str) -> dict:
    if stage not in ("early_warning", "notification", "final"):
        raise CraError("unknown stage")
    return {"event": ev["id"], "stage": stage, "product": ev["product"], "status": "draft_preview",
            "submitted": False, "needs": "named human approver before submission"}


def approve_submission(draft: dict, approver: str) -> dict:
    if not approver or approver.startswith("agent:"):
        raise CraError("a named human must approve a CRA submission")
    return {**draft, "status": "approved_for_submission", "approver": approver, "submitted": False}
