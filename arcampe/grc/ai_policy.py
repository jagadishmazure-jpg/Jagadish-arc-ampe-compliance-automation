"""The AI Development and Evaluation Policy control (AI-DEV-EVAL).

One control, four parts, each Ready or Not Ready on its own: Evidence, Monitoring, Policy, Approval. Each part
has an owner and a due date; the control is Ready only when all four are. It maps to ISO 42001, NIST AI RMF,
EU AI Act and AIUC-1 (author-built, approximate) and to the NIST 800-53 controls it leans on.
All values are synthetic.
"""
from __future__ import annotations

import datetime as dt

from .. import TODAY

CONTROL = {
    "id": "AI-DEV-EVAL",
    "title": "AI Development and Evaluation Policy",
    "statement": "AI features are built, evaluated and changed under a written policy: every model or prompt "
                 "change passes an evaluation gate with safety metrics, is approved by a named person, and is "
                 "monitored after release.",
    "maps_to": {"ISO42001": ("A.2", "A.6"), "NIST_AI_RMF": ("GOVERN 1", "MEASURE 2", "MANAGE 4"),
                "EU_AI_ACT": ("Art.9", "Art.15"), "AIUC_1": ("C Safety", "D Reliability"),
                "NIST_800_53": ("SA-08", "SA-11", "CA-07", "PL-02")},
    "parts": {
        "evidence": {"owner": "ml-lead", "due": "2026-11-15", "items": ["eval report v14", "red-team results"],
                     "required": 2},
        "monitoring": {"owner": "ml-ops", "due": "2026-11-30", "tests": {"eval_gate_in_ci": True,
                                                                        "drift_monitor": True,
                                                                        "safety_metric_at_1_0": False}},
        "policy": {"owner": "ai-governance-lead", "due": "2026-11-01", "approved_on": "2026-01-20",
                   "review_every_days": 365},
        "approval": {"owner": "ciso", "due": "2026-11-10", "approved_by": "", "approver_is_agent": False},
    },
}


def part_status(name: str, part: dict, today: str = TODAY) -> dict:
    if name == "evidence":
        ok = len(part["items"]) >= part["required"]
        why = f"{len(part['items'])} of {part['required']} evidence items"
    elif name == "monitoring":
        failing = [k for k, v in part["tests"].items() if not v]
        ok, why = not failing, "all monitoring tests pass" if not failing else f"failing: {failing}"
    elif name == "policy":
        age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(part["approved_on"])).days
        ok, why = age <= part["review_every_days"], f"policy approved {age} days ago"
    elif name == "approval":
        ok = bool(part["approved_by"]) and not part["approver_is_agent"]
        why = f"approved by {part['approved_by']}" if ok else "waiting for a human approver"
    else:
        raise KeyError(name)
    overdue = not ok and dt.date.fromisoformat(part["due"]) < dt.date.fromisoformat(today)
    return {"part": name, "ready": ok, "owner": part["owner"], "due": part["due"], "overdue": overdue, "why": why}


def status(control: dict | None = None, today: str = TODAY) -> dict:
    c = control or CONTROL
    parts = [part_status(n, p, today) for n, p in c["parts"].items()]
    return {"control": c["id"], "title": c["title"], "ready": all(p["ready"] for p in parts), "parts": parts,
            "ready_parts": sum(p["ready"] for p in parts), "of": len(parts)}
