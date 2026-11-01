"""Ten ready-made workflow recipes (A2), the notification lifecycle and a Monday digest (A3).

Each recipe has exactly one trigger, an optional condition and one action. Actions are written to a log as
"simulated"; nothing is sent. Turning on real delivery needs both `deliver=True` and an approver name, and even
then this module only marks the action "approved_for_delivery" for an outside system to pick up.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .. import TODAY

TRIGGERS = ("evidence.due_soon", "evidence.overdue", "control.not_ready", "test.failed", "risk.residual_high",
            "personnel.noncompliant", "owner.changed", "artifact.uploaded", "evidence.linked", "policy.new_version")
ACTIONS = ("notify", "escalate", "task", "webhook", "review_task", "reattest")


@dataclass(frozen=True)
class Recipe:
    id: str
    name: str
    trigger: str
    action: str
    target: str
    min_days: int = 0  # condition: event "days" must be >= this


RECIPES = (
    Recipe("R01", "Evidence renewal due in 10 days", "evidence.due_soon", "notify", "evidence owner"),
    Recipe("R02", "Evidence overdue 7+ days", "evidence.overdue", "escalate", "owner's manager", 7),
    Recipe("R03", "Control became Not Ready", "control.not_ready", "task", "control owner"),
    Recipe("R04", "Mapped test failed", "test.failed", "webhook", "ticketing (simulated Jira-style webhook)"),
    Recipe("R05", "Residual risk at or above threshold", "risk.residual_high", "task", "risk owner"),
    Recipe("R06", "Person out of compliance 14+ days", "personnel.noncompliant", "escalate", "manager", 14),
    Recipe("R07", "Control owner changed", "owner.changed", "notify", "new and old owner"),
    Recipe("R08", "Artifact uploaded", "artifact.uploaded", "review_task", "evidence reviewer"),
    Recipe("R09", "Evidence linked to a control", "evidence.linked", "review_task", "control owner"),
    Recipe("R10", "Policy has a new version", "policy.new_version", "reattest", "all employees in scope"),
)


RESIDUAL_THRESHOLD = 7.0


class RecipeError(ValueError):
    pass


def validate(r: Recipe) -> list[str]:
    errs = []
    if r.trigger not in TRIGGERS:
        errs.append(f"unknown trigger {r.trigger}")
    if r.action not in ACTIONS:
        errs.append(f"unknown action {r.action}")
    if not r.target:
        errs.append("target required")
    if r.min_days < 0:
        errs.append("min_days must be >= 0")
    return errs


def synthetic_events(today: str = TODAY) -> list[dict]:
    """Events derived from the synthetic data so the recipes run on something real."""
    from .. import assess
    from ..integrations.connectors import collect_all
    from . import access_review_import, evidence_status, risk_registers
    ev = []
    t = dt.date.fromisoformat(today)
    for e in collect_all():
        st = evidence_status.classify(e, today)
        if st["status"] == "Upcoming Renewal":
            ev.append({"type": "evidence.due_soon", "subject": e.evidence_id, "days": 0})
        elif st["status"] == "Needs Renewal":
            ev.append({"type": "evidence.overdue", "subject": e.evidence_id,
                       "days": st["age"] - st["window"]})
    for f in assess.run_all():
        if not f.passed and f.severity in ("critical", "high"):
            ev.append({"type": "test.failed", "subject": f"{f.check_id}:{f.resource_name}", "days": 0})
    for r in risk_registers.scores():
        if r["residual"] >= RESIDUAL_THRESHOLD:
            ev.append({"type": "risk.residual_high", "subject": r["id"], "days": 0})
    for i in access_review_import.issues(access_review_import.load()):
        ev.append({"type": "personnel.noncompliant", "subject": i["user"],
                   "days": (t - dt.date(2026, 10, 1)).days if i["type"] == "terminated_not_revoked" else 3})
    ev += [{"type": "owner.changed", "subject": "AC-02", "days": 0},
           {"type": "artifact.uploaded", "subject": "pentest-2026.pdf", "days": 0},
           {"type": "evidence.linked", "subject": "AC-02<-ev-access-q3", "days": 0},
           {"type": "policy.new_version", "subject": "AC-01 v2.1", "days": 0},
           {"type": "control.not_ready", "subject": "AU-06", "days": 0}]
    return ev


def run(events=None, recipes=RECIPES, today: str = TODAY) -> dict:
    events = synthetic_events(today) if events is None else events
    log = []
    for r in recipes:
        if validate(r):
            raise RecipeError(f"{r.id}: {validate(r)}")
        for e in events:
            if e["type"] == r.trigger and e.get("days", 0) >= r.min_days:
                log.append({"recipe": r.id, "action": r.action, "target": r.target, "subject": e["subject"],
                            "mode": "simulated", "sent": False})
    by = {r.id: sum(x["recipe"] == r.id for x in log) for r in recipes}
    return {"events": len(events), "actions": len(log), "by_recipe": by, "sent": 0, "log": log}


def approve_delivery(entry: dict, approver: str, deliver: bool = False) -> dict:
    if not deliver or not approver or approver.startswith("agent:"):
        raise RecipeError("delivery needs deliver=True and a named human approver")
    return {**entry, "mode": "approved_for_delivery", "approver": approver, "sent": False}


# ---------------------------------------------------------------- notification lifecycle and digest
def lifecycle(due: str, today: str = TODAY, done: bool = False) -> str:
    if done:
        return "done"
    left = (dt.date.fromisoformat(due) - dt.date.fromisoformat(today)).days
    return "overdue" if left < 0 else "upcoming" if left <= 7 else "assigned"


def monday_digest(tasks: list[dict], today: str = TODAY) -> str:
    """Plain-text digest of tasks due in the next 7 days and overdue tasks, grouped by owner. A file, not an email."""
    rows: dict[str, list[str]] = {}
    for t in tasks:
        st = lifecycle(t["due"], today, t.get("done", False))
        if st in ("upcoming", "overdue"):
            rows.setdefault(t["owner"], []).append(f"  [{st}] {t['id']} due {t['due']}: {t['title']}")
    lines = [f"Weekly digest for {today} (preview, not sent)"]
    for owner in sorted(rows):
        lines.append(f"{owner}:")
        lines += sorted(rows[owner])
    return "\n".join(lines) + "\n"


def tasks_from_poam(today: str = TODAY) -> list[dict]:
    from .. import assess, poam
    return [{"id": p.id, "owner": p.owner, "due": p.due, "title": p.weakness[:60]} for p in poam.build(assess.run_all())]
