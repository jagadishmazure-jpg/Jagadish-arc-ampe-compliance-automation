"""Owners, escalation, and an ownership agent that suggests owners (a human approves).

Escalation ladder for an overdue task: owner at day 0, the owner's manager at day 15, the CISO at day 30.
The agent suggests an owner for each unowned control from (1) the family default owner and (2) who owns most
controls in the same family already; it never assigns. A suggestion becomes an owner only after approve().
"""
from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, field

from .. import TODAY
from ..attest import OWNER_BY_FAMILY

MANAGERS = {"isso": "ciso", "cloud-platform": "platform-manager", "identity-team": "it-manager",
            "privacy-officer": "general-counsel", "procurement-lead": "cfo", "control-owner": "isso",
            "training-lead": "people-manager", "it-ops-manager": "cio", "facilities-security": "cio",
            "hr-security-liaison": "people-manager", "continuity-lead": "cio", "ir-lead": "isso"}
LADDER = ((0, "owner"), (15, "manager"), (30, "ciso"))


def escalation(owner: str, due: str, today: str = TODAY) -> dict:
    late = (dt.date.fromisoformat(today) - dt.date.fromisoformat(due)).days
    level = "none"
    who = None
    for days, lvl in LADDER:
        if late >= days:
            level = lvl
    if level == "owner":
        who = owner
    elif level == "manager":
        who = MANAGERS.get(owner, "ciso")
    elif level == "ciso":
        who = "ciso"
    return {"owner": owner, "due": due, "days_late": max(0, late), "level": level, "notify": who}


@dataclass
class OwnershipBoard:
    owners: dict = field(default_factory=dict)        # control -> owner
    suggestions: dict = field(default_factory=dict)   # control -> {owner, why, status}
    log: list = field(default_factory=list)

    def suggest(self, controls) -> list[dict]:
        out = []
        for c in controls:
            if c.id in self.owners:
                continue
            fam_owners = Counter(o for cid, o in self.owners.items() if cid.split("-")[0] == c.family)
            if fam_owners:
                who, n = fam_owners.most_common(1)[0]
                why = f"owns {n} other {c.family} controls"
            else:
                who = OWNER_BY_FAMILY.get(c.family, "isso")
                why = f"default owner for the {c.family} family"
            self.suggestions[c.id] = {"control": c.id, "owner": who, "why": why, "status": "suggested",
                                      "by": "agent:ownership"}
            out.append(self.suggestions[c.id])
        return out

    def approve(self, control: str, approver: str, owner: str | None = None) -> dict:
        if approver.startswith("agent:"):
            raise PermissionError("an agent cannot approve its own ownership suggestion")
        s = self.suggestions[control]
        s.update(status="approved" if owner in (None, s["owner"]) else "edited", approved_by=approver)
        self.owners[control] = owner or s["owner"]
        self.log.append(("approve", control, approver, self.owners[control]))
        return s

    def reject(self, control: str, approver: str, note: str) -> dict:
        s = self.suggestions[control]
        s.update(status="rejected", approved_by=approver, note=note)
        self.log.append(("reject", control, approver, note))
        return s

    def acceptance_rate(self) -> float:
        done = [s for s in self.suggestions.values() if s["status"] != "suggested"]
        return round(sum(s["status"] == "approved" for s in done) / len(done), 3) if done else 0.0


def overdue_tasks(today: str = TODAY) -> list[dict]:
    """Escalations for open POA&M items from the core POA&M builder."""
    from .. import assess, poam
    out = []
    for it in poam.build(assess.run_all()):
        e = escalation(it.owner, it.due, today)
        if e["level"] != "none":
            out.append({"item": it.id, "severity": it.severity, **e})
    return out


def ladder_counts(today: str = TODAY) -> dict:
    c = Counter(t["level"] for t in overdue_tasks(today))
    return {lvl: c.get(lvl, 0) for _, lvl in LADDER}
