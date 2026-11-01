"""Audit management: risk-based audit plan, findings tracking and a versioned evidence repository."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import TODAY


@dataclass
class EvidenceRepo:
    """Every upload is a new immutable version, addressed by SHA-256. Nothing is overwritten."""
    items: dict = field(default_factory=dict)       # name -> list of versions

    def put(self, name: str, content: bytes, by: str, at: str = TODAY, controls: tuple = ()) -> dict:
        v = {"version": len(self.items.get(name, [])) + 1, "sha256": hashlib.sha256(content).hexdigest(),
             "size": len(content), "by": by, "at": at, "controls": list(controls)}
        self.items.setdefault(name, []).append(v)
        return v

    def latest(self, name: str) -> dict:
        return self.items[name][-1]

    def history(self, name: str) -> list[dict]:
        return list(self.items[name])

    def verify(self, name: str, content: bytes, version: int | None = None) -> bool:
        v = self.items[name][(version or len(self.items[name])) - 1]
        return hashlib.sha256(content).hexdigest() == v["sha256"]


def audit_plan(by_control: dict, families: dict[str, str], capacity_days: int = 60) -> list[dict]:
    """Rank control families by failing-results share and plan audit days until capacity is used."""
    fam: dict[str, list[int]] = {}
    for cid, d in by_control.items():
        f = fam.setdefault(cid[:2], [0, 0])
        f[0] += d["failed"]
        f[1] += d["passed"] + d["failed"]
    ranked = sorted(((k, v[0] / v[1] if v[1] else 0.0, v[0]) for k, v in fam.items()), key=lambda x: (-x[1], x[0]))
    plan, used = [], 0
    for k, rate, failed in ranked:
        days = 5 if rate >= 0.3 else 3 if rate > 0 else 2
        if used + days > capacity_days:
            break
        used += days
        plan.append({"family": k, "name": families.get(k, k), "fail_rate": round(rate, 3), "failed": failed,
                     "days": days, "priority": "high" if rate >= 0.3 else "medium" if rate > 0 else "low"})
    return plan


@dataclass
class AuditFinding:
    id: str
    title: str
    control: str
    rating: str
    owner: str
    status: str = "open"           # open -> remediating -> validated -> closed
    history: list = field(default_factory=list)

    FLOW = {"open": "remediating", "remediating": "validated", "validated": "closed"}

    def advance(self, by: str, at: str = TODAY) -> str:
        if self.status not in self.FLOW:
            raise ValueError("finding already closed")
        if self.status == "remediating" and by == self.owner:
            raise PermissionError("owner cannot validate own fix")
        self.status = self.FLOW[self.status]
        self.history.append((at, by, self.status))
        return self.status
