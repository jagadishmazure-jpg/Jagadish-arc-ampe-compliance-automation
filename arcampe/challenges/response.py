"""Challenge: slow response. Route every open item to an owner with an SLA and escalate on breach."""
from __future__ import annotations

from ..poam import PoamItem

ESCALATION = {"due_soon": "owner", "overdue": "owner+isso", "on_track": None}
OVERDUE_CISO_DAYS = 30


def route(items: list[PoamItem]) -> list[dict]:
    out = []
    for i in items:
        notify = ESCALATION[i.sla_status]
        if i.sla_status == "overdue" and i.days_open - _sla(i) > OVERDUE_CISO_DAYS:
            notify = "owner+isso+ciso"
        out.append({"poam": i.id, "owner": i.owner, "severity": i.severity, "due": i.due, "sla": i.sla_status,
                    "notify": notify, "action": "draft reminder (not sent)" if notify else "none"})
    return out


def _sla(i: PoamItem) -> int:
    from ..params import SLA_DAYS
    return SLA_DAYS[i.severity]


def metrics(items: list[PoamItem]) -> dict:
    open_days = sorted(i.days_open for i in items)
    mid = open_days[len(open_days) // 2] if open_days else 0
    return {"open": len(items), "median_days_open": mid,
            "overdue": sum(i.sla_status == "overdue" for i in items),
            "pct_within_sla": round(100 * sum(i.sla_status != "overdue" for i in items) / len(items), 1)
            if items else 100.0}
