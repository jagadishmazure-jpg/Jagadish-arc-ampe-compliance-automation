"""Plan of Action and Milestones built automatically from failed findings.

One POA&M item per (check, resource). Due date = first seen + SI-02 SLA for the severity.
First-seen dates come from data/poam_history.json (synthetic) so the SLA clock is visible.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import asdict, dataclass

from . import DATA, TODAY
from .params import SLA_DAYS

MILESTONES = ("Confirm finding and owner", "Fix or compensating control in place", "Re-test passes", "Close")


@dataclass(frozen=True)
class PoamItem:
    id: str
    check_id: str
    resource: str
    weakness: str
    controls: tuple[str, ...]
    severity: str
    first_seen: str
    due: str
    days_open: int
    sla_status: str     # on_track | due_soon | overdue
    owner: str
    milestones: tuple[str, ...] = MILESTONES

    def row(self) -> dict:
        d = asdict(self)
        d["controls"] = ", ".join(self.controls)
        d["milestones"] = " -> ".join(self.milestones)
        return d


OWNER_BY_PREFIX = {"AZ": "cloud-platform", "ID": "identity-team", "EV": "isso", "PT": "privacy-officer",
                   "SR": "procurement-lead", "AT": "control-owner"}


def history(path=None) -> dict[str, str]:
    p = path or DATA / "poam_history.json"
    return json.loads(p.read_text()) if p.exists() else {}


def key(f) -> str:
    return f"{f.check_id}|{f.resource_id}"


def poam_id(k: str) -> str:
    return "POAM-" + hashlib.sha256(k.encode()).hexdigest()[:8].upper()


def build(findings, today: str = TODAY, first_seen: dict | None = None) -> list[PoamItem]:
    first_seen = history() if first_seen is None else first_seen
    t = dt.date.fromisoformat(today)
    items = []
    for f in findings:
        if f.passed:
            continue
        k = key(f)
        seen = dt.date.fromisoformat(first_seen.get(k, today))
        due = seen + dt.timedelta(days=SLA_DAYS[f.severity])
        left = (due - t).days
        status = "overdue" if left < 0 else "due_soon" if left <= 7 else "on_track"
        items.append(PoamItem(poam_id(k), f.check_id, f.resource_name, f.detail, tuple(f.controls), f.severity,
                              seen.isoformat(), due.isoformat(), (t - seen).days, status,
                              OWNER_BY_PREFIX.get(f.check_id.split("-")[0], "isso")))
    order = {s: i for i, s in enumerate(SLA_DAYS)}
    return sorted(items, key=lambda i: (order[i.severity], i.due, i.id))


def summary(items: list[PoamItem]) -> dict:
    out = {"open": len(items), "by_severity": {}, "by_sla": {"on_track": 0, "due_soon": 0, "overdue": 0}}
    for i in items:
        out["by_severity"][i.severity] = out["by_severity"].get(i.severity, 0) + 1
        out["by_sla"][i.sla_status] += 1
    return out


def to_csv(items: list[PoamItem]) -> str:
    import csv
    import io
    buf = io.StringIO()
    if not items:
        return ""
    w = csv.DictWriter(buf, fieldnames=list(items[0].row()), lineterminator="\n")
    w.writeheader()
    for i in items:
        w.writerow(i.row())
    return buf.getvalue()
