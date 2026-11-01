"""Workflow automation on a simulated clock: scheduled checks, evidence refresh, SLA alerts, reminders.

Nothing runs in the background. simulate(days) steps a fake clock day by day and records what each
job would have done, so the schedule is testable and repeatable. Messages are drafts, never sent.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .. import TODAY

FRESHNESS_DAYS = {"identity": 1, "cloud": 1, "security": 7, "itsm": 1, "devops": 1, "hr": 1, "platform": 1,
                  "collaboration": 7, "docs": 30, "finance": 30, "openapi": 7, "webhook": 1}


@dataclass(frozen=True)
class Job:
    name: str
    every_days: int
    weekday: int | None = None      # 0 = Monday; None = any day

    def due(self, day: dt.date, start: dt.date) -> bool:
        if self.weekday is not None:
            return day.weekday() == self.weekday
        return (day - start).days % self.every_days == 0


JOBS = (
    Job("run_config_checks", 1),
    Job("refresh_stale_evidence", 1),
    Job("poam_sla_alerts", 1),
    Job("weekly_log_review_reminder", 7, weekday=0),
    Job("attestation_reminders", 7, weekday=0),
    Job("monthly_conmon_report", 30),
    Job("vulnerability_scan_window", 30),
)


def stale_sources(last_refresh: dict[str, str], categories: dict[str, str], day: dt.date) -> list[str]:
    out = []
    for src, last in sorted(last_refresh.items()):
        limit = FRESHNESS_DAYS.get(categories[src], 7)
        if (day - dt.date.fromisoformat(last)).days >= limit:
            out.append(src)
    return out


def simulate(days: int = 30, start: str = TODAY, poam_items=None, connectors=None) -> dict:
    from ..integrations.connectors import ALL
    from ..params import SLA_DAYS

    connectors = connectors or ALL
    s = dt.date.fromisoformat(start)
    cats = {c.name: c.category for c in connectors}
    last = dict.fromkeys(cats, start)
    log: list[dict] = []
    counts: dict[str, int] = {}
    for i in range(days):
        day = s + dt.timedelta(days=i)
        for job in JOBS:
            if not job.due(day, s):
                continue
            counts[job.name] = counts.get(job.name, 0) + 1
            detail = ""
            if job.name == "refresh_stale_evidence":
                st = stale_sources(last, cats, day)
                for src in st:
                    last[src] = day.isoformat()
                detail = f"refreshed {len(st)} source(s)"
            elif job.name == "poam_sla_alerts" and poam_items:
                breached = [p for p in poam_items
                            if dt.date.fromisoformat(p.first_seen) + dt.timedelta(days=SLA_DAYS[p.severity]) == day]
                detail = f"{len(breached)} item(s) hit SLA today (draft alerts)"
            log.append({"day": day.isoformat(), "job": job.name, "detail": detail})
    return {"days": days, "runs": counts, "log": log}
