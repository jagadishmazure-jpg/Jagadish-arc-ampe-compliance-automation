"""Recurring tasks (A14): a small cadence engine for review work that has no automated test.

Cadences are counted in days. Every occurrence is a task with an owner; a task becomes overdue the day after its
due date. Completion needs a named person (agents cannot complete a recurring review).
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .. import TODAY

CADENCE_DAYS = {"weekly": 7, "bi-monthly": 61, "monthly": 30, "quarterly": 91, "semi-annual": 182, "annual": 365}


@dataclass(frozen=True)
class Recurring:
    id: str
    title: str
    cadence: str
    owner: str
    start: str
    controls: tuple[str, ...] = ()


DEFAULTS = (
    Recurring("RT-01", "Weekly control review", "weekly", "isso", "2026-09-07", ("CA-07",)),
    Recurring("RT-02", "Vendor reassessment", "bi-monthly", "procurement-lead", "2026-05-01", ("SR-03", "SA-09")),
    Recurring("RT-03", "AI policy review", "semi-annual", "ai-governance-lead", "2026-01-15", ("PM-09",)),
    Recurring("RT-04", "Firewall rule review", "quarterly", "network-lead", "2026-02-01", ("SC-07",)),
    Recurring("RT-05", "Privileged access review", "monthly", "iam-lead", "2026-06-01", ("AC-02(07)",)),
)


class RecurringError(ValueError):
    pass


def occurrences(r: Recurring, until: str = TODAY) -> list[str]:
    if r.cadence not in CADENCE_DAYS:
        raise RecurringError(f"unknown cadence {r.cadence}")
    d, end, step, out = dt.date.fromisoformat(r.start), dt.date.fromisoformat(until), CADENCE_DAYS[r.cadence], []
    while d <= end:
        out.append(d.isoformat())
        d += dt.timedelta(days=step)
    return out


def next_due(r: Recurring, today: str = TODAY) -> str:
    occ = occurrences(r, today)
    return (dt.date.fromisoformat(occ[-1]) + dt.timedelta(days=CADENCE_DAYS[r.cadence])).isoformat() if occ else r.start


# synthetic completion record: (task id, due date) -> completed by
COMPLETED = {("RT-01", d) for d in ("2026-09-07", "2026-09-14", "2026-09-21", "2026-10-05", "2026-10-12",
                                    "2026-10-19")} | {("RT-02", "2026-05-01"), ("RT-02", "2026-07-01"),
                                                      ("RT-03", "2026-01-15"), ("RT-04", "2026-02-01"),
                                                      ("RT-04", "2026-05-03"), ("RT-04", "2026-08-02")} | {
    ("RT-05", d) for d in ("2026-06-01", "2026-07-01", "2026-07-31", "2026-08-30", "2026-09-29")}


def complete(task_id: str, due: str, by: str, done: set | None = None) -> set:
    if not by or by.startswith("agent:"):
        raise RecurringError("a named person must complete a recurring review")
    done = set(COMPLETED if done is None else done)
    done.add((task_id, due))
    return done


def status(today: str = TODAY, items=DEFAULTS, done=None) -> list[dict]:
    done = COMPLETED if done is None else done
    rows = []
    for r in items:
        occ = occurrences(r, today)
        missed = [d for d in occ if (r.id, d) not in done and d < today]
        rows.append({"id": r.id, "title": r.title, "cadence": r.cadence, "owner": r.owner,
                     "occurrences": len(occ), "completed": sum((r.id, d) in done for d in occ),
                     "missed": missed, "next_due": next_due(r, today)})
    return rows


def on_time_rate(today: str = TODAY) -> float:
    rows = status(today)
    occ = sum(r["occurrences"] for r in rows)
    return round(100 * (occ - sum(len(r["missed"]) for r in rows)) / occ, 1) if occ else 100.0
