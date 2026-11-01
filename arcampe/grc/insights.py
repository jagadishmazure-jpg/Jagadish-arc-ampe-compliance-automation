"""Actionable insights (A4): which tests flipped pass->fail in the last 24h, 7d and 14d, and MTTR for failed tests.

The history is synthetic and deterministic: earlier daily snapshots are derived from today's real assessment
results with a seeded rule (a hash of check, resource and day). MTTR is the mean hours from a fail to the next
pass across the 30-day history. Trend is grouped by control family and by owner.
"""
from __future__ import annotations

import datetime as dt
import hashlib

from .. import TODAY

HISTORY_DAYS = 30
WINDOWS = {"24h": 1, "7d": 7, "14d": 14}


def _h(*parts) -> int:
    return int(hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:8], 16)


def _first_fail_day(key: str, today_passed: bool) -> int | None:
    """Days ago the current failure started (None if passing today). Deterministic in [0, 29]."""
    return None if today_passed else _h("ff", key) % HISTORY_DAYS


def history(findings=None, today: str = TODAY) -> list[dict]:
    """One row per test key with a 30-day pass/fail series (index 0 = 29 days ago, last = today)."""
    from .. import assess
    findings = assess.run_all() if findings is None else findings
    rows = []
    for f in findings:
        key = f"{f.check_id}:{f.resource_name}"
        ff = _first_fail_day(key, f.passed)
        series = []
        for ago in range(HISTORY_DAYS - 1, -1, -1):
            if ff is not None and ago <= ff:
                series.append(False)
            elif _h("old", key) % 5 == 0 and HISTORY_DAYS - 1 - ago in range(_h("s", key) % 10, _h("s", key) % 10 + 2 + _h("l", key) % 4):
                series.append(False)  # an earlier failure that was fixed
            else:
                series.append(True)
        rows.append({"key": key, "check": f.check_id, "family": (f.controls[0] if f.controls else "XX")[:2],
                     "severity": f.severity, "series": series})
    return rows


def flips(rows, window: str) -> list[dict]:
    n = WINDOWS[window]
    out = []
    for r in rows:
        s = r["series"]
        if not s[-1] and any(a and not b for a, b in zip(s[-1 - n:-1], s[-n:])):
            out.append({"key": r["key"], "family": r["family"], "severity": r["severity"]})
    return out


def mttr_hours(rows) -> float | None:
    """Mean hours from the first failing day to the next passing day, over closed failures only."""
    spans = []
    for r in rows:
        s, start = r["series"], None
        for i, ok in enumerate(s):
            if not ok and start is None:
                start = i
            elif ok and start is not None:
                spans.append((i - start) * 24)
                start = None
    return round(sum(spans) / len(spans), 1) if spans else None


def summary(findings=None, today: str = TODAY) -> dict:
    rows = history(findings, today)
    fl = {w: flips(rows, w) for w in WINDOWS}
    by_family: dict[str, int] = {}
    for x in fl["7d"]:
        by_family[x["family"]] = by_family.get(x["family"], 0) + 1
    closed = sum(1 for r in rows for a, b in zip(r["series"], r["series"][1:]) if not a and b)
    return {"tests": len(rows), "failing_now": sum(not r["series"][-1] for r in rows),
            "flipped": {w: len(v) for w, v in fl.items()}, "flipped_7d_by_family": dict(sorted(by_family.items())),
            "mttr_hours": mttr_hours(rows), "fixes_in_window": closed, "label": "synthetic history"}


def as_of(today: str, days_ago: int) -> str:
    return (dt.date.fromisoformat(today) - dt.timedelta(days=days_ago)).isoformat()
