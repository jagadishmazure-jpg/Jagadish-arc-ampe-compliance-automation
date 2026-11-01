"""Continuous monitoring: threat-detection rules over activity events and a vulnerability view.

Rule thresholds reuse ARC-AMPE values where one exists (AC-07: 5 failures in 15 minutes).
Detection quality is measured against the labelled synthetic scenarios in data/platform/events.json.
"""
from __future__ import annotations

import datetime as dt
import json
from collections import defaultdict

from .. import DATA
from ..params import PARAMS

EXFIL_COUNT = 500
TRAVEL_MINUTES = 120


def load_events(path=None) -> list[dict]:
    return json.loads((path or DATA / "platform" / "events.json").read_text())["events"]


def _t(e):
    return dt.datetime.fromisoformat(e["at"])


def detect(events: list[dict]) -> list[dict]:
    alerts = []
    p = PARAMS["AC-07"]
    fails = defaultdict(list)
    last_ok: dict[str, dict] = {}
    for e in events:
        if e["kind"] == "signin" and not e["ok"]:
            win = [x for x in fails[e["user"]] if (_t(e) - _t(x)).total_seconds() <= p["window_minutes"] * 60]
            win.append(e)
            fails[e["user"]] = win
            if len(win) == p["max_attempts"]:
                alerts.append({"rule": "brute-force", "user": e["user"], "at": e["at"], "controls": ["AC-07", "SI-04"]})
        if e["kind"] == "signin" and e["ok"]:
            prev = last_ok.get(e["user"])
            if prev and prev["country"] != e["country"] and (_t(e) - _t(prev)).total_seconds() <= TRAVEL_MINUTES * 60:
                alerts.append({"rule": "impossible-travel", "user": e["user"], "at": e["at"],
                               "controls": ["AC-02(12)", "SI-04"]})
            if e.get("admin") and e["country"] != "US":
                alerts.append({"rule": "admin-signin-outside-us", "user": e["user"], "at": e["at"],
                               "controls": ["AC-17", "SI-04"]})
            last_ok[e["user"]] = e
        if e["kind"] == "role_assignment" and not e.get("via_pim"):
            alerts.append({"rule": "privileged-role-outside-pim", "user": e["user"], "at": e["at"],
                           "controls": ["AC-02(07)", "AC-06(05)"]})
        if e["kind"] == "download" and e.get("count", 0) > EXFIL_COUNT:
            alerts.append({"rule": "mass-download", "user": e["user"], "at": e["at"], "controls": ["AC-04", "SI-04(04)"]})
    return alerts


def score(events: list[dict], alerts: list[dict]) -> dict:
    """Scenario-level detection rate and alert-level false positives against the labels."""
    scen = {e["scenario"] for e in events if e["scenario"]}
    key = {(e["user"], e["at"]): e["scenario"] for e in events}
    hit = {key.get((a["user"], a["at"])) for a in alerts} - {None}
    fp = sum(1 for a in alerts if not key.get((a["user"], a["at"])))
    return {"scenarios": len(scen), "detected": len(hit & scen), "missed": sorted(scen - hit),
            "alerts": len(alerts), "false_positives": fp}


def vulnerability_view(evidence) -> dict:
    """Roll up open findings from scanners and posture tools (Tenable, Qualys, Defender, AWS, GCP)."""
    out = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "hosts_with_sev5": 0, "sources": set()}
    for e in evidence:
        if e.kind == "posture_finding" and not e.attributes["healthy"]:
            sev = {"medium": "moderate", "informational": "low"}.get(e.attributes["severity"], e.attributes["severity"])
            if sev in out:
                out[sev] += 1
            out["sources"].add(e.source)
        if e.kind == "vuln_host" and e.attributes["sev5"]:
            out["hosts_with_sev5"] += 1
            out["sources"].add(e.source)
    out["sources"] = sorted(out["sources"])
    return out
