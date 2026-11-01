"""Import a user access review export and turn it into evidence for AC-02 (and SOC 2 CC6.2 / CC6.3).

The fixture data/grc/access_review_q3.json is a synthetic export: one row per user per app with the reviewer's
decision (keep, revoke, modify). The importer checks the campaign, not just the file:
* every row has a decision (pending rows block completion)
* no one reviewed their own access
* terminated people were revoked
* admin rows on high-risk apps that were kept with a login older than 90 days are flagged
Each app becomes one evidence record of kind access_review in the core evidence schema.
"""
from __future__ import annotations

import datetime as dt
import json

from .. import DATA, TODAY
from ..integrations import schema

DECISIONS = {"keep", "revoke", "modify"}
STALE_DAYS = 90


def load(path=None) -> dict:
    return json.loads((path or DATA / "grc" / "access_review_q3.json").read_text())


def validate(export: dict) -> list[str]:
    errs = []
    for k in ("campaign", "period", "due", "apps", "rows"):
        if k not in export:
            errs.append(f"missing {k}")
    apps = {a["id"] for a in export.get("apps", [])}
    for i, r in enumerate(export.get("rows", [])):
        if r.get("app") not in apps:
            errs.append(f"row {i}: unknown app {r.get('app')}")
        if r.get("decision") and r["decision"] not in DECISIONS:
            errs.append(f"row {i}: bad decision {r['decision']}")
        if r.get("decision") == "modify" and not r.get("new_role"):
            errs.append(f"row {i}: modify needs new_role")
    return errs


def issues(export: dict, today: str = TODAY) -> list[dict]:
    risk = {a["id"]: a["risk"] for a in export["apps"]}
    out = []
    for r in export["rows"]:
        who = r["user"].split("@")[0]
        if not r.get("decision"):
            out.append({"type": "pending", "app": r["app"], "user": r["user"]})
        if r.get("reviewer") == who:
            out.append({"type": "self_review", "app": r["app"], "user": r["user"]})
        if r.get("employment") == "terminated" and r.get("decision") != "revoke":
            out.append({"type": "terminated_not_revoked", "app": r["app"], "user": r["user"]})
        age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(r["last_login"])).days
        if r.get("role") == "admin" and risk[r["app"]] == "high" and r.get("decision") == "keep" and age > STALE_DAYS:
            out.append({"type": "stale_admin_kept", "app": r["app"], "user": r["user"], "days": age})
    return out


def summarize(export: dict, today: str = TODAY) -> dict:
    rows = export["rows"]
    iss = issues(export, today)
    done = sum(bool(r.get("decision")) for r in rows)
    late = dt.date.fromisoformat(today) > dt.date.fromisoformat(export["due"]) and done < len(rows)
    by = {d: sum(r.get("decision") == d for r in rows) for d in sorted(DECISIONS)}
    return {"campaign": export["campaign"], "rows": len(rows), "reviewed": done,
            "complete_pct": round(100 * done / len(rows), 1), "decisions": by, "late": late,
            "issues": {t: sum(i["type"] == t for i in iss) for t in
                       ("pending", "self_review", "terminated_not_revoked", "stale_admin_kept")}}


def to_evidence(export: dict, today: str = TODAY) -> list:
    errs = validate(export)
    if errs:
        raise ValueError("; ".join(errs))
    iss = issues(export, today)
    out = []
    for a in export["apps"]:
        rows = [r for r in export["rows"] if r["app"] == a["id"]]
        mine = [i for i in iss if i["app"] == a["id"]]
        out.append(schema.make("lakehaven", "access_review_import", "identity", "access_review", a["id"],
                               max(r["reviewed_on"] for r in rows),
                               {"campaign": export["campaign"], "app": a["name"], "rows": len(rows),
                                "reviewed": sum(bool(r.get("decision")) for r in rows),
                                "revoked": sum(r.get("decision") == "revoke" for r in rows),
                                "issues": len(mine), "soc2": ["CC6.2", "CC6.3"]},
                               control_hints=("AC-02", "AC-02(03)", "AC-06(07)")))
    return out
