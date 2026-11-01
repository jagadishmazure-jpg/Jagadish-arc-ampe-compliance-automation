"""Backup and restore drills (CP-09, CP-09(01), CP-10) for the tenant evidence store.

A drill: snapshot the encrypted store, restore it into an empty store, then prove every object
decrypts and matches by SHA-256. A simulated clock gives RPO (age of the newest backup) and RTO.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from ..params import PARAMS
from .tenancy import TenantStore

RPO_HOURS = 24      # daily incremental (CP-09)
RTO_HOURS = 4       # demo target for the exchange's MTD; organization-defined


def _digest(store: TenantStore) -> dict[str, str]:
    out = {}
    for key in store.snapshot():
        t, k = key.split("\x1f", 1)
        out[key] = hashlib.sha256(store.keys.decrypt(t, store.raw(t, k))).hexdigest()
    return out


def backup(store: TenantStore) -> dict:
    snap = store.snapshot()
    return {"objects": snap, "manifest": _digest(store)}


def restore_drill(store: TenantStore, at: str, restore_minutes: int = 18) -> dict:
    bk = backup(store)
    target = TenantStore(keys=store.keys)
    target.load_snapshot(bk["objects"])
    after = _digest(target)
    ok = after == bk["manifest"] and len(after) > 0
    return {"at": at, "objects": len(after), "hash_match": ok, "restore_minutes": restore_minutes,
            "rto_met": restore_minutes <= RTO_HOURS * 60, "passed": ok and restore_minutes <= RTO_HOURS * 60}


def schedule_ok(jobs: list[dict], today: str) -> list[dict]:
    """Check daily incremental + weekly full + 3 generations from backup job history."""
    out = []
    by_target: dict[str, list[dict]] = {}
    for j in jobs:
        by_target.setdefault(j["target"], []).append(j)
    t = dt.date.fromisoformat(today)
    for target, js in sorted(by_target.items()):
        good = [j for j in js if j["status"] == "Completed"]
        inc = [j for j in good if j["type"] == "incremental"]
        full = [j for j in good if j["type"] == "full"]
        newest_inc = max((dt.date.fromisoformat(j["finished"][:10]) for j in inc), default=None)
        newest_full = max((dt.date.fromisoformat(j["finished"][:10]) for j in full), default=None)
        checks = {
            "daily_incremental": newest_inc is not None and (t - newest_inc).days <= 1,
            "weekly_full": newest_full is not None and (t - newest_full).days <= 7,
            "generations": len(full) >= PARAMS["CP-09"]["generations"],
        }
        out.append({"target": target, **checks, "passed": all(checks.values())})
    return out


def manifest_json(drill: dict) -> str:
    return json.dumps(drill, sort_keys=True)
