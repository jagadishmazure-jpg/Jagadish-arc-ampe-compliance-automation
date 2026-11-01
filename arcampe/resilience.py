"""Resilience and business continuity: BIA, RTO/RPO coverage, plan tests, supply-chain dependencies."""
from __future__ import annotations

import datetime as dt

from . import TODAY

# Identity is a shared dependency of every process: if the directory is down, nobody signs in, including the
# backup console. Listed in every BIA row below and modelled as its own service with its own RTO/RPO.
IDENTITY = "Identity (AD forest + Entra tenant)"

BIA = [  # synthetic business impact analysis for the fictional exchange
    {"process": "eligibility determination", "system": "sql-lhx-elig", "mtd_hours": 24, "rto_hours": 8, "rpo_hours": 4,
     "depends_on": [IDENTITY, "Federal data services hub", "Harbor Identity Proofing"]},
    {"process": "plan enrollment", "system": "sql-lhx-enroll", "mtd_hours": 48, "rto_hours": 12, "rpo_hours": 24,
     "depends_on": [IDENTITY, "Bluequill Print and Mail"]},
    {"process": "consumer portal sessions", "system": "cosmos-lhx-session", "mtd_hours": 24, "rto_hours": 4,
     "rpo_hours": 1, "depends_on": [IDENTITY]},
    {"process": "call center case notes", "system": "vm-lhx-app04", "mtd_hours": 72, "rto_hours": 24,
     "rpo_hours": 24, "depends_on": [IDENTITY, "Northmere Call Center Services"]},
]
EXERCISES = [  # tabletop and functional exercises (synthetic)
    {"id": "TT-2026-1", "type": "tabletop", "scenario": "ransomware on enrollment", "date": "2026-04-14",
     "findings": 4, "closed": 3},
    {"id": "FX-2025-2", "type": "functional failover", "scenario": "region loss", "date": "2025-09-10",
     "findings": 2, "closed": 2},
]


def coverage(evidence, today: str = TODAY) -> list[dict]:
    """Compare each BIA RPO and restore-test date with backup evidence."""
    t = dt.date.fromisoformat(today)
    jobs: dict[str, list] = {}
    for e in evidence:
        if e.kind == "backup_job":
            jobs.setdefault(e.subject, []).append(e)
    out = []
    for b in BIA:
        js = [j for j in jobs.get(b["system"], []) if j.attributes["ok"]]
        newest = max((dt.date.fromisoformat(j.observed_at[:10]) for j in js), default=None)
        gap_h = None if newest is None else (t - newest).days * 24   # backup dates are day-level
        if gap_h is None or gap_h > max(b["rpo_hours"], 24):
            rpo = "missed"
        elif b["rpo_hours"] < 24:
            rpo = "unproven (day-level data cannot show an RPO under 24h)"
        else:
            rpo = "met"
        tests = [j.attributes["restore_tested_on"] for j in jobs.get(b["system"], []) if j.attributes["restore_tested_on"]]
        last_test = max(tests, default=None)
        out.append({"process": b["process"], "system": b["system"], "rpo_hours": b["rpo_hours"],
                    "hours_since_good_backup": gap_h,
                    "rpo_status": rpo,
                    "last_restore_test": last_test,
                    "restore_test_current": last_test is not None
                    and (dt.date.fromisoformat(today) - dt.date.fromisoformat(last_test)).days <= 365,
                    "dependencies": b["depends_on"]})
    return out


def exercise_status(today: str = TODAY) -> dict:
    last = max(EXERCISES, key=lambda x: x["date"])
    age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(last["date"])).days
    return {"last": last["id"], "age_days": age, "cp04_met": age <= 365,
            "open_findings": sum(x["findings"] - x["closed"] for x in EXERCISES)}


def dependency_concentration() -> dict[str, int]:
    out: dict[str, int] = {}
    for b in BIA:
        for d in b["depends_on"]:
            out[d] = out.get(d, 0) + 1
    return out


# ---------------------------------------------------------------------------------------------- identity resilience
# Synthetic identity service, backups and drills. Steps follow the public Microsoft AD forest recovery guidance and
# CISA eviction guidance (restore one DC per domain in isolation, reset krbtgt twice, restore AD before Entra sync).
IDENTITY_SERVICE = {"name": IDENTITY, "rto_hours": 8, "rpo_hours": 24, "owner": "identity-team",
                    "entra_object_types": ("users", "groups", "conditional_access", "pim_assignments",
                                           "app_registrations", "service_principals", "custom_roles",
                                           "auth_methods_policy")}
IDENTITY_BACKUPS = (
    {"id": "IDB-AD-1030", "scope": "ad_forest", "taken": "2026-10-30", "ok": True, "immutable": True,
     "isolated": True, "malware_scanned": True},
    {"id": "IDB-ENTRA-1030", "scope": "entra_tenant", "taken": "2026-10-30", "ok": True, "immutable": True,
     "isolated": False, "malware_scanned": True,
     "object_types": ("users", "groups", "conditional_access", "app_registrations", "service_principals",
                      "auth_methods_policy")},
)
IDENTITY_DRILLS = (
    {"id": "IDR-2026-1", "date": "2026-05-12", "type": "clean-room forest recovery", "clean_room": True,
     "measured_recovery_hours": 11.5, "krbtgt_double_reset": True, "ad_before_entra": True},
    {"id": "IDR-2025-2", "date": "2025-11-03", "type": "Entra object restore", "clean_room": False,
     "measured_recovery_hours": 3.0, "krbtgt_double_reset": False, "ad_before_entra": True},
)


def identity_evidence(tenant: str = "lakehaven") -> list:
    """Identity backup jobs and restore drills as evidence records (CP-9 / CP-4 / CP-10)."""
    from .integrations import schema
    out = []
    for b in IDENTITY_BACKUPS:
        attrs = {k: (list(v) if isinstance(v, tuple) else v) for k, v in b.items() if k not in ("id", "taken")}
        out.append(schema.make(tenant, "identity_backup", "identity", "identity_backup_job", b["id"], b["taken"],
                               attrs, ("CP-09",)))
    for d in IDENTITY_DRILLS:
        attrs = {k: v for k, v in d.items() if k not in ("id", "date")}
        out.append(schema.make(tenant, "identity_drill", "identity", "identity_restore_drill", d["id"], d["date"],
                               attrs, ("CP-04", "CP-10")))
    return out


def identity_checks(evidence=None, today: str = TODAY) -> list[dict]:
    """Pass/fail checks over identity evidence. Each row names the control it supports."""
    evidence = identity_evidence() if evidence is None else evidence
    t = dt.date.fromisoformat(today)
    backups = [e for e in evidence if e.kind == "identity_backup_job"]
    drills = sorted((e for e in evidence if e.kind == "identity_restore_drill"), key=lambda e: e.observed_at)
    rows = []

    def add(cid, control, passed, detail):
        rows.append({"id": cid, "control": control, "passed": bool(passed), "detail": detail})

    for scope in ("ad_forest", "entra_tenant"):
        good = [b for b in backups if b.attributes.get("scope") == scope and b.attributes.get("ok")]
        newest = max((dt.date.fromisoformat(b.observed_at[:10]) for b in good), default=None)
        age_h = None if newest is None else (t - newest).days * 24
        add(f"IDR-BK-{scope}", "CP-09", age_h is not None and age_h <= max(IDENTITY_SERVICE["rpo_hours"], 24),
            f"{scope}: hours since good backup = {age_h}")
        add(f"IDR-IMM-{scope}", "CP-09", good and all(b.attributes.get("immutable") for b in good),
            f"{scope}: immutable = {[b.attributes.get('immutable') for b in good]}")
        add(f"IDR-ISO-{scope}", "CP-09", good and all(b.attributes.get("isolated") for b in good),
            f"{scope}: isolated = {[b.attributes.get('isolated') for b in good]}")
    entra = [b for b in backups if b.attributes.get("scope") == "entra_tenant"]
    covered = set().union(*(set(b.attributes.get("object_types", [])) for b in entra)) if entra else set()
    missing = sorted(set(IDENTITY_SERVICE["entra_object_types"]) - covered)
    add("IDR-ENTRA-COVER", "CP-09", not missing, f"Entra object types not backed up: {missing}")
    clean = [d for d in drills if d.attributes.get("clean_room")]
    last = clean[-1] if clean else None
    age = None if last is None else (t - dt.date.fromisoformat(last.observed_at[:10])).days
    add("IDR-DRILL-365", "CP-04", age is not None and age <= 365, f"days since clean-room drill = {age}")
    add("IDR-RTO", "CP-10", last is not None
        and last.attributes["measured_recovery_hours"] <= IDENTITY_SERVICE["rto_hours"],
        f"measured {None if last is None else last.attributes['measured_recovery_hours']}h vs RTO "
        f"{IDENTITY_SERVICE['rto_hours']}h")
    add("IDR-KRBTGT", "CP-10", last is not None and last.attributes.get("krbtgt_double_reset"),
        "krbtgt reset twice in the last clean-room drill")
    add("IDR-ORDER", "CP-10", last is not None and last.attributes.get("ad_before_entra"),
        "AD restored before Entra sync re-enabled")
    return rows


def identity_kpis(today: str = TODAY) -> dict:
    ev = identity_evidence()
    checks = identity_checks(ev, today)
    t = dt.date.fromisoformat(today)
    clean = sorted((d for d in IDENTITY_DRILLS if d["clean_room"]), key=lambda d: d["date"])
    last = clean[-1]
    newest = max(dt.date.fromisoformat(b["taken"]) for b in IDENTITY_BACKUPS if b["ok"])
    entra = next(b for b in IDENTITY_BACKUPS if b["scope"] == "entra_tenant")
    return {"measured_rto_hours": last["measured_recovery_hours"], "target_rto_hours": IDENTITY_SERVICE["rto_hours"],
            "rto_met": last["measured_recovery_hours"] <= IDENTITY_SERVICE["rto_hours"],
            "days_since_drill": (t - dt.date.fromisoformat(last["date"])).days,
            "backup_age_hours": (t - newest).days * 24,
            "entra_object_coverage_pct": round(100 * len(entra["object_types"])
                                               / len(IDENTITY_SERVICE["entra_object_types"]), 1),
            "checks_passed": sum(c["passed"] for c in checks), "checks": len(checks)}
