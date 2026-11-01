"""Audit hub (A11): auditor requests (PBC) mapped to controls, a pre-audit package, an internal-audit program with
an independence check, and raw evidence kept as a hash-chained JSON log.

Requests are synthetic. Each one is mapped to a control by the existing keyword mapper; low-confidence mappings
go to a person to confirm. A request is "ready" when the mapped control has linked evidence. The independence
rule: an internal auditor may not test a control family they own.
"""
from __future__ import annotations

import hashlib
import json

from ..integrations import mapper
from . import auditor

GENESIS = "0" * 64

PBC_REQUESTS = (
    ("PBC-01", "Provide the list of user accounts disabled after 60 days of inactivity", "AC-02(03)"),
    ("PBC-02", "Provide evidence that backups were completed and tested this quarter", "CP-09"),
    ("PBC-03", "Show security awareness training completion for all workforce members", "AT-02"),
    ("PBC-04", "Provide the change tickets for production changes with approvals", "CM-03"),
    ("PBC-05", "Provide vulnerability scan results and remediation evidence", "RA-05"),
    ("PBC-06", "Show the incident response plan and the last tabletop exercise", "IR-08"),
    ("PBC-07", "Provide audit log review records for the last month", "AU-06"),
    ("PBC-08", "Show multi-factor authentication enforcement for privileged users", "IA-02(01)"),
    ("PBC-09", "Provide firewall rule review evidence", "SC-07"),
    ("PBC-10", "Provide the vendor risk assessments for critical vendors", "SR-03"),
    ("PBC-11", "Show the personnel termination checklist for leavers", "PS-04"),
    ("PBC-12", "Provide the data retention schedule", "SI-12"),
)

INTERNAL_AUDITORS = {"riya.ia": {"owns": {"AT", "PS"}}, "omar.ia": {"owns": {"MA"}}}
INTERNAL_PLAN = (("IA-Q1", "AC", "riya.ia"), ("IA-Q2", "CM", "omar.ia"), ("IA-Q3", "CP", "omar.ia"),
                 ("IA-Q4", "AT", "riya.ia"))  # IA-Q4 breaks independence on purpose


class IndependenceError(ValueError):
    pass


def map_requests(evidence=None) -> list[dict]:
    from ..integrations.connectors import collect_all
    evidence = collect_all() if evidence is None else evidence
    have: dict[str, int] = {}
    for e in evidence:
        for c in e.control_hints:
            have[c] = have.get(c, 0) + 1
    rows = []
    for rid, text, expected in PBC_REQUESTS:
        m = mapper.map_text(rid, text)
        ctl = m.control
        rows.append({"id": rid, "request": text, "mapped": ctl, "confidence": m.confidence,
                     "needs_confirmation": m.decision == "review", "correct": ctl == expected,
                     "evidence": have.get(ctl, 0) if ctl else 0,
                     "ready": bool(ctl and have.get(ctl) and m.decision == "auto")})
    return rows


def request_summary(rows=None) -> dict:
    rows = map_requests() if rows is None else rows
    return {"requests": len(rows), "auto_mapped": sum(not r["needs_confirmation"] for r in rows),
            "mapped_correctly": sum(r["correct"] for r in rows), "ready": sum(r["ready"] for r in rows),
            "label": "measured on synthetic requests"}


def pre_audit_package(rows=None, evidence=None) -> bytes:
    from ..integrations.connectors import collect_all
    evidence = collect_all() if evidence is None else evidence
    rows = map_requests(evidence) if rows is None else rows
    ctl = {r["mapped"] for r in rows if r["ready"]}
    return auditor.package([e for e in evidence if ctl & set(e.control_hints)], "pre-audit-package")


def check_independence(plan=INTERNAL_PLAN) -> list[dict]:
    out = []
    for aid, family, who in plan:
        ok = family not in INTERNAL_AUDITORS.get(who, {"owns": set()})["owns"]
        out.append({"audit": aid, "family": family, "auditor": who, "independent": ok})
    return out


def schedule_internal(aid: str, family: str, who: str) -> dict:
    if family in INTERNAL_AUDITORS.get(who, {"owns": set()})["owns"]:
        raise IndependenceError(f"{who} owns {family} and cannot audit it")
    return {"audit": aid, "family": family, "auditor": who, "status": "scheduled"}


# ------------------------------------------------------------------ hash-chained raw evidence
def chain(evidence) -> list[dict]:
    prev, out = GENESIS, []
    for e in sorted(evidence, key=lambda x: x.evidence_id):
        body = json.dumps(e.to_dict(), sort_keys=True)
        h = hashlib.sha256((prev + body).encode()).hexdigest()
        out.append({"evidence_id": e.evidence_id, "body": body, "prev": prev, "hash": h})
        prev = h
    return out


def verify_chain(entries: list[dict]) -> list[str]:
    prev, problems = GENESIS, []
    for i, x in enumerate(entries):
        if x["prev"] != prev:
            problems.append(f"entry {i} breaks the chain")
        if hashlib.sha256((x["prev"] + x["body"]).encode()).hexdigest() != x["hash"]:
            problems.append(f"entry {i} body changed")
        prev = x["hash"]
    return problems
