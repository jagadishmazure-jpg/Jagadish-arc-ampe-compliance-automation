"""Control readiness approval (A1): a control is Ready only when four parts are Ready AND a named internal
approver signs off.

Parts: evidence (at least one linked record that is Ready or Upcoming Renewal), tests (the automated result is
pass, or the control has no automated test), policies (the family's -01 policy document is fresh) and approvals
(an approved control statement exists in data/approvals.json). The sign-off stores the approver, the time and
the SHA-256 of every evidence record it covered, so a later change to that evidence voids the sign-off.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .. import DATA, TODAY, catalog

PARTS = ("evidence", "tests", "policies", "approvals")
APPROVER_ROLES = {"control_approver", "isso", "ciso"}


class ReadinessError(ValueError):
    pass


def _context():
    from .. import assess
    from ..integrations.connectors import collect_all
    from . import evidence_status
    ev = collect_all()
    fresh = {e.evidence_id for e in ev if evidence_status.classify(e)["status"] in ("Ready", "Upcoming Renewal")}
    approved = {r.get("control_id") or r.get("control") for r in json.loads((DATA / "approvals.json").read_text())}
    return ev, fresh, assess.by_control(), approved


def parts(cid: str, ctx=None) -> dict:
    ev, fresh, by, approved = ctx or _context()
    c = catalog.by_id()[cid]
    linked = [e for e in ev if cid in e.control_hints]
    pol = [e for e in ev if e.kind == "policy_doc" and f"{c.family}-01" in e.control_hints]
    test = by.get(cid, {}).get("status", "not_tested")
    return {
        "evidence": {"ready": any(e.evidence_id in fresh for e in linked), "detail": f"{len(linked)} linked"},
        "tests": {"ready": test in ("pass", "not_tested") and (test == "pass" or c.label == "attestation"),
                  "detail": test},
        "policies": {"ready": any(e.evidence_id in fresh for e in pol), "detail": f"{c.family}-01 policy"},
        "approvals": {"ready": cid in approved, "detail": "approved statement" if cid in approved else "none"},
    }


@dataclass
class Signoff:
    control: str
    approver: str
    at: str
    evidence_hashes: dict = field(default_factory=dict)


def sign_off(cid: str, approver: str, role: str, is_agent: bool = False, ctx=None, at: str = TODAY) -> Signoff:
    if is_agent or approver.startswith("agent:"):
        raise ReadinessError("agents cannot sign off control readiness")
    if role not in APPROVER_ROLES:
        raise ReadinessError(f"role {role} cannot sign off")
    p = parts(cid, ctx)
    missing = [k for k in PARTS if not p[k]["ready"]]
    if missing:
        raise ReadinessError(f"not ready: {missing}")
    ev = (ctx or _context())[0]
    return Signoff(cid, approver, at, {e.evidence_id: e.content_sha256 for e in ev if cid in e.control_hints})


def still_valid(s: Signoff, evidence) -> bool:
    now = {e.evidence_id: e.content_sha256 for e in evidence if s.control in e.control_hints}
    return now == s.evidence_hashes


def board(controls=None, ctx=None) -> dict:
    ctx = ctx or _context()
    controls = controls or [c.id for c in catalog.baseline("ae")]
    counts = {k: 0 for k in PARTS}
    all4 = 0
    for cid in controls:
        p = parts(cid, ctx)
        for k in PARTS:
            counts[k] += p[k]["ready"]
        all4 += all(p[k]["ready"] for k in PARTS)
    return {"controls": len(controls), "ready_by_part": counts, "all_four_ready": all4}


def evidence_digest(signoff: Signoff) -> str:
    return hashlib.sha256(json.dumps(signoff.evidence_hashes, sort_keys=True).encode()).hexdigest()[:16]
