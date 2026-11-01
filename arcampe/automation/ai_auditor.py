"""AI evidence auditor: scores each piece of evidence for quality, then a human must sign off.

The scorer is deterministic (stands in for a model). It never accepts evidence by itself: the
best it can say is "ready for sign-off". A person with signoff rights, who is not the uploader,
records the decision. Agents cannot sign off.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from .. import TODAY
from ..integrations.mapper import map_evidence
from ..integrations.schema import verify
from ..platform.rbac import AccessDenied, Principal, authorize

AUTHORITY = {"identity": 1.0, "cloud": 1.0, "security": 0.9, "itsm": 0.9, "devops": 0.9, "hr": 0.9,
             "platform": 1.0, "finance": 0.8, "collaboration": 0.8, "docs": 0.6, "openapi": 0.7, "webhook": 0.6}
MAX_AGE_DAYS = 90
READY = 0.75


def score(e, today: str = TODAY) -> dict:
    age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(e.observed_at[:10])).days
    fresh = 1.0 if age <= 30 else 0.6 if age <= MAX_AGE_DAYS else 0.2
    complete = 1.0 if e.attributes and all(v is not None for v in e.attributes.values()) else 0.5
    integrity = 1.0 if verify(e) else 0.0
    m = map_evidence(e)
    relevance = m.confidence if m.control in set(e.control_hints) or not e.control_hints else m.confidence * 0.7
    parts = {"freshness": fresh, "completeness": complete, "integrity": integrity,
             "authority": AUTHORITY.get(e.category, 0.5), "relevance": round(relevance, 3)}
    total = 0.0 if integrity == 0 else round(0.3 * fresh + 0.15 * complete + 0.2 * parts["authority"]
                                            + 0.35 * parts["relevance"], 3)
    reasons = [k for k, v in parts.items() if v < 0.6]
    return {"evidence_id": e.evidence_id, "source": e.source, "subject": e.subject, "age_days": age,
            "score": total, "parts": parts, "reasons": reasons,
            "recommendation": "ready for sign-off" if total >= READY else "needs better evidence"}


@dataclass
class SignOff:
    evidence_id: str
    reviewer: str
    decision: str      # accepted | rejected
    note: str
    at: str


def sign_off(review: dict, reviewer: Principal, decision: str, note: str, uploader: str,
             at: str = TODAY) -> SignOff:
    authorize(reviewer, "signoff_evidence", reviewer.tenant_id, owner_id=uploader)
    if decision not in ("accepted", "rejected"):
        raise ValueError(decision)
    if decision == "accepted" and review["recommendation"] != "ready for sign-off" and "override" not in note.lower():
        raise AccessDenied("accepting low-quality evidence needs an explicit override note")
    if not note.strip():
        raise ValueError("note required")
    return SignOff(review["evidence_id"], reviewer.id, decision, note, at)


def run(evidence, today: str = TODAY) -> dict:
    rows = [score(e, today) for e in evidence]
    return {"reviewed": len(rows), "ready": sum(r["recommendation"] == "ready for sign-off" for r in rows),
            "needs_work": sum(r["recommendation"] != "ready for sign-off" for r in rows),
            "signed_off": 0, "rows": rows}
