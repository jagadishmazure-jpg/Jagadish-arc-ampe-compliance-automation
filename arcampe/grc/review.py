"""Expert review per control, and the flag that sends a control back to review when it changes.

States: not_started -> in_progress -> submitted -> passing | returned; returned -> in_progress.
"Passing" means an internal expert agreed the evidence supports the control. It is NOT an auditor's
opinion. The reviewer must be a human with the expert role and cannot be the control owner.
If anything about a passing control is edited (statement, evidence list, owner), its content hash changes
and the control drops to needs_review with the old and new hashes recorded.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .. import TODAY

STATES = ("not_started", "in_progress", "submitted", "passing", "returned", "needs_review")
ALLOWED = {"not_started": {"in_progress"}, "in_progress": {"submitted"}, "submitted": {"passing", "returned"},
           "returned": {"in_progress"}, "passing": {"needs_review"}, "needs_review": {"submitted"}}
EXPERT_ROLES = {"isso", "grc_expert", "vciso"}


class ReviewError(ValueError):
    pass


def content_hash(content: dict) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


@dataclass
class ControlReview:
    control: str
    owner: str
    content: dict = field(default_factory=dict)
    state: str = "not_started"
    reviewer: str = ""
    approved_hash: str = ""
    history: list = field(default_factory=list)

    def _go(self, to: str, actor: str, note: str = "", at: str = TODAY) -> None:
        if to not in ALLOWED[self.state]:
            raise ReviewError(f"{self.control}: {self.state} -> {to} not allowed")
        self.history.append({"at": at, "from": self.state, "to": to, "actor": actor, "note": note})
        self.state = to

    def start(self, actor: str) -> None:
        self._go("in_progress", actor)

    def submit(self, actor: str) -> None:
        if actor != self.owner:
            raise ReviewError("only the control owner submits for review")
        if not self.content.get("evidence"):
            raise ReviewError("attach at least one piece of evidence before submitting")
        self._go("submitted", actor)

    def approve(self, reviewer: str, role: str, note: str) -> None:
        if reviewer.startswith("agent:"):
            raise ReviewError("an AI agent cannot approve a control")
        if role not in EXPERT_ROLES:
            raise ReviewError(f"role {role} is not an expert reviewer")
        if reviewer == self.owner:
            raise ReviewError("separation of duties: the owner cannot review their own control")
        if not note.strip():
            raise ReviewError("approval needs a note")
        self._go("passing", reviewer, note)
        self.reviewer = reviewer
        self.approved_hash = content_hash(self.content)

    def return_(self, reviewer: str, note: str) -> None:
        if not note.strip():
            raise ReviewError("say what needs fixing")
        self._go("returned", reviewer, note)

    def edit(self, actor: str, **changes) -> bool:
        """Apply an edit. Returns True if the edit sent a passing control back to review."""
        self.content = {**self.content, **changes}
        if self.state == "passing" and content_hash(self.content) != self.approved_hash:
            self._go("needs_review", actor, f"edited after compliant: {sorted(changes)}")
            return True
        return False


def drift_flags(reviews: list[ControlReview]) -> list[dict]:
    return [{"control": r.control, "owner": r.owner, "approved_hash": r.approved_hash[:12],
             "current_hash": content_hash(r.content)[:12]} for r in reviews if r.state == "needs_review"]


def board(reviews: list[ControlReview]) -> dict:
    out = {s: 0 for s in STATES}
    for r in reviews:
        out[r.state] += 1
    return out


def demo() -> dict:
    """Ten controls walked through review, with one edited after approval. Synthetic."""
    rs = []
    for i, cid in enumerate(("AC-02", "AC-07", "AU-06", "CM-06", "CP-09", "IA-02", "IR-04", "RA-05", "SC-08", "SI-02")):
        r = ControlReview(cid, owner=f"owner-{i % 3}", content={"statement": f"{cid} implemented",
                                                               "evidence": [f"ev-{i}"] if i != 9 else []})
        r.start(r.owner)
        if i < 9:
            r.submit(r.owner)
        if i < 6:
            r.approve("Riley Quist", "isso", "Evidence matches the statement.")
        elif i < 8:
            r.return_("Riley Quist", "Screenshot is older than 90 days.")
        rs.append(r)
    rs[2].edit("owner-2", statement="AU-06 reviewed weekly (was daily)")
    return {"board": board(rs), "drift": drift_flags(rs)}
