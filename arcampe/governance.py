"""Governance, policy and controls: a versioned policy repository with lifecycle, acknowledgments,
review reminders and named owners. Policies are the evidence for every "-01" control.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass, field, replace

from . import TODAY

LIFECYCLE = {"draft": {"in_review"}, "in_review": {"draft", "approved"}, "approved": {"in_review", "retired"},
             "retired": set()}
REVIEW_EVERY_DAYS = 365


@dataclass(frozen=True)
class PolicyVersion:
    version: int
    text_sha256: str
    approved_by: str | None
    approved_on: str | None


@dataclass(frozen=True)
class Policy:
    id: str
    title: str
    owner: str
    controls: tuple[str, ...]
    state: str = "draft"
    versions: tuple[PolicyVersion, ...] = ()
    acknowledgments: dict = field(default_factory=dict, hash=False, compare=False)   # user -> version

    @property
    def current(self) -> PolicyVersion | None:
        return self.versions[-1] if self.versions else None


def transition(p: Policy, to: str) -> Policy:
    if to not in LIFECYCLE[p.state]:
        raise ValueError(f"cannot move {p.id} from {p.state} to {to}")
    return replace(p, state=to)


def new_version(p: Policy, text: str) -> Policy:
    v = PolicyVersion(len(p.versions) + 1, hashlib.sha256(text.encode()).hexdigest(), None, None)
    return replace(p, versions=p.versions + (v,), state="draft")


def approve(p: Policy, approver: str, on: str = TODAY) -> Policy:
    if p.state != "in_review":
        raise ValueError("only policies in review can be approved")
    if approver == p.owner:
        raise PermissionError("owner cannot approve own policy")
    v = replace(p.current, approved_by=approver, approved_on=on)
    return replace(p, versions=p.versions[:-1] + (v,), state="approved")


def acknowledge(p: Policy, user: str) -> Policy:
    if p.state != "approved":
        raise ValueError("acknowledge approved policies only")
    acks = dict(p.acknowledgments)
    acks[user] = p.current.version
    return replace(p, acknowledgments=acks)


def ack_rate(p: Policy, users: list[str]) -> float:
    cur = p.current.version if p.current else 0
    return round(100 * sum(p.acknowledgments.get(u) == cur for u in users) / max(1, len(users)), 1)


def review_due(p: Policy, today: str = TODAY) -> dict:
    if not p.current or not p.current.approved_on:
        return {"policy": p.id, "status": "never approved"}
    age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(p.current.approved_on)).days
    return {"policy": p.id, "age_days": age,
            "status": "overdue" if age > REVIEW_EVERY_DAYS else "due_soon" if age > REVIEW_EVERY_DAYS - 30 else "ok"}
