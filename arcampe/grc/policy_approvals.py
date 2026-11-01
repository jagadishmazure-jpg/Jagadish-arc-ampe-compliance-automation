"""Configurable policy approval tiers (A5) and a policy version diff.

A workflow has 1 to 6 tiers. Each tier has named approvers and a rule: "all", "any" or "k-of-n". Tiers run in
order; a rejection at any tier stops the workflow. Agents cannot approve. The version diff is deterministic
(difflib). An optional change summary is labeled "AI-generated, approver must confirm" and does not count as an
approval; the summary here is a rule-based stand-in so the repo stays offline.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field

MAX_TIERS = 6
AI_LABEL = "AI-generated, approver must confirm"


class PolicyApprovalError(ValueError):
    pass


@dataclass(frozen=True)
class Tier:
    name: str
    approvers: tuple[str, ...]
    rule: str = "all"   # all | any | k-of-n
    k: int = 0


@dataclass
class Workflow:
    policy: str
    version: str
    tiers: tuple[Tier, ...]
    votes: dict = field(default_factory=dict)   # tier name -> {approver: "approve"|"reject"}
    status: str = "in_review"
    log: list = field(default_factory=list)


def validate(tiers) -> list[str]:
    errs = []
    if not 1 <= len(tiers) <= MAX_TIERS:
        errs.append(f"need 1 to {MAX_TIERS} tiers")
    for t in tiers:
        if not t.approvers:
            errs.append(f"{t.name}: no approvers")
        if any(a.startswith("agent:") for a in t.approvers):
            errs.append(f"{t.name}: agents cannot be approvers")
        if t.rule not in ("all", "any", "k-of-n"):
            errs.append(f"{t.name}: unknown rule {t.rule}")
        if t.rule == "k-of-n" and not 1 <= t.k <= len(t.approvers):
            errs.append(f"{t.name}: k must be 1..{len(t.approvers)}")
    if len({t.name for t in tiers}) != len(tiers):
        errs.append("tier names must be unique")
    return errs


def start(policy: str, version: str, tiers) -> Workflow:
    errs = validate(tiers)
    if errs:
        raise PolicyApprovalError("; ".join(errs))
    return Workflow(policy, version, tuple(tiers))


def current_tier(w: Workflow) -> Tier | None:
    for t in w.tiers:
        if not _tier_done(t, w.votes.get(t.name, {})):
            return t
    return None


def _tier_done(t: Tier, v: dict) -> bool:
    yes = sum(x == "approve" for x in v.values())
    need = len(t.approvers) if t.rule == "all" else 1 if t.rule == "any" else t.k
    return yes >= need


def vote(w: Workflow, approver: str, decision: str, note: str = "") -> Workflow:
    if w.status != "in_review":
        raise PolicyApprovalError(f"workflow is {w.status}")
    if approver.startswith("agent:"):
        raise PolicyApprovalError("agents cannot approve policies")
    if decision not in ("approve", "reject"):
        raise PolicyApprovalError("decision must be approve or reject")
    t = current_tier(w)
    if approver not in t.approvers:
        raise PolicyApprovalError(f"{approver} is not an approver for tier {t.name}")
    tv = w.votes.setdefault(t.name, {})
    if approver in tv:
        raise PolicyApprovalError("already voted")
    tv[approver] = decision
    w.log.append({"tier": t.name, "approver": approver, "decision": decision, "note": note})
    if decision == "reject":
        w.status = "rejected"
    elif current_tier(w) is None:
        w.status = "approved"
    return w


def diff(old: str, new: str) -> dict:
    a, b = old.splitlines(), new.splitlines()
    lines = list(difflib.unified_diff(a, b, "previous", "proposed", lineterm="", n=0))
    added = [x[1:] for x in lines if x.startswith("+") and not x.startswith("+++")]
    removed = [x[1:] for x in lines if x.startswith("-") and not x.startswith("---")]
    return {"added": added, "removed": removed, "unified": "\n".join(lines),
            "similarity": round(difflib.SequenceMatcher(None, old, new).ratio(), 3)}


_STRONG = ("must", "shall", "require", "within", "days", "hours", "every", "mfa")


def change_summary(old: str, new: str) -> dict:
    """Rule-based stand-in for an LLM summary. Always labeled; never counts as an approval."""
    d = diff(old, new)
    points = []
    for x in d["removed"]:
        if any(w in x.lower() for w in _STRONG):
            points.append(f"Removed or changed a requirement: '{x.strip()[:80]}'")
    for x in d["added"]:
        if any(w in x.lower() for w in _STRONG):
            points.append(f"Added or changed a requirement: '{x.strip()[:80]}'")
    return {"label": AI_LABEL, "points": points or ["Wording changes only"], "counts_as_approval": False,
            "lines_added": len(d["added"]), "lines_removed": len(d["removed"])}


SAMPLE_OLD = """Access Control Policy v2.0
Accounts must be reviewed every 90 days.
Inactive accounts are disabled after 60 days.
Privileged access requires MFA."""
SAMPLE_NEW = """Access Control Policy v2.1
Accounts must be reviewed every 90 days.
Inactive accounts are disabled after 45 days.
Privileged access requires phishing-resistant MFA.
Break-glass accounts are tested every quarter."""
SAMPLE_TIERS = (Tier("owner", ("iam-lead",)), Tier("security", ("isso", "ciso"), "any"),
                Tier("legal-privacy", ("counsel", "privacy-officer"), "all"),
                Tier("committee", ("cio", "cfo", "coo"), "k-of-n", 2))


def demo() -> dict:
    w = start("AC-01", "2.1", SAMPLE_TIERS)
    for who, d in (("iam-lead", "approve"), ("isso", "approve"), ("counsel", "approve"),
                   ("privacy-officer", "approve"), ("cio", "approve"), ("cfo", "approve")):
        vote(w, who, d)
    return {"status": w.status, "votes": len(w.log), "summary": change_summary(SAMPLE_OLD, SAMPLE_NEW),
            "diff": diff(SAMPLE_OLD, SAMPLE_NEW)}
