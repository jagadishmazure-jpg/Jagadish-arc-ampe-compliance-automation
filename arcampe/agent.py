"""Drafting agent for control implementation statements, with mandatory human approval.

Backends:
  * StubBackend (default, used in tests and CI): deterministic template text, no network.
  * FoundryBackend (planned): would call a model deployment in Microsoft Foundry over a private
    endpoint. It is not implemented here and refuses to run unless the egress check passes.

Rules the code enforces:
  1. Every draft cites the evidence it used (check IDs, evidence IDs, parameter values).
  2. Inputs pass a prompt-injection screen and PII redaction before any prompt is built.
  3. A draft is never "final" until a named human, who is not the drafter, approves it.
  4. The agent cannot mark a control as passing; status comes only from the checks.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import asdict, dataclass, field, replace

from . import DATA, ENTITY, TODAY, catalog
from .guards import screen
from .ids import base_of
from .params import PARAMS
from .redact import redact

APPROVER_ROLES = {"isso", "ciso", "privacy-officer", "system-owner"}


@dataclass(frozen=True)
class Draft:
    control: str
    text: str
    citations: tuple[str, ...]
    backend: str
    drafter: str
    input_sha256: str
    redactions: dict = field(default_factory=dict, hash=False, compare=False)
    blocked: tuple[str, ...] = ()
    status: str = "draft"            # draft | approved | rejected | blocked
    approver: str | None = None
    approved_on: str | None = None
    reviewer_note: str = ""


class StubBackend:
    name = "stub-deterministic"

    def complete(self, ctx: dict) -> str:
        c = ctx["control"]
        lines = [f"{ENTITY} implements {c['id']} ({c['title']}) for the eligibility and enrollment system."]
        if ctx["label"] == "automated":
            lines.append("The control is checked automatically by policy-as-code checks "
                         f"{', '.join(ctx['checks'])}; results are recorded in the assessment run.")
        elif ctx["label"] == "hybrid":
            lines.append("Technical settings are checked automatically where possible and the remaining "
                         "procedure is confirmed by the control owner.")
        else:
            lines.append("The control is procedural. The control owner attests to it on the recorded cadence and "
                         "stores the signed evidence in the evidence binder.")
        for k, v in ctx["params"].items():
            lines.append(f"Organization-defined value {k}: {v}.")
        if ctx["results"]:
            lines.append(f"Latest run: {ctx['results']['passed']} passing and {ctx['results']['failed']} failing "
                         "results; failing results are tracked in the POA&M.")
        if ctx["notes"]:
            lines.append(f"Owner notes: {ctx['notes']}")
        return " ".join(lines)


class FoundryBackend:  # pragma: no cover - planned, intentionally not runnable offline
    name = "microsoft-foundry"

    def __init__(self, endpoint: str):
        from .platform import secure_ai
        secure_ai.assert_egress_allowed(endpoint)
        self.endpoint = endpoint

    def complete(self, ctx: dict) -> str:
        raise NotImplementedError("Planned: call a Microsoft Foundry deployment over a private endpoint.")


def _context(cid: str, notes: str, results: dict | None) -> dict:
    from .labels import checks_for
    c = catalog.by_id()[cid]
    params = {k: v for k, v in PARAMS.items() if k in (c.id, base_of(c.id))}
    return {"control": {"id": c.id, "title": c.title}, "label": c.label, "checks": checks_for(cid),
            "params": {k: json.dumps(v, sort_keys=True) for k, v in params.items()}, "notes": notes,
            "results": results or {}}


def draft(cid: str, notes: str = "", results: dict | None = None, drafter: str = "agent:drafter",
          backend=None) -> Draft:
    backend = backend or StubBackend()
    hits = screen(notes)
    clean, counts = redact(notes)
    ctx = _context(cid, clean, results)
    digest = hashlib.sha256(json.dumps(ctx, sort_keys=True).encode()).hexdigest()
    cites = tuple(ctx["checks"]) + tuple(f"param:{k}" for k in ctx["params"]) + (f"catalog:{cid}",)
    if hits:
        return Draft(cid, "", cites, backend.name, drafter, digest, counts, tuple(hits), "blocked")
    return Draft(cid, backend.complete(ctx), cites, backend.name, drafter, digest, counts)


def approve(d: Draft, approver: str, role: str, note: str = "", on: str = TODAY) -> Draft:
    if d.status != "draft":
        raise PermissionError(f"cannot approve a {d.status} draft")
    if approver == d.drafter or approver.startswith("agent:"):
        raise PermissionError("approver must be a human who did not write the draft")
    if role not in APPROVER_ROLES:
        raise PermissionError(f"role {role!r} cannot approve implementation statements")
    if not note.strip():
        raise PermissionError("approval needs a reviewer note")
    dt.date.fromisoformat(on)
    return replace(d, status="approved", approver=approver, approved_on=on, reviewer_note=note)


def reject(d: Draft, approver: str, note: str) -> Draft:
    if approver == d.drafter:
        raise PermissionError("drafter cannot reject own draft")
    return replace(d, status="rejected", approver=approver, reviewer_note=note)


def final_text(d: Draft) -> str:
    """Only approved drafts may be published into the SSPP."""
    if d.status != "approved":
        raise PermissionError("statement is not approved")
    return d.text


def load_approvals(path=None) -> dict[str, dict]:
    p = path or DATA / "approvals.json"
    return {r["control"]: r for r in json.loads(p.read_text())} if p.exists() else {}


def as_record(d: Draft) -> dict:
    r = asdict(d)
    r["citations"] = list(d.citations)
    r["blocked"] = list(d.blocked)
    return r
