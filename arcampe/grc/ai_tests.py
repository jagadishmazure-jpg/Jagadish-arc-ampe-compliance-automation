"""AI-generated control tests (A9): propose -> validate (up to 3 retries) -> dedupe -> plain-English doc -> human
review -> live.

The "drafter" here is a deterministic stand-in for an LLM so the pipeline is testable offline: it turns a
plain-English request into a custom-test rule, and its first drafts contain realistic mistakes (wrong id prefix,
unknown operator, missing value) that it fixes only when given the validator's error list. Nothing goes live
without a named human reviewer (auditor or engineer). The acceptance rate is measured on the synthetic requests.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import custom_tests

MAX_RETRIES = 3
REVIEWER_ROLES = {"auditor", "engineer", "isso"}

REQUESTS = (  # (request id, plain-English ask, rule the drafter aims for, injected first-draft mistakes)
    ("Q01", "Key vaults must have soft delete on", {"resource_type": "Microsoft.KeyVault/vaults",
     "path": "properties.enableSoftDelete", "op": "truthy", "severity": "moderate", "controls": ["CP-09"]}, ["id"]),
    ("Q02", "Storage accounts must require TLS 1.2", {"resource_type": "Microsoft.Storage/storageAccounts",
     "path": "properties.minimumTlsVersion", "op": "eq", "value": "TLS1_2", "severity": "high",
     "controls": ["SC-08"]}, ["op"]),
    ("Q03", "SQL servers must not allow public network access", {"resource_type": "Microsoft.Sql/servers",
     "path": "properties.publicNetworkAccess", "op": "eq", "value": "Disabled", "severity": "high",
     "controls": ["SC-07"]}, []),
    ("Q04", "Production resources carry an env tag", {"resource_type": "Microsoft.Storage/storageAccounts",
     "path": "tags.env", "op": "exists", "severity": "low", "controls": ["CM-08"]}, []),  # duplicate of CT-02
    ("Q05", "Web apps only accept HTTPS", {"resource_type": "Microsoft.Web/sites", "path": "properties.httpsOnly",
     "op": "truthy", "severity": "high", "controls": ["SC-08"]}, ["value", "id"]),
    ("Q06", "Key vaults use purge protection", {"resource_type": "Microsoft.KeyVault/vaults",
     "path": "properties.enablePurgeProtection", "op": "truthy", "severity": "moderate",
     "controls": ["CP-09"]}, []),  # duplicate of CT-03
    ("Q07", "VM disks are encrypted with customer keys", {"resource_type": "Microsoft.Compute/virtualMachines",
     "path": "properties.storageProfile.osDisk.encryption.type", "op": "eq", "value": "CMK", "severity": "moderate",
     "controls": ["SC-28"]}, ["op", "value", "id", "control"]),  # still broken after 3 retries
    ("Q08", "Container registries disable the admin user", {"resource_type": "Microsoft.ContainerRegistry/registries",
     "path": "properties.adminUserEnabled", "op": "eq", "value": False, "severity": "moderate",
     "controls": ["AC-06"]}, ["control"]),
    ("Q09", "Log analytics keeps logs at least 90 days", {"resource_type": "Microsoft.OperationalInsights/workspaces",
     "path": "properties.retentionInDays", "op": "gte", "value": 90, "severity": "moderate",
     "controls": ["AU-11"]}, []),
    ("Q10", "Cosmos DB disables local key auth", {"resource_type": "Microsoft.DocumentDB/databaseAccounts",
     "path": "properties.disableLocalAuth", "op": "truthy", "severity": "high", "controls": ["IA-02"]}, ["op"]),
)
# synthetic reviewer decisions for drafts that reach review
REVIEW = {"Q01": "approve", "Q02": "approve", "Q03": "approve", "Q05": "edit", "Q08": "approve",
          "Q09": "reject", "Q10": "approve"}


def _draft(qid: str, ask: str, target: dict, mistakes: list[str], attempt: int) -> dict:
    """Each retry fixes one mistake (the stand-in 'learns' from the validator feedback)."""
    left = mistakes[attempt:]
    rule = {"id": f"CT-AI-{qid}", "title": ask, **target, "rationale": f"AI-drafted from request {qid}"}
    if "id" in left:
        rule["id"] = f"TEST-{qid}"
    if "op" in left:
        rule["op"] = "equals"
    if "value" in left and rule["op"] not in ("exists", "not_exists", "truthy"):
        rule.pop("value", None)
    elif "value" in left:
        rule["op"] = "eq"
    if "control" in left:
        rule["controls"] = ["ZZ-99"]
    return rule


def _key(rule: dict) -> tuple:
    return (rule["resource_type"], rule["path"], rule["op"], repr(rule.get("value")))


def explain(rule: dict) -> str:
    v = "" if rule["op"] in ("exists", "not_exists", "truthy") else f" {rule.get('value')!r}"
    return (f"For every {rule['resource_type'].split('/')[-1]}, check that {rule['path']} {rule['op']}{v}. "
            f"Fails map to {', '.join(rule['controls'])} at {rule['severity']} severity.")


@dataclass
class Proposal:
    request: str
    rule: dict
    attempts: int
    status: str            # invalid | duplicate | pending_review | live | rejected
    errors: list = field(default_factory=list)
    doc: str = ""
    reviewer: str = ""


def pipeline(existing=None) -> list[Proposal]:
    existing = custom_tests.load_rules() if existing is None else existing
    seen = {_key(r) for r in existing}
    out = []
    for qid, ask, target, mistakes in REQUESTS:
        errs, rule = [], {}
        for attempt in range(MAX_RETRIES + 1):
            rule = _draft(qid, ask, target, mistakes, attempt)
            errs = custom_tests.validate(rule)
            if not errs:
                break
        if errs:
            out.append(Proposal(qid, rule, attempt + 1, "invalid", errs))
            continue
        if _key(rule) in seen:
            out.append(Proposal(qid, rule, attempt + 1, "duplicate"))
            continue
        seen.add(_key(rule))
        out.append(Proposal(qid, rule, attempt + 1, "pending_review", doc=explain(rule)))
    return out


class ReviewError(ValueError):
    pass


def review(p: Proposal, reviewer: str, role: str, decision: str) -> Proposal:
    if p.status != "pending_review":
        raise ReviewError(f"{p.request} is {p.status}")
    if reviewer.startswith("agent:") or role not in REVIEWER_ROLES:
        raise ReviewError("a human auditor or engineer must review AI-generated tests")
    if decision not in ("approve", "edit", "reject"):
        raise ReviewError("decision must be approve, edit or reject")
    p.status = "rejected" if decision == "reject" else "live"
    p.reviewer = reviewer
    return p


def summary() -> dict:
    props = pipeline()
    for p in props:
        if p.status == "pending_review":
            review(p, "dana.auditor", "auditor", REVIEW[p.request])
    st = [p.status for p in props]
    reviewed = st.count("live") + st.count("rejected")
    return {"requests": len(props), "invalid_after_retries": st.count("invalid"), "duplicates": st.count("duplicate"),
            "reviewed": reviewed, "live": st.count("live"), "rejected": st.count("rejected"),
            "edited_before_approval": sum(REVIEW.get(p.request) == "edit" for p in props if p.status == "live"),
            "acceptance_pct": round(100 * st.count("live") / reviewed, 1) if reviewed else 0.0,
            "first_try_valid": sum(p.attempts == 1 for p in props if p.status != "invalid"),
            "label": "measured on synthetic requests"}
