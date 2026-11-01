"""Event-driven workflow builder: "when this happens, if these conditions hold, do these actions".

Actions are ticket, Slack-style message and webhook. In this repo every action is SIMULATED: it is
rendered, checked and written to a hash-chained outbox log, and nothing leaves the machine. Webhook
hosts must be on an allow-list, templates may use only whitelisted fields, and one event can trigger at
most MAX_ACTIONS_PER_EVENT actions (fan-out guard). Actions never emit new events, so loops are impossible.
"""
from __future__ import annotations

import string
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .. import TODAY
from ..platform.audit_log import AuditLog

EVENTS = ("control.not_ready", "control.ready", "evidence.needs_renewal", "poam.overdue", "vendor.requested",
          "access_review.removal", "control.edited_after_compliant", "risk.score_increased")
ACTION_TYPES = ("ticket", "slack", "webhook")
OPS = ("eq", "ne", "in", "gte", "lte", "contains")
TEMPLATE_FIELDS = {"control", "severity", "owner", "unit", "detail", "event", "resource", "days_overdue"}
WEBHOOK_ALLOWLIST = ("hooks.lakehaven-hx.example", "itsm.lakehaven-hx.example")
MAX_ACTIONS_PER_EVENT = 10
SEV_RANK = {"low": 1, "moderate": 2, "high": 3, "critical": 4}


class WorkflowError(ValueError):
    pass


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: object

    def holds(self, event: dict) -> bool:
        v = event.get(self.field)
        if self.field == "severity" and self.op in ("gte", "lte"):
            a, b = SEV_RANK.get(str(v), 0), SEV_RANK.get(str(self.value), 0)
            return a >= b if self.op == "gte" else a <= b
        if self.op == "eq":
            return v == self.value
        if self.op == "ne":
            return v != self.value
        if self.op == "in":
            return v in self.value  # type: ignore[operator]
        if self.op == "contains":
            return isinstance(v, str) and str(self.value) in v
        if v is None:
            return False
        return v >= self.value if self.op == "gte" else v <= self.value  # type: ignore[operator]


@dataclass(frozen=True)
class Action:
    type: str
    target: str
    template: str


@dataclass(frozen=True)
class Workflow:
    id: str
    name: str
    trigger: str
    conditions: tuple[Condition, ...] = ()
    actions: tuple[Action, ...] = ()
    enabled: bool = True


def template_fields(t: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(t) if f}


def validate(w: Workflow) -> list[str]:
    errs = []
    if w.trigger not in EVENTS:
        errs.append(f"unknown trigger {w.trigger}")
    if not w.actions:
        errs.append("workflow has no actions")
    for c in w.conditions:
        if c.op not in OPS:
            errs.append(f"unknown operator {c.op}")
    for a in w.actions:
        if a.type not in ACTION_TYPES:
            errs.append(f"unknown action {a.type}")
        bad = template_fields(a.template) - TEMPLATE_FIELDS
        if bad:
            errs.append(f"template uses fields not allowed: {sorted(bad)}")
        if a.type == "webhook":
            u = urlparse(a.target)
            if u.scheme != "https":
                errs.append("webhook must use https")
            if u.hostname not in WEBHOOK_ALLOWLIST:
                errs.append(f"webhook host not on allow-list: {u.hostname}")
    return errs


def build(d: dict) -> Workflow:
    """Build a workflow from a JSON-style dict and validate it."""
    w = Workflow(d["id"], d["name"], d["trigger"],
                 tuple(Condition(c["field"], c["op"], c["value"]) for c in d.get("conditions", [])),
                 tuple(Action(a["type"], a["target"], a["template"]) for a in d.get("actions", [])),
                 d.get("enabled", True))
    errs = validate(w)
    if errs:
        raise WorkflowError("; ".join(errs))
    return w


class _Safe(dict):
    def __missing__(self, k):
        return "-"


@dataclass
class Engine:
    workflows: list[Workflow]
    log: AuditLog = field(default_factory=AuditLog)
    outbox: list[dict] = field(default_factory=list)

    def emit(self, event: dict, at: str = TODAY) -> list[dict]:
        if event.get("event") not in EVENTS:
            raise WorkflowError(f"unknown event {event.get('event')}")
        fired: list[dict] = []
        for w in self.workflows:
            if not w.enabled or w.trigger != event["event"]:
                continue
            if not all(c.holds(event) for c in w.conditions):
                continue
            for a in w.actions:
                if len(fired) >= MAX_ACTIONS_PER_EVENT:
                    self.log.append(at, "lakehaven", "workflow-engine", "fanout.blocked", w.id, {"event": event["event"]})
                    return fired
                body = a.template.format_map(_Safe({k: event.get(k, "-") for k in TEMPLATE_FIELDS}))
                rec = {"workflow": w.id, "action": a.type, "target": a.target, "body": body, "status": "simulated",
                       "sent": False}
                self.log.append(at, "lakehaven", "workflow-engine", f"{a.type}.simulated", a.target,
                                {"workflow": w.id, "body": body})
                self.outbox.append(rec)
                fired.append(rec)
        return fired


DEFAULT = (
    {"id": "WF-01", "name": "Monitoring tests for DevOps", "trigger": "control.not_ready",
     "conditions": [{"field": "severity", "op": "gte", "value": "high"}],
     "actions": [
         {"type": "ticket", "target": "itsm:SECOPS", "template": "[{severity}] {control} not ready: {detail}"},
         {"type": "slack", "target": "#sec-alerts", "template": "{control} failed ({severity}); owner {owner}"},
         {"type": "webhook", "target": "https://hooks.lakehaven-hx.example/grc",
          "template": "{event}|{control}|{severity}"}]},
    {"id": "WF-02", "name": "Evidence renewal reminder", "trigger": "evidence.needs_renewal",
     "actions": [{"type": "slack", "target": "@owner", "template": "Evidence for {control} needs renewal ({owner})"}]},
    {"id": "WF-03", "name": "Overdue POA&M escalation", "trigger": "poam.overdue",
     "conditions": [{"field": "days_overdue", "op": "gte", "value": 15}],
     "actions": [{"type": "ticket", "target": "itsm:GRC", "template": "{control} overdue {days_overdue} days"},
                 {"type": "slack", "target": "#ciso-desk", "template": "Escalation: {control} {days_overdue}d late"}]},
    {"id": "WF-04", "name": "Send control back to review", "trigger": "control.edited_after_compliant",
     "actions": [{"type": "ticket", "target": "itsm:GRC", "template": "Re-review {control}: edited after compliant"}]},
    {"id": "WF-05", "name": "New vendor request intake", "trigger": "vendor.requested",
     "actions": [{"type": "ticket", "target": "itsm:PROC", "template": "Vendor request: {resource} ({owner})"}]},
)


def default_engine() -> Engine:
    return Engine([build(d) for d in DEFAULT])


def events_from_findings(findings) -> list[dict]:
    """One control.not_ready event per failed finding (first control), owner from the POA&M prefix map."""
    from ..poam import OWNER_BY_PREFIX
    out = []
    for f in findings:
        if f.passed:
            continue
        out.append({"event": "control.not_ready", "control": f.controls[0] if f.controls else "-",
                    "severity": f.severity, "owner": OWNER_BY_PREFIX.get(f.check_id.split("-")[0], "control-owner"),
                    "detail": f.detail, "resource": f.resource_name})
    return out


def run_on_findings(findings=None) -> dict:
    from .. import assess
    findings = assess.run_all() if findings is None else findings
    eng = default_engine()
    for e in events_from_findings(findings):
        eng.emit(e)
    by: dict[str, int] = {}
    for r in eng.outbox:
        by[r["action"]] = by.get(r["action"], 0) + 1
    ok, msg = eng.log.verify()
    return {"events": len(events_from_findings(findings)), "actions": len(eng.outbox), "by_action": by,
            "sent": sum(r["sent"] for r in eng.outbox), "log": msg if ok else "BROKEN"}
