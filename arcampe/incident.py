"""Incident and breach management: log, classify, playbooks, chain of custody, deadlines, review."""
from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass, field

from .params import PARAMS

PLAYBOOKS = {
    "ransomware": ["isolate hosts", "disable affected accounts", "preserve memory and disk images",
                   "restore from last tested backup", "report to CMS within 1 hour if PII may be affected"],
    "pii-misdirected-mail": ["retrieve or confirm destruction", "log recipients", "risk-of-harm assessment",
                             "report to CMS within 1 hour", "notify individuals if required"],
    "account-takeover": ["revoke sessions and tokens", "reset credentials and MFA", "review sign-in logs",
                         "check mailbox rules and data access"],
    "vendor-breach": ["get vendor incident report", "confirm data involved", "report to CMS within 1 hour",
                      "review contract obligations"],
}
DEADLINES_HOURS = {"cms_report": PARAMS["IR-06"]["report_within_hours"], "post_incident_review": 14 * 24}


@dataclass
class Incident:
    id: str
    title: str
    detected: str            # ISO datetime
    kind: str
    pii: bool
    severity: str = "unclassified"
    custody: list = field(default_factory=list)
    events: list = field(default_factory=list)

    def classify(self, records_affected: int, systems_down: bool) -> str:
        if self.pii and records_affected >= 500 or systems_down:
            self.severity = "high"
        elif self.pii or records_affected:
            self.severity = "moderate"
        else:
            self.severity = "low"
        return self.severity

    def add_artifact(self, name: str, content: bytes, handler: str, at: str) -> dict:
        prev = self.custody[-1]["chain"] if self.custody else "0" * 64
        digest = hashlib.sha256(content).hexdigest()
        rec = {"name": name, "sha256": digest, "handler": handler, "at": at,
               "chain": hashlib.sha256((prev + digest + handler + at).encode()).hexdigest()}
        self.custody.append(rec)
        return rec

    def custody_intact(self, artifacts: dict[str, bytes]) -> bool:
        prev = "0" * 64
        for r in self.custody:
            d = hashlib.sha256(artifacts[r["name"]]).hexdigest()
            if d != r["sha256"]:
                return False
            if hashlib.sha256((prev + d + r["handler"] + r["at"]).encode()).hexdigest() != r["chain"]:
                return False
            prev = r["chain"]
        return True

    def deadlines(self) -> dict[str, str]:
        t = dt.datetime.fromisoformat(self.detected)
        out = {"post_incident_review": (t + dt.timedelta(hours=DEADLINES_HOURS["post_incident_review"])).isoformat()}
        if self.pii:
            out["cms_report"] = (t + dt.timedelta(hours=DEADLINES_HOURS["cms_report"])).isoformat()
        return out

    def log(self, at: str, what: str) -> None:
        self.events.append((at, what))

    def met(self, name: str) -> bool | None:
        due = self.deadlines().get(name)
        done = [a for a, w in self.events if w == name]
        if due is None:
            return None
        return bool(done) and min(done) <= due

    def playbook(self) -> list[str]:
        return PLAYBOOKS.get(self.kind, ["follow the general incident response plan"])
