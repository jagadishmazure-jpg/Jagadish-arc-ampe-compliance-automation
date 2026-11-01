"""Vendor request and questionnaire workflow.

Lifecycle: requested -> intake -> questionnaire_sent -> answered -> under_review -> approved | rejected.
* intake records the business owner, data types and spend; the tier comes from supply_chain.Vendor.tier().
* "questionnaire_sent" is simulated: the outbox entry has sent=False. Nothing leaves the box.
* Answers are scored with the core supply_chain.score(); high-band vendors need the CISO, others the
  procurement lead. The requester can never approve their own vendor. Agents can only draft.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from .. import TODAY
from ..supply_chain import QUESTIONS, Vendor, score

FLOW = {"requested": {"intake"}, "intake": {"questionnaire_sent"}, "questionnaire_sent": {"answered"},
        "answered": {"under_review"}, "under_review": {"approved", "rejected"}}
SLA_DAYS = {"critical": 10, "high": 15, "moderate": 20, "low": 30}


class RequestError(ValueError):
    pass


@dataclass
class VendorRequest:
    id: str
    vendor_name: str
    service: str
    requester: str
    opened: str = TODAY
    state: str = "requested"
    pii_access: bool = False
    annual_spend: int = 0
    data_location: str = "US"
    answers: dict = field(default_factory=dict)
    outbox: list = field(default_factory=list)
    history: list = field(default_factory=list)
    result: dict = field(default_factory=dict)

    def _go(self, to: str, actor: str, at: str = TODAY, note: str = "") -> None:
        if to not in FLOW.get(self.state, set()):
            raise RequestError(f"{self.id}: {self.state} -> {to} not allowed")
        self.history.append((at, self.state, to, actor, note))
        self.state = to

    def vendor(self) -> Vendor:
        return Vendor(self.id, self.vendor_name, self.service, self.pii_access, self.annual_spend,
                      self.data_location, self.answers, None if self.state != "approved" else TODAY)

    def intake(self, actor: str, pii_access: bool, annual_spend: int, data_location: str = "US") -> str:
        if annual_spend < 0:
            raise RequestError("spend cannot be negative")
        self.pii_access, self.annual_spend, self.data_location = pii_access, annual_spend, data_location
        self._go("intake", actor)
        return self.vendor().tier()

    def send_questionnaire(self, actor: str, contact: str) -> dict:
        if "@" not in contact:
            raise RequestError("contact must be an email address")
        msg = {"to": contact, "subject": f"Security questionnaire: {self.vendor_name}",
               "questions": list(QUESTIONS), "sent": False, "mode": "simulated"}
        self.outbox.append(msg)
        self._go("questionnaire_sent", actor)
        return msg

    def record_answers(self, actor: str, answers: dict) -> None:
        bad = set(answers) - set(QUESTIONS)
        if bad:
            raise RequestError(f"unknown questions {sorted(bad)}")
        if not all(isinstance(v, bool) for v in answers.values()):
            raise RequestError("answers must be true or false")
        self.answers = dict(answers)
        self._go("answered", actor)

    def review(self, actor: str) -> dict:
        self._go("under_review", actor)
        s = score(self.vendor())
        self.result = {"score": s["score"], "band": s["band"], "tier": s["tier"],
                       "approver_role": "ciso" if s["band"] == "high" else "procurement-lead",
                       "gaps": [q for q in QUESTIONS if self.answers.get(q) is not True]}
        return self.result

    def decide(self, actor: str, role: str, approve: bool, note: str) -> None:
        if actor.startswith("agent:"):
            raise RequestError("agents cannot approve vendors")
        if actor == self.requester:
            raise RequestError("the requester cannot approve their own vendor")
        if role != self.result.get("approver_role") and role != "ciso":
            raise RequestError(f"needs {self.result.get('approver_role')}")
        if not note.strip():
            raise RequestError("a decision needs a note")
        self._go("approved" if approve else "rejected", actor, note=note)

    def sla(self, today: str = TODAY) -> dict:
        tier = Vendor(self.id, "", "", self.pii_access, self.annual_spend, "US", {}, None).tier()
        age = (dt.date.fromisoformat(today) - dt.date.fromisoformat(self.opened)).days
        done = self.state in ("approved", "rejected")
        return {"tier": tier, "age": age, "sla": SLA_DAYS[tier], "breached": not done and age > SLA_DAYS[tier]}


def demo() -> list[dict]:
    """Three synthetic requests: one approved, one stuck in questionnaire, one rejected."""
    yes = {q: True for q in QUESTIONS}
    a = VendorRequest("VR-101", "Fernhollow Survey Tools", "patient surveys", "pat.moreno", opened="2026-10-20")
    a.intake("procurement", True, 40_000)
    a.send_questionnaire("procurement", "security@fernhollow.example")
    a.record_answers("procurement", yes)
    a.review("agent:tprm")
    a.decide("Dana Whitlock", "procurement-lead", True, "All answers yes; SOC 2 report on file.")
    b = VendorRequest("VR-102", "Quarrystone Translation", "document translation", "lee.okafor", opened="2026-10-02")
    b.intake("procurement", True, 300_000, "CA")
    b.send_questionnaire("procurement", "trust@quarrystone.example")
    c = VendorRequest("VR-103", "Ashgrove Chat Widgets", "web chat", "pat.moreno", opened="2026-10-12")
    c.intake("procurement", True, 120_000)
    c.send_questionnaire("procurement", "sec@ashgrove.example")
    c.record_answers("procurement", {**yes, "Q2": False, "Q4": False, "Q7": False})
    c.review("agent:tprm")
    c.decide("Morgan Hale", "ciso", False, "Offshore PII and no 1-hour breach notice.")
    return [{"id": r.id, "vendor": r.vendor_name, "state": r.state, **r.sla(), **({"score": r.result["score"],
             "band": r.result["band"]} if r.result else {})} for r in (a, b, c)]
