"""Attestation tracking for procedural controls: who signs, how often, what is stale.

An attestation is a dated statement by a named role that a procedural control is in place,
with a pointer to the evidence file. The repo cannot judge the statement; it tracks freshness,
drafts reminders (never sends them) and turns overdue items into POA&M entries.
"""
from __future__ import annotations

import datetime as dt
import json
import random
from dataclasses import dataclass

from . import DATA, TODAY

DUE_SOON_DAYS = 30
ESCALATE_AFTER_DAYS = 30
OWNER_BY_FAMILY = {"AT": "training-lead", "MA": "it-ops-manager", "MP": "it-ops-manager",
                   "PE": "facilities-security", "PL": "isso", "PM": "ciso", "PS": "hr-security-liaison",
                   "PT": "privacy-officer", "SA": "procurement-lead", "SR": "procurement-lead",
                   "CP": "continuity-lead", "IR": "ir-lead", "CA": "isso", "RA": "isso"}
# ARC-AMPE asks for yearly reviews of most policies, plans and trainings.
FREQ_DAYS = {"default": 365, "PE-06": 90, "PE-08": 90, "MA-02": 180}


@dataclass(frozen=True)
class Attestation:
    control: str
    owner: str
    frequency_days: int
    last_attested: str | None
    evidence_ref: str | None

    def age(self, today: str = TODAY) -> int | None:
        if not self.last_attested:
            return None
        return (dt.date.fromisoformat(today) - dt.date.fromisoformat(self.last_attested)).days

    def due_date(self) -> str | None:
        if not self.last_attested:
            return None
        return (dt.date.fromisoformat(self.last_attested) + dt.timedelta(days=self.frequency_days)).isoformat()

    def status(self, today: str = TODAY) -> str:
        age = self.age(today)
        if age is None:
            return "missing"
        if age > self.frequency_days:
            return "overdue"
        if age > self.frequency_days - DUE_SOON_DAYS:
            return "due_soon"
        return "current"


def generate(controls: list[str], seed: int = 31) -> list[dict]:
    """Synthetic register: a realistic mix of current, due soon, overdue and missing."""
    rng = random.Random(seed)
    today = dt.date.fromisoformat(TODAY)
    out = []
    for c in controls:
        freq = FREQ_DAYS.get(c, FREQ_DAYS["default"])
        roll = rng.random()
        if roll < 0.06:
            last = None
        elif roll < 0.18:
            last = today - dt.timedelta(days=freq + rng.randint(1, 120))
        elif roll < 0.30:
            last = today - dt.timedelta(days=freq - rng.randint(1, DUE_SOON_DAYS - 1))
        else:
            last = today - dt.timedelta(days=rng.randint(5, freq - DUE_SOON_DAYS - 1))
        out.append({"control": c, "owner": OWNER_BY_FAMILY.get(c[:2], "isso"), "frequency_days": freq,
                    "last_attested": last.isoformat() if last else None,
                    "evidence_ref": f"evidence/attestations/{c}.pdf" if last else None})
    return out


def load(path=None) -> list[Attestation]:
    p = path or DATA / "attestations.json"
    return [Attestation(**r) for r in json.loads(p.read_text())]


def summary(items: list[Attestation], today: str = TODAY) -> dict:
    out = {"current": 0, "due_soon": 0, "overdue": 0, "missing": 0}
    for a in items:
        out[a.status(today)] += 1
    out["total"] = len(items)
    return out


def reminders(items: list[Attestation], today: str = TODAY) -> list[dict]:
    """Draft reminders grouped by owner. Drafts only: nothing is sent from this repo."""
    by_owner: dict[str, list[Attestation]] = {}
    for a in items:
        if a.status(today) != "current":
            by_owner.setdefault(a.owner, []).append(a)
    out = []
    for owner, lst in sorted(by_owner.items()):
        lst.sort(key=lambda a: a.control)
        overdue = [a for a in lst if a.status(today) in ("overdue", "missing")]
        escalate = [a.control for a in overdue
                    if a.status(today) == "missing" or (a.age(today) or 0) - a.frequency_days > ESCALATE_AFTER_DAYS]
        lines = [f"- {a.control}: {a.status(today).replace('_', ' ')}"
                 + (f" (due {a.due_date()})" if a.due_date() else "") for a in lst]
        out.append({"to_role": owner, "cc_role": "isso" if escalate else None, "status": "draft",
                    "subject": f"[ARC-AMPE] {len(lst)} attestation(s) need your signature",
                    "body": "Please review and re-attest these controls:\n" + "\n".join(lines),
                    "escalate": escalate})
    return out
