"""PT family and privacy program: inventory (ROPA), notices, consent, SSN handling, DPIA, rights requests.

ARC-AMPE added the PT family. This module works on a synthetic data inventory for the fictional
exchange and returns findings that feed the POA&M like any other check.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass

from . import DATA, TODAY
from .params import PARAMS

SSN_RE = re.compile(r"(?<!\d)(\d{3})-?(\d{2})-?(\d{4})(?!\d)")
DSR_DEADLINE_DAYS = 30   # organization-defined response target used in this demo


def _days(a: str, b: str = TODAY) -> int:
    return (dt.date.fromisoformat(b) - dt.date.fromisoformat(a)).days


# ---------------- SSN handling (PT-07, PT-07(01)) ----------------
def valid_ssn(area: str, group: str, serial: str) -> bool:
    """SSA structural rules: area not 000, 666 or 900-999; group not 00; serial not 0000."""
    a = int(area)
    return a != 0 and a != 666 and a < 900 and group != "00" and serial != "0000"


def find_ssns(text: str) -> list[str]:
    return [m.group(0) for m in SSN_RE.finditer(text) if valid_ssn(*m.groups())]


def mask_ssn(text: str) -> str:
    def repl(m: re.Match) -> str:
        return f"***-**-{m.group(3)}" if valid_ssn(*m.groups()) else m.group(0)
    return SSN_RE.sub(repl, text)


def pseudonymize(value: str, key: bytes | None = None) -> str:
    """Keyed HMAC-SHA256 token. The key comes from ARCAMPE_PSEUDO_KEY; a fixed demo key is used offline."""
    k = key or os.environ.get("ARCAMPE_PSEUDO_KEY", "demo-only-not-a-secret").encode()
    return "tok_" + hmac.new(k, value.encode(), hashlib.sha256).hexdigest()[:20]


# ---------------- inventory and checks ----------------
@dataclass(frozen=True)
class PrivacyFinding:
    id: str
    control: str
    subject: str
    passed: bool
    detail: str


def load_inventory(path=None) -> dict:
    return json.loads((path or DATA / "privacy" / "inventory.json").read_text())


def check_inventory(inv: dict, today: str = TODAY) -> list[PrivacyFinding]:
    out: list[PrivacyFinding] = []
    purposes = {p["id"] for p in inv["purposes"]}
    for a in inv["processing_activities"]:
        # PT-02 authority to process, PT-03 purpose specification
        out.append(PrivacyFinding("PT-AUTH", "PT-02", a["id"], bool(a.get("legal_authority")),
                                  f"authority={a.get('legal_authority')}"))
        bad = [p for p in a["purposes"] if p not in purposes]
        out.append(PrivacyFinding("PT-PURP", "PT-03", a["id"], not bad,
                                  "purposes registered" if not bad else f"unregistered purposes {bad}"))
        # PT-07(01) SSN: collect only with a documented necessity and masked in non-prod
        if "ssn" in a["data_elements"]:
            ok = bool(a.get("ssn_justification")) and a.get("ssn_masked_nonprod") is True
            out.append(PrivacyFinding("PT-SSN", "PT-07(01)", a["id"], ok,
                                      "SSN justified and masked outside prod" if ok else "SSN use not justified or not masked"))
        # SA-09(05) / PT cross-border
        out.append(PrivacyFinding("PT-XB", "SA-09(05)", a["id"], a.get("storage_country") == "US",
                                  f"stored in {a.get('storage_country')}"))
        # RA-08 privacy impact assessment
        pia = a.get("pia_completed")
        ok = bool(pia) and _days(pia, today) <= 365
        out.append(PrivacyFinding("PT-PIA", "RA-08", a["id"], ok,
                                  f"PIA {('none' if not pia else str(_days(pia, today)) + ' days old')}"))
    # PT-05 notice reviewed yearly
    for n in inv["notices"]:
        age = _days(n["last_reviewed"], today)
        out.append(PrivacyFinding("PT-NOTICE", "PT-05", n["id"], age <= PARAMS["PT-05"]["notice_review_every_days"],
                                  f"notice reviewed {age} days ago, plain language score {n['readability_grade']}"))
        out.append(PrivacyFinding("PT-PLAIN", "PT-05", n["id"], n["readability_grade"] <= 8,
                                  f"reading grade {n['readability_grade']} (target 8 or lower)"))
    # PT-04 consent: processing that needs consent must have a live, purpose-matched consent
    need = {a["id"]: a for a in inv["processing_activities"] if a.get("basis") == "consent"}
    for c in inv["consents"]:
        act = need.get(c["activity"])
        if not act:
            continue
        ok = c["status"] == "granted" and c["purpose"] in act["purposes"]
        out.append(PrivacyFinding("PT-CONSENT", "PT-04", c["id"], ok, f"{c['status']} for {c['purpose']}"))
    return out


def rights_requests(inv: dict, today: str = TODAY) -> list[dict]:
    """Individual access/correction requests (AC-03(14) individual access): open past deadline = late."""
    out = []
    for r in inv["rights_requests"]:
        age = _days(r["received"], r.get("closed") or today)
        out.append({**r, "age_days": age, "late": age > DSR_DEADLINE_DAYS,
                    "due": (dt.date.fromisoformat(r["received"]) + dt.timedelta(days=DSR_DEADLINE_DAYS)).isoformat()})
    return out


def dpia(activity: dict) -> dict:
    """A simple, transparent privacy-impact score (1-25) with the drivers listed."""
    drivers = []
    likelihood = 1 + sum([activity.get("volume", 0) > 100_000, "ssn" in activity["data_elements"],
                          activity.get("shared_with_vendor", False), activity.get("storage_country") != "US"])
    impact = 1 + sum(["ssn" in activity["data_elements"], "health" in activity["data_elements"],
                      "income" in activity["data_elements"], activity.get("automated_decision", False)])
    for flag, text in [("ssn" in activity["data_elements"], "SSN collected"),
                       (activity.get("shared_with_vendor"), "shared with a vendor"),
                       (activity.get("automated_decision"), "automated eligibility decision"),
                       (activity.get("storage_country") != "US", "stored outside the U.S.")]:
        if flag:
            drivers.append(text)
    score = min(likelihood, 5) * min(impact, 5)
    level = "high" if score >= 12 else "moderate" if score >= 6 else "low"
    return {"activity": activity["id"], "likelihood": min(likelihood, 5), "impact": min(impact, 5),
            "score": score, "level": level, "drivers": drivers}
