"""Dynamic control mapping: evidence -> ARC-AMPE control (-> NIST, HIPAA, SOC 2 via the crosswalk).

The default mapper is a deterministic keyword scorer that stands in for an AI model, so results are
repeatable in CI. Each mapping carries a confidence. Below THRESHOLD it goes to a human review queue
instead of being applied. Quality is measured on a labelled synthetic set (data/mapping/labeled.json).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .. import DATA
from ..crosswalk import map_control

THRESHOLD = 0.6
HINT_BONUS = 1.5

KEYWORDS: dict[str, dict[str, float]] = {
    "AC-02": {"account": 1, "provisioning": 1.5, "user list": 1, "joiner": 1, "access request": 1.5},
    "AC-02(03)": {"inactive": 2, "dormant": 2, "stale account": 2, "days since login": 1.5},
    "AC-06": {"least privilege": 2, "privileged": 1, "admin rights": 1.5},
    "AC-06(05)": {"global admin": 2, "standing admin": 2, "pim": 1.5, "just-in-time": 1.5},
    "AC-07": {"lockout": 2, "failed logon": 2, "failed login": 2, "unsuccessful": 1.5},
    "AC-11": {"screen lock": 2, "idle timeout": 2, "session lock": 2},
    "AC-22": {"public website": 1.5, "external sharing": 2, "anonymous link": 2, "publicly accessible": 1.5},
    "AT-02": {"awareness training": 2, "training completion": 2, "phishing simulation": 1.5, "course": 1},
    "AU-02": {"audit logging": 2, "diagnostic settings": 1.5, "log enabled": 1.5},
    "AU-06": {"log review": 2, "reviewed logs": 2, "siem review": 2, "weekly review": 1.5},
    "AU-11": {"retention": 2, "archive": 1, "retained": 1.5},
    "CA-08": {"penetration test": 2.5, "pen test": 2.5, "rules of engagement": 2},
    "CM-03": {"change request": 2, "change ticket": 2, "cab": 1.5, "change approval": 2, "pull request": 1},
    "CM-06": {"baseline configuration": 1.5, "cis benchmark": 2, "policy compliance": 1.5, "hardening": 1.5},
    "CM-08": {"asset inventory": 2.5, "cmdb": 2, "asset tag": 1.5, "hostname": 0.5},
    "CP-09": {"backup": 2, "snapshot": 1.5, "full backup": 1},
    "CP-09(01)": {"restore test": 2.5, "test restore": 2.5, "recovery drill": 1.5},
    "IA-02(01)": {"mfa": 2, "multi-factor": 2, "two-factor": 2, "authenticator": 1},
    "IR-06": {"reported to cms": 2.5, "incident report": 2, "notified within": 1.5, "breach notification": 1.5},
    "PS-04": {"termination": 2, "offboarding": 2, "leaver": 2, "separated": 1.5},
    "PT-04": {"consent": 2.5, "opt-in": 2, "opt out": 1.5},
    "PT-05": {"privacy notice": 2.5, "privacy act statement": 2, "notice": 0.5},
    "RA-05": {"vulnerability scan": 2.5, "scan results": 2, "cve": 1.5, "scanner": 1.5},
    "SA-09(05)": {"data location": 2, "offshore": 2, "region": 1, "outside the us": 2},
    "SA-11": {"code scanning": 2.5, "sast": 2, "static analysis": 2, "dependency scan": 1.5},
    "SC-07": {"firewall": 1.5, "network security group": 2, "public network access": 1.5, "boundary": 1.5},
    "SC-08": {"tls": 2, "https": 1.5, "in transit": 2},
    "SC-28": {"encryption at rest": 2.5, "encrypted disk": 2, "tde": 2, "cmk": 1},
    "SI-02": {"patch": 2, "patched": 2, "missing update": 1.5, "kb": 1},
    "SI-04": {"alert": 1, "monitoring": 1.5, "detection rule": 2, "anomaly": 1.5},
    "SR-03": {"vendor": 1, "supplier": 1.5, "questionnaire": 1.5, "third-party": 1.5, "flow-down": 2},
    "SR-08": {"breach notice clause": 2.5, "contract clause": 1.5, "notification agreement": 2},
}


@dataclass(frozen=True)
class Mapping:
    item: str
    control: str | None
    confidence: float
    decision: str           # auto | review
    frameworks: dict
    top3: tuple


def _score(text: str, hints: tuple[str, ...] = ()) -> list[tuple[str, float]]:
    t = " " + re.sub(r"[^a-z0-9()\- ]+", " ", text.lower()) + " "
    out = []
    for c, kws in KEYWORDS.items():
        s = sum(w for k, w in kws.items() if f" {k} " in t or (len(k) > 4 and k in t))
        if c in hints:
            s += HINT_BONUS
        out.append((c, s))
    return sorted(out, key=lambda x: (-x[1], x[0]))


def map_text(item_id: str, text: str, hints: tuple[str, ...] = (), threshold: float = THRESHOLD) -> Mapping:
    ranked = _score(text, hints)
    (c1, s1), (_, s2) = ranked[0], ranked[1]
    conf = 0.0 if s1 < 1.5 else round(s1 / (s1 + s2), 3)
    decision = "auto" if conf >= threshold else "review"
    fw = map_control(c1) if s1 > 0 else {}
    return Mapping(item_id, c1 if s1 > 0 else None, conf, decision,
                   {"ARC-AMPE": c1, "NIST_800_53": c1, **{k: list(v) for k, v in fw.items()
                                                          if k in ("HIPAA", "SOC2")}} if s1 > 0 else {},
                   tuple(ranked[:3]))


def map_evidence(e, threshold: float = THRESHOLD) -> Mapping:
    text = f"{e.kind.replace('_', ' ')} {e.source.replace('_', ' ')} " + " ".join(
        f"{k.replace('_', ' ')} {v}" for k, v in e.attributes.items())
    return map_text(e.evidence_id, text, tuple(e.control_hints), threshold)


def load_labeled(path=None) -> list[dict]:
    return json.loads((path or DATA / "mapping" / "labeled.json").read_text())["items"]


def evaluate(items: list[dict] | None = None, threshold: float = THRESHOLD) -> dict:
    """Precision = correct auto-maps / all auto-maps. Recall = correct auto-maps / all items."""
    items = items or load_labeled()
    auto = correct = review = review_would_be_wrong = 0
    for it in items:
        m = map_text(it["id"], it["text"], tuple(it.get("hints", ())), threshold)
        if m.decision == "auto":
            auto += 1
            correct += m.control == it["label"]
        else:
            review += 1
            review_would_be_wrong += m.control != it["label"]
    n = len(items)
    return {"items": n, "threshold": threshold, "auto": auto, "review": review,
            "precision": round(correct / auto, 3) if auto else 0.0,
            "recall": round(correct / n, 3) if n else 0.0,
            "review_queue_caught_errors": review_would_be_wrong}


def sweep(thresholds=(0.5, 0.55, 0.6, 0.7, 0.8, 0.9)) -> list[dict]:
    return [evaluate(threshold=t) for t in thresholds]
