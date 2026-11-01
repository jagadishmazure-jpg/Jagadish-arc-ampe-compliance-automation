"""Risk program extras: register owners and moves with history (A6), FAIR-style loss ranges per register (A7)
and risk SLAs by severity (A8).

FAIR here is a teaching approximation: event frequency comes from the register's likelihood input and loss
magnitude from its impact input via fixed, documented tables. All money values are SYNTHETIC. The board view
shows P50 / P90 / P95 annualized loss and the sentence "95% of simulated years lose no more than $X", with no
red/amber/green colors. Risk appetite needs a CRO sign-off before it is shown as approved.
"""
from __future__ import annotations

import datetime as dt
import random
from dataclasses import dataclass, field, replace

from .. import TODAY
from ..risk.cyber import pct, pert, poisson
from . import risk_registers as rr

SEED = 20261031
ITERATIONS = 4000
# likelihood 1..5 -> threat events per year (min, most likely, max); impact 1..5 -> loss per event in USD
TEF = {1: (0.02, 0.05, 0.2), 2: (0.05, 0.2, 0.5), 3: (0.2, 0.5, 1.5), 4: (0.5, 1.5, 4), 5: (1, 4, 10)}
LOSS = {1: (5e3, 2e4, 6e4), 2: (2e4, 8e4, 2.5e5), 3: (8e4, 3e5, 1e6), 4: (3e5, 1.2e6, 4e6), 5: (1e6, 4e6, 1.5e7)}

SLA_DAYS = {  # severity band -> days allowed to identify (log + score), remediate, or formally accept
    "high": {"identify": 5, "remediate": 60, "accept": 15},
    "moderate": {"identify": 10, "remediate": 120, "accept": 30},
    "low": {"identify": 30, "remediate": 365, "accept": 90},
}


class RiskProgramError(ValueError):
    pass


# ------------------------------------------------------------------ A6 registers and moves
@dataclass
class TrackedRisk:
    risk: rr.Risk
    history: list = field(default_factory=list)


def move(t: TrackedRisk, to_register: str, by: str, reason: str, at: str = TODAY) -> TrackedRisk:
    """Move a risk to another register. Only the owner of the source or target register may move it."""
    src, dst = rr.register(t.risk.register), rr.register(to_register)
    if by not in (src.owner, dst.owner):
        raise RiskProgramError(f"{by} owns neither {src.id} nor {dst.id}")
    if not reason:
        raise RiskProgramError("a reason is required")
    before = rr.score(t.risk)
    new = replace(t.risk, register=to_register)
    after = rr.score(new)
    t.history.append({"at": at, "by": by, "from": src.id, "to": dst.id, "reason": reason,
                      "residual_before": before["residual"], "residual_after": after["residual"]})
    t.risk = new
    return t


def rollup(risks=None) -> dict:
    """One cross-register view. Each register keeps its own formula; the roll-up compares by normalized score."""
    risks = rr.default_risks() if risks is None else risks
    out = {}
    for s in rr.scores(risks):
        reg = rr.register(s["register"])
        norm = round(100 * s["residual"] / reg.scale_max, 1)
        out.setdefault(reg.id, {"owner": reg.owner, "risks": 0, "high": 0, "max_normalized": 0.0})
        o = out[reg.id]
        o["risks"] += 1
        o["high"] += s["band"] == "high"
        o["max_normalized"] = max(o["max_normalized"], norm)
    return out


# ------------------------------------------------------------------ A7 FAIR ranges
def _simulate_register(risks, iterations: int, seed: int) -> list[float]:
    totals = [0.0] * iterations
    for r in risks:
        rng = random.Random(f"{seed}:{r.id}")
        inp = r.inputs
        vuln = max(0.0, 1 - inp["control_effectiveness"])
        for i in range(iterations):
            n = poisson(rng, pert(rng, *TEF[int(inp["likelihood"])]) * vuln)
            totals[i] += sum(pert(rng, *LOSS[int(inp["impact"])]) for _ in range(n))
    return totals


def fair(risks=None, iterations: int = ITERATIONS, seed: int = SEED) -> dict:
    risks = rr.default_risks() if risks is None else risks
    regs: dict[str, list] = {}
    for r in risks:
        regs.setdefault(r.register, []).append(r)
    out = {}
    for rid, rs in sorted(regs.items()):
        ale = _simulate_register(rs, iterations, seed)
        p50, p90, p95 = (round(pct(ale, q)) for q in (0.5, 0.9, 0.95))
        out[rid] = {"risks": len(rs), "p50": p50, "p90": p90, "p95": p95,
                    "sentence": f"95% of simulated years lose no more than ${p95:,.0f}", "label": "SYNTHETIC"}
    return out


@dataclass
class Appetite:
    register: str
    max_p95_usd: float
    signed_by: str = ""
    signed_at: str = ""


def sign_appetite(a: Appetite, by: str, role: str, at: str = TODAY) -> Appetite:
    if role != "cro" or by.startswith("agent:"):
        raise RiskProgramError("only a human CRO can sign the risk appetite")
    return replace(a, signed_by=by, signed_at=at)


def board_view(appetites=None, risks=None) -> list[dict]:
    f = fair(risks)
    apps = {a.register: a for a in (appetites or [])}
    rows = []
    for rid, x in f.items():
        a = apps.get(rid)
        within = None if a is None or not a.signed_by else x["p95"] <= a.max_p95_usd
        rows.append({"register": rid, "p50": x["p50"], "p90": x["p90"], "p95": x["p95"], "sentence": x["sentence"],
                     "appetite": "not signed" if within is None else ("within" if within else "above")})
    return rows


# ------------------------------------------------------------------ A8 risk SLAs
SYNTHETIC_TIMELINE = {  # risk id -> (opened, identified/scored, remediated or accepted, decision)
    "RR-SEC-01": ("2026-08-01", "2026-08-03", "", "remediate"),
    "RR-PRV-02": ("2026-07-10", "2026-07-25", "2026-09-30", "remediate"),
    "RR-ENT-03": ("2026-06-01", "2026-06-04", "2026-06-10", "accept"),
    "RR-SEC-04": ("2026-09-15", "2026-09-17", "", "remediate"),
    "RR-AI-05": ("2026-05-01", "2026-05-02", "2026-06-15", "remediate"),
    "RR-AI-06": ("2026-10-20", "", "", "remediate"),
    "RR-ENT-07": ("2026-04-01", "2026-04-03", "2026-05-20", "accept"),
    "RR-PRV-09": ("2026-09-01", "2026-09-03", "", "accept"),
}
ACCEPTANCES = {"RR-ENT-03": {"owner": "ciso", "expires": "2027-06-10"},
               "RR-ENT-07": {"owner": "", "expires": "2026-10-01"}}  # second one is invalid on purpose


def _days(a: str, b: str) -> int:
    return (dt.date.fromisoformat(b) - dt.date.fromisoformat(a)).days


def sla(risks=None, today: str = TODAY) -> dict:
    scores = {s["id"]: s for s in rr.scores(risks)}
    rows = []
    for rid, (opened, ident, closed, decision) in SYNTHETIC_TIMELINE.items():
        band = scores.get(rid, {}).get("band", "moderate")
        lim = SLA_DAYS[band]
        id_days = _days(opened, ident or today)
        stage = "accept" if decision == "accept" else "remediate"
        act_days = _days(ident or opened, closed or today)
        ok_id = id_days <= lim["identify"]
        ok_act = act_days <= lim[stage]
        acc = ACCEPTANCES.get(rid)
        acc_valid = None if decision != "accept" or not closed else bool(acc and acc["owner"] and acc["expires"] > today)
        rows.append({"id": rid, "band": band, "identify_days": id_days, "identify_ok": ok_id, "stage": stage,
                     "stage_days": act_days, "stage_ok": ok_act, "open": not closed, "acceptance_valid": acc_valid})
    checks = [r["identify_ok"] for r in rows] + [r["stage_ok"] for r in rows]
    return {"rows": rows, "adherence_pct": round(100 * sum(checks) / len(checks), 1),
            "breaches": sum(not c for c in checks),
            "invalid_acceptances": [r["id"] for r in rows if r["acceptance_valid"] is False]}
