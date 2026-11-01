"""IT & cyber risk lifecycle: identify -> assess -> analyze (FAIR-style Monte Carlo) -> mitigate.

FAIR-style here means: loss event frequency = threat event frequency x vulnerability, and loss
magnitude per event, both sampled from PERT distributions, giving annualized loss exposure (ALE).
Inputs are synthetic. A fixed seed makes every number reproducible.
"""
from __future__ import annotations

import math
import random

from ..crosswalk import map_control
from . import builder

SEED = 20261031
ITERATIONS = 10_000
FRAMEWORKS_8 = ("GDPR", "HIPAA", "PCI_DSS", "CCPA", "NIST_800_53", "ISO27001", "SOC2", "COBIT")


def pert(rng: random.Random, lo: float, ml: float, hi: float, lamb: float = 4.0) -> float:
    if hi == lo:
        return lo
    a = 1 + lamb * (ml - lo) / (hi - lo)
    b = 1 + lamb * (hi - ml) / (hi - lo)
    return lo + rng.betavariate(a, b) * (hi - lo)


def poisson(rng: random.Random, lam: float) -> int:
    # Knuth; lam is small (< 30) for these inputs
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


def pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    i = q * (len(s) - 1)
    lo, hi = math.floor(i), math.ceil(i)
    return s[lo] + (s[hi] - s[lo]) * (i - lo)


def simulate(threat: dict, iterations: int = ITERATIONS, seed: int = SEED, scale: float = 1.0,
             key: str | None = None) -> dict:
    """Same key + seed -> same random stream, so inherent and residual runs are directly comparable."""
    rng = random.Random(f"{seed}:{key or threat['id']}")
    ale = []
    for _ in range(iterations):
        tef = pert(rng, *threat["tef"])
        events = poisson(rng, tef * threat["vuln"])
        ale.append(scale * sum(pert(rng, *threat["loss_usd"]) for _ in range(events)))
    return {"mean": round(sum(ale) / len(ale)), "p10": round(pct(ale, 0.10)), "p50": round(pct(ale, 0.50)),
            "p90": round(pct(ale, 0.90)), "p_any_loss": round(sum(a > 0 for a in ale) / len(ale), 4)}


def control_health(controls: list[str], findings) -> float:
    """Share of the threat's controls with no failing finding (untested counts as healthy-unknown = 0.5)."""
    status: dict[str, bool] = {}
    for f in findings:
        for c in f.controls:
            status[c] = status.get(c, True) and f.passed
    vals = [1.0 if status.get(c) else 0.0 if c in status else 0.5 for c in controls]
    return round(sum(vals) / len(vals), 3) if vals else 0.5


def frameworks_for(controls: list[str]) -> dict[str, list[str]]:
    out = {k: set() for k in FRAMEWORKS_8}
    for c in controls:
        m = map_control(c)
        out["NIST_800_53"].add(c)
        for k in ("GDPR", "HIPAA", "PCI_DSS", "CCPA", "ISO27001", "SOC2", "COBIT"):
            out[k].update(m[k])
    return {k: sorted(v) for k, v in out.items()}


def analyze(module: dict | None = None, findings=None, iterations: int = ITERATIONS, seed: int = SEED) -> list[dict]:
    m = module or builder.load()
    findings = findings or ()
    assets = {a["id"]: a for a in m["assets"]}
    threats = {t["id"]: t for t in m["threats"]}
    treat = {t["scenario"]: t for t in m.get("treatments", [])}
    rows = []
    for s in m["scenarios"]:
        t = threats[s["threat"]]
        inherent = s["likelihood"] * s["impact"]
        exposure = s.get("exposure", 1.0)
        sim = simulate(t, iterations, seed, scale=exposure, key=s["id"])
        tr = treat.get(s["id"], {"decision": "untreated", "effectiveness": 0.0})
        health = control_health(t["controls"], findings)
        eff = round(tr["effectiveness"] * health, 3)
        residual_sim = simulate(t, iterations, seed, scale=exposure * (1 - eff), key=s["id"])
        rows.append({
            "id": s["id"], "asset": assets[s["asset"]]["name"], "threat": t["name"], "category": t["category"],
            "likelihood": s["likelihood"], "impact": s["impact"], "inherent_score": inherent,
            "inherent_level": "high" if inherent >= 15 else "moderate" if inherent >= 8 else "low",
            "ale": sim, "treatment": tr["decision"], "planned_effectiveness": tr["effectiveness"],
            "control_health": health, "effective_reduction": eff, "residual_ale": residual_sim,
            "recommended_controls": t["controls"], "frameworks": frameworks_for(t["controls"]),
            "exceeds_appetite": residual_sim["p90"] > m["appetite"]["max_residual_ale_p90_usd"]
            or inherent > m["appetite"]["max_inherent_score"] and tr["decision"] == "untreated",
        })
    return rows


def top10(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (-r["residual_ale"]["p90"], r["id"]))[:10]


def top10_markdown(rows: list[dict]) -> str:
    out = ["| # | Risk | Inherent (LxI) | Chance of any loss / yr | ALE P10 | ALE P50 | ALE mean | ALE P90 | Treatment "
           "| Control health | Residual P90 | Over appetite |",
           "|---:|---|---:|---:|---:|---:|---:|---:|---|---:|---:|:-:|"]
    for i, r in enumerate(top10(rows), 1):
        a, ra = r["ale"], r["residual_ale"]
        out.append(f"| {i} | {r['id']} {r['threat']} -> {r['asset']} | {r['likelihood']}x{r['impact']}="
                   f"{r['inherent_score']} | {a['p_any_loss']:.0%} | ${a['p10']:,} | ${a['p50']:,} | ${a['mean']:,} | "
                   f"${a['p90']:,} | {r['treatment']} | {r['control_health']} | ${ra['p90']:,} | "
                   f"{'yes' if r['exceeds_appetite'] else 'no'} |")
    return "\n".join(out)


def heatmap(rows: list[dict]) -> list[list[int]]:
    grid = [[0] * 5 for _ in range(5)]
    for r in rows:
        grid[5 - r["likelihood"]][r["impact"] - 1] += 1
    return grid
