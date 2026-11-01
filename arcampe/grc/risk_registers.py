"""Several risk registers, each with its own scoring formula, plus a risk library and dated snapshots.

Formulas are small arithmetic expressions over named inputs (likelihood, impact, control_effectiveness,
velocity, exposure). They are parsed with Python's ast module and only numbers, those names, + - * /,
parentheses and min()/max()/round() are allowed. Nothing is passed to eval().
A snapshot freezes every risk score on a date and becomes an evidence record (hash + lineage), so
"what did the register say on 1 October?" has a provable answer.
"""
from __future__ import annotations

import ast
import operator
from dataclasses import dataclass, field

from .. import TODAY
from ..integrations import schema

VARS = ("likelihood", "impact", "control_effectiveness", "velocity", "exposure")
_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
_FUNCS = {"min": min, "max": max, "round": round}
MAX_FORMULA_LEN = 200


class FormulaError(ValueError):
    pass


def parse(formula: str) -> ast.Expression:
    if len(formula) > MAX_FORMULA_LEN:
        raise FormulaError("formula too long")
    try:
        tree = ast.parse(formula, mode="eval")
    except SyntaxError as e:
        raise FormulaError(f"syntax: {e.msg}") from None
    for node in ast.walk(tree):
        if isinstance(node, (ast.Expression, ast.Load, ast.operator, ast.unaryop)):
            continue
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
            continue
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            continue
        if isinstance(node, ast.Name) and (node.id in VARS or node.id in _FUNCS):
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FUNCS \
                and not node.keywords:
            continue
        raise FormulaError(f"not allowed: {type(node).__name__}")
    return tree


def evaluate(formula: str, values: dict) -> float:
    tree = parse(formula)

    def ev(n):
        if isinstance(n, ast.Expression):
            return ev(n.body)
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            if n.id not in values:
                raise FormulaError(f"missing input {n.id}")
            return float(values[n.id])
        if isinstance(n, ast.UnaryOp):
            return -ev(n.operand)
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left), ev(n.right)
            if isinstance(n.op, ast.Div) and b == 0:
                raise FormulaError("division by zero")
            return _BIN[type(n.op)](a, b)
        if isinstance(n, ast.Call):
            return _FUNCS[n.func.id](*[ev(x) for x in n.args])
        raise FormulaError("unsupported")  # pragma: no cover - parse() already rejects

    return round(float(ev(tree)), 2)


@dataclass(frozen=True)
class Register:
    id: str
    name: str
    owner: str
    formula: str            # residual score
    inherent_formula: str
    scale_max: float
    bands: tuple[tuple[str, float], ...]  # (band, minimum score), highest first

    def band(self, score: float) -> str:
        for name, lo in self.bands:
            if score >= lo:
                return name
        return self.bands[-1][0]


@dataclass
class Risk:
    id: str
    register: str
    title: str
    category: str
    owner: str
    inputs: dict = field(default_factory=dict)
    library_ref: str = ""


LIBRARY = (  # reusable templates (author-written)
    {"ref": "LIB-01", "title": "Ransomware encrypts enrollment systems", "category": "cyber",
     "inputs": {"likelihood": 3, "impact": 5, "control_effectiveness": 0.6, "velocity": 3, "exposure": 4}},
    {"ref": "LIB-02", "title": "Misdirected notice exposes PII", "category": "privacy",
     "inputs": {"likelihood": 4, "impact": 3, "control_effectiveness": 0.5, "velocity": 2, "exposure": 3}},
    {"ref": "LIB-03", "title": "Vendor breach exposes consumer data", "category": "third_party",
     "inputs": {"likelihood": 3, "impact": 4, "control_effectiveness": 0.4, "velocity": 2, "exposure": 4}},
    {"ref": "LIB-04", "title": "Cloud storage made public by mistake", "category": "cyber",
     "inputs": {"likelihood": 3, "impact": 4, "control_effectiveness": 0.8, "velocity": 3, "exposure": 3}},
    {"ref": "LIB-05", "title": "AI drafter states a control is met when it is not", "category": "ai",
     "inputs": {"likelihood": 3, "impact": 3, "control_effectiveness": 0.7, "velocity": 1, "exposure": 2}},
    {"ref": "LIB-06", "title": "Prompt injection through evidence notes", "category": "ai",
     "inputs": {"likelihood": 2, "impact": 3, "control_effectiveness": 0.7, "velocity": 2, "exposure": 2}},
    {"ref": "LIB-07", "title": "Open enrollment outage", "category": "operational",
     "inputs": {"likelihood": 2, "impact": 5, "control_effectiveness": 0.5, "velocity": 3, "exposure": 5}},
    {"ref": "LIB-08", "title": "Key staff leave during audit", "category": "operational",
     "inputs": {"likelihood": 2, "impact": 2, "control_effectiveness": 0.3, "velocity": 1, "exposure": 1}},
    {"ref": "LIB-09", "title": "Consent not recorded for data sharing", "category": "privacy",
     "inputs": {"likelihood": 2, "impact": 4, "control_effectiveness": 0.6, "velocity": 1, "exposure": 3}},
    {"ref": "LIB-10", "title": "Privileged account takeover", "category": "cyber",
     "inputs": {"likelihood": 2, "impact": 5, "control_effectiveness": 0.7, "velocity": 3, "exposure": 4}},
    {"ref": "LIB-11", "title": "Unreviewed AI model change reaches production", "category": "ai",
     "inputs": {"likelihood": 2, "impact": 4, "control_effectiveness": 0.5, "velocity": 2, "exposure": 3}},
    {"ref": "LIB-12", "title": "Subprocessor moves data offshore", "category": "third_party",
     "inputs": {"likelihood": 2, "impact": 4, "control_effectiveness": 0.3, "velocity": 1, "exposure": 3}},
)

REGISTERS = (
    Register("RR-ENT", "Enterprise risk", "ciso", "likelihood * impact * (1 - control_effectiveness)",
             "likelihood * impact", 25, (("high", 8), ("moderate", 4), ("low", 0))),
    Register("RR-SEC", "IT security risk", "isso",
             "round(likelihood * impact * (1 - control_effectiveness) * (1 + velocity / 10), 2)",
             "likelihood * impact * (1 + velocity / 10)", 32.5, (("high", 9), ("moderate", 5), ("low", 0))),
    Register("RR-PRV", "Privacy risk", "privacy-officer", "max(likelihood, exposure) * impact * (1 - control_effectiveness)",
             "max(likelihood, exposure) * impact", 25, (("high", 8), ("moderate", 4), ("low", 0))),
    Register("RR-AI", "AI risk", "ai-governance-lead", "(likelihood + exposure) / 2 * impact * (1 - control_effectiveness)",
             "(likelihood + exposure) / 2 * impact", 25, (("high", 6), ("moderate", 3), ("low", 0))),
)
CATEGORY_TO_REGISTER = {"cyber": "RR-SEC", "privacy": "RR-PRV", "ai": "RR-AI", "third_party": "RR-ENT",
                        "operational": "RR-ENT"}
OWNER_BY_CATEGORY = {"cyber": "isso", "privacy": "privacy-officer", "ai": "ai-governance-lead",
                     "third_party": "procurement-lead", "operational": "it-ops-manager"}


def register(rid: str) -> Register:
    for r in REGISTERS:
        if r.id == rid:
            return r
    raise KeyError(rid)


def from_library(ref: str, rid: str | None = None, overrides: dict | None = None) -> Risk:
    t = next((x for x in LIBRARY if x["ref"] == ref), None)
    if t is None:
        raise KeyError(ref)
    reg = rid or CATEGORY_TO_REGISTER[t["category"]]
    return Risk(f"{reg}-{ref[-2:]}", reg, t["title"], t["category"], OWNER_BY_CATEGORY[t["category"]],
                {**t["inputs"], **(overrides or {})}, ref)


def default_risks() -> list[Risk]:
    return [from_library(t["ref"]) for t in LIBRARY]


def score(risk: Risk) -> dict:
    reg = register(risk.register)
    inherent = evaluate(reg.inherent_formula, risk.inputs)
    residual = evaluate(reg.formula, risk.inputs)
    return {"id": risk.id, "register": reg.id, "title": risk.title, "owner": risk.owner, "inherent": inherent,
            "residual": residual, "band": reg.band(residual), "reduction_pct":
            round(100 * (1 - residual / inherent), 1) if inherent else 0.0}


def scores(risks=None) -> list[dict]:
    return [score(r) for r in (default_risks() if risks is None else risks)]


def by_register(risks=None) -> dict[str, dict]:
    out: dict[str, dict] = {r.id: {"name": r.name, "risks": 0, "high": 0, "moderate": 0, "low": 0} for r in REGISTERS}
    for s in scores(risks):
        d = out[s["register"]]
        d["risks"] += 1
        d[s["band"]] += 1
    return out


def snapshot(on: str = TODAY, risks=None, tenant: str = "lakehaven"):
    """Freeze every score on a date as one evidence record."""
    rows = sorted(scores(risks), key=lambda s: s["id"])
    return schema.make(tenant, "risk_registers", "platform", "risk_snapshot", f"risk-registers@{on}", on,
                       {"date": on, "scores": rows}, ("RA-03", "PM-09"))


def diff(old, new) -> list[dict]:
    """Per-risk change in residual score between two snapshots."""
    a = {r["id"]: r for r in old.attributes["scores"]}
    b = {r["id"]: r for r in new.attributes["scores"]}
    out = []
    for rid in sorted(set(a) | set(b)):
        x, y = a.get(rid), b.get(rid)
        if x is None or y is None:
            out.append({"id": rid, "change": "added" if x is None else "removed"})
        elif x["residual"] != y["residual"]:
            out.append({"id": rid, "change": "up" if y["residual"] > x["residual"] else "down",
                        "from": x["residual"], "to": y["residual"]})
    return out


# Monthly history for the trend chart: the same library with control effectiveness improving over time.
HISTORY_MONTHS = ("2026-06-30", "2026-07-31", "2026-08-31", "2026-09-30", "2026-10-31")
_CE_DELTA = (-0.2, -0.15, -0.1, -0.05, 0.0)


def history() -> list[dict]:
    out = []
    for month, d in zip(HISTORY_MONTHS, _CE_DELTA):
        risks = [from_library(t["ref"], overrides={"control_effectiveness":
                                                   max(0.0, round(t["inputs"]["control_effectiveness"] + d, 2))})
                 for t in LIBRARY]
        s = scores(risks)
        out.append({"date": month, "total_residual": round(sum(x["residual"] for x in s), 2),
                    "high": sum(x["band"] == "high" for x in s)})
    return out
