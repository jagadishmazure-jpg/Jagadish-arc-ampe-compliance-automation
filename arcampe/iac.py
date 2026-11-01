"""Evaluate the Azure Policy rule files offline against the simulated estate.

This is a tiny subset of the Azure Policy language (field, equals, notEquals, in, notIn, exists,
allOf, anyOf, not), enough for the six ARC-AMPE rules. It proves the deployed rules and the Python
checks agree on the same fixtures. It is not a full Azure Policy engine.
"""
from __future__ import annotations

import json
import re

from . import ROOT

POLICY_DIR = ROOT / "policies" / "azure-policy"
_PARAM = re.compile(r"^\[parameters\('(\w+)'\)\]$")


def load() -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text()) for p in sorted(POLICY_DIR.glob("*.json"))}


def _field(res: dict, name: str):
    if name in ("type", "location", "name"):
        return res.get(name)
    if name.startswith("tags["):
        return res.get("tags", {}).get(name[6:-2])
    prefix = res["type"] + "/"
    if name.startswith(prefix):
        return res.get("properties", {}).get(name[len(prefix):], _MISSING)
    return _MISSING


_MISSING = object()


def _val(v, params: dict):
    if isinstance(v, str):
        m = _PARAM.match(v)
        if m:
            return params[m.group(1)]
    return v


def matches(cond: dict, res: dict, params: dict) -> bool:
    if "allOf" in cond:
        return all(matches(c, res, params) for c in cond["allOf"])
    if "anyOf" in cond:
        return any(matches(c, res, params) for c in cond["anyOf"])
    if "not" in cond:
        return not matches(cond["not"], res, params)
    v = _field(res, cond["field"])
    if "exists" in cond:
        return (v is not _MISSING) == bool(cond["exists"])
    v = None if v is _MISSING else v
    for op, fn in (("equals", lambda a, b: a == b), ("notEquals", lambda a, b: a != b),
                   ("in", lambda a, b: a in b), ("notIn", lambda a, b: a not in b)):
        if op in cond:
            return fn(v, _val(cond[op], params))
    raise ValueError(f"unsupported condition: {cond}")


def evaluate(resources: list[dict], effect: str = "Audit") -> list[dict]:
    """Return one row per (rule, resource) that the rule flags."""
    out = []
    for name, body in load().items():
        params = {k: v.get("defaultValue") for k, v in body["parameters"].items()}
        params["effect"] = effect
        for r in resources:
            if matches(body["policyRule"]["if"], r, params):
                out.append({"policy": name, "check": body["metadata"]["arcampeCheck"], "resource": r["name"],
                            "effect": effect})
    return out


def parity(resources: list[dict], findings) -> dict:
    """Compare policy hits with failing Python check results for the same check IDs and resources."""
    rules = load()
    checks = {b["metadata"]["arcampeCheck"] for b in rules.values()}
    pol = {(h["check"], h["resource"]) for h in evaluate(resources)}
    names = {r["name"] for r in resources}
    py = {(f.check_id, f.resource_name) for f in findings
          if f.check_id in checks and not f.passed and f.resource_name in names}
    # The Python check covers more resource types than the policy file (e.g. AZ-03 is checked on every
    # resource; AZ-05 also on web apps). Compare only resource types the policy rule targets.
    targeted = set()
    for b in rules.values():
        types = [c.get("equals") for c in b["policyRule"]["if"]["allOf"] if c.get("field") == "type"]
        for r in resources:
            if not types or r["type"] in types:
                targeted.add((b["metadata"]["arcampeCheck"], r["name"]))
    py &= targeted
    return {"policy_hits": len(pol), "python_fails": len(py), "both": len(pol & py),
            "policy_only": sorted(pol - py), "python_only": sorted(py - pol)}
