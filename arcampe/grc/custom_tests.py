"""Custom test builder: write a check as a small JSON rule instead of Python.

A rule names a resource type, a dotted property path, an operator and a value. It compiles into the same
Check object the built-in registry uses, so custom tests feed findings, the POA&M and workflows like any
other check. Paths are read-only lookups; there is no code execution.
"""
from __future__ import annotations

import json

from .. import DATA, catalog
from ..checks import registry
from ..checks.base import SEVERITIES, Check

OPS = ("eq", "ne", "in", "not_in", "gte", "lte", "exists", "not_exists", "contains", "truthy")
MAX_PATH_DEPTH = 6


class RuleError(ValueError):
    pass


def lookup(obj, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


class _Missing:
    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()


def evaluate(op: str, actual, expected) -> bool:
    if op == "exists":
        return actual is not _MISSING
    if op == "not_exists":
        return actual is _MISSING
    if actual is _MISSING:
        return False
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op == "contains":
        return isinstance(actual, (list, str)) and expected in actual
    if op == "truthy":
        return bool(actual)
    try:
        return actual >= expected if op == "gte" else actual <= expected
    except TypeError:
        return False


def validate(rule: dict) -> list[str]:
    errs = []
    for k in ("id", "title", "resource_type", "path", "op", "severity", "controls"):
        if k not in rule:
            errs.append(f"missing {k}")
    extra = set(rule) - {"id", "title", "resource_type", "path", "op", "value", "severity", "controls", "rationale"}
    if extra:
        errs.append(f"unknown keys {sorted(extra)}")
    if errs:
        return errs
    if not str(rule["id"]).startswith("CT-"):
        errs.append("custom test ids start with CT-")
    if rule["op"] not in OPS:
        errs.append(f"unknown operator {rule['op']}")
    if rule["op"] not in ("exists", "not_exists", "truthy") and "value" not in rule:
        errs.append("operator needs a value")
    if rule["severity"] not in SEVERITIES:
        errs.append(f"bad severity {rule['severity']}")
    if len(str(rule["path"]).split(".")) > MAX_PATH_DEPTH or "__" in str(rule["path"]):
        errs.append("path too deep or uses a dunder")
    known = catalog.by_id()
    for c in rule["controls"]:
        if c not in known:
            errs.append(f"unknown control {c}")
    if not rule["controls"]:
        errs.append("map the test to at least one control")
    return errs


def compile_rule(rule: dict) -> Check:
    errs = validate(rule)
    if errs:
        raise RuleError("; ".join(errs))

    def fn(r: dict, rule=rule):
        actual = lookup(r, rule["path"])
        ok = evaluate(rule["op"], actual, rule.get("value"))
        return ok, f"{rule['path']}={actual!r} ({rule['op']} {rule.get('value', '')!r})".strip()

    return Check(rule["id"], rule["title"], tuple(rule["controls"]), rule["severity"], (rule["resource_type"],), fn,
                 rule.get("rationale", "custom test"))


def load_rules(path=None) -> list[dict]:
    return json.loads((path or DATA / "grc" / "custom_tests.json").read_text())


def run(rules=None, resources=None) -> list:
    checks = [compile_rule(r) for r in (load_rules() if rules is None else rules)]
    return registry.run(resources=resources, checks=checks)


def summary(rules=None) -> list[dict]:
    rules = load_rules() if rules is None else rules
    res = run(rules)
    out = []
    for r in rules:
        fs = [f for f in res if f.check_id == r["id"]]
        out.append({"id": r["id"], "title": r["title"], "evaluated": len(fs), "failed": sum(not f.passed for f in fs)})
    return out
