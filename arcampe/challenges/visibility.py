"""Challenge: fragmented visibility. One risk view across cloud, identity, evidence, privacy, vendors."""
from __future__ import annotations

from collections import defaultdict

from .business_context import contextualize


def source_of(f) -> str:
    rid = f.resource_id
    return "azure" if rid.startswith("/subscriptions") else rid.split("/")[0]


def unified_view(findings) -> dict:
    by_source: dict = defaultdict(lambda: {"open": 0, "passed": 0, "worst": 0.0})
    by_family: dict = defaultdict(lambda: {"open": 0, "passed": 0})
    for f in findings:
        s = by_source[source_of(f)]
        fams = {c[:2] for c in f.controls}
        if f.passed:
            s["passed"] += 1
        else:
            s["open"] += 1
            s["worst"] = max(s["worst"], contextualize(f)["weighted"])
        for fam in fams:
            by_family[fam]["passed" if f.passed else "open"] += 1
    return {"by_source": dict(sorted(by_source.items())), "by_family": dict(sorted(by_family.items())),
            "sources": len(by_source)}


def to_markdown(view: dict) -> str:
    rows = ["| Source | Open | Passed | Worst business-weighted score |", "|---|---:|---:|---:|"]
    for k, v in view["by_source"].items():
        rows.append(f"| {k} | {v['open']} | {v['passed']} | {v['worst']} |")
    return "\n".join(rows)
