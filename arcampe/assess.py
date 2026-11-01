"""One assessment run: every source of findings, normalized to the same Finding shape."""
from __future__ import annotations

from functools import lru_cache

from . import attest, privacy, supply_chain
from .checks import evidence_checks, registry
from .checks.base import Finding

_ATTEST_SEVERITY = {"overdue": "moderate", "missing": "high"}


def attestation_findings() -> list[Finding]:
    out = []
    for a in attest.load():
        st = a.status()
        if st in ("current", "due_soon"):
            out.append(Finding("AT-ST", f"attestation/{a.control}", a.control, True, "low", (a.control,),
                               f"attested {a.age()} days ago"))
        else:
            out.append(Finding("AT-ST", f"attestation/{a.control}", a.control, False, _ATTEST_SEVERITY[st],
                               (a.control,), "never attested" if st == "missing" else
                               f"attestation {a.age()} days old (every {a.frequency_days})"))
    return out


def privacy_findings() -> list[Finding]:
    sev = {"PT-SSN": "high", "PT-XB": "high", "PT-CONSENT": "moderate"}
    return [Finding(f.id, f"privacy/{f.subject}", f.subject, f.passed, sev.get(f.id, "moderate"), (f.control,),
                    f.detail) for f in privacy.check_inventory(privacy.load_inventory())]


def vendor_findings() -> list[Finding]:
    return [Finding(f["id"], f"vendor/{f['subject']}", f["subject"], f["passed"],
                    "high" if f["id"] == "SR-LOC" else "moderate", (f["control"],), f["detail"])
            for f in supply_chain.findings(supply_chain.load())]


@lru_cache(maxsize=1)
def run_all() -> tuple[Finding, ...]:
    return tuple(registry.run() + evidence_checks.run() + privacy_findings() + vendor_findings()
                 + attestation_findings())


def by_control(findings=None) -> dict[str, dict]:
    """Per-control result: pass, fail or not_tested, with counts."""
    findings = run_all() if findings is None else findings
    out: dict[str, dict] = {}
    for f in findings:
        for c in f.controls:
            d = out.setdefault(c, {"passed": 0, "failed": 0})
            d["passed" if f.passed else "failed"] += 1
    for d in out.values():
        d["status"] = "fail" if d["failed"] else "pass"
    return out


def summary(findings=None) -> dict:
    findings = run_all() if findings is None else findings
    srcs: dict[str, list[int]] = {}
    for f in findings:
        s = f.resource_id.split("/")[0] if not f.resource_id.startswith("/subscriptions") else "azure"
        srcs.setdefault(s, [0, 0])[0 if f.passed else 1] += 1
    return {"findings": len(findings), "passed": sum(f.passed for f in findings),
            "failed": sum(not f.passed for f in findings),
            "by_source": {k: {"passed": v[0], "failed": v[1]} for k, v in sorted(srcs.items())}}
