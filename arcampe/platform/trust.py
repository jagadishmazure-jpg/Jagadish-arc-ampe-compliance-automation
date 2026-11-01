"""Security & Trust self-assessment: each claim is a function that runs and returns proof.

Nothing here certifies anything. Each item maps to NIST 800-53, SOC 2 (TSC), ISO 27001:2022 Annex A
and HIPAA references (author-built), names its code and test, and runs a live proof on synthetic data.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from .. import DATA, TODAY


@dataclass(frozen=True)
class TrustItem:
    id: str
    claim: str
    code: str
    test: str
    nist: tuple[str, ...]
    soc2: tuple[str, ...]
    iso: tuple[str, ...]
    hipaa: tuple[str, ...]
    proof: Callable[[], tuple[bool, str]]


def _secure_by_design():
    from .secure_ai import scan_source
    bad = scan_source()
    return not bad, f"{len(bad)} network imports or hard-coded URLs in package; connectors refuse live calls"


def _monitoring():
    from ..integrations.connectors import collect_all
    from .monitoring import detect, load_events, score, vulnerability_view
    ev = load_events()
    s = score(ev, detect(ev))
    v = vulnerability_view(collect_all())
    return s["detected"] == s["scenarios"], (f"{s['detected']}/{s['scenarios']} synthetic attack scenarios detected, "
                                             f"{s['false_positives']} false positives; {len(v['sources'])} scanner feeds")


def _data_protection():
    from .crypto import KeyRing, transit_policy_ok
    k = KeyRing()
    blob = k.encrypt("t1", b"pii")
    try:
        k.decrypt("t2", blob)
        cross = False
    except Exception:
        cross = True
    ok_tls = transit_policy_ok({"scheme": "https", "min_tls": "1.2"})[0]
    bad_tls = not transit_policy_ok({"scheme": "https", "min_tls": "1.0"})[0]
    ok = k.decrypt("t1", blob) == b"pii" and cross and ok_tls and bad_tls
    return ok, "AES-256-GCM per tenant; cross-tenant decrypt fails; TLS < 1.2 rejected"


def _compliance():
    from .. import catalog
    n = len(catalog.baseline("ae"))
    m = sum(c.nist_moderate for c in catalog.baseline("ae"))
    return n == 402, f"{n} ARC-AMPE AE controls catalogued; {m} also in the NIST Moderate baseline (FedRAMP-style proxy)"


def _isolation():
    from .rbac import AccessDenied, Principal
    from .tenancy import TenantStore
    s = TenantStore()
    a = Principal("a", "t1", ("control_owner",))
    b = Principal("b", "t2", ("isso",), mfa=True, phishing_resistant=True)
    s.put(a, "t1", "k", {"x": 1}, TODAY)
    try:
        s.get(b, "t1", "k", TODAY)
        return False, "cross-tenant read allowed"
    except AccessDenied:
        return s.log.verify()[0], "cross-tenant read denied and logged"


def _least_privilege():
    from .rbac import AccessDenied, Principal, authorize
    p = Principal("i", "t1", ("isso",), mfa=True, phishing_resistant=False)
    try:
        authorize(p, "approve_statement", "t1")
        return False, "privileged action without phishing-resistant MFA"
    except AccessDenied:
        pass  # expected: denial is the passing outcome
    agent = Principal("agent:drafter", "t1", ("isso",), mfa=True, phishing_resistant=True, is_agent=True)
    try:
        authorize(agent, "approve_statement", "t1")
        return False, "agent could approve"
    except AccessDenied:
        return True, "privileged actions need phishing-resistant MFA; agents cannot approve"


def _audited():
    from .assurance import cadence_status, load, validate
    c = cadence_status(load())
    v = validate(load())
    return all(x["ok"] for x in c), (f"VA, pen test and control assessment within cadence; "
                                     f"{sum(not x['ok'] for x in v)} mislabelled or weak record(s) flagged")


def _backup():
    from .backup import restore_drill, schedule_ok
    from .rbac import Principal
    from .tenancy import TenantStore
    s = TenantStore()
    p = Principal("o", "t1", ("control_owner",))
    for i in range(5):
        s.put(p, "t1", f"k{i}", {"i": i}, TODAY)
    d = restore_drill(s, TODAY)
    jobs = json.loads((DATA / "fixtures" / "connectors" / "backup_jobs.json").read_text())["jobs"]
    sch = schedule_ok(jobs, TODAY)
    return d["passed"], (f"restore drill {d['objects']} objects hash-matched; "
                         f"{sum(x['passed'] for x in sch)}/{len(sch)} backup targets meet daily/weekly/3-generation")


ITEMS = (
    TrustItem("T1", "Secure by design", "arcampe/platform/secure_ai.py, arcampe/integrations/sdk.py",
              "tests/test_platform.py::test_no_network_code", ("SA-08", "SA-11", "SC-07"), ("CC8.1",),
              ("A.8.25", "A.8.27"), ("164.308(a)(1)",), _secure_by_design),
    TrustItem("T2", "Continuous monitoring (threat detection, vulnerability scanning)",
              "arcampe/platform/monitoring.py", "tests/test_platform.py::test_detection",
              ("SI-04", "RA-05", "CA-07"), ("CC7.1", "CC7.2"), ("A.8.8", "A.8.16"), ("164.308(a)(1)(ii)(D)",),
              _monitoring),
    TrustItem("T3", "Data protection (encryption in transit and at rest, strict access)",
              "arcampe/platform/crypto.py", "tests/test_platform.py::test_crypto_cross_tenant",
              ("SC-08", "SC-13", "SC-28", "SC-12"), ("CC6.1", "CC6.7"), ("A.8.24",),
              ("164.312(a)(2)(iv)", "164.312(e)(1)"), _data_protection),
    TrustItem("T4", "Compliance aligned (NIST 800-53, FedRAMP-style baseline)", "arcampe/catalog.py",
              "tests/test_catalog.py", ("CA-02", "PL-02"), ("CC4.1",), ("A.5.36",), ("164.316(a)",), _compliance),
    TrustItem("T5", "Isolated multi-tenant cloud", "arcampe/platform/tenancy.py",
              "tests/test_platform.py::test_tenant_isolation", ("AC-04", "SC-04", "SC-02"), ("CC6.1",),
              ("A.8.3",), ("164.312(a)(1)",), _isolation),
    TrustItem("T6", "Least privilege (RBAC plus MFA)", "arcampe/platform/rbac.py",
              "tests/test_platform.py::test_rbac", ("AC-06", "AC-05", "IA-02(01)"), ("CC6.3",),
              ("A.5.15", "A.8.2", "A.8.5"), ("164.312(d)", "164.308(a)(4)"), _least_privilege),
    TrustItem("T7", "Audited and tested (pen test and assessment evidence)", "arcampe/platform/assurance.py",
              "tests/test_platform.py::test_assurance", ("CA-02", "CA-08", "RA-05"), ("CC4.1",),
              ("A.5.35", "A.8.8"), ("164.308(a)(8)",), _audited),
    TrustItem("T8", "Backup and disaster recovery (automated backup and restore tests)",
              "arcampe/platform/backup.py", "tests/test_platform.py::test_backup",
              ("CP-09", "CP-09(01)", "CP-10"), ("A1.2", "A1.3"), ("A.8.13", "A.5.30"), ("164.308(a)(7)",), _backup),
)


def self_assessment() -> list[dict]:
    out = []
    for i in ITEMS:
        ok, detail = i.proof()
        out.append({"id": i.id, "claim": i.claim, "passed": ok, "detail": detail, "code": i.code, "test": i.test,
                    "nist": list(i.nist), "soc2": list(i.soc2), "iso27001": list(i.iso), "hipaa": list(i.hipaa)})
    return out
