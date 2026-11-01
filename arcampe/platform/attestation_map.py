"""Readiness map for FedRAMP Moderate, PCI DSS SAQ D for service providers and a HIPAA BAA.

SELF-ASSESSMENT ONLY. Nothing here is a certification, authorization or attestation of compliance.
Each requirement area points to the repo module and test that would produce evidence for it, and
the status says whether that evidence exists in this repo (ready), exists in part (partial) or not (gap).
"""
from __future__ import annotations

DISCLAIMER = "Self-assessment readiness only. Not a FedRAMP authorization, PCI attestation or signed BAA."

MAP = {
    "FedRAMP Moderate (proxy: NIST 800-53B Moderate)": [
        ("Control baseline coverage", "arcampe/catalog.py", "tests/test_catalog.py", "ready"),
        ("Continuous monitoring (monthly scans, POA&M)", "arcampe/conmon.py, arcampe/poam.py", "tests/test_poam.py", "ready"),
        ("System security plan", "arcampe/sspp.py", "tests/test_sspp.py", "partial"),
        ("Independent assessment (3PAO)", "arcampe/platform/assurance.py", "tests/test_platform.py", "gap"),
        ("FIPS 140 validated cryptography", "arcampe/platform/crypto.py", "tests/test_platform.py", "partial"),
        ("Incident reporting", "arcampe/incident.py", "tests/test_solutions.py", "ready"),
    ],
    "PCI DSS v4.0 SAQ D (service provider)": [
        ("Req 1 network security controls", "arcampe/checks/registry.py (AZ-01, AZ-13)", "tests/test_checks.py", "ready"),
        ("Req 3 protect stored account data", "arcampe/platform/crypto.py", "tests/test_platform.py", "partial"),
        ("Req 4 strong cryptography in transit", "arcampe/checks/registry.py (AZ-04)", "tests/test_checks.py", "ready"),
        ("Req 6 secure development and patching", "arcampe/checks/evidence_checks.py (EV-05), registry AZ-19", "tests/test_checks.py", "ready"),
        ("Req 8 identification and MFA", "arcampe/platform/rbac.py", "tests/test_platform.py", "ready"),
        ("Req 10 logging and monitoring", "arcampe/platform/audit_log.py", "tests/test_platform.py", "ready"),
        ("Req 11 testing (scans, pen test)", "arcampe/platform/assurance.py", "tests/test_platform.py", "ready"),
        ("Req 12.8 third-party service providers", "arcampe/supply_chain.py", "tests/test_supply_chain.py", "ready"),
        ("Cardholder data scope", "-", "-", "gap"),
    ],
    "HIPAA BAA readiness": [
        ("Safeguards per 164.308-164.312", "arcampe/crosswalk.py", "tests/test_crosswalk.py", "ready"),
        ("Breach notification to covered entity", "arcampe/incident.py", "tests/test_solutions.py", "ready"),
        ("Subcontractor flow-down", "arcampe/supply_chain.py (SR-FLOW)", "tests/test_supply_chain.py", "ready"),
        ("Return or destroy PHI at termination", "-", "-", "gap"),
        ("Access to PHI for individual rights", "arcampe/privacy.py (rights_requests)", "tests/test_privacy.py", "partial"),
    ],
}


def summary() -> dict[str, dict[str, int]]:
    out = {}
    for prog, items in MAP.items():
        d = {"ready": 0, "partial": 0, "gap": 0}
        for *_, status in items:
            d[status] += 1
        out[prog] = d
    return out


def to_markdown() -> str:
    lines = [f"> {DISCLAIMER}", ""]
    for prog, items in MAP.items():
        lines += [f"**{prog}**", "", "| Area | Code | Test | Status |", "|---|---|---|---|"]
        lines += [f"| {a} | `{c}` | `{t}` | {s} |" for a, c, t, s in items]
        lines.append("")
    return "\n".join(lines)
