"""GRC capability areas and where this repo covers each one.

Status: built = runs offline and is tested; partial = smaller than the capability; gap = not built.
"""
from __future__ import annotations

# (area slug, capability, our module(s), test file, status, note)
# status: built = runs offline and is tested; partial = smaller than the capability; gap = not built
AREAS: list[tuple[str, str, str, str, str, str]] = [
    ("arc-ampe", "ARC-AMPE control catalog, SSPP, POA&M, ATO binder",
     "arcampe/catalog.py arcampe/sspp.py arcampe/poam.py arcampe/binder.py", "tests/test_catalog.py", "built",
     "AE baseline from the public CMS workbook; DEE subset is a third-party parse"),
    ("audit-regulatory-controls", "Evidence collection, control monitoring, versioned evidence, audit plan, findings",
     "arcampe/audit.py arcampe/integrations/connectors.py arcampe/conmon.py", "tests/test_solutions.py", "built",
     "dashboard is a static HTML/Markdown file, not real time"),
    ("automation-solutions-ai", "Scheduled jobs, evidence quality scoring, human sign-off, no-code recipes",
     "arcampe/automation/scheduler.py arcampe/automation/ai_auditor.py arcampe/integrations/nocode.py",
     "tests/test_solutions.py", "built", "scheduler is simulated over 30 days; nothing runs on a timer"),
    ("compliance-cartography", "Control mapping across frameworks",
     "arcampe/crosswalk.py arcampe/risk/cyber.py", "tests/test_crosswalk.py", "partial",
     "8 author-built crosswalks plus custom YAML frameworks, not hundreds"),
    ("custom-risk-compliance-programs", "Custom frameworks with links to catalog controls and scoring",
     "arcampe/custom.py arcampe/risk/builder.py", "tests/test_solutions.py", "built", "YAML, validated on load"),
    ("enterprise-operational-risk", "Risk register, KRIs, maturity, BIA link",
     "arcampe/risk/erm.py arcampe/resilience.py", "tests/test_risk.py", "built", "synthetic register of 6 risks"),
    ("governance-policy-controls", "Policy lifecycle, versioning, approval, acknowledgment, review reminders",
     "arcampe/governance.py", "tests/test_solutions.py", "built", "no email distribution; reminders are drafts"),
    ("incident-responses-breach-management", "Classification, playbooks, chain of custody, notice deadlines",
     "arcampe/incident.py arcampe/platform/procedures.py", "tests/test_solutions.py", "built",
     "1-hour CMS reporting clock from the ARC-AMPE IR-06 parameter"),
    ("integration-solutions", "Connectors, API and no-code methods, event intake, lineage",
     "arcampe/integrations/sdk.py arcampe/integrations/openapi.py arcampe/integrations/webhooks.py",
     "tests/test_integrations.py", "partial", "24 fixture connectors, no live API calls"),
    ("internal-audit-financial-controls", "COSO-tagged controls, sampling, self-assessment, KCIs",
     "arcampe/internal_audit.py", "tests/test_solutions.py", "partial", "5 COSO components, 8 synthetic controls"),
    ("privacy-data-protections", "Processing inventory, DPIA, rights requests, consent, SSN handling",
     "arcampe/privacy.py arcampe/redact.py", "tests/test_privacy.py", "built", "U.S. Medicaid/marketplace focus"),
    ("regulatory-changes-management", "Change feed, impact on mapped controls, review tasks",
     "arcampe/regchange.py", "tests/test_solutions.py", "partial", "3 synthetic changes; no live feed"),
    ("resiliency-business-continuity", "BIA, backup coverage, exercises, dependency concentration",
     "arcampe/resilience.py arcampe/platform/backup.py", "tests/test_platform.py", "built",
     "RPO under 24h cannot be proven from day-level data and is reported as unproven"),
    ("risk-management-audit", "IT risk register, scoring, treatment, vulnerability link",
     "arcampe/risk/cyber.py arcampe/challenges/business_context.py", "tests/test_risk.py", "built",
     "FAIR-style Monte Carlo with synthetic inputs"),
    ("risk-management-cyberrisk", "Custom cyber risk modules defined in YAML",
     "arcampe/risk/builder.py data/risk/modules/cyber.yaml", "tests/test_risk.py", "built", "one module shipped"),
    ("ai-governance-risks", "AI inventory, AI risk checks, AI control mapping",
     "arcampe/risk/ai_governance.py arcampe/agent.py", "tests/test_risk.py", "partial",
     "5 checks against NIST AI RMF functions"),
    ("security", "Encryption, RBAC, audit logs, secure AI processing, shared responsibility, attestations",
     "arcampe/platform/trust.py arcampe/platform/responsibility.py arcampe/platform/attestation_map.py",
     "tests/test_platform.py", "built", "self-assessment only; no certification is claimed"),
    ("third-party-vendor-risk", "Vendor tiering, questionnaires, scoring, contract flow-down",
     "arcampe/supply_chain.py arcampe/challenges/third_party.py", "tests/test_supply_chain.py", "built",
     "6 fictional vendors"),
]


def counts() -> dict[str, int]:
    out: dict[str, int] = {}
    for a in AREAS:
        out[a[4]] = out.get(a[4], 0) + 1
    return out


def to_markdown() -> str:
    lines = ["| Area | Capability | Where in this repo | Test | Status | Note |",
             "|---|---|---|---|---|---|"]
    for slug, cap, mods, test, status, note in AREAS:
        where = "<br>".join(f"`{m}`" for m in mods.split())
        lines.append(f"| {slug} | {cap} | {where} | `{test}` | {status} | {note} |")
    c = counts()
    lines += ["", (f"Areas: {len(AREAS)} (built {c.get('built', 0)}, partial {c.get('partial', 0)}, "
                   f"gap {c.get('gap', 0)})")]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(to_markdown(), end="")
