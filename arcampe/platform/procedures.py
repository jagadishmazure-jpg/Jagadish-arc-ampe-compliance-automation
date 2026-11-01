"""Change management and incident response procedures as data, plus validators and a doc request pack.

Keeping the procedure as data means the same steps drive the docs, the checks and the workflow engine.
"""
from __future__ import annotations

import datetime as dt

CHANGE_PROCEDURE = [  # (step, owner, evidence required) - CM-03, CM-04, CM-05
    ("Request: describe the change, systems and data touched", "requester", "ticket"),
    ("Security impact analysis", "isso", "impact_analysis"),
    ("Peer review of code or config", "engineer (not the author)", "approved_pr"),
    ("Test in non-production", "engineer", "test_evidence"),
    ("Change advisory approval", "change board", "approval"),
    ("Deploy through pipeline only", "pipeline", "deployment_log"),
    ("Verify and close; update baseline and SSPP if needed", "requester", "closure_note"),
]
EMERGENCY_RULE = "Emergency changes may deploy first but need review and approval within 2 business days."

IR_PROCEDURE = [  # (phase, target, action) - IR-04, IR-06, IR-08
    ("Detect and log", "at once", "Create incident with time detected, reporter and systems"),
    ("Classify", "15 minutes", "Severity and whether PII is involved"),
    ("Report to CMS", f"{1} hour", "PII incidents to CMS within one hour of discovery (IR-06, ARC-AMPE)"),
    ("Contain", "4 hours", "Isolate hosts, revoke tokens, block indicators"),
    ("Preserve evidence", "with containment", "Chain of custody: hash every artifact, log every handler"),
    ("Eradicate and recover", "per plan", "Remove cause, restore from tested backups"),
    ("Notify individuals", "per law", "Breach notices where required"),
    ("Post-incident review", "14 days", "Root cause, lessons, POA&M items, update playbooks"),
]


def validate_change(ch: dict) -> list[str]:
    missing = [ev for _, _, ev in CHANGE_PROCEDURE if not ch.get(ev)]
    if ch.get("emergency") and ch.get("approval_date") and ch.get("deploy_date"):
        late = (dt.date.fromisoformat(ch["approval_date"]) - dt.date.fromisoformat(ch["deploy_date"])).days > 2
        if late:
            missing.append("late emergency approval")
    if ch.get("approved_pr") and ch.get("author") and ch.get("reviewer") == ch.get("author"):
        missing.append("self-review")
    return missing


def doc_request_pack(entity: str, system: str) -> dict[str, str]:
    """Templates a customer's security team usually asks for. Filled-in placeholders, not claims."""
    white = f"""# Security whitepaper (template)

System: {system}
Prepared for: {entity}
Status: TEMPLATE - fill in and have your security lead approve before sharing.

## 1. Overview
What the platform does, who uses it and what data it holds.

## 2. Security model
- Tenant isolation: per-tenant encryption keys and scoped queries (see docs/SECURITY_AND_TRUST.md).
- Identity: Entra ID single sign-on, phishing-resistant MFA for privileged actions.
- Audit: hash-chained audit trail.

## 3. Data protection
Encryption in transit (TLS 1.2+), at rest (AES-256-GCM, customer keys optional), U.S.-only residency.

## 4. AI processing
Runs in Microsoft Foundry over a private endpoint. Customer evidence is not used to train models.
PII is redacted before any prompt. Humans approve every AI draft.

## 5. Assurance
List independent assessments with dates. Do not list a certification you do not hold.

## 6. Contacts
Security contact, incident hotline, vulnerability disclosure address.
"""
    arch = f"""# Architecture overview (template)

System: {system}

1. Data flow diagram (connectors -> evidence store -> checks -> POA&M / SSPP / binder).
2. Trust boundaries (customer tenant, platform, Azure, Microsoft Foundry private endpoint).
3. Network: private endpoints, no public data-plane access, WAF in prevention mode.
4. Regions: U.S. only. List each region used.
5. Sub-processors and what each one can see.
6. Shared responsibility matrix (docs/shared_responsibility.csv).
"""
    questionnaire = """# Security documentation request checklist

- [ ] Security whitepaper
- [ ] Architecture overview and data flow diagram
- [ ] Shared responsibility matrix
- [ ] Latest pen test summary letter (not full report)
- [ ] Vulnerability scan summary (last 30 days)
- [ ] Incident response and change management procedures
- [ ] Business continuity and restore-test results
- [ ] Sub-processor list
- [ ] Self-assessment readiness map (clearly labelled self-assessment)
"""
    return {"whitepaper_template.md": white, "architecture_overview_template.md": arch,
            "request_checklist.md": questionnaire}
