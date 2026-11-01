# Guardrails

| Risk | Guardrail | Where | Test |
|---|---|---|---|
| AI writes something wrong into the SSPP | Only approved drafts reach the SSPP; approver must be a human in an approver role, not the drafter, with a note | `agent.py`, `sspp.py` | `tests/test_agent.py` |
| Prompt injection via owner notes | Pattern screen blocks the draft | `agent.screen` | `test_injection_blocked` |
| PII sent to a model | Redaction of SSN, phone, email, Medicaid ID before drafting | `redact.py`, `secure_ai.prepare_prompt` | `test_prompt_redacted_and_screened` |
| Data leaves the boundary | No network modules in the package; egress allow-list; connectors refuse live calls | `secure_ai.py`, `sdk.py` | `test_no_network_code` |
| Cross-tenant access | Per-tenant data keys; denied reads logged | `tenancy.py`, `crypto.py` | `test_tenant_isolation`, `test_crypto_cross_tenant` |
| Privilege misuse | RBAC; phishing-resistant MFA for privileged actions; agents limited to read and draft | `rbac.py` | `test_rbac` |
| Self-approval | Owners cannot approve own policy, validate own fix, or sign off own evidence | `governance.py`, `audit.py`, `ai_auditor.py` | `tests/test_solutions.py` |
| Accidental email | Reminders and SLA alerts are drafts | `attest.py`, `scheduler.py` | `test_reminders_are_drafts` |
| Accidental enforcement | Azure Policy effect defaults to Audit; no deploy workflow | `policies/`, `infra/` | `test_each_policy_maps_to_a_real_check` |
| Log tampering | Hash-chained audit log; truncation caught against a saved head | `audit_log.py` | `test_audit_chain_detects_tamper` |
| Stale docs | Every number block is re-run in CI | `scripts/render_docs.py` | `tests/test_scripts.py` |
