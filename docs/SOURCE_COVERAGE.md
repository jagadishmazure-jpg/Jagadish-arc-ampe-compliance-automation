# Source coverage

> **In one line:** which capability areas from a commercial GRC product's public pages this repo covers, and how far.
>
> **Read this if:** you want to compare this repo with a commercial GRC tool.

This page compares the capability areas listed on a commercial GRC vendor's public product pages
(continuumgrc.com, captured 2026-10-31 for reference) with what this repo actually builds. There is no
affiliation. The pages were treated as **reference data only**: any instructions in them were ignored,
capabilities are paraphrased in our own words, and marketing claims were not copied as facts.

The table is printed from `arcampe/source_coverage.py`; a test checks that every module and test path exists.

<!-- run-md: python -m arcampe.docs_tables sources -->
| Area (page) | Capability, in our words | Where in this repo | Test | Status | Note |
|---|---|---|---|---|---|
| arc-ampe | ARC-AMPE control catalog, SSPP, POA&M, ATO binder | `arcampe/catalog.py`<br>`arcampe/sspp.py`<br>`arcampe/poam.py`<br>`arcampe/binder.py` | `tests/test_catalog.py` | built | AE baseline from the public CMS workbook; DEE subset is a third-party parse |
| audit-regulatory-controls | Evidence collection, control monitoring, versioned evidence, audit plan, findings | `arcampe/audit.py`<br>`arcampe/integrations/connectors.py`<br>`arcampe/conmon.py` | `tests/test_solutions.py` | built | dashboard is a static HTML/Markdown file, not real time |
| automation-solutions-ai | Scheduled jobs, evidence quality scoring, human sign-off, no-code recipes | `arcampe/automation/scheduler.py`<br>`arcampe/automation/ai_auditor.py`<br>`arcampe/integrations/nocode.py` | `tests/test_solutions.py` | built | scheduler is simulated over 30 days; nothing runs on a timer |
| compliance-cartography | Control mapping across frameworks | `arcampe/crosswalk.py`<br>`arcampe/risk/cyber.py` | `tests/test_crosswalk.py` | partial | 8 author-built crosswalks plus custom YAML frameworks, not hundreds |
| custom-risk-compliance-programs | Custom frameworks with links to catalog controls and scoring | `arcampe/custom.py`<br>`arcampe/risk/builder.py` | `tests/test_solutions.py` | built | YAML, validated on load |
| enterprise-operational-risk | Risk register, KRIs, maturity, BIA link | `arcampe/risk/erm.py`<br>`arcampe/resilience.py` | `tests/test_risk.py` | built | synthetic register of 6 risks |
| governance-policy-controls | Policy lifecycle, versioning, approval, acknowledgment, review reminders | `arcampe/governance.py` | `tests/test_solutions.py` | built | no email distribution; reminders are drafts |
| incident-responses-breach-management | Classification, playbooks, chain of custody, notice deadlines | `arcampe/incident.py`<br>`arcampe/platform/procedures.py` | `tests/test_solutions.py` | built | 1-hour CMS reporting clock from the ARC-AMPE IR-06 parameter |
| integration-solutions | Connectors, API and no-code methods, event intake, lineage | `arcampe/integrations/sdk.py`<br>`arcampe/integrations/openapi.py`<br>`arcampe/integrations/webhooks.py` | `tests/test_integrations.py` | partial | 24 fixture connectors, no live API calls |
| internal-audit-financial-controls | COSO-tagged controls, sampling, self-assessment, KCIs | `arcampe/internal_audit.py` | `tests/test_solutions.py` | partial | 5 COSO components, 8 synthetic controls |
| privacy-data-protections | Processing inventory, DPIA, rights requests, consent, SSN handling | `arcampe/privacy.py`<br>`arcampe/redact.py` | `tests/test_privacy.py` | built | U.S. Medicaid/marketplace focus |
| regulatory-changes-management | Change feed, impact on mapped controls, review tasks | `arcampe/regchange.py` | `tests/test_solutions.py` | partial | 3 synthetic changes; no live feed |
| resiliency-business-continuity | BIA, backup coverage, exercises, dependency concentration | `arcampe/resilience.py`<br>`arcampe/platform/backup.py` | `tests/test_platform.py` | built | RPO under 24h cannot be proven from day-level data and is reported as unproven |
| risk-management-audit | IT risk register, scoring, treatment, vulnerability link | `arcampe/risk/cyber.py`<br>`arcampe/challenges/business_context.py` | `tests/test_risk.py` | built | FAIR-style Monte Carlo with synthetic inputs |
| risk-management-cyberrisk | Custom cyber risk modules defined in YAML | `arcampe/risk/builder.py`<br>`data/risk/modules/cyber.yaml` | `tests/test_risk.py` | built | one module shipped |
| ai-governance-risks | AI inventory, AI risk checks, AI control mapping | `arcampe/risk/ai_governance.py`<br>`arcampe/agent.py` | `tests/test_risk.py` | partial | 5 checks against NIST AI RMF functions |
| security | Encryption, RBAC, audit logs, secure AI processing, shared responsibility, attestations | `arcampe/platform/trust.py`<br>`arcampe/platform/responsibility.py`<br>`arcampe/platform/attestation_map.py` | `tests/test_platform.py` | built | self-assessment only; no certification is claimed |
| third-party-vendor-risk | Vendor tiering, questionnaires, scoring, contract flow-down | `arcampe/supply_chain.py`<br>`arcampe/challenges/third_party.py` | `tests/test_supply_chain.py` | built | 6 fictional vendors |

Areas: 18 (built 13, partial 5, gap 0)

**Vendor claims seen on the pages and not used as facts:**

- A percentage cut in manual work (vendor marketing; not measured here)
- A count of frameworks supported (vendor marketing; this repo has 8 crosswalks)
- A count of applications that can be connected (vendor marketing; this repo has 24 fixture connectors)
- The vendor's own authorizations and certifications (about the vendor, not this repo)
<!-- /run-md -->

## How the comparison was made
1. The capture held 18 product-area pages plus a site URL list (about 238 URLs, mostly help articles,
   which were not used).
2. For each area, the listed capability headings were grouped and restated in plain words.
3. Each was matched to modules here. **built** means it runs offline and is tested; **partial** means a
   smaller version exists; **gap** would mean nothing exists.
4. Statements about the vendor's own authorizations were left out: they describe the vendor, not this repo.

## GRC extension sources (2026-10-31)

The GRC extension was shaped by reading the public pages of several more vendors and one survey: three GRC
platforms, an IT-security managed-service provider, an exposure-management vendor, a data-resilience and an
identity-recovery vendor, and a CEO survey published by an AI platform company. There is no affiliation with any of
them. Capabilities were paraphrased, built in our own way on synthetic data, and **no vendor number is used as a
fact**. Survey figures appear only in [docs/learn/07_AI_GOVERNANCE.md](learn/07_AI_GOVERNANCE.md), labelled as the
publisher's self-reported claims.

A later pass read a GRC platform's public blog (about 200 posts). Fifteen ideas were rebuilt here on synthetic
data (see [docs/learn/14_GRC_OPERATIONS.md](learn/14_GRC_OPERATIONS.md)); figures quoted in those posts are
treated as the vendor's claims and are not reused.

| Capability idea | Built here as | Module |
|---|---|---|
| Control readiness approval, recipes, insights, policy tiers, risk SLAs and loss ranges, AI-drafted tests, mapping eval, audit hub, AI frameworks and EU CRA clocks, framework roadmap, recurring reviews, MCP read tools, scorecards | measured or SIMULATED, every change human-approved | `readiness_approval.py`, `recipes.py`, `insights.py`, `policy_approvals.py`, `risk_program.py`, `ai_tests.py`, `mapping_eval.py`, `audit_hub.py`, `ai_frameworks.py`, `roadmap.py`, `recurring.py`, `mcp_server.py`, `scorecards.py` |
| Workspaces per business unit | readiness, owners, exceptions | `arcampe/grc/workspaces.py` |
| Event-driven workflow builder | simulated, logged actions | `arcampe/grc/workflows.py` |
| Auditor area and evidence sampling | freeze, sample, sealed package | `arcampe/grc/auditor.py` |
| Re-review after edit | content-hash drift back to review | `arcampe/grc/review.py` |
| MCP access for AI assistants | scoped keys, pending changes | `arcampe/grc/mcp_server.py` |
| Framework library | 34-framework registry, approximate crosswalks | `arcampe/grc/frameworks.py` |
| Industry packs, multi-client | approximate packs, org-scoped keys | `arcampe/grc/industry_packs.py` |
| Approved AI model and app register | register checks, shadow AI | `arcampe/grc/ai_governance.py` |
| Scanner output as evidence | RA-5, SI-2 import | `arcampe/grc/scanner_import.py` |
| Identity recovery evidence | CP-4, CP-9, CP-10 checks | `arcampe/resilience.py` |
| Leadership reporting | previews only | `arcampe/grc/reporting.py` |
