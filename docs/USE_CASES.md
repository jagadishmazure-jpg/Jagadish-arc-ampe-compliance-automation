# Use cases, end to end

> **In one line:** seven real-world stories (first ATO, daily monitoring, yearly renewal, new vendor, privacy
> incident, regulatory change, auditor visit), each with who acts, what starts it, the exact commands, the real
> output and the result.
>
> **Read this if:** you want to see how a compliance team would actually use this repo day to day.

Everything below runs offline on the fictional Lakehaven Health Connector (`lakehaven-hx.example`). Every output
block is printed by `python -m arcampe.usecases <case>` and re-checked in CI, so the numbers cannot drift from the
code. This is a **self-assessment design**: nothing here is a CMS ATO, an Authority to Connect, a FedRAMP
authorization or any other certification. The "today" date in the data is 2026-10-31.

| # | Use case | Actor | Trigger | Main modules |
|---:|---|---|---|---|
| 1 | [First ATO package](#1-a-new-state-exchange-prepares-its-first-ato) | ISSO | New system needs authorization | catalog, assess, sspp, poam, binder |
| 2 | [Public storage caught and closed](#2-daily-monitoring-catches-a-public-storage-account) | Cloud platform team | Daily check run | checks, iac, poam |
| 3 | [Yearly renewal binder](#3-the-yearly-renewal-binder) | ISSO and control owners | Renewal date approaching | attest, conmon, binder |
| 4 | [New vendor onboarding](#4-onboarding-a-new-vendor-that-sees-pii) | Procurement lead | Contract request | supply_chain |
| 5 | [Privacy incident](#5-a-privacy-incident-with-the-1-hour-breach-clock) | Privacy officer | Misdirected mail reported | incident, privacy |
| 6 | [Regulatory change](#6-a-regulatory-change-hits-controls) | Compliance analyst | New or proposed rule | regchange, crosswalk |
| 7 | [Auditor with an AI copilot](#7-an-auditor-walkthrough-with-the-ai-copilot) | External assessor and ISSO | Audit fieldwork starts | audit, ai_auditor, agent, rbac |

How they connect:

```mermaid
flowchart LR
  A[1. First ATO] --> B[2. Daily monitoring]
  B --> C[3. Yearly renewal]
  D[4. New vendor] --> B
  E[5. Incident] --> B
  F[6. Regulatory change] --> A
  B --> G[7. Auditor visit]
  C --> G
```

---

## 1. A new state exchange prepares its first ATO

- **Actor:** the ISSO (Information System Security Officer) of a new state-based exchange.
- **Trigger:** the exchange must show CMS it meets the ARC-AMPE baseline before it can go live.
- **Goal:** a complete, honest package: every control labelled, every failure tracked, one verifiable binder.

```mermaid
flowchart TB
  L[Load AE baseline<br/>402 controls] --> R[Run every check<br/>531 findings]
  R --> S[SSPP workbook<br/>pass / fail / not tested]
  R --> P[POA&M<br/>one item per failure]
  S --> B[Binder zip + manifest]
  P --> B
  B --> I[ISSO reviews, then<br/>submits for assessment]
```

**Steps**

1. Load the baseline and its labels (`python -m arcampe catalog` prints the family table).
2. Run the first full assessment (`python -m arcampe assess`).
3. Build the SSPP workbook (`python -m arcampe sspp` writes `out/sspp.xlsx`).
4. Open POA&M items for every failure (`python -m arcampe poam` writes `out/poam.csv`).
5. Build and verify the binder (`python -m arcampe binder` writes `out/ato_binder.zip`).

<!-- run: python -m arcampe.usecases first_ato -->
```text
1. Load the AE baseline: 402 controls {'attestation': 130, 'automated': 65, 'hybrid': 207}
2. First full assessment: 531 findings, 428 pass, 103 fail
3. SSPP workbook status per control: {'fail': 84, 'not tested': 202, 'pass': 116}
4. POA&M opened automatically: 103 items {'critical': 2, 'high': 41, 'moderate': 59, 'low': 1}
5. Binder: 10 files, verify: intact
   same input, same bytes: True
```
<!-- /run -->

**Result:** in one run the ISSO knows exactly where the system stands: 116 controls pass, 84 fail and 202 are
"not tested" because they need a person (hybrid) or a signature (attestation). Nothing is hidden: "not tested" is
shown as its own status, never counted as a pass. The binder is reproducible, so the assessor can rebuild it and
get the same bytes.

---

## 2. Daily monitoring catches a public storage account

- **Actor:** the cloud platform team, with the ISSO watching the POA&M.
- **Trigger:** the daily check run (continuous monitoring) finds `stlhxstaticweb` reachable from the internet.
- **Goal:** detect it, track it with an owner and a due date, fix it, prove the fix, close the item.

```mermaid
flowchart LR
  D[Daily check run] --> F{AZ-01 public<br/>network access?}
  F -->|Enabled| P[POA&M item<br/>high, 30-day SLA<br/>owner cloud-platform]
  F -->|Azure Policy agrees| P
  P --> X[Fix: disable public access,<br/>add private endpoint]
  X --> T[Re-test]
  T -->|PASS| C[POA&M closed]
  T -->|FAIL| P
```

**Steps**

1. The scheduler runs the Azure checks every day (`python -m arcampe schedule` simulates 30 days).
2. Three checks fail on the same storage account; the Azure Policy rule `arcampe-storage-no-public-network`
   flags it as well, so two independent layers agree.
3. Each failure becomes a POA&M item with an owner and a due date from the SLA (high = 30 days).
4. The team turns public access off and adds a private endpoint.
5. The next run re-tests the fixed configuration; no failures means no open POA&M items.

<!-- run: python -m arcampe.usecases conmon_public_storage -->
```text
Day 1, daily check run, failures on stlhxstaticweb:
  AZ-01 high     publicNetworkAccess=Enabled  controls=['SC-07', 'AC-04']
  AZ-02 high     0 approved private endpoint(s)  controls=['SC-07(04)', 'SC-07(05)']
  AZ-22 moderate Azure Policy compliance state=False  controls=['CM-06', 'CM-02']
  Azure Policy (offline evaluation) flags it too: ['arcampe-storage-no-public-network']
  POA&M POAM-C6EF1944 AZ-02 high owner=cloud-platform due=2026-11-20 (on_track)
  POA&M POAM-C455623B AZ-01 high owner=cloud-platform due=2026-11-30 (on_track)
  POA&M POAM-F1F8E4C4 AZ-22 moderate owner=cloud-platform due=2026-10-21 (overdue)
After the fix (public access off, private endpoint added), re-test:
  AZ-01 PASS publicNetworkAccess=Disabled
  AZ-02 PASS 1 approved private endpoint(s)
  AZ-22 PASS Azure Policy compliance state=True
Open POA&M items for stlhxstaticweb after re-test: 0 -> closed
```
<!-- /run -->

**Result:** the item went from detected to closed with a full trail: which check, which controls (SC-07, AC-04),
who owned it, when it was due and the passing re-test. One fact worth noticing: AZ-22 was already overdue because
the policy non-compliance was first seen earlier, so the dashboard shows it in red even though AZ-01 is new.

---

## 3. The yearly renewal binder

- **Actor:** the ISSO, with every control owner who must sign an attestation.
- **Trigger:** the yearly authorization renewal is coming up. (An Administering Entity also needs an Authority to
  Connect, ATC, to link to CMS systems; this repo calls its package the "ATO binder".)
- **Goal:** fresh attestations, a current CONMON report and a binder whose integrity can be proven.

```mermaid
flowchart TB
  A[Attestation status<br/>current / due soon / overdue / missing] --> R[Reminder drafts<br/>to each owner]
  R --> S[Owners sign]
  S --> C[CONMON report<br/>pass / fail, POA&M, readiness]
  C --> B[Binder: SSPP, POA&M, CONMON,<br/>evidence, attestations, risk, trust]
  B --> M[manifest.json<br/>SHA-256 of every file]
```

**Steps**

1. Check attestation status (`python -m arcampe attest`). Reminders are drafts only; nothing is sent.
2. Produce the CONMON report (`python -m arcampe conmon` writes Markdown and HTML).
3. Build the binder and check the manifest (`python -m arcampe binder`).

<!-- run: python -m arcampe.usecases annual_renewal -->
```text
1. Attestations: {'current': 90, 'due_soon': 14, 'overdue': 16, 'missing': 10, 'total': 130}
2. Reminder drafts (not sent): 9, e.g. to=ciso subject='[ARC-AMPE] 11 attestation(s) need your signature'
3. CONMON: findings 428 pass / 103 fail; POA&M open 103 overdue 22 | readiness score 57.5
4. Binder contents:
   01_sspp/sspp.xlsx
   02_poam/poam.csv
   03_conmon/conmon.html
   03_conmon/conmon.md
   04_evidence/evidence.jsonl
   05_attestations/attestations.json
   06_risk/top10.md
   07_trust/self_assessment.json
   07_trust/shared_responsibility.csv
   manifest.json
5. Manifest entries: 9 | verify: intact
```
<!-- /run -->

**Result:** the renewal starts from facts, not a blank template: 26 attestations need work (16 overdue, 10
missing), 22 POA&M items are overdue, and the readiness score is 57.5. Those gaps are the to-do list before the
package goes out. The manifest lets anyone prove later that no file was changed after sign-off.

---

## 4. Onboarding a new vendor that sees PII

- **Actor:** the procurement lead, with the privacy officer.
- **Trigger:** a business team wants to hire Lumenfield Translation Services (fictional) to translate consumer
  notices, which means the vendor will see consumer PII.
- **Goal:** tier the vendor, find questionnaire and contract gaps, and only sign when the risk is acceptable.

```mermaid
flowchart LR
  Q[Questionnaire Q1-Q7] --> T[Tier from PII access<br/>and spend]
  T --> S[Risk score 0-100<br/>named factors]
  S --> F{SR findings}
  F -->|FAIL| N[Negotiate: 1-hour breach notice,<br/>45 CFR 155.260 flow-down,<br/>independent assessment]
  N --> S
  F -->|PASS| OK[Approve and add<br/>to monitoring]
```

**Steps**

1. Send the 7-question questionnaire and record the answers.
2. Score the vendor: the score is a sum of named factors, so anyone can see why it is high or low.
3. Run the SR findings (assessment age, U.S. data location, contract flow-down).
4. Fix the gaps in the contract, get an assessment, and re-score.

<!-- run: python -m arcampe.usecases new_vendor -->
```text
Vendor: Lumenfield Translation Services | PII: True | spend: $180,000 | tier: high
Questionnaire gaps: ['Q4 Will you notify us of a suspected breach within one hour?', 'Q5 Do you provide a software bill of materials (SBOM) for delivered software?', 'Q6 Do you flow down 45 CFR 155.260 privacy and security terms to subcontractors?']
Risk score (0-100): 46 moderate {'tier': 20, 'questionnaire_gaps': 16, 'assessment_stale': 10, 'open_issues': 0}
  SR-ASSESS SR-03     FAIL  Lumenfield Translation Services: last assessed None days ago
  SR-LOC    SA-09(05) PASS  Lumenfield Translation Services: data in US
  SR-FLOW   SR-03     FAIL  Lumenfield Translation Services: flow-down clause=False
After contract fixes and an assessment: 20 low {'tier': 20, 'questionnaire_gaps': 0, 'open_issues': 0}
```
<!-- /run -->

**Result:** the vendor started at 46 (moderate) with two failing SR findings. After the contract was fixed and an
assessment was done, the score fell to 20 (low); the remaining 20 points are the tier itself, because any vendor
with PII access stays "high" tier and keeps being monitored.

---

## 5. A privacy incident with the 1-hour breach clock

- **Actor:** the privacy officer, with the incident response team.
- **Trigger:** 820 renewal notices containing consumer PII were mailed to the wrong addresses.
- **Goal:** classify, follow the playbook, report to CMS inside 1 hour (the AE IR-06 parameter), and keep evidence
  that can be proven untouched.

```mermaid
sequenceDiagram
  participant M as Mailroom
  participant P as Privacy officer
  participant S as System
  participant C as CMS
  M->>P: 09:12 wrong addresses reported
  P->>S: log incident, 820 records, PII
  S-->>P: severity high, playbook, CMS due 10:12
  P->>C: 09:58 report sent (inside 1 hour)
  P->>S: add evidence files (hash chain)
  S-->>P: custody intact, any edit is detected
```

**Steps**

1. Log the incident with its detection time and whether PII is involved.
2. Classify it (500 or more PII records = high) and follow the matching playbook.
3. Watch the deadlines: CMS report within 1 hour, post-incident review within 14 days.
4. Add each piece of evidence to a hash chain so it can be proven unchanged.
5. Mask SSNs in any notes before they are shared (the output counts full SSNs; it never prints one).

<!-- run: python -m arcampe.usecases privacy_incident -->
```text
Severity: high
Playbook: ['retrieve or confirm destruction', 'log recipients', 'risk-of-harm assessment', 'report to CMS within 1 hour', 'notify individuals if required']
Deadlines: {'post_incident_review': '2026-11-12T09:12:00', 'cms_report': '2026-10-29T10:12:00'}
CMS report sent 09:58, met 1-hour clock: True
Post-incident review done yet: False
Chain of custody intact: True
After editing one artifact: False
Full SSNs left in the notes after masking: 0 (before: 1)
```
<!-- /run -->

**Result:** the CMS clock was met (sent at 09:58, due at 10:12), the review is still open and shows as not yet
met, and the evidence chain breaks the moment one byte changes. The incident then feeds daily monitoring as new
POA&M and lessons-learned work.

---

## 6. A regulatory change hits controls

- **Actor:** the compliance analyst.
- **Trigger:** a regulator proposes or finalizes a change (the feed here is synthetic: a shorter CMS reporting
  window, a fictional state data-rights act and an HHS Security Rule update).
- **Goal:** know within minutes which controls are affected and open review tasks for them.

```mermaid
flowchart LR
  R[Regulatory change] --> W{Which framework?}
  W -->|ARC-AMPE id| C[Controls directly]
  W -->|HIPAA / CCPA clause| X[Reverse crosswalk<br/>clause -> controls]
  X --> C
  C --> L[Count by label]
  L --> T[Review tasks:<br/>statement + checks]
```

**Steps**

1. Add the change to the feed (in production: a reviewed subscription read by an analyst, not blind scraping).
2. Map it to controls, directly or through the reverse crosswalk.
3. Count the affected controls by label: automated ones need a check update, attestation ones need a new signature.
4. Open review tasks for each affected control.

<!-- run: python -m arcampe.usecases reg_change -->
```text
RC-01 Shorter incident reporting window proposed: 1 controls {'automated': 1}
   first controls: ['IR-06']
   first task: Review IR-06 implementation statement and checks
RC-02 Lakehaven consumer data rights act: 10 controls {'attestation': 3, 'hybrid': 7}
   first controls: ['PT-01', 'PT-02', 'PT-03', 'PT-04', 'PT-04(03)', 'PT-05']
   first task: Review PT-01 implementation statement and checks
RC-03 Security Rule update: encryption and MFA expectations: 74 controls {'hybrid': 53, 'automated': 19, 'attestation': 2}
   first controls: ['AC-01', 'AC-02', 'AC-02(01)', 'AC-02(02)', 'AC-02(03)', 'AC-02(04)']
   first task: Review AC-01 implementation statement and checks
```
<!-- /run -->

**Result:** a one-control change (IR-06) is a quick parameter update; the HIPAA Security Rule update touches 74
controls, 53 of them hybrid, which tells the team it is mostly people work, not code work.

---

## 7. An auditor walkthrough with the AI copilot

- **Actor:** an external assessor, the ISSO and internal audit. The AI copilot helps but never decides.
- **Trigger:** audit fieldwork starts.
- **Goal:** spend audit days where failures are, let the copilot pre-sort evidence, and keep every decision human.

```mermaid
flowchart TB
  P[Audit plan ranked by<br/>failure rate] --> E[Copilot scores evidence:<br/>fresh, complete, intact,<br/>authoritative, relevant]
  E --> H{Human sign-off}
  H -->|agent| X1[Refused: agents<br/>cannot sign off]
  H -->|uploader| X2[Refused: separation<br/>of duties]
  H -->|other ISSO| OK[Accepted]
  OK --> D[Copilot drafts answers<br/>with citations]
  D --> F[Findings: owner fixes,<br/>someone else validates]
```

**Steps**

1. Rank control families by failure rate and plan 60 audit days (`python -m arcampe audit`).
2. The copilot scores all evidence records; low scores come with reasons.
3. A person signs off. Code refuses an agent, and refuses anyone signing off their own upload.
4. The copilot drafts control answers with citations to checks and parameters; a human approves them
   (see [AUDIT_AUTOMATION_EXPLAINED.md](AUDIT_AUTOMATION_EXPLAINED.md), step 10).
5. Audit findings move open -> remediating -> validated -> closed, and the owner cannot validate their own fix.

<!-- run: python -m arcampe.usecases auditor_copilot -->
```text
1. Risk-based audit plan (first 5 of 18 families, 60 days):
   AT Awareness and Training                   fail rate 0.857 -> 5 days (high)
   SI System and Information Integrity         fail rate 0.375 -> 5 days (high)
   CM Configuration Management                 fail rate 0.346 -> 5 days (high)
   SR Supply Chain Risk Management             fail rate 0.294 -> 3 days (medium)
   PS Personnel Security                       fail rate 0.273 -> 3 days (medium)
2. Copilot pre-scores 153 evidence records: 101 ready for sign-off, 52 need better evidence, 0 signed off by AI
   weakest: docs_library AC-01 score 0.33 reasons ['freshness', 'relevance']
3. Human sign-off rules:
   sign-off by agent:copilot on its own upload: refused - agent:copilot lacks signoff_evidence
   sign-off by Riley Quist on its own upload: refused - separation of duties: cannot approve own work
   sign-off by Riley Quist on evidence uploaded by a connector: accepted
4. Copilot drafts the AC-02 answer: draft | citations: ['AZ-12', 'catalog:AC-02']
5. Finding AF-01 validation by its owner: refused - owner cannot validate own fix
   validated by internal-audit, then: closed
```
<!-- /run -->

**Result:** the assessor starts with Awareness and Training (86% failing) instead of reading 402 controls in
order, the copilot flags 52 weak evidence records before anyone wastes time on them, and every accept, approval
and closure carries a human name.

---

## Run them yourself

```bash
pip install -r requirements-dev.txt
python -m arcampe.usecases            # all seven
python -m arcampe.usecases new_vendor # one case
pytest tests/test_usecases.py -q
```
