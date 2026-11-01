# Purpose

## The problem
A state-based exchange or Medicaid eligibility vendor (an "Administering Entity", AE) must protect
consumer data under CMS ARC-AMPE. ARC-AMPE is built on NIST SP 800-53 Rev 5. Each year teams rebuild
the same evidence by hand: screenshots, spreadsheets, signed forms, a POA&M and a large SSPP workbook.

## The approach
Treat each control as code where possible and as a dated signature where not.

| Label | Count | What happens |
|---|---:|---|
| automated | 65 | A check decides pass/fail from machine data |
| hybrid | 207 | A check gathers evidence; a person decides |
| attestation | 130 | A named owner signs; the repo tracks when it goes stale |

## Who it is for
- ISSOs and compliance leads at exchanges and their vendors.
- Platform engineers who own the Azure estate.
- Assessors who want a binder they can verify.
- Hiring managers looking for GRC engineering skills.

## Out of scope
- Real ATO decisions, legal advice, or any certification.
- Live connections to real systems.
