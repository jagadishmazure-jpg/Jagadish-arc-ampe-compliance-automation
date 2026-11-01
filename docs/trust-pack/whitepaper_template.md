# Security whitepaper (template)

System: Lakehaven eligibility and enrollment platform
Prepared for: Lakehaven Health Connector (fictional)
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
