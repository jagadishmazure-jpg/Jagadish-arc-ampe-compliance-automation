# Glossary

> **In one line:** every acronym and term used in this repo, in one sentence each.
>
> **Read this if:** a word in another page is unfamiliar.

| Term | Meaning |
|---|---|
| AE | Administering Entity: a state exchange or agency that runs ACA eligibility and enrollment |
| ALE | Annualized loss expectancy: expected dollars lost per year from one risk |
| ARC-AMPE | CMS's security and privacy requirements for AEs, built on NIST SP 800-53 Rev 5 |
| Attestation | A dated statement signed by a control owner; goes stale after its cadence |
| ATO | Authority to Operate: the formal decision by an authorizing official that a system may run |
| Binder | The zip of SSPP, POA&M, CONMON, evidence and manifest handed to an assessor |
| CMS | Centers for Medicare & Medicaid Services |
| CONMON | Continuous monitoring: re-running checks and reporting on a schedule |
| Control | One requirement, e.g. IA-02 (identify and authenticate users) |
| Crosswalk | A map from one framework's control to another framework's clauses |
| DEE | Direct Enrollment Entity; its baseline here is an unverified third-party parse |
| Evidence record | One fact with source, time, attributes, control hints, SHA-256 hash and lineage |
| FAIR | Factor Analysis of Information Risk: a method to express risk in dollars |
| FedRAMP proxy | Here, "is the control in the NIST 800-53B Moderate baseline"; not the FedRAMP baseline itself |
| Hybrid | A control where a machine gathers evidence but a person must judge it |
| ISSO | Information System Security Officer: the person who approves SSPP statements here |
| Lineage | The list of processing steps an evidence record went through, each with input and output hashes |
| OSCAL | NIST's machine-readable format for control catalogs and baselines |
| P10 / P50 / P90 | 10th, 50th and 90th percentile of simulated yearly loss |
| Policy as code | A rule written as a file (Azure Policy JSON) so the cloud can audit or block it |
| POA&M | Plan of Action and Milestones: every open weakness with owner, due date and status |
| RPO / RTO | Recovery point / time objective: how much data and how much time you can afford to lose |
| SLA | Here, the days allowed to fix a weakness by severity (15 / 30 / 90 / 365) |
| SSPP | System Security and Privacy Plan: one implementation statement per control |
| STRIDE | Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege |
