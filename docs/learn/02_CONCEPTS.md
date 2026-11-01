# 02. Concepts

**What you'll learn:** the handful of terms you need: control, evidence, finding, POA&M, readiness, crosswalk and approval.

**Read this after:** [01_THE_PROBLEM](01_THE_PROBLEM.md)

| Term | Plain meaning in this repo |
|---|---|
| **Control** | A rule from the baseline, such as AC-02 "manage accounts". 402 in the AE baseline. |
| **Label** | How a control is proven: *automated* (machine check), *hybrid* (check plus a person) or *attestation* (a signed statement). |
| **Evidence** | A record with a kind, a date, attributes and a SHA-256 hash, so tampering is detectable. |
| **Finding** | The result of one check on one resource: pass or fail, with severity. |
| **POA&M** | Plan of Action and Milestones: one item per failure with an owner, a due date and an SLA status. |
| **Readiness** | Tested-pass controls divided by mapped controls. Untested controls count as **not ready**. |
| **Crosswalk** | A mapping from our controls to another framework. Most are marked **approximate**. |
| **Freshness** | Evidence is Ready, Upcoming (renewal in 15 days), Needs Renewal (stale) or Error. |
| **Audit mode** | A freeze: while it is on, evidence cannot be written or deleted. |
| **Human approval** | No agent can approve its own work or change a control's status. A named person with the right role must. |
| **AI decision record** | Evidence of one AI decision: input, model and version, guardrails, citations, approver and outcome. |
| **Autonomy level** | suggest-only, act-with-approval or act-then-notify. Every agent here is suggest-only except the evidence mapper (act-with-approval). |

The three labels come from [ADR 0001](../adr/0001-three-labels.md). Human approval for AI comes from
[ADR 0003](../adr/0003-human-approval-for-ai.md).

---

**Next:** [03_ARCHITECTURE](03_ARCHITECTURE.md)
