# ADR 0003: AI drafts need human approval; offline stub in CI

> An ADR (architecture decision record) explains one design choice: the problem, what was decided and what it costs.

**Status:** accepted

**Context.** Statements in an SSPP are signed claims. A model can be wrong or manipulated.

**Decision.** The drafter only drafts. Approval needs a human approver role, a different person from the drafter, and a note. CI uses a deterministic stub; a Microsoft Foundry backend is planned behind the same interface.

**Consequences.** Only 12 of 402 statements are approved today, which lowers the readiness score honestly.
