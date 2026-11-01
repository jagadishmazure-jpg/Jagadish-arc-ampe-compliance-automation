# ADR 0002: Azure Policy JSON is the single source for Terraform and Bicep

**Status:** accepted

**Context.** Python checks, Terraform and Bicep can drift.

**Decision.** `scripts/make_policies.py` writes policy JSON; Terraform reads it with `for_each`, Bicep with `loadJsonContent`; `iac.parity()` compares hits with Python check failures.

**Consequences.** One edit updates all three. Parity is tested (6 of 6). Effect defaults to Audit.
