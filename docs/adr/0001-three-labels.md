# ADR 0001: Label every control automated, hybrid or attestation

**Status:** accepted

**Context.** Teams over-claim automation. Assessors need to know which evidence is machine-made.

**Decision.** Three labels. "Automated" is computed from tested checks; the rest follow a rule set in `labels.py`.

**Consequences.** Counts change only when checks change. The hybrid/attestation split is a judgement and is documented as such.
