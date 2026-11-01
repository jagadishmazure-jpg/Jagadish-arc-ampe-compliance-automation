# ADR 0004: Every generated artefact is deterministic

**Status:** accepted

**Context.** Evidence must be reproducible and CI must detect drift.

**Decision.** Seeded generators, a fixed "today" (2026-10-31), fixed zip timestamps, a pinned `dcterms:modified` in the SSPP.

**Consequences.** CI regenerates data and fails on any diff; the binder has identical bytes on every build.
