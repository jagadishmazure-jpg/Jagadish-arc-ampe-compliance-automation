# Interview points

> **In one line:** short answers to the questions a reviewer or interviewer is likely to ask.
>
> **Read this if:** you are preparing to explain this work out loud.

| Topic | 30-second answer |
|---|---|
| Why three labels? | Not every control can be automated. Saying "65 automated, 207 hybrid, 130 attestation" is honest and tells the team where people are still needed. |
| How do you avoid over-claiming automation? | "Automated" is computed from the check registry and a test fails if an automated control has no check. |
| How do Python checks and Azure Policy stay in sync? | Policy JSON is generated from one script; an offline evaluator runs the JSON against the same estate; parity is 6 of 6. |
| How does the AI stay safe? | Agents can only read and draft. A human approver with the right role, who is not the drafter, must add a note. Notes are screened and redacted first. |
| How do you prove the binder is untampered? | SHA-256 manifest of every file, fixed zip timestamps, reproducible bytes, `verify()` lists any changed file. |
| What is the hardest honesty call? | RPO: day-level backup dates cannot prove a sub-day RPO, so it is reported as unproven, not met. |
| Why is P50 loss $0? | Losses happen in a minority of simulated years; the median year has none. Mean and P90 carry the risk. |
| What would you do next? | Real connectors, a Foundry backend with an eval set, and DEE baseline verification. |
| What did the tests catch? | An injection pattern that missed "reveal your system prompt", internal-audit controls covering only 2 of 5 COSO components, and a backup check reading the wrong fixture. |
