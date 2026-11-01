# Presentation guide

**What you'll learn:** how to present this repo in 5 or 15 minutes, what to show on screen, which commands to
run live, likely interview questions with short answers, and a one-page cheat card.

**Read this after:** [docs/learn/14_GRC_OPERATIONS.md](docs/learn/14_GRC_OPERATIONS.md)

Everything you show is synthetic and offline. Say so in the first minute.

## 5-minute script

| Time | Say | Show |
|---|---|---|
| 0:00-0:45 | "State health exchanges must prove 402 security controls to CMS every year, mostly with spreadsheets. I turned the baseline into code." | README top and the test count |
| 0:45-2:00 | "Every check is code, every piece of evidence has a date and a hash, and every failure becomes a tracked fix with an owner and a deadline." | `python -m arcampe.usecases conmon_public_storage` |
| 2:00-3:15 | "Leadership gets a daily and weekly email built from the same data. It only writes previews; sending needs a config, an approval flag and a transport the team adds." | `out/reports/weekly.html` in a browser, then `python -m arcampe.usecases leadership_report` (step 6, refused send) |
| 3:15-4:30 | "AI agents only propose. A person approves. Every AI decision is recorded and an auditor can replay it." | `python -m arcampe.usecases ai_accountability` |
| 4:30-5:00 | "What's synthetic: everything. What's approximate: 30 of 34 framework mappings and the industry packs. Next: live connectors and a Microsoft Foundry drafter." | [13_LIMITATIONS](docs/learn/13_LIMITATIONS.md) |

## 15-minute script

1. **Problem (2 min).** [01_THE_PROBLEM](docs/learn/01_THE_PROBLEM.md). Stale evidence, unowned gaps, many frameworks.
2. **Architecture (2 min).** The Mermaid diagram in [03_ARCHITECTURE](docs/learn/03_ARCHITECTURE.md). Core
   versus the `grc` extension; "no network code" rule.
3. **Live run (3 min).** `python -m pytest -q` (show the count), `python -m arcampe all --out out`,
   `python -m arcampe.grc all --out out`.
4. **Workflows (2 min).** `python -m arcampe.usecases control_drift_review` and `pr_gate_and_audit_package`.
5. **Frameworks (2 min).** Open `out/grc/dashboard.html`: rings per framework. Explain "tested-pass divided by
   mapped; untested counts as not ready". Then `python -m arcampe.usecases industry_packs_multi_org`.
6. **AI governance (2 min).** The 12 KPIs: `python -m arcampe.grc ai-governance --out out`. Point at replay
   (24/25), the deliberate decision-rights gap (AI-VENDOR) and the model register (3 of 7 uses in scope).
7. **Resilience and scanning (1 min).** `python -m arcampe.usecases identity_recovery` (11.5h vs 8h target) and
   `scanner_evidence`.
8. **Readiness sign-off and scorecards (1 min, optional swap for 7).** `python -m arcampe.usecases
   control_readiness_and_audit` then `leadership_scorecards`: named sign-off bound to evidence hashes; loss ranges
   instead of colors. See [14_GRC_OPERATIONS](docs/learn/14_GRC_OPERATIONS.md).
9. **Limits and next steps (1 min).**

## What to have open

- `README.md`, `docs/learn/00_START_HERE.md`
- `out/reports/weekly.html`, `out/reports/daily.pdf`, `out/grc/dashboard.html`
- A terminal in the repo with the virtual environment active

## Demo commands (copy and paste)

```bash
python -m pytest -q
python -m arcampe.grc all --out out
python -m arcampe.usecases leadership_report
python -m arcampe.usecases ai_accountability
python -m arcampe.usecases industry_packs_multi_org
python -m arcampe.usecases scanner_evidence
python -m arcampe.usecases control_readiness_and_audit
python -m arcampe.usecases leadership_scorecards
python -m arcampe.grc scorecards
python -m arcampe.grc report --out out --kind daily
```

## Interview questions and answers

| Question | Short answer |
|---|---|
| How do you know the numbers are real? | Every number in the docs is printed by a command and CI re-runs it (`render_docs.py --check`). |
| Why count untested controls as not ready? | Honest readiness. A control nobody tested is not evidence of anything. |
| Are the framework mappings official? | No. 30 of 34 and all industry packs are approximate, family-level, author-built; labelled as such. |
| What stops an AI agent from marking a control compliant? | Write tools only create pending changes; approval needs a human with the isso or ciso role, a note, and not the proposer. Tested. |
| How do you audit an AI decision? | Each decision is stored with its input, model and version, guardrails, citations and approver. An auditor samples 25 and re-runs them; one tampered record fails. |
| Could the report email someone by accident? | No transport ships with the repo; `send()` needs a config, an approval flag and a transport. |
| How do you stop one client seeing another's data? | Multi-org keys are scoped to one org; cross-org reads raise and are logged in a hash chain. |
| What would you do with a real scanner? | Map its export to the same import fields; scan age then drives evidence freshness and SI-2 SLA. |
| What is hard about identity recovery? | Restore AD before Entra, reset krbtgt twice, and prove it with a timed drill. Ours took 11.5h against 8h. |
| What is next? | Live connectors, a Microsoft Foundry drafter with an eval set, and verification of the DEE baseline. |
| Can an AI agent mark a control ready? | No. A named ISSO, CISO or control approver signs, and the sign-off is bound to the evidence hashes; if the evidence changes, it is void. |
| How do you show risk to the board? | Loss ranges (P50, P90, P95) from a FAIR-style simulation on synthetic inputs, with no red/amber/green, and a CRO-signed appetite. |
| Do AI-written tests go straight to production? | No. Validator with up to 3 retries, duplicate check, plain-English description, then an auditor or engineer approves. 85.7% acceptance on 7 synthetic reviews. |
| How good is the evidence mapper on hard inputs? | Measured: MRR 0.983 exact, 0.900 paraphrase, 0.883 partial, 0.400 keyword-only. Low confidence goes to a person. |

## One-page cheat card

- **What:** ARC-AMPE (402 controls) as code, plus a GRC extension. Fictional Lakehaven Health Connector.
- **Proof:** test count in README; 531 findings; 115 of 200 tested controls pass; replay 24/25; identity RTO 11.5h vs 8h.
- **Safety:** no network code; agents propose, humans approve; reports are previews; audit mode freezes evidence.
- **Honesty:** synthetic data; approximate crosswalks; SIMULATED ROI and trust-to-revenue labelled.
- **Frameworks:** 34 in the registry (native 1, proxy 1, approximate 30, custom 1, gap 1) plus 3 industry-pack frameworks.
- **Run:** `pip install -r requirements-dev.txt && python -m pytest -q && python -m arcampe.grc all --out out`.

---

**Next:** go back to [docs/learn/00_START_HERE.md](docs/learn/00_START_HERE.md) and pick the page your audience cares about.
