# Use cases: Jagadish-arc-ampe-compliance-automation

**What this file covers:** who this repo is for, what you can do with it, how to try each part offline, and when not to use it.
Everything here runs offline on synthetic or simulated data for fictional companies. No real systems are touched.

## Who it is for

| Reader | What they get |
|---|---|
| ISSO / compliance lead at a state exchange or Medicaid E&E vendor | A control-by-control plan of what can be automated and what must stay a signature |
| Cloud / platform engineer | Python checks plus the same rules as Azure Policy in Terraform and Bicep |
| Assessor | A binder with a SHA-256 manifest, evidence lineage and a POA&M that is rebuilt from findings |
| Recruiter / hiring manager | Evidence of GRC engineering, Azure, IaC, test discipline and safe AI use |

## What you can do with it

Each step below is built and covered by tests in `tests/`:

1. **Catalog.** `arcampe/catalog.py` loads the 402-control AE baseline. Each control gets one label.
2. **Evidence.** Connectors read JSON fixtures, hash each record and record where it came from.
3. **Checks.** 30 Azure checks, 13 identity/evidence checks, attestation clocks, privacy and vendor checks.
4. **POA&M.** Every failing finding becomes an item with a due date from CMS SLA days (15/30/90/365).
5. **Statements.** An AI drafter (deterministic stub offline) writes a draft; only a human ISSO can approve.
6. **Outputs.** SSPP workbook, CONMON Markdown/HTML and a zip binder whose manifest can be re-verified.

## Try it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
python -m arcampe all --out out        # SSPP, POA&M, CONMON, binder and the rest into ./out
python -m arcampe.grc all --out out    # GRC extension, reports (previews only) and dashboard
python scripts/render_docs.py --check  # docs still match a fresh run
```

The suite has 2174 tests (measured: collected by pytest and checked against the README in CI).

## When not to use it

- The DEE baseline (308 controls) comes from a third-party parse and is not verified against CMS.
- FedRAMP Moderate is approximated by NIST SP 800-53B Moderate, not the FedRAMP baseline.
- Crosswalks to HIPAA, SOC 2, ISO 27001, PCI DSS, GDPR, CCPA and COBIT are author-built.

Full list: [README, Limitations](README.md#limitations).
