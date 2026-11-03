# 11. How to run

**What you'll learn:** the exact commands to install, test and produce every output offline.

**Read this after:** [10_USE_CASES](10_USE_CASES.md)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
python -m arcampe all --out out          # core: SSPP, POA&M, CONMON, binder
python -m arcampe.grc all --out out      # GRC extension, reports and dashboard
python -m arcampe.usecases leadership_report
```

Single GRC commands: `workspaces, workflows, custom-tests, risk, frameworks, audit-package, review, cac, mcp,
ai-policy, soc2, evidence, owners, vendors, access-review, ai-governance, identity, industry-packs, scanner,
report, dashboard, schedule`.

<!-- run: python scripts/count_tests.py -->
```text
2174 tests collected
```
<!-- /run -->

---

**Next:** [12_RESULTS](12_RESULTS.md)
