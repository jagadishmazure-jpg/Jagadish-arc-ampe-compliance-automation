# 12. Results

**What you'll learn:** the measured numbers, all from the synthetic data.

**Read this after:** [11_HOW_TO_RUN](11_HOW_TO_RUN.md)

<!-- run: python -m arcampe.grc workspaces --out out -->
```text
| Unit | Lead | Controls | Tested | Passing | Failing | Readiness | Active exceptions |
|---|---|---:|---:|---:|---:|---:|---:|
| Marketplace Platform | platform-director | 193 | 60 | 14 | 46 | 23.3% | 1 |
| Consumer Services | consumer-services-director | 44 | 29 | 16 | 13 | 55.2% | 1 |
| Infrastructure and Facilities | it-ops-manager | 67 | 52 | 40 | 12 | 76.9% | 0 |
| Program Office | ciso | 98 | 59 | 45 | 14 | 76.3% | 1 |
```
<!-- /run -->

<!-- run: python -m arcampe.grc soc2 --out out -->
```text
3 of 36 SOC 2 requirements checked
 - A1.1 Capacity is planned and monitored: fix test linked controls
 - CC1.3 Structures, reporting lines and authority are set: fix PM-02
 - CC2.1 Quality information supports internal control: fix test linked controls
 - CC2.3 The company communicates with outside parties: fix test linked controls
 - CC3.3 Fraud risk is considered: fix test linked controls
```
<!-- /run -->

<!-- run: python -m arcampe.grc ai-policy --out out -->
```text
AI-DEV-EVAL: 2/4 parts ready
  evidence: Ready (2 of 2 evidence items; owner ml-lead)
  monitoring: Not ready (failing: ['safety_metric_at_1_0']; owner ml-ops)
  policy: Ready (policy approved 284 days ago; owner ai-governance-lead)
  approval: Not ready (waiting for a human approver; owner ciso)
```
<!-- /run -->

Headline numbers (synthetic, measured): 200 of 402 controls tested, 115 pass; 103 open POA&M items, 22 overdue;
evidence 84.3% fresh; access review 97.9% complete with 9 issues; replay audit 24 of 25 reproduced; identity
recovery measured 11.5h against an 8h target.

---

**Next:** [13_LIMITATIONS](13_LIMITATIONS.md)
