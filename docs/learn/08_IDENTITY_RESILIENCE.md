# 08. Identity resilience

**What you'll learn:** why identity (AD and Entra) is the first thing to restore, and how the repo proves it with evidence for CP-4, CP-9 and CP-10.

**Read this after:** [07_AI_GOVERNANCE](07_AI_GOVERNANCE.md)

If the directory is down, nobody can sign in to restore anything else. So `resilience.py` lists
**Identity (AD forest + Entra tenant)** as the first dependency of every business-critical service.

Evidence types: `identity_backup_job` (CP-09) and `identity_restore_drill` (CP-04, CP-10). Checks cover backup age,
immutability, isolation, Entra object coverage, drill age, measured recovery time against the 8-hour target,
the krbtgt double reset, and restoring AD before Entra sync.

<!-- run: python -m arcampe.grc identity --out out -->
```text
IDR-BK-ad_forest CP-09 PASS ad_forest: hours since good backup = 24
IDR-IMM-ad_forest CP-09 PASS ad_forest: immutable = [True]
IDR-ISO-ad_forest CP-09 PASS ad_forest: isolated = [True]
IDR-BK-entra_tenant CP-09 PASS entra_tenant: hours since good backup = 24
IDR-IMM-entra_tenant CP-09 PASS entra_tenant: immutable = [True]
IDR-ISO-entra_tenant CP-09 FAIL entra_tenant: isolated = [False]
IDR-ENTRA-COVER CP-09 FAIL Entra object types not backed up: ['custom_roles', 'pim_assignments']
IDR-DRILL-365 CP-04 PASS days since clean-room drill = 172
IDR-RTO CP-10 FAIL measured 11.5h vs RTO 8h
IDR-KRBTGT CP-10 PASS krbtgt reset twice in the last clean-room drill
IDR-ORDER CP-10 PASS AD restored before Entra sync re-enabled
{"measured_rto_hours": 11.5, "target_rto_hours": 8, "rto_met": false, "days_since_drill": 172, "backup_age_hours": 24, "entra_object_coverage_pct": 75.0, "checks_passed": 8, "checks": 11}
```
<!-- /run -->

The measured drill took 11.5 hours against an 8-hour target, so CP-10 has an open gap. Vendor claims about
faster recovery are not used anywhere.

---

**Next:** [09_EXECUTIVE_REPORTING](09_EXECUTIVE_REPORTING.md)
