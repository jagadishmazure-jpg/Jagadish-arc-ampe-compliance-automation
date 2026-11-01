# Limitations and known gaps

> **In one line:** what is synthetic, unproven or simplified, and how each gap is kept visible.
>
> **Read this if:** you want the honest caveats before relying on any number.

| Limitation | Why it matters | Kept visible by |
|---|---|---|
| DEE baseline is a third-party parse | Do not rely on DEE counts | `docs/control-catalog.md` |
| FedRAMP is a proxy (800-53B Moderate) | Not the FedRAMP baseline or its parameters | `crosswalk.py` docstring |
| Crosswalks are author-built | Mappings are judgement calls | `docs/crosswalks.md` |
| Labels other than "automated" are a rule set | Another team could label differently | `labels.py` |
| FAIR inputs are synthetic | Dollar figures show method, not real exposure | `cyber.yaml` header |
| Mapper evaluated on 60 self-labelled items | Precision 0.983 / recall 0.95 is a regression check | `test_mapper_measured` |
| Detection rules written knowing the 5 scenarios | 5/5 with 0 false positives is not a detection-rate claim | `test_detection` |
| Connector shapes are simplified | Real APIs page, throttle and differ | `INTEGRATIONS.md` |
| Zero data retention is a config claim | Real Azure needs Microsoft approval for the opt-out | `SECURITY_AND_TRUST.md` |
| RPO under 24 h is unproven | Day-level backup dates cannot show sub-day RPO | `test_rpo_status_is_honest` |
| 2 of 4 backup targets meet daily/weekly/3-generation | Planted gap | `test_backup_schedule_from_fixtures` |
| Pen test record PT-2025-02 is a scan labelled as a pen test | Planted gap | `test_assurance` |
| Only 12 of 402 statements approved | Readiness is 57.5 | `test_readiness_measured` |
| Nothing deployed | Terraform/Bicep validated and unit-tested only | `infra.yml` |
| Dashboard is static | No real-time view | `conmon.py` |
