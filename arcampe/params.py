"""Organization-defined values that ARC-AMPE sets for an ACA Administering Entity.

Each value was read from the public CMS workbook (ARC-AMPE Vol II SSPP, ACA AE v1.02, sheet
"AE Mandatory Baseline") and is restated here as a number, with the control it comes from.
Check them against the workbook version you are assessed on before you rely on them.
"""
from __future__ import annotations

US_REGIONS = frozenset({
    "eastus", "eastus2", "centralus", "northcentralus", "southcentralus", "westcentralus",
    "westus", "westus2", "westus3", "usgovvirginia", "usgovarizona", "usgovtexas",
})

PARAMS: dict[str, dict] = {
    "AC-02(03)": {"disable_within_hours": 24, "inactive_days": 60},
    "AC-07": {"max_attempts": 5, "window_minutes": 15, "lockout_minutes": 30},
    "AC-11": {"device_lock_minutes": 15},
    "AU-06": {"review_every_days": 7},
    "AU-11": {"online_days": 90, "archive_years": 10},
    "AT-02": {"training_every_days": 365},
    "CA-07": {"scan_every_days": 30},
    "CA-08": {"pentest_every_days": 365},
    "CP-04": {"cp_test_every_days": 365},
    "CP-09": {"incremental": "daily", "full": "weekly", "generations": 3},
    "IR-06": {"report_within_hours": 1},
    "PS-04": {"disable_same_day": True},
    "PT-05": {"notice_review_every_days": 365},
    "RA-05": {"scan_every_days": 30},
    "SA-09(05)": {"pii_locations": "continental U.S., Hawaii or U.S. territories", "offshore_notice_days": 60},
    "SI-02": {"critical_days": 15, "high_days": 30, "moderate_days": 90, "low_days": 365},
}

# Remediation clock for POA&M items, from the SI-02 flaw-remediation timeframes.
SLA_DAYS = {"critical": 15, "high": 30, "moderate": 90, "low": 365}
