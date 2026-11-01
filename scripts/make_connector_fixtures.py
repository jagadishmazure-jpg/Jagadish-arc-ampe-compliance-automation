"""Generate offline fixture payloads for every connector (deterministic, all names made up).

Shapes are simplified versions of what each product's API returns. They are for tests and demos
only; real field names differ by product and API version. Run: python scripts/make_connector_fixtures.py
"""
from __future__ import annotations

import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "fixtures" / "connectors"
AS_OF = "2026-10-31"


def day(n: int) -> str:
    """Date n days before the as-of date (simple, no calendar library needed)."""
    import datetime as dt
    return (dt.date.fromisoformat(AS_OF) - dt.timedelta(days=n)).isoformat()


def build() -> dict[str, dict]:
    rng = random.Random(7)
    f: dict[str, dict] = {}
    # ---------------- HR (people events drive PS controls) ----------------
    f["hris"] = {"events": [
        {"employeeId": f"E{100 + i}", "upn": f"user{i:03d}@lakehaven-hx.example", "event": ev, "effective": day(d)}
        for i, ev, d in [(5, "termination", 10), (6, "termination", 40), (9, "transfer", 15), (12, "termination", 3),
                         (30, "hire", 20), (31, "hire", 8), (14, "termination", 25)]
    ], "training": [
        {"upn": f"user{i:03d}@lakehaven-hx.example", "course": "security-privacy-awareness",
         "completed": day(rng.choice([20, 60, 120, 200, 300, 400]))} for i in range(40)
    ]}
    # ---------------- Identity ----------------
    f["entra_id"] = {"value": [
        {"id": "u-005", "userPrincipalName": "user005@lakehaven-hx.example", "accountEnabled": False,
         "disabledOn": day(10), "mfaRegistered": True},
        {"id": "u-006", "userPrincipalName": "user006@lakehaven-hx.example", "accountEnabled": False,
         "disabledOn": day(38), "mfaRegistered": True},
        {"id": "u-012", "userPrincipalName": "user012@lakehaven-hx.example", "accountEnabled": True,
         "disabledOn": None, "mfaRegistered": True},
        {"id": "u-014", "userPrincipalName": "user014@lakehaven-hx.example", "accountEnabled": False,
         "disabledOn": day(25), "mfaRegistered": True},
        {"id": "u-030", "userPrincipalName": "user030@lakehaven-hx.example", "accountEnabled": True,
         "disabledOn": None, "mfaRegistered": False},
    ]}
    f["active_directory"] = {"objects": [
        {"sAMAccountName": "svc-batch01", "enabled": True, "passwordNeverExpires": True, "lastLogonDays": 3},
        {"sAMAccountName": "user012", "enabled": True, "passwordNeverExpires": False, "lastLogonDays": 1},
        {"sAMAccountName": "user006", "enabled": False, "passwordNeverExpires": False, "lastLogonDays": 45},
    ]}
    f["okta"] = {"users": [
        {"login": "user005@lakehaven-hx.example", "status": "DEPROVISIONED", "statusChanged": day(10),
         "factors": ["push"]},
        {"login": "user012@lakehaven-hx.example", "status": "ACTIVE", "statusChanged": day(200),
         "factors": ["push", "webauthn"]},
        {"login": "user031@lakehaven-hx.example", "status": "ACTIVE", "statusChanged": day(8), "factors": []},
    ]}
    # ---------------- Cloud ----------------
    f["azure_resource_graph"] = {"data": json.loads((ROOT / "data/estate/azure_resources.json").read_text())[:12]}
    f["defender_for_cloud"] = {"value": [
        {"name": f"assess-{i}", "resourceId": f"res-{i}", "displayName": t, "status": s, "severity": sev}
        for i, (t, s, sev) in enumerate([("Storage should disable public network access", "Unhealthy", "High"),
                                         ("Machines should have vulnerability findings resolved", "Unhealthy", "High"),
                                         ("MFA should be enabled on accounts with owner permissions", "Healthy", "High"),
                                         ("Diagnostic logs in Key Vault should be enabled", "Unhealthy", "Low")])
    ]}
    f["sentinel"] = {"reviews": [{"workspace": "law-lhx-sec-prod", "reviewedOn": day(d), "reviewer": "soc-analyst-2"}
                                 for d in (2, 9, 16, 23)],
                     "dataConnectors": ["AzureActivity", "EntraID", "DefenderForCloud", "Office365", "PaloAlto"],
                     "incidents": [
                         {"id": "INC-SIM-101", "severity": "High", "detected": "2026-10-20T14:00",
                          "reportedToCms": "2026-10-20T14:40", "pii": True},
                         {"id": "INC-SIM-102", "severity": "Medium", "detected": "2026-10-25T09:00",
                          "reportedToCms": "2026-10-25T11:30", "pii": True},
                         {"id": "INC-SIM-103", "severity": "Low", "detected": "2026-10-28T08:00",
                          "reportedToCms": None, "pii": False}]}
    f["purview"] = {"dlpPolicies": [
        {"name": "PII-SSN-block-external", "mode": "Enforce", "locations": ["Exchange", "SharePoint", "OneDrive"]},
        {"name": "PHI-audit", "mode": "TestWithNotifications", "locations": ["Teams"]}]}
    f["aws_security_hub"] = {"Findings": [
        {"Id": "arn:sim:finding/1", "Title": "S3 bucket allows public read", "Severity": {"Label": "CRITICAL"},
         "Workflow": {"Status": "NEW"}, "Region": "us-east-1", "FirstObservedAt": day(20)},
        {"Id": "arn:sim:finding/2", "Title": "Root account MFA enabled", "Severity": {"Label": "INFORMATIONAL"},
         "Workflow": {"Status": "RESOLVED"}, "Region": "us-east-1", "FirstObservedAt": day(90)}]}
    f["gcp_scc"] = {"findings": [
        {"name": "organizations/0/sources/1/findings/a", "category": "OPEN_FIREWALL", "severity": "HIGH",
         "state": "ACTIVE", "eventTime": day(5), "location": "us-central1"}]}
    # ---------------- ITSM ----------------
    f["servicenow"] = {"result": [
        {"number": f"CHG00{100 + i}", "type": "normal", "approval": a, "state": "closed", "env": "prod",
         "linkedPr": pr, "testEvidence": te, "closed_at": day(d)}
        for i, (a, pr, te, d) in enumerate([("approved", "lhx-portal#41", True, 5), ("approved", "lhx-portal#44", True, 9),
                                            ("not requested", None, False, 12), ("approved", "lhx-elig#7", False, 20)])
    ]}
    f["jira"] = {"issues": [
        {"key": "LHX-201", "fields": {"issuetype": "Change", "status": "Done", "approver": "cab-chair",
                                      "pr": "lhx-elig#9", "tested": True, "resolved": day(6)}},
        {"key": "LHX-202", "fields": {"issuetype": "POAM", "status": "In Progress", "approver": None,
                                      "pr": None, "tested": False, "resolved": None}}]}
    # ---------------- Collaboration ----------------
    f["m365"] = {"auditLogSearch": {"enabled": True, "retentionDays": 365},
                 "externalSharing": {"teamsGuestAccess": False}}
    f["slack"] = {"workspace": {"name": "lakehaven-hx", "sso_required": True, "external_channels_allowed": True,
                                "retention_days": 400, "dlp_enabled": False}}
    f["sharepoint"] = {"sites": [
        {"url": "/sites/enrollment-ops", "sharingCapability": "Disabled", "sensitivity": "PII"},
        {"url": "/sites/public-notices", "sharingCapability": "ExternalUserAndGuestSharing", "sensitivity": "Public"},
        {"url": "/sites/appeals", "sharingCapability": "ExternalUserSharingOnly", "sensitivity": "PII"}]}
    # ---------------- Security tools ----------------
    f["splunk"] = {"results": [{"search": "weekly-audit-review", "last_run": day(4), "owner": "soc-analyst-1"}]}
    f["tenable"] = {"scans": [{"name": "lhx-monthly-internal", "last_run": day(12), "plugin_feed_updated": day(1),
                               "credentialed": True, "targets": 48},
                              {"name": "lhx-dmz", "last_run": day(35), "plugin_feed_updated": day(1),
                               "credentialed": False, "targets": 6}]}
    f["qualys"] = {"HOST_LIST": [{"IP": "10.20.3.4", "QID_SEVERITY_5": 1, "LAST_SCAN": day(7)},
                                 {"IP": "10.20.3.9", "QID_SEVERITY_5": 0, "LAST_SCAN": day(7)}]}
    f["palo_alto"] = {"rules": [
        {"name": "allow-web", "from": "untrust", "to": "dmz", "source": "any", "application": "ssl", "action": "allow"},
        {"name": "temp-any-any", "from": "trust", "to": "untrust", "source": "any", "application": "any",
         "action": "allow"},
        {"name": "deny-all", "from": "any", "to": "any", "source": "any", "application": "any", "action": "deny"}]}
    f["datadog"] = {"monitors": [
        {"name": "auth-failures-spike", "type": "log alert", "notify": ["@soc-oncall"], "muted": False},
        {"name": "portal-uptime", "type": "synthetics alert", "notify": ["@ops-oncall"], "muted": False},
        {"name": "waf-blocks-anomaly", "type": "log alert", "notify": [], "muted": True}]}
    # ---------------- DevOps ----------------
    f["github"] = {"repos": [
        {"name": "lhx-portal", "code_scanning": True, "secret_scanning": True, "branch_protection": True},
        {"name": "lhx-elig", "code_scanning": True, "secret_scanning": True, "branch_protection": True},
        {"name": "lhx-batch", "code_scanning": False, "secret_scanning": True, "branch_protection": False}],
        "pulls": [{"ref": "lhx-portal#41", "approved_reviews": 1}, {"ref": "lhx-portal#44", "approved_reviews": 2},
                  {"ref": "lhx-elig#7", "approved_reviews": 1}, {"ref": "lhx-elig#9", "approved_reviews": 0}]}
    # ---------------- Docs ----------------
    f["docs_library"] = {"documents": [
        {"title": f"{fam} Policy and Procedures", "control": f"{fam}-01", "version": "2.1",
         "approved": day(rng.choice([30, 100, 200, 380, 500])), "owner": "isso"}
        for fam in ("AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP",
                    "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR")]}
    # ---------------- Finance / vendors (SR) ----------------
    f["finance_vendors"] = {"vendors": [
        {"vendorId": "V-001", "name": "Northmere Call Center Services", "annualSpend": 1_200_000, "piiAccess": True,
         "dataLocation": "US", "contract": {"breachNotifyHours": 1, "flowdown45CFR155260": True}},
        {"vendorId": "V-002", "name": "Bluequill Print and Mail", "annualSpend": 310_000, "piiAccess": True,
         "dataLocation": "US", "contract": {"breachNotifyHours": 72, "flowdown45CFR155260": True}},
        {"vendorId": "V-003", "name": "Cedar Analytics Labs", "annualSpend": 95_000, "piiAccess": True,
         "dataLocation": "IN", "contract": {"breachNotifyHours": 24, "flowdown45CFR155260": False}},
        {"vendorId": "V-004", "name": "Granite Office Supply", "annualSpend": 22_000, "piiAccess": False,
         "dataLocation": "US", "contract": {"breachNotifyHours": None, "flowdown45CFR155260": False}},
        {"vendorId": "V-005", "name": "Harbor Identity Proofing", "annualSpend": 640_000, "piiAccess": True,
         "dataLocation": "US", "contract": {"breachNotifyHours": 1, "flowdown45CFR155260": True}}]}
    # ---------------- Platform backups (CP) ----------------
    f["backup_jobs"] = {"jobs": [
        {"target": t, "type": ty, "finished": day(d), "status": s, "restoreTestedOn": day(rt) if rt else None}
        for t, ty, d, s, rt in [("sql-lhx-elig", "incremental", 0, "Completed", 40),
                                ("sql-lhx-elig", "full", 3, "Completed", 40),
                                ("sql-lhx-elig", "full", 10, "Completed", 40),
                                ("sql-lhx-elig", "full", 17, "Completed", 40),
                                ("sql-lhx-enroll", "incremental", 0, "Completed", 400),
                                ("sql-lhx-enroll", "full", 5, "Completed", 400),
                                ("sql-lhx-enroll", "full", 12, "Completed", 400),
                                ("sql-lhx-enroll", "full", 19, "Completed", 400),
                                ("cosmos-lhx-session", "incremental", 1, "Completed", 90),
                                ("cosmos-lhx-session", "full", 2, "Completed", 90),
                                ("vm-lhx-app04", "full", 9, "Failed", None)]]}
    return f


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fx = build()
    for name, body in fx.items():
        (OUT / f"{name}.json").write_text(json.dumps(body, indent=1) + "\n")
    print(f"wrote {len(fx)} connector fixtures")


if __name__ == "__main__":
    main()
