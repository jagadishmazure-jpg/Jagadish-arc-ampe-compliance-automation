"""Offline fixture connectors, grouped by category. Each one normalizes to the Evidence schema.

Product names are the technologies a real connector would read from. All data is synthetic.
"""
from __future__ import annotations

from collections.abc import Iterator

from .sdk import BaseConnector


def _r(kind, subject, observed_at, attributes, hints=()):
    return {"kind": kind, "subject": subject, "observed_at": observed_at, "attributes": attributes,
            "control_hints": tuple(hints)}


# ---------------- identity ----------------
class EntraID(BaseConnector):
    name, category, product = "entra_id", "identity", "Microsoft Entra ID (Graph API)"
    read_only_scopes = ("User.Read.All", "AuditLog.Read.All")

    def records(self, raw) -> Iterator[dict]:
        for u in raw["value"]:
            yield _r("account", u["userPrincipalName"].lower(), u.get("disabledOn") or self.as_of,
                     {"enabled": u["accountEnabled"], "disabled_on": u.get("disabledOn"),
                      "mfa": u["mfaRegistered"], "idp": "entra"}, ("AC-02", "IA-02(01)"))


class ActiveDirectory(BaseConnector):
    name, category, product = "active_directory", "identity", "Active Directory (LDAP export)"

    def records(self, raw):
        for o in raw["objects"]:
            yield _r("account", o["sAMAccountName"], self.as_of,
                     {"enabled": o["enabled"], "password_never_expires": o["passwordNeverExpires"],
                      "idle_days": o["lastLogonDays"], "idp": "ad"}, ("AC-02", "IA-05"))


class Okta(BaseConnector):
    name, category, product = "okta", "identity", "Okta (Users API)"

    def records(self, raw):
        for u in raw["users"]:
            enabled = u["status"] == "ACTIVE"
            yield _r("account", u["login"].lower(), u["statusChanged"],
                     {"enabled": enabled, "disabled_on": None if enabled else u["statusChanged"],
                      "mfa": bool(u["factors"]), "idp": "okta"}, ("AC-02", "IA-02(01)"))


# ---------------- cloud ----------------
class AzureResourceGraph(BaseConnector):
    name, category, product = "azure_resource_graph", "cloud", "Azure Resource Graph"

    def records(self, raw):
        for r in raw["data"]:
            yield _r("cloud_resource", r["id"], self.as_of,
                     {"type": r["type"], "location": r["location"], "tags": r.get("tags", {}),
                      "public": r.get("properties", {}).get("publicNetworkAccess") == "Enabled"}, ("CM-08",))


class DefenderForCloud(BaseConnector):
    name, category, product = "defender_for_cloud", "cloud", "Microsoft Defender for Cloud"

    def records(self, raw):
        for a in raw["value"]:
            yield _r("posture_finding", a["resourceId"], self.as_of,
                     {"title": a["displayName"], "healthy": a["status"] == "Healthy",
                      "severity": a["severity"].lower()}, ("RA-05", "SI-04"))


class Sentinel(BaseConnector):
    name, category, product = "sentinel", "cloud", "Microsoft Sentinel"

    def records(self, raw):
        for rv in raw["reviews"]:
            yield _r("log_review", rv["workspace"], rv["reviewedOn"], {"reviewer": rv["reviewer"]}, ("AU-06",))
        yield _r("siem_sources", "law-lhx-sec-prod", self.as_of, {"sources": raw["dataConnectors"]}, ("AU-06(01)",))
        for i in raw["incidents"]:
            yield _r("incident", i["id"], i["detected"][:10],
                     {"severity": i["severity"].lower(), "detected": i["detected"],
                      "reported_to_cms": i["reportedToCms"], "pii": i["pii"]}, ("IR-06", "IR-04"))


class Purview(BaseConnector):
    name, category, product = "purview", "cloud", "Microsoft Purview"

    def records(self, raw):
        for p in raw["dlpPolicies"]:
            yield _r("dlp_policy", p["name"], self.as_of, {"enforced": p["mode"] == "Enforce",
                                                           "locations": p["locations"]}, ("SC-07(24)", "PT-02"))


class AwsSecurityHub(BaseConnector):
    name, category, product = "aws_security_hub", "cloud", "AWS Security Hub"

    def records(self, raw):
        for f in raw["Findings"]:
            yield _r("posture_finding", f["Id"], f["FirstObservedAt"],
                     {"title": f["Title"], "healthy": f["Workflow"]["Status"] == "RESOLVED",
                      "severity": f["Severity"]["Label"].lower(), "region": f["Region"]}, ("RA-05", "SI-04"))


class GcpScc(BaseConnector):
    name, category, product = "gcp_scc", "cloud", "Google Cloud Security Command Center"

    def records(self, raw):
        for f in raw["findings"]:
            yield _r("posture_finding", f["name"], f["eventTime"],
                     {"title": f["category"], "healthy": f["state"] != "ACTIVE", "severity": f["severity"].lower(),
                      "region": f["location"]}, ("RA-05", "SI-04"))


# ---------------- ITSM ----------------
class ServiceNow(BaseConnector):
    name, category, product = "servicenow", "itsm", "ServiceNow (Table API)"

    def records(self, raw):
        for c in raw["result"]:
            yield _r("change", c["number"], c["closed_at"],
                     {"approved": c["approval"] == "approved", "env": c["env"], "pr": c["linkedPr"],
                      "tested": c["testEvidence"]}, ("CM-03", "CM-03(02)"))


class Jira(BaseConnector):
    name, category, product = "jira", "itsm", "Jira (REST API)"

    def records(self, raw):
        for i in raw["issues"]:
            f = i["fields"]
            if f["issuetype"] == "Change":
                yield _r("change", i["key"], f["resolved"] or self.as_of,
                         {"approved": bool(f["approver"]), "env": "prod", "pr": f["pr"], "tested": f["tested"]},
                         ("CM-03", "CM-03(02)"))
            else:
                yield _r("ticket", i["key"], self.as_of, {"type": f["issuetype"], "status": f["status"]}, ("CA-05",))


# ---------------- collaboration ----------------
class M365(BaseConnector):
    name, category, product = "m365", "collaboration", "Microsoft 365 (admin settings)"

    def records(self, raw):
        a = raw["auditLogSearch"]
        yield _r("saas_setting", "m365/audit", self.as_of, {"audit_enabled": a["enabled"],
                                                             "retention_days": a["retentionDays"]}, ("AU-02",))
        yield _r("saas_setting", "m365/teams-guest", self.as_of,
                 {"guest_access": raw["externalSharing"]["teamsGuestAccess"]}, ("AC-21",))


class Slack(BaseConnector):
    name, category, product = "slack", "collaboration", "Slack (admin settings)"

    def records(self, raw):
        w = raw["workspace"]
        yield _r("saas_setting", f"slack/{w['name']}", self.as_of,
                 {"sso_required": w["sso_required"], "external_channels": w["external_channels_allowed"],
                  "dlp_enabled": w["dlp_enabled"], "retention_days": w["retention_days"]}, ("AC-21", "IA-02"))


class SharePoint(BaseConnector):
    name, category, product = "sharepoint", "collaboration", "SharePoint Online"

    def records(self, raw):
        for s in raw["sites"]:
            yield _r("share_setting", s["url"], self.as_of,
                     {"sharing": s["sharingCapability"], "sensitivity": s["sensitivity"]}, ("AC-22", "AC-21"))


# ---------------- security ----------------
class Splunk(BaseConnector):
    name, category, product = "splunk", "security", "Splunk (saved searches)"

    def records(self, raw):
        for r in raw["results"]:
            yield _r("log_review", r["search"], r["last_run"], {"reviewer": r["owner"]}, ("AU-06",))


class Tenable(BaseConnector):
    name, category, product = "tenable", "security", "Tenable (scans API)"

    def records(self, raw):
        for s in raw["scans"]:
            yield _r("vuln_scan", s["name"], s["last_run"],
                     {"feed_updated": s["plugin_feed_updated"], "credentialed": s["credentialed"],
                      "targets": s["targets"]}, ("RA-05", "RA-05(02)"))


class Qualys(BaseConnector):
    name, category, product = "qualys", "security", "Qualys (host list)"

    def records(self, raw):
        for h in raw["HOST_LIST"]:
            yield _r("vuln_host", h["IP"], h["LAST_SCAN"], {"sev5": h["QID_SEVERITY_5"]}, ("RA-05", "SI-02"))


class PaloAlto(BaseConnector):
    name, category, product = "palo_alto", "security", "Palo Alto Networks firewall (rulebase)"

    def records(self, raw):
        for r in raw["rules"]:
            yield _r("firewall_rule", r["name"], self.as_of,
                     {"any_any_allow": r["action"] == "allow" and r["source"] == "any" and r["application"] == "any",
                      "action": r["action"]}, ("SC-07(05)",))


class Datadog(BaseConnector):
    name, category, product = "datadog", "security", "Datadog (monitors)"

    def records(self, raw):
        for m in raw["monitors"]:
            yield _r("monitor", m["name"], self.as_of, {"routed": bool(m["notify"]) and not m["muted"],
                                                        "type": m["type"]}, ("SI-04(05)",))


# ---------------- devops ----------------
class GitHub(BaseConnector):
    name, category, product = "github", "devops", "GitHub (repos and pulls API)"

    def records(self, raw):
        for r in raw["repos"]:
            yield _r("repo_setting", r["name"], self.as_of,
                     {"code_scanning": r["code_scanning"], "secret_scanning": r["secret_scanning"],
                      "branch_protection": r["branch_protection"]}, ("SA-11", "CM-05"))
        for p in raw["pulls"]:
            yield _r("pull_request", p["ref"], self.as_of, {"approved_reviews": p["approved_reviews"]}, ("CM-03",))


# ---------------- docs ----------------
class DocsLibrary(BaseConnector):
    name, category, product = "docs_library", "docs", "Document library (policy store)"

    def records(self, raw):
        for d in raw["documents"]:
            yield _r("policy_doc", d["control"], d["approved"],
                     {"title": d["title"], "version": d["version"], "owner": d["owner"]}, (d["control"],))


# ---------------- HR ----------------
class Hris(BaseConnector):
    name, category, product = "hris", "hr", "HR information system (people events and training)"

    def records(self, raw):
        for e in raw["events"]:
            yield _r("hr_event", e["upn"].lower(), e["effective"], {"event": e["event"], "employee": e["employeeId"]},
                     ("PS-04", "PS-05", "PS-07"))
        for t in raw["training"]:
            yield _r("training", t["upn"].lower(), t["completed"], {"course": t["course"]}, ("AT-02", "AT-03"))


# ---------------- finance / vendors ----------------
class FinanceVendors(BaseConnector):
    name, category, product = "finance_vendors", "finance", "Accounts payable vendor master"

    def records(self, raw):
        for v in raw["vendors"]:
            yield _r("vendor", v["vendorId"], self.as_of,
                     {"name": v["name"], "spend": v["annualSpend"], "pii": v["piiAccess"],
                      "location": v["dataLocation"], **{f"contract_{k}": x for k, x in v["contract"].items()}},
                     ("SR-03", "SR-08", "SA-09"))


# ---------------- platform ----------------
class BackupJobs(BaseConnector):
    name, category, product = "backup_jobs", "platform", "Azure Backup job history"

    def records(self, raw):
        for j in raw["jobs"]:
            yield _r("backup_job", j["target"], j["finished"],
                     {"type": j["type"], "ok": j["status"] == "Completed", "restore_tested_on": j["restoreTestedOn"]},
                     ("CP-09", "CP-09(01)"))


ALL = (EntraID, ActiveDirectory, Okta, AzureResourceGraph, DefenderForCloud, Sentinel, Purview, AwsSecurityHub,
       GcpScc, ServiceNow, Jira, M365, Slack, SharePoint, Splunk, Tenable, Qualys, PaloAlto, Datadog, GitHub,
       DocsLibrary, Hris, FinanceVendors, BackupJobs)


def by_category() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for c in ALL:
        out.setdefault(c.category, []).append(c.name)
    return out


def collect_all(tenant_id: str = "lakehaven") -> list:
    ev = []
    for c in ALL:
        ev.extend(c(tenant_id).collect())
    return ev
