"""Policy-as-code checks over simulated Azure resource configs and an Entra-style directory.

Each check returns (passed, detail). Thresholds come from arcampe.params (ARC-AMPE AE values).
Nothing here calls Azure. The same rules are shown as Azure Policy JSON under policies/.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from .. import DATA
from ..params import PARAMS, US_REGIONS
from .base import Check, Finding

STORAGE = "Microsoft.Storage/storageAccounts"
KV = "Microsoft.KeyVault/vaults"
SQL = "Microsoft.Sql/servers"
COG = "Microsoft.CognitiveServices/accounts"
SEARCH = "Microsoft.Search/searchServices"
COSMOS = "Microsoft.DocumentDB/databaseAccounts"
LAW = "Microsoft.OperationalInsights/workspaces"
VM = "Microsoft.Compute/virtualMachines"
NSG = "Microsoft.Network/networkSecurityGroups"
WEB = "Microsoft.Web/sites"
AGW = "Microsoft.Network/applicationGateways"
AFD = "Microsoft.Network/frontDoors"
AKS = "Microsoft.ContainerService/managedClusters"
PRICING = "Microsoft.Security/pricings"
DATA_PLANE = (STORAGE, KV, SQL, COG, SEARCH, COSMOS, WEB)
ADMIN_PORTS = {22, 3389, 5985, 5986}
OPEN_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}
REQUIRED_PLANS = ("VirtualMachines", "SqlServers", "StorageAccounts", "KeyVaults", "Containers", "AI", "Arm")
TLS_OK = {"TLS1_2", "TLS1_3", "1.2", "1.3", "Tls12", "Tls13", "TLSv1_2", "TLSv1_3"}


def _p(r: dict) -> dict:
    return r.get("properties", {})


# ---- resource checks -------------------------------------------------------------------------

def public_network_disabled(r):
    v = _p(r).get("publicNetworkAccess")
    return v == "Disabled", f"publicNetworkAccess={v}"


def private_endpoint(r):
    pes = [p for p in _p(r).get("privateEndpointConnections", []) if p.get("status") == "Approved"]
    return bool(pes), f"{len(pes)} approved private endpoint(s)"


def us_region(r):
    loc = r.get("location", "")
    return loc in US_REGIONS or loc == "global", f"location={loc}"


def tls_min(r):
    p = _p(r)
    v = p.get("minimumTlsVersion") or p.get("minimalTlsVersion") or p.get("minTlsVersion") or p.get("minProtocol")
    return v in TLS_OK, f"minimum TLS={v}"


def https_only(r):
    p = _p(r)
    v = p.get("supportsHttpsTrafficOnly", p.get("httpsOnly"))
    return v is True, f"https only={v}"


def encryption_at_rest(r):
    p = _p(r)
    if r["type"] == STORAGE:
        ok = p.get("encryption", {}).get("enabled") is True
        return ok, f"storage encryption={ok}"
    if r["type"] == SQL:
        st = p.get("transparentDataEncryption", {}).get("state")
        return st == "Enabled", f"TDE={st}"
    if r["type"] == VM:
        d = p.get("diskEncryption", {})
        ok = bool(d.get("osDisk")) and bool(d.get("dataDisks"))
        return ok, f"disk encryption os={d.get('osDisk')} data={d.get('dataDisks')}"
    return True, "platform-managed encryption"


def cmk_for_pii(r):
    if r.get("tags", {}).get("data_class") != "PII":
        return True, "not a PII store"
    src = _p(r).get("encryption", {}).get("keySource")
    return src == "Microsoft.Keyvault", f"PII store key source={src}"


def kv_protection(r):
    p = _p(r)
    ok = p.get("enableSoftDelete") is True and p.get("enablePurgeProtection") is True
    return ok, f"softDelete={p.get('enableSoftDelete')} purgeProtection={p.get('enablePurgeProtection')}"


def diagnostics(r):
    ds = _p(r).get("diagnosticSettings", [])
    return bool(ds), f"{len(ds)} diagnostic setting(s)"


def log_retention(r):
    p = _p(r)
    online, total = p.get("retentionInDays", 0), p.get("totalRetentionInDays", 0)
    need_online = PARAMS["AU-11"]["online_days"]
    need_total = PARAMS["AU-11"]["archive_years"] * 365
    return online >= need_online and total >= need_total, (
        f"online {online}d (need {need_online}), total {total}d (need {need_total})")


def shared_key_disabled(r):
    v = _p(r).get("allowSharedKeyAccess")
    return v is False, f"allowSharedKeyAccess={v}"


def local_auth_disabled(r):
    p = _p(r)
    if r["type"] == SQL:
        v = p.get("azureADOnlyAuthentication")
        return v is True, f"Entra-only auth={v}"
    v = p.get("disableLocalAuth", p.get("disableLocalAccounts"))
    return v is True, f"local auth disabled={v}"


def nsg_admin_ports(r):
    bad = [x["name"] for x in _p(r).get("securityRules", [])
           if x.get("direction") == "Inbound" and x.get("access") == "Allow"
           and x.get("source") in OPEN_SOURCES and x.get("port") in ADMIN_PORTS]
    return not bad, "no admin ports open to the internet" if not bad else f"open admin rules: {bad}"


def defender_plans(r):
    plans = _p(r).get("plans", {})
    off = [k for k in REQUIRED_PLANS if plans.get(k) != "Standard"]
    return not off, "all required plans on" if not off else f"plans not on: {off}"


def backup_enabled(r):
    b = _p(r).get("backup", {})
    ok = b.get("enabled") is True and (not b.get("geoRedundant") or b.get("pairedRegion") in US_REGIONS)
    return ok, f"backup={b.get('enabled')} paired={b.get('pairedRegion')}"


def sql_auditing(r):
    st = _p(r).get("auditing", {}).get("state")
    return st == "Enabled", f"auditing={st}"


def waf_prevention(r):
    w = _p(r).get("waf", {})
    ok = w.get("enabled") is True and w.get("mode") == "Prevention"
    return ok, f"waf enabled={w.get('enabled')} mode={w.get('mode')}"


def vuln_scan_age(r):
    age = _p(r).get("lastVulnScanDaysAgo")
    need = PARAMS["RA-05"]["scan_every_days"]
    return age is not None and age <= need, f"last scan {age} days ago (max {need})"


def patch_sla(r):
    late = []
    for p in _p(r).get("missingPatches", []):
        limit = PARAMS["SI-02"][f"{p['severity']}_days"]
        if p["released_days_ago"] > limit:
            late.append(f"{p['id']} {p['severity']} {p['released_days_ago']}d>{limit}d")
    return not late, "patches inside SI-02 timeframes" if not late else "late: " + "; ".join(late)


def aks_private(r):
    p = _p(r)
    ok = p.get("apiServerAccessProfile", {}).get("enablePrivateCluster") is True and p.get("enableRBAC") is True
    return ok, f"private API={p.get('apiServerAccessProfile', {}).get('enablePrivateCluster')} rbac={p.get('enableRBAC')}"


def inventory_tags(r):
    t = r.get("tags", {})
    missing = [k for k in ("owner", "data_class") if not t.get(k)]
    return not missing, "owner and data_class tagged" if not missing else f"missing tags: {missing}"


def policy_compliant(r):
    v = _p(r).get("x_policy_compliant")
    return v is True, f"Azure Policy compliance state={v}"


# ---- directory checks ---------------------------------------------------------------------------

def mfa_all_users(d):
    ok = any(p["state"] == "enabled" and p["users"] == "All" and "mfa" in p["grant"] for p in d["conditionalAccess"])
    return ok, "MFA required for all users" if ok else "no enabled all-users MFA policy"


def admin_phishing_resistant(d):
    ok = any(p["state"] == "enabled" and p["users"] == "DirectoryRoles"
             and any(g.startswith("authStrength:phishingResistant") for g in p["grant"])
             for p in d["conditionalAccess"])
    return ok, "phishing-resistant MFA for admins" if ok else "admins not on phishing-resistant MFA"


def legacy_auth_blocked(d):
    ok = any(p["state"] == "enabled" and "legacy" in p.get("clientApps", []) and "block" in p["grant"]
             for p in d["conditionalAccess"])
    return ok, "legacy authentication blocked" if ok else "legacy authentication allowed"


def inactive_accounts(d):
    limit = PARAMS["AC-02(03)"]["inactive_days"]
    bad = [u["upn"] for u in d["users"] if u["enabled"] and u["lastSignInDaysAgo"] > limit]
    return not bad, f"no enabled account idle > {limit}d" if not bad else f"{len(bad)} enabled idle account(s): {bad}"


def lockout_policy(d):
    p, need = d["lockout"], PARAMS["AC-07"]
    ok = (p["threshold"] <= need["max_attempts"] and p["windowMinutes"] >= need["window_minutes"]
          and p["durationMinutes"] >= need["lockout_minutes"])
    return ok, f"threshold {p['threshold']}, window {p['windowMinutes']}m, lock {p['durationMinutes']}m"


def session_lock(d):
    idle = d["sessionControls"]["idleTimeoutMinutes"]
    need = PARAMS["AC-11"]["device_lock_minutes"]
    return idle <= need, f"idle timeout {idle}m (max {need})"


def guest_no_pii(d):
    bad = [u["upn"] for u in d["users"] if u["type"] == "Guest" and u["enabled"]
           and set(u["groups"]) & set(d["pii_groups"])]
    return not bad, "no guest in a PII group" if not bad else f"guests with PII access: {bad}"


def no_standing_admin(d):
    privileged = {"Global Administrator", "Security Administrator", "Privileged Role Administrator"}
    bad = [a["principal"] for a in d["roleAssignments"] if a["role"] in privileged and a["type"] != "Eligible"]
    return not bad, "privileged roles are just-in-time" if not bad else f"standing privileged roles: {bad}"


def _c(*ids: str) -> tuple[str, ...]:
    return ids


CHECKS: tuple[Check, ...] = (
    Check("AZ-01", "Public network access is disabled", _c("SC-07", "AC-04"), "high", DATA_PLANE,
          public_network_disabled, "PII data services must not be reachable from the internet"),
    Check("AZ-02", "Data services use approved private endpoints", _c("SC-07(04)", "SC-07(05)"), "high",
          DATA_PLANE, private_endpoint, "traffic stays on the private network"),
    Check("AZ-03", "Resource is in a U.S. region", _c("SA-09(05)"), "critical",
          (STORAGE, KV, SQL, COG, SEARCH, COSMOS, LAW, VM, WEB, AKS, NSG, AGW), us_region,
          "PII is processed and stored in the U.S."),
    Check("AZ-04", "Minimum TLS 1.2", _c("SC-08", "SC-08(01)", "SC-13"), "high",
          (STORAGE, SQL, COSMOS, WEB, AGW), tls_min, "protect data in transit"),
    Check("AZ-05", "HTTPS only", _c("SC-23"), "high", (STORAGE, WEB), https_only, "no clear-text sessions"),
    Check("AZ-06", "Encryption at rest is on", _c("SC-28", "SC-28(01)"), "high", (STORAGE, SQL, VM),
          encryption_at_rest, "protect data at rest"),
    Check("AZ-07", "PII stores use customer-managed keys", _c("SC-12"), "moderate", (STORAGE,), cmk_for_pii,
          "key ownership for PII"),
    Check("AZ-08", "Key Vault soft delete and purge protection", _c("SC-12"), "moderate", (KV,),
          kv_protection, "keys cannot be destroyed by mistake"),
    Check("AZ-09", "Diagnostic logs are sent to the security workspace", _c("AU-02", "AU-12"), "moderate",
          (STORAGE, KV, SQL, COG, SEARCH, COSMOS, VM, WEB, AKS), diagnostics, "events are recorded"),
    Check("AZ-10", "Log retention 90 days online and 10 years total", _c("AU-11", "AU-04"), "moderate",
          (LAW,), log_retention, "ARC-AMPE AU-11 retention"),
    Check("AZ-11", "Storage shared keys are disabled", _c("IA-02", "AC-03"), "high", (STORAGE,),
          shared_key_disabled, "identity-based access only"),
    Check("AZ-12", "Local or key auth is disabled", _c("AC-02", "IA-05"), "high", (COG, SEARCH, COSMOS, SQL, AKS),
          local_auth_disabled, "no shared secrets"),
    Check("AZ-13", "No admin ports open to the internet", _c("SC-07(03)", "AC-17", "CM-07"), "critical", (NSG,),
          nsg_admin_ports, "no internet RDP/SSH"),
    Check("AZ-14", "Defender for Cloud plans are on", _c("SI-04", "SI-03"), "high", (PRICING,), defender_plans,
          "threat detection coverage"),
    Check("AZ-15", "Backups on, geo copy stays in the U.S.", _c("CP-09", "CP-06"), "high", (SQL, COSMOS, VM),
          backup_enabled, "ARC-AMPE CP-09 backups"),
    Check("AZ-16", "SQL auditing is on", _c("AU-03", "AU-03(01)"), "moderate", (SQL,), sql_auditing,
          "database events have content"),
    Check("AZ-17", "WAF in prevention mode at the edge", _c("SC-07(08)", "SI-04(04)"), "high", (AGW, AFD),
          waf_prevention, "block web attacks"),
    Check("AZ-18", "Vulnerability scan in the last 30 days", _c("RA-05", "CA-07"), "high", (VM,), vuln_scan_age,
          "ARC-AMPE RA-05 30-day scans"),
    Check("AZ-19", "Patches applied inside SI-02 timeframes", _c("SI-02", "SI-02(02)"), "high", (VM,), patch_sla,
          "critical 15d, high 30d, moderate 90d, low 1y"),
    Check("AZ-20", "AKS API is private with RBAC", _c("AC-03", "AC-06"), "high", (AKS,), aks_private,
          "least privilege on the cluster"),
    Check("AZ-21", "Owner and data class tags present", _c("CM-08"), "low",
          (STORAGE, KV, SQL, COG, SEARCH, COSMOS, VM, WEB, AKS), inventory_tags, "complete inventory"),
    Check("AZ-22", "Azure Policy baseline is compliant", _c("CM-06", "CM-02"), "moderate",
          (STORAGE, KV, SQL, COG, SEARCH, COSMOS, VM, WEB, AKS, NSG, AGW, AFD, LAW), policy_compliant,
          "configuration matches the baseline"),
    Check("ID-01", "MFA required for all users", _c("IA-02(01)", "IA-02(02)"), "critical", ("directory",),
          mfa_all_users, "ARC-AMPE IA-02(01)"),
    Check("ID-02", "Phishing-resistant MFA for admins", _c("IA-02(06)"), "high", ("directory",),
          admin_phishing_resistant, "stronger factor for privileged users"),
    Check("ID-03", "Legacy authentication blocked", _c("IA-02(08)"), "high", ("directory",), legacy_auth_blocked,
          "replay-resistant sign-in"),
    Check("ID-04", "Idle accounts disabled after 60 days", _c("AC-02(03)"), "moderate", ("directory",),
          inactive_accounts, "ARC-AMPE AC-02(03)"),
    Check("ID-05", "Lockout after 5 tries in 15 minutes for 30 minutes", _c("AC-07"), "moderate", ("directory",),
          lockout_policy, "ARC-AMPE AC-07"),
    Check("ID-06", "Session locks after 15 minutes idle", _c("AC-11", "AC-12"), "moderate", ("directory",),
          session_lock, "ARC-AMPE AC-11"),
    Check("ID-07", "No guest accounts can reach PII", _c("AC-02(09)", "AC-03(14)"), "high", ("directory",),
          guest_no_pii, "no guest or shared access to PII"),
    Check("ID-08", "No standing privileged roles", _c("AC-02(07)", "AC-06(05)"), "high", ("directory",),
          no_standing_admin, "just-in-time admin"),
)


def all_checks() -> tuple[Check, ...]:
    return CHECKS


def load_estate() -> list[dict]:
    return json.loads((DATA / "estate" / "azure_resources.json").read_text())


def load_directory() -> dict:
    return json.loads((DATA / "estate" / "directory.json").read_text())


def run(resources: Iterable[dict] | None = None, directory: dict | None = None,
        checks: Iterable[Check] = CHECKS) -> list[Finding]:
    resources = load_estate() if resources is None else list(resources)
    directory = load_directory() if directory is None else directory
    out: list[Finding] = []
    for chk in checks:
        if chk.applies_to == ("directory",):
            ok, detail = chk.fn(directory)
            out.append(Finding(chk.id, f"directory/{directory.get('tenant', 'tenant')}", "directory", ok,
                               chk.severity, chk.controls, detail))
            continue
        for r in resources:
            if r["type"] in chk.applies_to:
                ok, detail = chk.fn(r)
                out.append(Finding(chk.id, r["id"], r["name"], ok, chk.severity, chk.controls, detail))
    return out
