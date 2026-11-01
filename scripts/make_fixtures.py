"""Generate the synthetic Azure estate and directory for the fictional Lakehaven Health Connector.

Deterministic (fixed seed). Every name, ID and person is made up. Some settings are wrong on
purpose so the checkers, POA&M and dashboard have real failures to show.
Run: python scripts/make_fixtures.py   (output is committed under data/estate/)
"""
from __future__ import annotations

import json
import pathlib
import random

ROOT = pathlib.Path(__file__).resolve().parent.parent
SUB = "/subscriptions/00000000-0000-4000-8000-00000000a1b2"



def rid(rg: str, provider: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{rg}/providers/{provider}/{name}"


def res(kind: str, name: str, rg: str, location: str = "eastus2", tags=None, **props) -> dict:
    return {"id": rid(rg, kind, name), "type": kind, "name": name, "location": location,
            "tags": {"owner": "platform-team", "data_class": "internal", "env": "prod", **(tags or {})},
            "properties": props}


DIAG = [{"workspace": "law-lhx-sec-prod", "categories": ["allLogs"]}]
PE = [{"name": "pe-1", "status": "Approved"}]


def estate() -> list[dict]:
    r: list[dict] = []
    # Storage accounts
    for i, (name, data_class, bad) in enumerate([
        ("stlhxenrolldocs", "PII", None), ("stlhxapplogs", "internal", None), ("stlhxbackup", "PII", None),
        ("stlhxstaticweb", "public", "public"), ("stlhxdevscratch", "internal", "tls"),
        ("stlhxarchive", "PII", "region"), ("stlhxreports", "PII", "sharedkey"), ("stlhxtemp", "internal", "https"),
    ]):
        r.append(res("Microsoft.Storage/storageAccounts", name, "rg-lhx-data",
                     location="canadacentral" if bad == "region" else "eastus2",
                     tags={"data_class": data_class},
                     publicNetworkAccess="Enabled" if bad == "public" else "Disabled",
                     privateEndpointConnections=[] if bad == "public" else PE,
                     minimumTlsVersion="TLS1_0" if bad == "tls" else "TLS1_2",
                     supportsHttpsTrafficOnly=bad != "https",
                     allowSharedKeyAccess=bad == "sharedkey",
                     encryption={"enabled": True, "keySource": "Microsoft.Keyvault" if data_class == "PII" and i != 2
                                 else "Microsoft.Storage"},
                     diagnosticSettings=DIAG, x_policy_compliant=bad is None))
    # Key vaults
    for name, purge in [("kv-lhx-app", True), ("kv-lhx-cmk", True), ("kv-lhx-legacy", False)]:
        r.append(res("Microsoft.KeyVault/vaults", name, "rg-lhx-sec", publicNetworkAccess="Disabled",
                     privateEndpointConnections=PE, enableSoftDelete=True, enablePurgeProtection=purge,
                     enableRbacAuthorization=True, diagnosticSettings=DIAG if purge else [],
                     x_policy_compliant=purge))
    # SQL servers
    for name, aad_only, auditing in [("sql-lhx-elig", True, True), ("sql-lhx-enroll", True, True),
                                     ("sql-lhx-reporting", False, False)]:
        r.append(res("Microsoft.Sql/servers", name, "rg-lhx-data", tags={"data_class": "PII"},
                     publicNetworkAccess="Disabled", privateEndpointConnections=PE, minimalTlsVersion="1.2",
                     azureADOnlyAuthentication=aad_only, auditing={"state": "Enabled" if auditing else "Disabled"},
                     transparentDataEncryption={"state": "Enabled"}, backup={"enabled": True, "geoRedundant": True,
                                                                              "pairedRegion": "centralus"},
                     diagnosticSettings=DIAG, x_policy_compliant=aad_only and auditing))
    # AI services (Microsoft Foundry / Azure OpenAI) and search
    r.append(res("Microsoft.CognitiveServices/accounts", "oai-lhx-assist", "rg-lhx-ai", publicNetworkAccess="Disabled",
                 privateEndpointConnections=PE, disableLocalAuth=True, diagnosticSettings=DIAG, x_policy_compliant=True))
    r.append(res("Microsoft.CognitiveServices/accounts", "oai-lhx-sandbox", "rg-lhx-ai", tags={"env": "dev"},
                 publicNetworkAccess="Disabled", privateEndpointConnections=PE, disableLocalAuth=False,
                 diagnosticSettings=DIAG, x_policy_compliant=False))
    r.append(res("Microsoft.Search/searchServices", "srch-lhx-kb", "rg-lhx-ai", publicNetworkAccess="Enabled",
                 privateEndpointConnections=[], disableLocalAuth=True, diagnosticSettings=DIAG,
                 x_policy_compliant=False))
    r.append(res("Microsoft.DocumentDB/databaseAccounts", "cosmos-lhx-session", "rg-lhx-data",
                 tags={"data_class": "PII"}, publicNetworkAccess="Disabled", privateEndpointConnections=PE,
                 minimalTlsVersion="Tls12", disableLocalAuth=True, diagnosticSettings=DIAG, x_policy_compliant=True,
                 backup={"enabled": True, "geoRedundant": True, "pairedRegion": "centralus"}))
    # Log Analytics
    r.append(res("Microsoft.OperationalInsights/workspaces", "law-lhx-sec-prod", "rg-lhx-sec",
                 retentionInDays=90, totalRetentionInDays=3650, x_policy_compliant=True))
    r.append(res("Microsoft.OperationalInsights/workspaces", "law-lhx-dev", "rg-lhx-dev", tags={"env": "dev"},
                 retentionInDays=30, totalRetentionInDays=30, x_policy_compliant=False))
    # Virtual machines
    for i in range(8):
        name = f"vm-lhx-app{i:02d}"
        scan_age = [3, 9, 12, 41, 5, 28, 2, 64][i]
        patches = []
        if i == 3:
            patches = [{"id": "KB-SIM-0001", "severity": "critical", "released_days_ago": 22}]
        if i == 5:
            patches = [{"id": "KB-SIM-0002", "severity": "high", "released_days_ago": 12}]
        if i == 7:
            patches = [{"id": "KB-SIM-0003", "severity": "moderate", "released_days_ago": 120}]
        r.append(res("Microsoft.Compute/virtualMachines", name, "rg-lhx-app",
                     tags={"data_class": "PII" if i < 4 else "internal"},
                     diskEncryption={"osDisk": True, "dataDisks": i != 6}, backup={"enabled": i != 4,
                     "geoRedundant": True, "pairedRegion": "centralus"},
                     lastVulnScanDaysAgo=scan_age, missingPatches=patches, diagnosticSettings=DIAG,
                     x_policy_compliant=i not in (3, 4, 6, 7)))
    # NSGs
    for name, bad_port in [("nsg-lhx-web", None), ("nsg-lhx-app", None), ("nsg-lhx-data", None),
                           ("nsg-lhx-jump", 3389)]:
        rules = [{"name": "allow-https-from-agw", "direction": "Inbound", "access": "Allow",
                  "source": "10.20.1.0/24", "port": 443}]
        if bad_port:
            rules.append({"name": "temp-rdp", "direction": "Inbound", "access": "Allow",
                          "source": "*", "port": bad_port})
        r.append(res("Microsoft.Network/networkSecurityGroups", name, "rg-lhx-net", securityRules=rules,
                     x_policy_compliant=bad_port is None))
    # Web apps
    for name, https in [("app-lhx-portal", True), ("app-lhx-broker", True), ("app-lhx-legacy", False)]:
        r.append(res("Microsoft.Web/sites", name, "rg-lhx-app", httpsOnly=https,
                     minTlsVersion="1.2" if https else "1.0", publicNetworkAccess="Disabled",
                     privateEndpointConnections=PE, diagnosticSettings=DIAG, x_policy_compliant=https))
    r.append(res("Microsoft.Network/applicationGateways", "agw-lhx-edge", "rg-lhx-net",
                 waf={"enabled": True, "mode": "Prevention"}, minProtocol="TLSv1_2", x_policy_compliant=True))
    r.append(res("Microsoft.Network/frontDoors", "afd-lhx-public", "rg-lhx-net",
                 waf={"enabled": True, "mode": "Detection"}, x_policy_compliant=False))
    # AKS
    for name, private in [("aks-lhx-api", True), ("aks-lhx-batch", False)]:
        r.append(res("Microsoft.ContainerService/managedClusters", name, "rg-lhx-app",
                     apiServerAccessProfile={"enablePrivateCluster": private}, enableRBAC=True,
                     disableLocalAccounts=private, diagnosticSettings=DIAG, x_policy_compliant=private))
    # Defender for Cloud plans
    r.append({"id": f"{SUB}/providers/Microsoft.Security/pricings", "type": "Microsoft.Security/pricings",
              "name": "defender-plans", "location": "global", "tags": {},
              "properties": {"plans": {"VirtualMachines": "Standard", "SqlServers": "Standard",
                                       "StorageAccounts": "Standard", "KeyVaults": "Standard",
                                       "Containers": "Free", "AI": "Standard", "Arm": "Standard"}}})
    # One resource with no owner tag (inventory gap)
    r.append({"id": rid("rg-lhx-dev", "Microsoft.Storage/storageAccounts", "stlhxorphan"),
              "type": "Microsoft.Storage/storageAccounts", "name": "stlhxorphan", "location": "eastus",
              "tags": {}, "properties": {"publicNetworkAccess": "Disabled", "privateEndpointConnections": PE,
                                         "minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": True,
                                         "allowSharedKeyAccess": False,
                                         "encryption": {"enabled": True, "keySource": "Microsoft.Storage"},
                                         "diagnosticSettings": DIAG, "x_policy_compliant": True}})
    return r


FIRST = ["Avery", "Blake", "Casey", "Devon", "Emery", "Finley", "Gray", "Harper", "Indy", "Jules", "Kai", "Lane",
         "Morgan", "Noel", "Oakley", "Parker", "Quinn", "Reese", "Sage", "Tatum"]
LAST = ["Ashdown", "Brookfell", "Carrow", "Dunmere", "Elstow", "Fenwick", "Greywater", "Holloway"]


def directory() -> dict:
    rng = random.Random(20261031)
    users = []
    for i in range(40):
        name = f"{FIRST[i % 20]} {LAST[i % 8]}"
        upn = f"user{i:03d}@lakehaven-hx.example"
        last = rng.choice([1, 2, 3, 5, 8, 13, 21, 30, 44])
        users.append({"id": f"u-{i:03d}", "displayName": name, "upn": upn, "type": "Member",
                      "enabled": True, "lastSignInDaysAgo": last, "groups": ["grp-exchange-staff"]})
    users[7]["lastSignInDaysAgo"] = 75          # inactive but still enabled -> AC-02(03) failure
    users[19]["lastSignInDaysAgo"] = 91
    users[22]["enabled"] = False
    users[22]["lastSignInDaysAgo"] = 120          # inactive and disabled -> fine
    users.append({"id": "g-001", "displayName": "Vendor Guest", "upn": "guest001@vendor.example", "type": "Guest",
                  "enabled": True, "lastSignInDaysAgo": 4, "groups": ["grp-pii-readers"]})
    users.append({"id": "g-002", "displayName": "Auditor Guest", "upn": "guest002@audit.example", "type": "Guest",
                  "enabled": True, "lastSignInDaysAgo": 2, "groups": ["grp-audit-readonly"]})
    return {
        "tenant": "lakehaven-hx.example",
        "users": users,
        "pii_groups": ["grp-pii-readers"],
        "conditionalAccess": [
            {"name": "CA01-require-mfa-all-users", "state": "enabled", "users": "All", "grant": ["mfa"]},
            {"name": "CA02-block-legacy-auth", "state": "enabled", "users": "All", "clientApps": ["legacy"],
             "grant": ["block"]},
            {"name": "CA03-admin-phishing-resistant", "state": "enabled", "users": "DirectoryRoles",
             "grant": ["authStrength:phishingResistant"]},
        ],
        "sessionControls": {"signInFrequencyMinutes": 720, "idleTimeoutMinutes": 15},
        "lockout": {"threshold": 5, "windowMinutes": 15, "durationMinutes": 30},
        "roleAssignments": [
            {"principal": "u-001", "role": "Global Administrator", "type": "Eligible"},
            {"principal": "u-002", "role": "Security Administrator", "type": "Eligible"},
            {"principal": "u-003", "role": "Global Administrator", "type": "Active-Permanent"},
            {"principal": "u-004", "role": "Reader", "type": "Active-Permanent"},
        ],
    }


def main() -> None:
    out = ROOT / "data" / "estate"
    out.mkdir(parents=True, exist_ok=True)
    (out / "azure_resources.json").write_text(json.dumps(estate(), indent=1) + "\n")
    (out / "directory.json").write_text(json.dumps(directory(), indent=1) + "\n")
    print(f"wrote {len(estate())} resources and {len(directory()['users'])} directory users")


if __name__ == "__main__":
    main()
