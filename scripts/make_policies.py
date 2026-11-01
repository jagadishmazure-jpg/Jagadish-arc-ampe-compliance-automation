"""Write the Azure Policy rule files that Bicep and Terraform both load (single source of truth).

Each rule mirrors one offline check in arcampe/checks/registry.py, so the same requirement is
tested in Python (simulated estate) and enforced by Azure Policy (when someone deploys it).
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from arcampe.params import US_REGIONS  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent.parent / "policies" / "azure-policy"
EFFECT = {"type": "String", "allowedValues": ["Audit", "Deny", "Disabled"], "defaultValue": "Audit",
          "metadata": {"displayName": "Effect"}}
ST = "Microsoft.Storage/storageAccounts"


def rule(name, display, check, controls, cond, resource_type=None, extra_params=None, mode="Indexed"):
    allof = ([{"field": "type", "equals": resource_type}] if resource_type else []) + cond
    return name, {
        "displayName": display, "mode": mode,
        "metadata": {"category": "ARC-AMPE (synthetic demo)", "version": "1.0.0", "arcampeCheck": check,
                     "controls": controls},
        "parameters": {**(extra_params or {}), "effect": EFFECT},
        "policyRule": {"if": {"allOf": allof}, "then": {"effect": "[parameters('effect')]"}},
    }


RULES = [
    rule("arcampe-us-locations", "ARC-AMPE: resources stay in U.S. regions", "AZ-03", ["SA-09(05)"],
         [{"field": "location", "notIn": "[parameters('allowedLocations')]"},
          {"field": "location", "notEquals": "global"}],
         extra_params={"allowedLocations": {"type": "Array", "defaultValue": sorted(US_REGIONS),
                                            "metadata": {"displayName": "Allowed U.S. locations",
                                                         "strongType": "location"}}}),
    rule("arcampe-storage-min-tls12", "ARC-AMPE: storage requires TLS 1.2", "AZ-04", ["SC-08", "SC-08(01)"],
         [{"field": f"{ST}/minimumTlsVersion", "notEquals": "TLS1_2"}], ST),
    rule("arcampe-storage-https-only", "ARC-AMPE: storage accepts HTTPS only", "AZ-05", ["SC-23"],
         [{"field": f"{ST}/supportsHttpsTrafficOnly", "notEquals": True}], ST),
    rule("arcampe-storage-no-public-network", "ARC-AMPE: storage public network access disabled", "AZ-01",
         ["SC-07", "AC-04"], [{"field": f"{ST}/publicNetworkAccess", "notEquals": "Disabled"}], ST),
    rule("arcampe-storage-no-shared-key", "ARC-AMPE: storage shared key access disabled", "AZ-11",
         ["IA-02", "AC-03"], [{"field": f"{ST}/allowSharedKeyAccess", "notEquals": False}], ST),
    rule("arcampe-kv-purge-protection", "ARC-AMPE: Key Vault purge protection on", "AZ-08", ["SC-12"],
         [{"anyOf": [{"field": "Microsoft.KeyVault/vaults/enablePurgeProtection", "exists": False},
                     {"field": "Microsoft.KeyVault/vaults/enablePurgeProtection", "notEquals": True}]}],
         "Microsoft.KeyVault/vaults"),
]

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, body in RULES:
        (OUT / f"{name}.json").write_text(json.dumps(body, indent=2) + "\n")
    print(f"wrote {len(RULES)} policy files to {OUT}")
