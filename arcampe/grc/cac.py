"""Compliance as code: fix suggestions for failing checks, and a pipeline gate.

suggest() turns each failing Azure/identity finding into a Terraform-style patch an engineer can review.
It is a SUGGESTION: nothing is applied, and the patch text only uses values from this repo's parameters.
gate() compares a pull request's findings with the main-branch baseline and fails only when the change
introduces a NEW failing finding at or above the blocking severity (so old debt does not block every PR,
but nothing new slips in). Each result names who may override the gate (a human, with a reason).
"""
from __future__ import annotations

from ..checks.base import SEVERITIES

FIXES: dict[str, tuple[str, str]] = {  # check id -> (terraform attribute, value)
    "AZ-01": ("public_network_access_enabled", "false"),
    "AZ-02": ("private_endpoint", "required (azurerm_private_endpoint)"),
    "AZ-03": ("location", '"eastus2"'),
    "AZ-04": ("min_tls_version", '"TLS1_2"'),
    "AZ-05": ("https_only", "true"),
    "AZ-06": ("infrastructure_encryption_enabled", "true"),
    "AZ-07": ("customer_managed_key", "key_vault_key_id = azurerm_key_vault_key.cmk.id"),
    "AZ-08": ("purge_protection_enabled", "true"),
    "AZ-09": ("azurerm_monitor_diagnostic_setting", "log_analytics_workspace_id = var.sec_workspace_id"),
    "AZ-10": ("retention_in_days", "90"),
    "AZ-11": ("shared_access_key_enabled", "false"),
    "AZ-12": ("local_authentication_enabled", "false"),
    "AZ-13": ("security_rule.source_address_prefix", '"VirtualNetwork"'),
    "AZ-14": ("azurerm_security_center_subscription_pricing.tier", '"Standard"'),
    "AZ-15": ("geo_backup_enabled", "true"),
    "AZ-16": ("azurerm_mssql_server_extended_auditing_policy", "enabled = true"),
    "AZ-17": ("waf_configuration.firewall_mode", '"Prevention"'),
    "AZ-20": ("api_server_access_profile.authorized_ip_ranges", "[] # private cluster"),
    "AZ-21": ("tags", '{ owner = "...", data_class = "..." }'),
    "ID-01": ("conditional_access_policy.grant_controls", '["mfa"]'),
    "ID-02": ("authentication_strength_policy", '"phishing-resistant"'),
    "ID-03": ("conditional_access_policy.client_app_types", '["exchangeActiveSync", "other"] -> block'),
}
MANUAL = {"AZ-18": "run the vulnerability scan job", "AZ-19": "apply pending patches in the maintenance window",
          "AZ-22": "fix the specific policy that is non-compliant"}


def suggest(findings) -> list[dict]:
    out = []
    for f in findings:
        if f.passed:
            continue
        if f.check_id in FIXES:
            attr, val = FIXES[f.check_id]
            out.append({"check": f.check_id, "resource": f.resource_name, "severity": f.severity, "kind": "patch",
                        "patch": f"# {f.resource_name}: {f.detail}\n{attr} = {val}", "applied": False})
        elif f.check_id in MANUAL:
            out.append({"check": f.check_id, "resource": f.resource_name, "severity": f.severity, "kind": "manual",
                        "patch": MANUAL[f.check_id], "applied": False})
    return out


def _key(f) -> tuple[str, str]:
    return (f.check_id, f.resource_id)


def gate(baseline, current, block_at: str = "high") -> dict:
    if block_at not in SEVERITIES:
        raise ValueError(block_at)
    limit = SEVERITIES.index(block_at)
    old = {_key(f) for f in baseline if not f.passed}
    new_fail = [f for f in current if not f.passed and _key(f) not in old]
    fixed = old - {_key(f) for f in current if not f.passed}
    blocking = [f for f in new_fail if SEVERITIES.index(f.severity) <= limit]
    return {"result": "fail" if blocking else "pass", "new_failures": len(new_fail), "blocking": len(blocking),
            "fixed": len(fixed), "blocking_ids": sorted(f"{f.check_id}:{f.resource_name}" for f in blocking),
            "override": "security lead, with a written reason (logged)"}


def demo() -> dict:
    """Simulate a PR that fixes the public storage account and opens an admin port on a new NSG."""
    import copy

    from ..checks import registry
    base_estate = registry.load_estate()
    base = registry.run(base_estate)
    pr = copy.deepcopy(base_estate)
    for r in pr:
        if r["name"] == "stlhxstaticweb":
            r["properties"]["publicNetworkAccess"] = "Disabled"
    pr.append({"id": "/subscriptions/x/resourceGroups/rg-lhx-new/providers/Microsoft.Network/networkSecurityGroups/nsg-new",
               "type": "Microsoft.Network/networkSecurityGroups", "name": "nsg-lhx-new", "location": "eastus2",
               "tags": {"owner": "platform-team", "data_class": "none", "env": "prod"},
               "properties": {"securityRules": [{"name": "rdp", "direction": "Inbound", "access": "Allow",
                                                  "source": "*", "port": 3389}],
                              "x_policy_compliant": True}})
    cur = registry.run(pr)
    return {"suggestions": len(suggest(base)), "gate": gate(base, cur)}
