# ARC-AMPE guardrails as Azure Policy. Definitions, an initiative and one assignment are free;
# this stack creates no billable resources. Rules are read from ../../policies/azure-policy/*.json,
# the same files Bicep loads. There is no deploy workflow: applying is a manual, approved step.
locals {
  dir   = "${path.module}/../../policies/azure-policy"
  rules = { for f in fileset(local.dir, "*.json") : trimsuffix(f, ".json") => jsondecode(file("${local.dir}/${f}")) }
}

resource "azurerm_policy_definition" "rule" {
  for_each     = local.rules
  name         = each.key
  policy_type  = "Custom"
  mode         = each.value.mode
  display_name = each.value.displayName
  metadata     = jsonencode(each.value.metadata)
  parameters   = jsonencode(each.value.parameters)
  policy_rule  = jsonencode(each.value.policyRule)
}

resource "azurerm_policy_set_definition" "arcampe" {
  name         = "arcampe-guardrails"
  policy_type  = "Custom"
  display_name = "ARC-AMPE guardrails (synthetic demo)"
  metadata     = jsonencode({ category = "ARC-AMPE (synthetic demo)", version = "1.0.0" })
  parameters = jsonencode({
    effect           = { type = "String", allowedValues = ["Audit", "Deny", "Disabled"], defaultValue = "Audit" }
    allowedLocations = { type = "Array" }
  })

  dynamic "policy_definition_reference" {
    for_each = azurerm_policy_definition.rule
    content {
      policy_definition_id = policy_definition_reference.value.id
      reference_id         = policy_definition_reference.key
      parameter_values = jsonencode(merge(
        { effect = { value = "[parameters('effect')]" } },
        policy_definition_reference.key == "arcampe-us-locations" ? { allowedLocations = { value = "[parameters('allowedLocations')]" } } : {}
      ))
    }
  }
}

resource "azurerm_subscription_policy_assignment" "arcampe" {
  name                 = "arcampe-guardrails"
  subscription_id      = var.subscription_id
  policy_definition_id = azurerm_policy_set_definition.arcampe.id
  parameters = jsonencode({
    effect           = { value = var.effect }
    allowedLocations = { value = var.allowed_locations }
  })
}
