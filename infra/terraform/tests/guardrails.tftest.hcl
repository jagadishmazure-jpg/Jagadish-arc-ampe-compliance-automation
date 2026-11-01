# Offline plan with a mocked provider: no Azure credentials, nothing created.
mock_provider "azurerm" {}

variables {
  subscription_id = "/subscriptions/00000000-0000-0000-0000-000000000000"
}

run "plan_all_rules" {
  command = plan

  assert {
    condition     = length(azurerm_policy_definition.rule) == 6
    error_message = "expected 6 ARC-AMPE policy definitions"
  }
  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.arcampe.parameters).effect.value == "Audit"
    error_message = "default effect must be Audit"
  }
  assert {
    condition     = !contains(var.allowed_locations, "canadacentral")
    error_message = "only U.S. regions are allowed"
  }
}

run "bad_effect_rejected" {
  command = plan
  variables {
    effect = "Allow"
  }
  expect_failures = [var.effect]
}
