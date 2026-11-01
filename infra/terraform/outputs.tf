output "policy_definition_names" {
  description = "Names of the ARC-AMPE policy definitions."
  value       = sort(keys(azurerm_policy_definition.rule))
}

output "initiative_id" {
  description = "ID of the ARC-AMPE initiative."
  value       = azurerm_policy_set_definition.arcampe.id
}
