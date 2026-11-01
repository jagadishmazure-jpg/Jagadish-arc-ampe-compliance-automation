variable "subscription_id" {
  description = "Subscription to assign the ARC-AMPE initiative to (/subscriptions/<guid>)."
  type        = string

  validation {
    condition     = can(regex("^/subscriptions/[0-9a-f-]{36}$", var.subscription_id))
    error_message = "subscription_id must look like /subscriptions/<guid>."
  }
}

variable "effect" {
  description = "Policy effect for every rule: start with Audit, move to Deny after review."
  type        = string
  default     = "Audit"

  validation {
    condition     = contains(["Audit", "Deny", "Disabled"], var.effect)
    error_message = "effect must be Audit, Deny or Disabled."
  }
}

# Must match arcampe.params.US_REGIONS; a pytest checks this.
variable "allowed_locations" {
  description = "U.S. regions allowed by SA-09(05)."
  type        = list(string)
  default = [
    "centralus", "eastus", "eastus2", "northcentralus", "southcentralus", "usgovarizona",
    "usgovtexas", "usgovvirginia", "westcentralus", "westus", "westus2", "westus3",
  ]
}
