// ARC-AMPE guardrails as Azure Policy, at subscription scope. Parity with ../terraform: both load
// the same rule files from ../../policies/azure-policy. Creates no billable resources.
targetScope = 'subscription'

@allowed([
  'Audit'
  'Deny'
  'Disabled'
])
@description('Policy effect for every rule: start with Audit, move to Deny after review.')
param effect string = 'Audit'

// Must match arcampe.params.US_REGIONS; a pytest checks this.
@description('U.S. regions allowed by SA-09(05).')
param allowedLocations array = [
  'centralus'
  'eastus'
  'eastus2'
  'northcentralus'
  'southcentralus'
  'usgovarizona'
  'usgovtexas'
  'usgovvirginia'
  'westcentralus'
  'westus'
  'westus2'
  'westus3'
]

var rules = [
  { name: 'arcampe-kv-purge-protection', body: loadJsonContent('../../policies/azure-policy/arcampe-kv-purge-protection.json') }
  { name: 'arcampe-storage-https-only', body: loadJsonContent('../../policies/azure-policy/arcampe-storage-https-only.json') }
  { name: 'arcampe-storage-min-tls12', body: loadJsonContent('../../policies/azure-policy/arcampe-storage-min-tls12.json') }
  { name: 'arcampe-storage-no-public-network', body: loadJsonContent('../../policies/azure-policy/arcampe-storage-no-public-network.json') }
  { name: 'arcampe-storage-no-shared-key', body: loadJsonContent('../../policies/azure-policy/arcampe-storage-no-shared-key.json') }
  { name: 'arcampe-us-locations', body: loadJsonContent('../../policies/azure-policy/arcampe-us-locations.json') }
]

resource defs 'Microsoft.Authorization/policyDefinitions@2023-04-01' = [for r in rules: {
  name: r.name
  properties: {
    policyType: 'Custom'
    mode: r.body.mode
    displayName: r.body.displayName
    metadata: r.body.metadata
    parameters: r.body.parameters
    policyRule: r.body.policyRule
  }
}]

resource initiative 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: 'arcampe-guardrails'
  properties: {
    policyType: 'Custom'
    displayName: 'ARC-AMPE guardrails (synthetic demo)'
    metadata: {
      category: 'ARC-AMPE (synthetic demo)'
      version: '1.0.0'
    }
    parameters: {
      effect: {
        type: 'String'
        allowedValues: [
          'Audit'
          'Deny'
          'Disabled'
        ]
        defaultValue: 'Audit'
      }
      allowedLocations: {
        type: 'Array'
      }
    }
    policyDefinitions: [for (r, i) in rules: {
      policyDefinitionId: defs[i].id
      policyDefinitionReferenceId: r.name
      parameters: r.name == 'arcampe-us-locations' ? {
        effect: { value: '[parameters(\'effect\')]' }
        allowedLocations: { value: '[parameters(\'allowedLocations\')]' }
      } : {
        effect: { value: '[parameters(\'effect\')]' }
      }
    }]
  }
}

resource assignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'arcampe-guardrails'
  properties: {
    policyDefinitionId: initiative.id
    parameters: {
      effect: { value: effect }
      allowedLocations: { value: allowedLocations }
    }
  }
}

output initiativeId string = initiative.id
output policyCount int = length(rules)
