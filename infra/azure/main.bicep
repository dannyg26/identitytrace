targetScope = 'resourceGroup'

@description('Use a dedicated resource group. This template creates billable pilot resources.')
param location string = resourceGroup().location
@minLength(3)
@maxLength(20)
param prefix string = 'identitytrace'
param tenantId string
param browserClientId string
param apiClientId string
@secure()
param postgresAdminPassword string
@secure()
param appDatabasePassword string
@secure()
param browserClientSecret string
@secure()
param sessionSecret string
@description('Required destination for operational alerts; no notification is sent until deployed.')
param alertEmail string
@description('First day of the deployment month, ISO 8601, e.g. 2026-09-01T00:00:00Z.')
param budgetStartDate string
@minValue(1)
param monthlyBudget int = 40

var suffix = uniqueString(resourceGroup().id)
var appName = '${prefix}-${suffix}'
var pgName = '${prefix}-pg-${suffix}'
var authority = '${environment().authentication.loginEndpoint}${tenantId}'
var commonTags = { application: 'IdentityTrace', environment: 'pilot' }

resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet-${location}'
  location: location
  tags: commonTags
  properties: {
    addressSpace: { addressPrefixes: ['10.42.0.0/16'] }
    subnets: [
      {
        name: 'web'
        properties: {
          addressPrefix: '10.42.1.0/26'
          delegations: [{ name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } }]
        }
      }
      {
        name: 'database'
        properties: {
          addressPrefix: '10.42.2.0/27'
          delegations: [{ name: 'postgres', properties: { serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers' } }]
        }
      }
    ]
  }
}
resource dns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${prefix}.postgres.database.azure.com'
  location: 'global'
  tags: commonTags
}
resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: dns
  name: 'identitytrace-vnet'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: network.id } }
}
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: pgName
  location: location
  tags: commonTags
  sku: { name: 'Standard_B1ms', tier: 'Burstable' }
  properties: {
    version: '17'
    administratorLogin: 'identitytrace_admin'
    administratorLoginPassword: postgresAdminPassword
    storage: { storageSizeGB: 32, autoGrow: 'Disabled' }
    backup: { backupRetentionDays: 14, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
    network: {
      publicNetworkAccess: 'Disabled'
      delegatedSubnetResourceId: '${network.id}/subnets/database'
      privateDnsZoneArmResourceId: dns.id
    }
  }
  dependsOn: [dnsLink]
}
resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: postgres
  name: 'identitytrace'
  properties: { charset: 'UTF8', collation: 'en_US.utf8' }
}
resource tls 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgres
  name: 'require_secure_transport'
  properties: { value: 'on', source: 'user-override' }
}
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${prefix}-plan-${location}'
  location: location
  tags: commonTags
  kind: 'linux'
  sku: { name: 'B1', tier: 'Basic', capacity: 1 }
  properties: { reserved: true }
}
resource web 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: commonTags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    virtualNetworkSubnetId: '${network.id}/subnets/web'
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      appCommandLine: 'python -m infra.azure.startup'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      healthCheckPath: '/ready'
      http20Enabled: true
      appSettings: [
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'IDENTITYTRACE_ENV', value: 'production' }
        { name: 'IDENTITYTRACE_AZURE_PROVISIONING', value: '1' }
        { name: 'IDENTITYTRACE_ORGANIZATION_ID', value: tenantId }
        { name: 'IDENTITYTRACE_PUBLIC_URL', value: 'https://${appName}.azurewebsites.net' }
        { name: 'IDENTITYTRACE_OIDC_ISSUER', value: '${authority}/v2.0' }
        { name: 'IDENTITYTRACE_OIDC_JWKS_URL', value: '${authority}/discovery/v2.0/keys' }
        { name: 'IDENTITYTRACE_OIDC_AUTHORIZE_URL', value: '${authority}/oauth2/v2.0/authorize' }
        { name: 'IDENTITYTRACE_OIDC_TOKEN_URL', value: '${authority}/oauth2/v2.0/token' }
        { name: 'IDENTITYTRACE_OIDC_CLIENT_ID', value: browserClientId }
        { name: 'IDENTITYTRACE_OIDC_AUDIENCE', value: apiClientId }
        { name: 'IDENTITYTRACE_OIDC_SCOPE', value: 'openid profile api://${apiClientId}/access_as_user' }
        { name: 'IDENTITYTRACE_OIDC_ORG_CLAIM', value: 'tid' }
        { name: 'IDENTITYTRACE_OIDC_SUBJECT_CLAIM', value: 'oid' }
        { name: 'IDENTITYTRACE_OIDC_ROLE_MAP', value: '{"IdentityTrace.Viewer":"viewer","IdentityTrace.Analyst":"analyst","IdentityTrace.Admin":"admin","IdentityTrace.Ingestor":"ingestor"}' }
        { name: 'AZURE_PG_HOST', value: postgres.properties.fullyQualifiedDomainName }
        { name: 'AZURE_APP_DB_PASSWORD', value: appDatabasePassword }
        { name: 'AZURE_OIDC_CLIENT_SECRET', value: browserClientSecret }
        { name: 'AZURE_SESSION_SECRET', value: sessionSecret }
      ]
    }
  }
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: web
  name: 'ftp'
  properties: { allow: false }
}
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: web
  name: 'scm'
  properties: { allow: false }
}
resource actions 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${prefix}-operations'
  location: 'global'
  properties: {
    groupShortName: 'IDTrace'
    enabled: true
    emailReceivers: [{ name: 'owner', emailAddress: alertEmail, useCommonAlertSchema: true }]
  }
}
var alertRules = [
  { name: 'http-5xx', scope: web.id, namespace: 'Microsoft.Web/sites', metric: 'Http5xx', aggregation: 'Total', threshold: 5 }
  { name: 'unhealthy-app', scope: web.id, namespace: 'Microsoft.Web/sites', metric: 'HealthCheckStatus', aggregation: 'Average', threshold: 1 }
  { name: 'database-storage', scope: postgres.id, namespace: 'Microsoft.DBforPostgreSQL/flexibleServers', metric: 'storage_percent', aggregation: 'Average', threshold: 80 }
  { name: 'database-cpu', scope: postgres.id, namespace: 'Microsoft.DBforPostgreSQL/flexibleServers', metric: 'cpu_percent', aggregation: 'Average', threshold: 85 }
]
resource alerts 'Microsoft.Insights/metricAlerts@2018-03-01' = [for rule in alertRules: {
  name: '${prefix}-${rule.name}'
  location: 'global'
  properties: {
    description: 'IdentityTrace pilot: ${rule.name}. Follow docs/azure-pilot.md.'
    severity: 2
    enabled: true
    scopes: [rule.scope]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    autoMitigate: true
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [{
        name: rule.name
        metricName: rule.metric
        metricNamespace: rule.namespace
        operator: rule.name == 'unhealthy-app' ? 'LessThan' : 'GreaterThanOrEqual'
        threshold: rule.threshold
        timeAggregation: rule.aggregation
        criterionType: 'StaticThresholdCriterion'
      }]
    }
    actions: [{ actionGroupId: actions.id }]
  }
}]

output publicUrl string = 'https://${web.properties.defaultHostName}'
output redirectUri string = 'https://${web.properties.defaultHostName}/auth/callback'
output postgresHost string = postgres.properties.fullyQualifiedDomainName
output webAppName string = web.name

// Budget notifications are delayed alerts, never a spending cap or shutdown policy.
resource budget 'Microsoft.Consumption/budgets@2023-05-01' = {
  name: '${prefix}-monthly'
  properties: {
    category: 'Cost'
    amount: monthlyBudget
    timeGrain: 'Monthly'
    timePeriod: { startDate: budgetStartDate }
    notifications: {
      actual80: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [alertEmail]
      }
    }
  }
}
