# Raw event -> normalized event -> detection evidence

One real event, traced through every stage of the pipeline
(`app/pipeline.py`: normalize -> baseline -> persist/detect -> correlate), computed by actually
running `app/normalizers/entra.normalize()` and
`app/detections/engine.evaluate_event()` against the real record - nothing
below is written by hand. It is the admin-consent grant step from the real
A2 benign twin (docs/evaluation.md, "A2 Benign Twin — Detection vs Intent"),
chosen because it also demonstrates the scope-delta fix: the grant's
cumulative scope includes four risky-looking permissions, but only one of
them (`Mail.ReadWrite`) was actually added by *this* event, and that is the
only one detection sees.

**Identifiers are redacted for this public artifact** (tenant domain, IPs,
the tenant-specific service principal IDs, the event's own ID) using the
artifact-local placeholder conventions used in `evidence_pack/` and
`docs/evidence/`'s other screenshots (aliases can differ across artifacts) - see `docs/evidence-pack.md`. Nothing else was changed;
this is the real record.

## 1. Raw Entra audit event (`GET /auditLogs/directoryAudits`)

```json
{
  "id": "evt-demo-twin-grant",
  "category": "ApplicationManagement",
  "correlationId": "corr-demo-twin-grant",
  "result": "success",
  "resultReason": "",
  "activityDisplayName": "Add delegated permission grant",
  "activityDateTime": "2026-09-21T16:36:34.6036619Z",
  "loggedByService": "Core Directory",
  "operationType": "Assign",
  "initiatedBy": {
    "app": null,
    "user": {
      "id": "evt-demo-002",
      "displayName": "Azure ESTS Service",
      "userPrincipalName": "idt-admin@exampletenant.onmicrosoft.com",
      "ipAddress": "203.0.113.31",
      "userType": null,
      "agentType": "notAgentic",
      "homeTenantId": null,
      "homeTenantName": null
    }
  },
  "targetResources": [
    {
      "id": "sp-demo-graph",
      "displayName": "Microsoft Graph",
      "type": "ServicePrincipal",
      "userPrincipalName": null,
      "groupType": null,
      "modifiedProperties": [
        {
          "displayName": "DelegatedPermissionGrant.Scope",
          "oldValue": "\" AppRegistration.Create AuditLog.Read.All RoleManagement.ReadWrite.Directory User.Create User.ReadUpdate.All offline_access openid profile User.Read Files.Read.All Mail.Read\"",
          "newValue": "\" AppRegistration.Create AuditLog.Read.All RoleManagement.ReadWrite.Directory User.Create User.ReadUpdate.All offline_access openid profile User.Read Files.Read.All Mail.Read Mail.ReadWrite\""
        },
        {
          "displayName": "DelegatedPermissionGrant.ConsentType",
          "oldValue": "\"AllPrincipals\"",
          "newValue": "\"AllPrincipals\""
        },
        {
          "displayName": "ServicePrincipal.ObjectID",
          "oldValue": null,
          "newValue": "\"sp-demo-001\""
        },
        { "displayName": "ServicePrincipal.DisplayName", "oldValue": null, "newValue": null },
        { "displayName": "ServicePrincipal.AppId", "oldValue": null, "newValue": null },
        { "displayName": "ServicePrincipal.Name", "oldValue": null, "newValue": null },
        {
          "displayName": "TargetId.ServicePrincipalNames",
          "oldValue": null,
          "newValue": "\"00000003-0000-0000-c000-000000000000/ags.windows.net;00000003-0000-0000-c000-000000000000;https://canary.graph.microsoft.com;https://graph.microsoft.com;https://ags.windows.net;https://graph.microsoft.us;https://graph.microsoft.com/;https://dod-graph.microsoft.us;https://canary.graph.microsoft.com/;https://graph.microsoft.us/;https://dod-graph.microsoft.us/\""
        }
      ]
    },
    { "id": "sp-demo-001", "displayName": null, "type": "ServicePrincipal", "userPrincipalName": null, "groupType": null, "modifiedProperties": [] }
  ],
  "additionalDetails": [
    { "key": "User-Agent", "value": "EvoSTS" },
    { "key": "AppId", "value": "00000003-0000-0000-c000-000000000000" },
    { "key": "ServicePrincipalProvisioningType", "value": "Other" }
  ]
}
```

`00000003-0000-0000-c000-000000000000` is Microsoft Graph's universal,
public application ID (identical in every tenant) - not redacted, because
it identifies nothing about this tenant.

## 2. Normalized IdentityTrace event (`app/normalizers/entra.normalize()`)

```json
{
  "event_id": "evt-demo-twin-grant",
  "timestamp": "2026-09-21T16:36:34.603661Z",
  "source": "entra",
  "event_type": "oauth_consent",
  "action": "Add delegated permission grant",
  "result": "success",
  "actor_id": "idt-admin@exampletenant.onmicrosoft.com",
  "actor_type": "user",
  "session_id": null,
  "device_id": null,
  "ip_address": "203.0.113.31",
  "geo_country": null,
  "user_agent": null,
  "auth_protocol": null,
  "mfa_result": null,
  "app_id": null,
  "service_principal_id": "sp-demo-001",
  "permissions": ["Mail.ReadWrite"],
  "resource_id": null,
  "resource_type": null,
  "bytes_transferred": null
}
```

**Note `permissions`.** The raw event's `DelegatedPermissionGrant.Scope`
`newValue` lists twelve scopes, including `Mail.Read` and `Files.Read.All`.
The normalizer computes `newValue - oldValue` (see docs/evaluation.md, "A2
Benign Twin — Detection vs Intent"), so only `Mail.ReadWrite` - what this
specific event actually granted - reaches detection. `oldValue` and
`newValue` above are still both present, verbatim, for anyone who wants to
verify that arithmetic by hand.

## 3. Detection evidence (`app/detections/engine.evaluate_event()`)

```json
[
  {
    "rule_id": "IDT-ENTRA-001",
    "title": "Risky OAuth consent scope granted",
    "score": 35,
    "severity": "medium",
    "signal": "risky_oauth_consent",
    "reasons": [
      "permissions includes ['Mail.ReadWrite'] (from ['Mail.Read', 'Mail.ReadWrite', 'Files.Read.All', 'Directory.ReadWrite.All'])"
    ]
  }
]
```

`IDT-ENTRA-002` (the heavier `offline_access` rule, weight 45) does **not**
fire here - `offline_access` is in the grant's cumulative scope, but it was
granted by an earlier event, not this one. This is the exact effect the
scope-delta fix produces on real data, shown at the single-event level
rather than as an aggregate metric.

From here, `risky_oauth_consent` is one signal in `IDT-CORR-006`'s 3-step
sequence - see `docs/evidence/01-real-a2-workflow.png` / `02-a2-benign-twin.png`
for the resulting incident.
