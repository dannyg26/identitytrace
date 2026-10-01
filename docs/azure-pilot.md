# Azure pilot deployment and acceptance

Status: the pilot passed HTTPS, database readiness, interactive Entra sign-in,
and a synthetic ingestion-to-report workflow on 2026-09-29. Hosting was removed
at the owner's request on 2026-09-30; deletion of the dedicated resource group
was confirmed on 2026-10-01. This document is a redeployment guide, not a live URL.
Sustained cloud load, Azure recovery, alert delivery, and broader independent
detection accuracy have not been verified. See `docs/release-v1.3.md`.

## Proposed resources

Use a **new dedicated resource group**. The historical pilot used Canada Central. Never deploy into an existing
Sentinel resource group or any unrelated project resource group.

| Resource | Pilot configuration |
|---|---|
| App Service | Linux B1, Python 3.12, one worker, always on |
| Public address | Azure-provided `https://<app>.azurewebsites.net`; managed TLS |
| PostgreSQL | Flexible Server 17, B1ms, 32 GB, private subnet, no public access |
| Networking | Dedicated VNet, delegated app/database subnets, private DNS |
| Backups | Managed automatic backups, 14-day retention; restore drill required |
| Monitoring | 5xx count, app health, database CPU and storage metric alerts |
| Cost alerts | Monthly $40 budget, actual 80% and forecast 100% notifications |
| Secrets | Secure deployment parameters and encrypted App Service settings; private ephemeral files at runtime |

This is a small **single-instance pilot**, with no zone failover, autoscaling, WAF,
long-term backup vault or centralized application log analytics. Metric alerts do
not replace an external uptime probe; missing samples may not trigger an alert.
Backups do not establish recovery performance until a restore has been tested.
Storage growth is disabled to make expansion deliberate; respond before storage fills.
Azure operators who can read app configuration can access its secrets. Limit their
RBAC access. Normal runtime does not need the database administrator password.
The temporary bootstrap path used during the pilot requires it only during
provisioning; remove it and both bootstrap/provisioning flags before normal use.

## Cost estimate

Microsoft Retail Prices API checked 2026-09-29, Canada Central, USD, consumption rates:

| Item | Calculation | Estimated monthly cost |
|---|---|---:|
| App Service Linux B1 | 730 hours x $0.018 | $13.14 |
| PostgreSQL B1ms compute | 730 hours x $0.0185 | $13.51 |
| PostgreSQL storage | 32 GB x $0.1265 | $4.05 |
| Core subtotal (before line-item rounding) | | **$30.69** |
| Private DNS, alert rules, traffic, backup overage, taxes | Usage-dependent; not priced into subtotal | Additional |

Plan for roughly **$35–45/month** for a lightly used pilot, not a guaranteed quote
or ceiling. Restore drills temporarily add another database server and storage.
The $40 budget only sends alerts; **it does not stop charges**. Do not deploy until
the owner approves recurring spend and the chosen alert recipient. Check quota,
regional SKU availability and current prices again immediately before provisioning.

## Deployment procedure

1. Pin all hosting commands to your chosen subscription and hosting tenant.
   Check that the subscription is enabled and preserve any spending limit.
   Application authentication may use a different Entra tenant: keep its Azure
   CLI configuration separate, verify the token tenant before Graph writes, and
   do not modify unrelated organizations' application registrations.
2. Use dedicated resource group `rg-identitytrace-pilot`. Its metadata location is
   West US 2, but the actual app, network and database resources use **Canada Central**.
   West US 2 rejected B1 quota; East US passed template validation but PostgreSQL
   creation failed because of subscription-offer restrictions. The empty East US
   hosting plan and network were removed before retrying in Canada Central.
   Run `python infra/azure/check_region.py --subscription <id> --location <region>`
   before ARM validation. This checks actual PostgreSQL version/SKU capabilities;
   it does not replace App Service quota checks. Existing projects remain untouched.
3. Supply `infra/azure/main.bicep` parameters through a protected local parameters
   file, never command-line literal secrets or a committed file. Use separate random
   database administrator and application passwords (at least 32 characters), the
   existing Entra web client secret and persistent session secret. Set tenant ID,
   API client ID, browser client ID, alert email and the first day of the current
   month as `budgetStartDate`. Budget currency follows the subscription billing currency;
   recheck the amount if it is not USD.
4. Run `az deployment group validate` and `az deployment group what-if` against
   this resource group with the parameter file. Inspect the changes; do not print
   app settings, passwords, raw deployment debug logs or secret parameter files.
   Bicep compilation alone cannot verify subscription permissions, quota or runtime support.
5. Deploy with `az deployment group create`. Use deployment outputs to obtain the
   actual hostname; never guess it. The template enables **provisioning mode**,
   which returns HTTP 503 and exposes no application routes until bootstrap completes.
6. Build the source ZIP with `python infra/azure/package.py <new-file.zip>` and
   deploy it with `az webapp deploy --resource-group rg-identitytrace-pilot --name
   <output-webAppName> --src-path <zip> --type zip`. Azure CLI must support Entra
   authentication to SCM; basic publishing and FTP authentication are disabled.
   Confirm Oryx installed `requirements.txt` into the runtime virtual environment.
7. Open an authenticated App Service SSH operator session (inside its VNet).
   Activate the Oryx application environment and change to the deployed source root.
   Run `python -m infra.azure.bootstrap_database`; enter the database administrator
   password at its no-echo prompt. It creates a restricted application role,
   migrates using that role and permanently binds the database to the tenant.
   This script intentionally refuses an existing role: if interrupted, inspect
   the migration state and recover deliberately, rather than rerunning role creation.
   Do not place the admin password in application settings or retain it on the worker.
8. Add the exact deployment-output redirect URI to **IdentityTrace Web** in Entra,
   preserving any other approved redirects. This is a real app registration update,
   not merely changing a local JSON file. Keep both apps single-tenant, with user
   assignment required and separate API/browser audiences.
9. Delete the `IDENTITYTRACE_AZURE_PROVISIONING` app setting and restart the web app.
   Verify startup, readiness and all acceptance checks below. A future template
   redeployment re-enables provisioning mode intentionally; plan a maintenance window
   and remove it again after checks. Do not run schema upgrades on application startup.

## Required acceptance evidence before calling this live

| Check | Required evidence |
|---|---|
| HTTPS | Valid public certificate; HTTP redirects to HTTPS; no insecure app route |
| Readiness | `/ready` 200 against PostgreSQL with the correct schema/tenant binding |
| Actual Entra login | Assigned user completes authorization-code/PKCE callback and opens incidents |
| Denial checks | Unassigned user denied; wrong tenant/audience/role denied; logout revokes session |
| Browser security | Secure HttpOnly cookies, no provider tokens in browser storage or logs |
| Database | Public network disabled; worker validates server TLS; runtime role has no superuser/create-role privileges |
| Alert delivery | Deliberately test action group to the approved recipient and record receipt; restore thresholds afterward |
| Recovery | Point-in-time restore to a separate private server; compare row counts/content hashes and tenant/schema; measure recovery time |
| Sustained load | On isolated synthetic data: staged 1/4/8 concurrent clients, then 60-minute soak; collect throughput, p50/p95/p99, errors, 429s, CPU/memory/connections |
| Detection accuracy | Frozen independently labeled real corpus, source coverage, false positives/negatives and confidence intervals |

Load testing must include authenticated ingestion and incident reads, not just `/health`.
Define pass criteria before the run (initial pilot target: no data loss/5xx, read p95
under 1 second, ingestion p95 under 3 seconds at the agreed event rate). Report achieved
capacity and rate-limited requests separately. A short local lab does not pass a soak test.
Run tests on a dedicated tenant-bound test database with a restricted synthetic-data
ingestor, not against a customer's real investigation history. Export the final
summary without tokens, incident contents or raw identities.

For restore drills, retain the existing server, restore to a new name on the same
private network, validate it without switching live traffic, then remove only the
explicitly identified temporary resource after verification. Record actual recovery
point and time; do not claim a guaranteed RPO/RTO from the backup configuration alone.

There is no independently labeled real detection dataset added by this deployment.
Use `docs/independent-evaluation.md` and `scripts/evaluate_dataset.py` when a permitted
corpus and independent labels are available. Synthetic performance cannot substitute
for that evidence.

## Operations and rollback

On 5xx/unhealthy alerts: inspect App Service platform logs, readiness, database
connectivity and schema. Do not enable demo mode to bypass authentication failures.
On CPU/storage alerts: inspect demand, connections and storage before approving a
larger SKU. Treat leaked secrets as compromised: rotate and invalidate sessions.

Preserve the last known deployment ZIP and the pre-upgrade database recovery point.
For code rollback, redeploy the previous ZIP only if its schema is compatible.
For incompatible schema changes, restore to a separate server and explicitly
validate/switch the database connection; never overwrite the sole surviving database.
See `docs/operations.md` for broader operational procedures.

## Sources

- [Azure subscription states](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/subscription-states)
- [App Service FastAPI and private PostgreSQL tutorial](https://learn.microsoft.com/en-us/azure/app-service/tutorial-python-postgresql-app-fastapi)
- [PostgreSQL backup and restore](https://learn.microsoft.com/en-us/azure/postgresql/backup-restore/concepts-backup-restore)
- [Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
