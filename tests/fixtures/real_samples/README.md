# Real-schema fixtures

Every field name and enum value in these files is checked against each
source's **real, officially-published API schema** - not invented for
this project's own convenience. Sources:

- **Entra (`entra_*.json`)**: Microsoft Graph API v1.0/beta resource docs -
  [`signIn`](https://learn.microsoft.com/en-us/graph/api/resources/signin),
  [`directoryAudit`](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit),
  [`deviceDetail`](https://learn.microsoft.com/en-us/graph/api/resources/devicedetail),
  [`signInLocation`](https://learn.microsoft.com/en-us/graph/api/resources/signinlocation),
  [`targetResource`](https://learn.microsoft.com/en-us/graph/api/resources/targetresource),
  [`auditActivityInitiator`](https://learn.microsoft.com/en-us/graph/api/resources/auditactivityinitiator).
  Checked 2026-09-10. `modifiedProperty`'s own `displayName`/`oldValue`/
  `newValue` shape is the widely-documented real form (used in Microsoft's
  own audit log walkthroughs) but wasn't independently re-verified via a
  fetched schema page in this pass - flagged so this claim isn't overstated.
- **GitHub (`github_*.json`)**: GitHub's documented enterprise audit log
  schema (`@timestamp`, `action`, `actor`, `actor_id`, `actor_location`,
  `_document_id`, `org`, `repo`) plus its "Authentication Metadata for Git
  Events" feature (`hashed_token`, `programmatic_access_type`, `token_id`) -
  [docs.github.com/.../rest/enterprise-admin/audit-log](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log),
  [github.blog/changelog/2023-09-27-authentication-metadata-for-git-events-public-beta](https://github.blog/changelog/2023-09-27-authentication-metadata-for-git-events-public-beta/).
- **M365 (`m365_*.json`)**: Office 365 Management Activity API common
  schema (`CreationTime`, `Operation`, `Workload`, `UserId`, `ClientIP`,
  `ResultStatus`, `ObjectId`) -
  [learn.microsoft.com/.../office-365-management-activity-api-schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema).

None of the official docs publish full realistic example payloads with
plausible field *values* (they publish schemas/property tables, not
worked examples) - the values here (names, IPs, app names, etc.) are
invented for readability, but every **field name and enum value** is real.

This check surfaced two real bugs in this project's normalizers, both
fixed as part of this pass:

1. `app/normalizers/github.py` read `actor_location.country_code`; GitHub's
   real field is `country_name`.
2. `app/normalizers/entra.py` relied solely on `mfaDetail.result`, a
   documented-deprecated field; added `authenticationRequirement` as the
   documented modern replacement, with `mfaDetail` still checked first for
   backward compatibility.

And one real gap this project's own schema already had a fix for but
never used: `app/normalizers/m365.py` collapsed the real `ResultStatus:
"PartiallySucceeded"` value into `"failure"` instead of using this
project's own `result="partial"`, which existed in the schema
(`app/models/event.py`) unused by any normalizer until now.
