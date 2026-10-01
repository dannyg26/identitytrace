# Threat Model & Attack Scenario Catalog

Summarized from the project blueprint (§4) as this project's own working
reference - the vocabulary here (`device_code`, `oauth_consent`, `repo_enum`,
`bulk_clone`, etc.) is what later detections and correlation rules target.

IdentityTrace assumes the attacker has obtained or abused a legitimate
authentication path and attempts to use trusted access to reach SaaS,
developer, or cloud resources. The platform detects the behavioral
consequences of identity compromise, including cases where authentication
itself appears successful.

## Protected entities

- Human user identities
- Privileged / administrator identities
- Service principals and OAuth applications
- Sessions and access tokens
- Developer accounts and personal access tokens
- SaaS resources, repositories, files, and sensitive data stores
- Identity-provider configuration and role assignments

## Required attack scenarios (A1-A6)

| ID | Adversary story | Key evidence |
|---|---|---|
| A1 - Device-code phishing | A user completes a legitimate device-code authentication that is then used from attacker-controlled infrastructure. | New/unfamiliar IP or device; device-code flow; session used rapidly against SaaS or developer resources; unusual resource access. |
| A2 - Malicious OAuth consent | A compromised or socially engineered user authorizes an application with risky permissions. | New app; unusual publisher/app; high-risk scopes; `offline_access`; follow-on API activity; resource access. |
| A3 - Session/token theft | A stolen session cookie or token is reused without a fresh password challenge. | Session reuse from new network/device context; impossible/improbable travel; abrupt behavior change; no expected interactive-auth sequence. |
| A4 - Developer token compromise | A GitHub-like personal access token is used by an attacker. | Unusual source infrastructure; repository enumeration; access to sensitive/config repos; large clone/download volume; secret-oriented paths. |
| A5 - Identity privilege escalation | A compromised identity gains or grants elevated permissions. | New role assignment; high privilege; policy/security change; subsequent access to sensitive resources. |
| A6 - SaaS data theft | A compromised identity uses legitimate APIs or sessions to collect data. | Volume anomaly; unusual resource types; rare API patterns; rapid access after new session/app/token; bulk download/exfil behavior. |

## Detection coverage

The detection library and correlation engine implement checks against these scenarios.
The catalog describes intended evidence requirements; actual coverage depends on the
available telemetry. Fields such as `auth_protocol`, `permissions`, `bytes_transferred`,
and `raw_event_ref` connect normalized events to that evidence. See the
[detection library](detections.md) and [evaluation](evaluation.md) for implemented
rules, measured coverage, false positives, and missed attacks.
