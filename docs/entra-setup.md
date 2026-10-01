# Microsoft Entra deployment

Version 1.3 includes server-side authorization-code sign-in with S256 PKCE. Use
two **single-tenant** registrations in your existing workforce tenant: a Web
browser client and an IdentityTrace API. No registrations are created by the code.

## Registration values

| Value | Where it is used |
| --- | --- |
| Directory (tenant) ID | Pinned issuer, JWKS endpoint and database organization binding |
| Web application's client ID | ID-token audience and authorization-code exchange |
| API application's client ID | Access-token audience; must differ from the Web client ID |
| Public HTTPS origin | Exact callback origin, such as `https://identity.example.com` |
| Web application's client secret | Local protected file, never chat, git or browser storage |

1. In the API registration, set `api.requestedAccessTokenVersion` to `2` in
   the Microsoft Graph-format manifest. Expose `api://API-CLIENT-ID/access_as_user`
   as a delegated scope. This scope belongs to IdentityTrace, not Microsoft Graph.
2. Define API app roles `IdentityTrace.Viewer`, `IdentityTrace.Analyst` and
   `IdentityTrace.Admin` for users/groups. Define `IdentityTrace.Ingestor` for
   applications if using unattended collectors. Assign each principal exactly one
   mapped role on the **API enterprise application**. An unassigned user receives
   no app access; two different mapped roles are rejected instead of combined.
3. Register the Web client with the exact Web redirect URI
   `https://YOUR-HOST/auth/callback`. Enable authorization-code flow; implicit
   access/ID-token grants are unnecessary. Add the API's delegated `access_as_user`
   permission to this client and grant consent under your tenant's policy.
4. Create a Web client credential and save its **value** in the generated
   `secrets/client-secret.txt`. Record its expiry in your credential management
   system. Supply your trusted certificate chain and private key in the TLS files.
5. Generate a bundle, substituting your real non-secret IDs:

```text
python scripts/onboard_customer.py customer-one --tenant-id TENANT-UUID --client-id WEB-UUID --api-id API-UUID --public-url https://YOUR-HOST
```

Follow the bundle's `START.md`. Each bundle has a distinct Compose project, network,
database volume, database credentials and session signing secret. The app uses a
non-superuser database role. The initialization script runs only on a **new**
database volume; replacing a file does not rotate existing PostgreSQL passwords.
Bind the database with `scripts/migrate_database.py --organization-id TENANT-UUID`.
An already-bound database cannot be reassigned to another organization.

The gateway defaults to loopback port 8443. Route the public hostname to it using
your hosting infrastructure, preserving the original Host header. Run `docker compose
config --quiet` before deployment. This repository's local lab does not validate
the Caddy image, your DNS, certificate renewal, firewall or cloud load balancer.

## Acceptance checks on the actual deployment

| Check | Expected outcome |
| --- | --- |
| Browser opens the public incidents URL | Redirect to your tenant, successful callback, incidents table |
| Viewer attempts to update an incident | 403; analyst/admin access follows the assigned role |
| Unassigned user or wrong-tenant token | No application access |
| Logout then replay the old session cookie | 401 on a protected API request |
| Another customer's app points at this database | Startup rejects the organization binding |
| Connection without a trusted certificate | TLS verification fails |
| Backup restored to a separate database | Evidence counts and hashes agree; never restore over the live database for a drill |

API audience is the API client UUID for v2 tokens. The browser ID token is checked
against the Web client UUID. Entra's `oid` identifies the same object across both
tokens; `sub` can differ between applications. Both tokens must have the configured
`tid`, issuer and valid signature/lifetime. State, nonce and PKCE protect the code flow.

Browser sessions last at most 15 minutes or the shorter token lifetime. Only a
random cookie is sent to the browser and its hash is stored in PostgreSQL. No refresh
tokens are retained. Role changes take effect at the next sign-in or session expiry;
local logout revokes this app's session, not the Microsoft session. Restoring a
backup can restore unexpired sessions: delete `browser_sessions` before serving a
recovered deployment if all prior sessions must remain revoked.

## Evidence and remaining work

`evidence_pack/production-lab-v1.3-final.json` records a real local PostgreSQL 17.11,
HTTPS and PKCE exercise against a **local test issuer**. It is not evidence of a
successful Microsoft Entra login. Real tenant and public-host acceptance remains
pending until those values and deployment access are available.

Microsoft references: [Expose an API](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-expose-web-apis),
[Web client permissions](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-access-web-apis),
[Authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow),
[ID-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference).
