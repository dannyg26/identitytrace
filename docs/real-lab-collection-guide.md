# Real Lab Telemetry Collection Guide

> Historical planning/collection reference. v1.0 collection is closed.
> Unmet expansion targets are accepted limitations or possible v1.1 work;
> this guide does not add release requirements. See the
> [final release review](release-readiness-v1.0.md).


**Superseded by [`phase9b-first-collection-checklist.md`](phase9b-first-collection-checklist.md)**,
which drives `scripts/collect_entra_telemetry.py` and
`scripts/collect_github_telemetry.py` to automate almost everything
below (device-code login, test-user creation, benign/attack activity,
raw log retrieval) - the only steps that stay manual are the ones that
are genuinely impossible to script (an interactive sign-in/MFA per test
identity, one browser click to authorize `gh`, one org-creation click).
Use this doc only as a manual fallback if you'd rather click through the
portals yourself, or the scripts don't apply to your setup.

The division of labor underneath either path (per the project's own
discussion in `docs/phase9-external-evaluation.md`): **you** create a
small lab environment and export raw vendor logs exactly as the vendor
produces them; **the project** consumes those files unmodified via
`scripts/ingest_real_export.py`. This doc is the exact, low-friction
manual path to do your half.

You need neither a huge enterprise environment nor Splunk. 3-5 identities
with different roles, generated over an hour or two, is enough.

## Part 1: Entra ID

### Get a free lab tenant

[Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program)
gives you a free, instant sandbox tenant with an E5 subscription (25 test
user licenses) - this is the standard way security researchers get a real
Entra tenant without paying anything, and E5 includes the Entra ID P2
features (risk levels, full sign-in/audit log detail) production P1/P2
licensing would otherwise require. Sign up, wait for tenant provisioning
(~minutes), and you have a real `*.onmicrosoft.com` tenant with global
admin access.

### Create test identities

In the [Entra admin center](https://entra.microsoft.com): Identity >
Users > New user. Create 3-5, with different roles: one Global
Administrator, 2-3 regular Members, optionally one Guest. Real names/UPNs
are fine here (`test-user1@yourtenant.onmicrosoft.com`) - this is your
own throwaway lab tenant, not a real org's identities.

### Generate legitimate activity (the real_benign export)

Sign in as each test user (browser, incognito windows per identity) and
perform:

- Normal interactive sign-in (just sign in normally)
- A deliberately failed sign-in (wrong password once)
- MFA: enable per-user MFA (Entra admin center > that user > Authentication
  methods) or a Conditional Access policy requiring it, then sign in and
  complete the challenge
- Device-code sign-in: `az login --use-device-code` (Azure CLI) or
  `Connect-MgGraph -UseDeviceAuthentication` (PowerShell, `Install-Module
  Microsoft.Graph` first) - either produces a genuine `deviceCode`
  `authenticationProtocol` sign-in
- App registration + OAuth consent: Entra admin center > App registrations
  > New registration (any test app), then as a *different* test user,
  consent to it (Graph Explorer, below, will prompt for this naturally)
- Role assignment: assign a directory role (e.g. "User Administrator") to
  a test user - Identity > Roles & administration > pick a role > Add
  assignment
- Account changes: reset a test user's password, update their profile

### Generate controlled attack-like sequences (the real_controlled_attack exports)

Still entirely within your own lab - never against anything you don't
own. One export file per simulated attack, matching one blueprint
scenario:

- **A2** (malicious OAuth consent): device-code sign-in as a test user,
  then immediately consent to a test app requesting a broad scope
  (`Files.Read.All` or similar), then access a file/mailbox as that user
- **A1/A3** (new-location session): sign in as a test user from your
  normal network, then sign in again minutes later from a different
  network (phone hotspot, VPN, or a different Wi-Fi) - a genuinely
  different IP - followed by a large-looking file operation
- **A5** (privilege escalation): assign an elevated role to a test user,
  then have that user access a sensitive-looking resource shortly after

Keep each simulated attack's events in their own export file - the
ingestion script's `--label real_controlled_attack --attack-type A2`
treats every event in one file as ground truth for one attack run.

### Export the raw JSON

**Recommended - [Graph Explorer](https://developer.microsoft.com/graph/graph-explorer)**,
zero setup: sign in as your lab tenant's admin, run:
```
GET https://graph.microsoft.com/v1.0/auditLogs/signIns
GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits
```
Copy the `value` array from the response pane - those items are exactly
the raw `signIn`/`directoryAudit` objects this project's `entra.py`
normalizer expects, straight from Microsoft's own API, no transformation
needed.

Alternative (PowerShell): `Connect-MgGraph -Scopes "AuditLog.Read.All"`,
then `Get-MgAuditLogSignIn | ConvertTo-Json -Depth 10 > signins.json` and
`Get-MgAuditLogDirectoryAudit | ConvertTo-Json -Depth 10 > audits.json`.

Alternative (no scripting at all): Entra admin center > Monitoring &
health > Sign-in logs / Audit logs > filter to your time range > Download
(CSV). Works, but you'll need to convert CSV to the JSON array shape
below yourself - Graph Explorer is genuinely less work.

### Wrap and ingest

```json
{"source": "entra", "events": [ /* the value array, or your PowerShell export */ ]}
```

```bash
python scripts/ingest_real_export.py entra_benign.json --label real_benign
python scripts/ingest_real_export.py entra_a2_attack.json \
    --label real_controlled_attack --attack-type A2
```

## Part 2: GitHub

You do **not** need GitHub Enterprise Cloud for this - a free personal
account is enough for the easiest path.

### Generate legitimate activity

Using your own account or a throwaway test account: create a repo, clone
it, push a commit, create a Personal Access Token and use it for a clone
or API call, add a collaborator, change a repo's visibility, create a
free org and add a member.

### Generate controlled attack-like sequences

**A4** (developer token compromise): create a PAT, use it to access a
normal repo, then a repo you name with `secret`/`vault`/`credential` in
it (a decoy repo you create yourself - no real secrets in it), then clone
it - all within a few minutes, from the same token.

### Export the raw JSON

**Easiest (any account, no Enterprise) - your own security log**:
[github.com/settings/security-log](https://github.com/settings/security-log)
lists your account's own real events (sign-ins, PAT creation/use, ...)
and has an **Export** (JSON) button. This is available to every account
for free.

**If you have GitHub Enterprise Cloud or a paid org with audit-log
access** (not required, but the closest match to this project's
`github.py` normalizer, which was built against this exact schema):
Settings > Audit log > Export, or `GET /orgs/{org}/audit-log`
(`gh api orgs/{org}/audit-log` if you have the `gh` CLI authenticated -
this project's own dev environment doesn't, but yours might).

**Public repo events** (no auth needed, any repo): `GET
https://api.github.com/repos/{owner}/{repo}/events` returns real GitHub
event JSON - note this is a *different* shape (`type: "PushEvent"`, etc.)
than the audit-log format `github.py` expects. Useful for exploring real
GitHub API shapes, but expect normalization failures if you feed these
directly through `--source github` - that's real, correctly-reported
signal (see `scripts/ingest_real_export.py`'s failure report), not
something to route around; extending the normalizer for this second
GitHub event shape would be a legitimate follow-up, not a quick fix.

### Wrap and ingest

```json
{"source": "github", "events": [ /* your exported events */ ]}
```

```bash
python scripts/ingest_real_export.py github_benign.json --label real_benign
python scripts/ingest_real_export.py github_a4_attack.json \
    --label real_controlled_attack --attack-type A4
```

## After ingesting

```bash
python scripts/report_by_provenance.py *.provenance.json
```

reports results segmented by exactly which file each came from - never
silently mixed with the synthetic harness's own numbers
(`docs/evaluation.md`). Expect some normalization failures on your first
real export; that's the whole point of this exercise (`docs/normalizer-
fidelity.md` already found and fixed four real bugs the same way). Report
them back and they can be fixed the same way those were.

## What NOT to do

- Don't commit real tenant IDs, real user emails, real tokens, or real
  secrets to this repo. Sanitize (or keep entirely local) any export
  before it goes anywhere near git - per the blueprint's §13 ethics
  section, which this project follows throughout.
- Don't run "controlled attack" activity against anything you don't own.
  Your own free lab tenant and your own repos only.
- Don't tune the detector to make a specific real export "pass" once
  you've looked at what it produced - see `docs/holdout.md`'s freeze
  discipline, which applies just as much to real data as synthetic.
