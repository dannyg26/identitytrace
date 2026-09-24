# Phase 9B: First Real Collection Checklist

> Historical planning/collection reference. v1.0 collection is closed.
> Unmet expansion targets are accepted limitations or possible v1.1 work;
> this guide does not add release requirements. See the
> [final release review](release-readiness-v1.0.md).


Two scripts do almost all of this now:
[`scripts/collect_entra_telemetry.py`](../scripts/collect_entra_telemetry.py) and
[`scripts/collect_github_telemetry.py`](../scripts/collect_github_telemetry.py).
Each runs on **your** machine against **your own** tenant/account and either
performs a real, auditable API action (so it's real telemetry, not a
simulation) or retrieves and saves a vendor's raw response body
unmodified. Neither can complete the handful of steps below that are
genuinely, technically impossible to script - each is called out with
*why* in its subcommand's docstring, not just flagged as "manual."

This doc is the authoritative one. `real-lab-collection-guide.md`
describes the older, fully-manual portal-clicking path as a fallback if
you ever can't/don't want to use the scripts.

Target for this first batch: 3-5 lab identities, 100-500 real Entra
events, 100-500 real GitHub events, a few controlled attack sequences.

## Part A - Entra ID

### A0. One-time setup

1. Join the [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program)
   (free, no card) - provisions a sandbox tenant with an E5 subscription
   (needed for full sign-in/audit log detail).
2. On this machine: `pip install -e ".[real-collection]"`

No app registration step - the script uses Microsoft's own pre-registered
"Microsoft Graph Command Line Tools" client, present in every tenant.

### A1. Admin login (manual - one device-code sign-in)

```bash
python scripts/collect_entra_telemetry.py login
```
Prints a code and a `https://microsoft.com/devicelogin` link. Open it,
sign in as your Developer Program admin account, complete MFA if
prompted. **This is the actual credential check - there is no scripting
around it.** The first time these scopes are used in the tenant you may
also see a one-time admin-consent page - click Accept (you're granting
consent to yourself, the Global Admin). The resulting token is cached in
`.entra_token_cache.json` (gitignored) - every command after this is
silent.

### A2. Create test identities (automatic)

```bash
python scripts/collect_entra_telemetry.py seed-users --count 3
```
Creates `idt-test-user1..3@<yourtenant>.onmicrosoft.com` via a real
`POST /users` call. Prints each temporary password - save them, you need
them for A3. Not written to `real_data/` or git.

### A3. Generate real_benign activity

**Automatic** (admin-side actions - zero interaction):
```bash
python scripts/collect_entra_telemetry.py seed-benign
```
Runs a profile update, an app registration, a directory-role assignment,
and a password reset - each a real `directoryAudits` entry.

**Manual, once per test user** (this is the one irreducible Entra step -
a sign-in log entry only exists because a real authentication happened):
```bash
python scripts/collect_entra_telemetry.py signin --upn idt-test-user1@<yourtenant>.onmicrosoft.com
```
Prints a device-code link; sign in as that user with the temp password
from A2. Repeat for user2/user3 to get sign-ins attributed to each
identity. Run it a few times across 2-3 days per user to build volume
toward 100-500 sign-in events.

### A4. Generate real_controlled_attack sequences

```bash
python scripts/collect_entra_telemetry.py attack-sequence \
    --upn idt-test-user1@<yourtenant>.onmicrosoft.com --scope Files.Read.All
```
Same one manual sign-in as A3, but timed tightly with an immediate
consented resource access (OAuth-consent + rapid-access pattern). Prints
the exact `--since`/`--until` window to hand to export. Run once per
attack scenario you want (A2-style OAuth misuse, A5-style privilege
escalation via a `seed-benign`-style role assignment right before a
sign-in, etc.) - keep each sequence's window narrow and separate.

### A5. Export + ingest (automatic)

```bash
python scripts/collect_entra_telemetry.py export \
    --since 2026-09-01 --out-prefix real_data/entra_benign_day1 \
    --ingest real_benign

python scripts/collect_entra_telemetry.py export \
    --since <window-start> --until <window-end> \
    --out-prefix real_data/entra_a2_attack \
    --ingest real_controlled_attack --attack-type A2
```
Pulls the raw `signIns`/`directoryAudits` responses (paginated
automatically), saves them unmodified to `real_data/`, and immediately
runs `ingest_real_export.py` for you.

## Part B - GitHub

### B0. One-time setup

```powershell
winget install --id GitHub.cli
python scripts/collect_github_telemetry.py check
```
If it reports "NOT logged in", run:
```bash
gh auth login --scopes "repo,read:audit_log"
```
which opens your browser for one OAuth click ("Authorize"). The
`--scopes` flag matters - gh's own default grants `repo` and `read:org`;
this project doesn't use `read:org` anywhere and does need the separate
`read:audit_log` scope (for `export --org`), which gh doesn't request by
default. `check` verifies you have both of what's actually needed and
tells you the exact fix if not (`gh auth refresh -h github.com -s ...`,
no full re-login required). No PAT is needed for anything below - every
action rides on this one credential.

### B1. Generate real_benign activity (automatic)

```bash
python scripts/collect_github_telemetry.py seed-benign --prefix idt-lab
```
Creates a repo, commits a file via the API, adds a topic, and toggles
visibility - all real API writes, zero further interaction. Pass
`--collaborator <username>` to also generate a collaborator-invite
event.

### B2. Generate real_controlled_attack sequence (automatic)

```bash
python scripts/collect_github_telemetry.py seed-attack --prefix idt-lab
```
Creates a decoy repo named like a secrets store and accesses it
rapidly - a stolen-credential access pattern, all within one tight
window, using the same credential as B1 (or pass `--pat "<token>"` if
you've manually created one for closer "stolen developer token"
fidelity - optional, see below).

### B3. Export

**Only if you have GitHub Enterprise Cloud** - fully automatic:
```bash
python scripts/collect_github_telemetry.py export \
    --org <your-org> --since 2026-09-01 \
    --out real_data/github_benign.json --ingest real_benign
```
Confirmed directly (a free org actually tried against this returned a
real 404, and GitHub's own docs state the org audit-log REST API
requires Enterprise Cloud): creating a free org does **not** unlock
this, even with the `read:audit_log` scope granted. If you don't have
Enterprise Cloud, skip straight to the personal-log path below (or
export the org's audit log manually from its Settings > Audit log page
if you do have a free/Team org and want that source anyway).

**Personal security log, UI-export only** (GitHub exposes no API for
this at all, on any plan):
```bash
python scripts/collect_github_telemetry.py export --personal --out real_data/github_benign.json
```
prints the exact manual steps (Settings → Security log → Export → JSON).
**Known gap**: that export uses `actor_location.country_code`, while
`github.py`'s normalizer was validated against the org audit-log API's
`country_name` - `geo_country` will likely come back empty from this
path specifically. Expected, not a bug to pre-fix - let it surface as a
real ingestion finding (see below).

Then ingest it same as the Entra files:
```bash
python scripts/ingest_real_export.py real_data/github_benign.json --source github --label real_benign
```

## Optional: a manually-created PAT

Nothing above needs one. If you specifically want the "stolen developer
PAT" scenario to use an actual personal access token rather than gh's
OAuth token: Settings → Developer settings → Personal access tokens →
Generate new token (GitHub only allows creating these interactively in
the browser - no API can mint a new credential using another
credential). Pass it to `seed-attack --pat "<token>"`. Purely optional.

## Part C - Report

```bash
python scripts/report_by_provenance.py real_data/*.provenance.json
```

**PowerShell note**: `*` doesn't glob-expand in PowerShell like bash.
Use:
```powershell
python scripts\report_by_provenance.py (Get-ChildItem real_data\*.provenance.json | ForEach-Object FullName)
```

## What happens to failures

Every ingest run prints exactly how many events normalized and, for any
that didn't, the index and reason. **That's a result, not an error to
work around.** It gets fixed the same documented way the four bugs in
`normalizer-fidelity.md` were: a real assumption, checked against what
actually broke, corrected, and written up - never a workaround, never a
silent edit of the raw export.

## WHAT I NEED TO DO NOW

Everything that genuinely cannot be scripted - nothing else is required:

- [ ] `pip install -e ".[real-collection]"` (once)
- [ ] Join the Microsoft 365 Developer Program (once, free)
- [ ] `python scripts/collect_entra_telemetry.py login` - one device-code
      sign-in as the tenant admin, possibly with a one-time admin-consent
      click
- [ ] `python scripts/collect_entra_telemetry.py signin --upn ...` - one
      device-code sign-in **per test user**, repeated a few times over
      2-3 days for volume (this is the one thing that can never be
      scripted: a sign-in log entry requires a real authentication)
- [ ] `winget install --id GitHub.cli` then `gh auth login` - one browser
      click to authorize (once)
- [ ] For GitHub export: either export the personal security log
      manually (Settings > Security log > Export > JSON - GitHub has no
      API for this on any plan), or, only if you have GitHub Enterprise
      Cloud, use `export --org` (a free org does **not** unlock this -
      confirmed by a real 404, not just assumed)
- [ ] (optional, only if you want literal-PAT attack fidelity) create one
      PAT at github.com/settings/tokens - GitHub has no API to mint one

Everything else - creating test users, seeding benign/attack activity,
retrieving and saving raw logs, ingesting, and reporting - is a command
I've already written and tested; run it yourself or hand me the
resulting files in `real_data/` and I'll run it.
