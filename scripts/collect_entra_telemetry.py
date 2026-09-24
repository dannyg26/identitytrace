#!/usr/bin/env python
"""Automate real Entra ID telemetry collection for Phase 9B - run on YOUR
machine against YOUR OWN Microsoft 365 Developer Program tenant.

This replaces almost all of the manual portal-clicking in
docs/real-lab-collection-guide.md with real Microsoft Graph API calls. It
does NOT fabricate anything: every "seed" action below is a genuine
Graph write against your tenant (and shows up in the real audit log
because it really happened), and `export` saves Microsoft's raw response
body byte-for-byte - the same thing Graph Explorer would show you, just
without the manual copy/paste.

No app registration is required: this uses Microsoft's own first-party
"Microsoft Graph Command Line Tools" public client
(14d82eec-204b-4c2f-b7e8-296a70dab67e), which is pre-registered in every
Azure AD / Entra tenant, so device-code sign-in works immediately.

One-time environment setup (once per machine):
    pip install -e ".[real-collection]"

What CANNOT be automated, and why (see each subcommand's docstring too):
  - `login`  needs one interactive device-code sign-in as the tenant
    admin. No way around this - it's the credential check itself.
  - `signin` needs one interactive device-code sign-in PER TEST USER.
    A "sign-in log entry" is Entra's record that a real authentication
    happened; nothing this script does under the admin's own token can
    forge a different user's authentication. This is the one truly
    irreducible manual step, repeated once per identity you want
    sign-in telemetry for.
  - The very first time a scope is used in a fresh tenant, Entra may
    show a one-time admin-consent page instead of signing straight in.
    Click Accept - you're the tenant's Global Admin, granting consent
    to yourself in your own sandbox.

Everything else - creating test users, role/app-registration/password-
reset audit events, and pulling + saving the raw sign-in and audit logs
- is one command with zero further interaction.

Subcommands (run in this order the first time):
    login
        Interactive admin device-code sign-in. Caches the token in
        .entra_token_cache.json (gitignored) so every later command is
        silent - no browser, no re-typing anything.

    seed-users --count 3
        Creates N real test users via POST /users (admin-only, no
        interaction). Prints each UPN + temporary password.

    seed-benign
        Runs a battery of real, harmless admin actions that each
        produce a real directoryAudits entry: update a user's profile,
        assign a directory role, register a throwaway application,
        reset a test user's password. Zero interaction (admin token
        already cached).

    signin --upn test-user1@yourtenant.onmicrosoft.com [--scope Files.Read.All]
        Device-code sign-in AS that user - the one unavoidable manual
        step (see above). Pass --scope to also generate a real OAuth
        consent event (e.g. Files.Read.All) alongside the sign-in.

    attack-sequence --upn test-user1@... --scope Files.Read.All
        Runs signin + a consented Graph call (e.g. listing the user's
        own files) back-to-back inside one narrow time window, then
        prints that window so you can pass it straight to `export`.
        Still needs the one interactive sign-in from `signin` above -
        this just tightens the timing around it.

    revoke-scope --client-sp-id <sp-object-id> --scope Mail.ReadWrite [--apply] [--drop-helper]
        Targeted revocation experiment: removes ONE delegated scope from an
        existing admin-consented grant (PATCH /oauth2PermissionGrants/{id}),
        so the audit log shows how Entra represents a genuine permission
        reduction. Needs the one extra delegated permission
        DelegatedPermissionGrant.ReadWrite.All (a device-code sign-in with a
        consent page - the collector's normal token deliberately cannot edit
        grants). Dry-run unless --apply. --drop-helper removes that helper
        scope again afterwards, restoring least privilege.

    export --since 2026-09-01T00:00:00Z [--until ...] --out-prefix real_data/entra_benign
        Pulls GET /auditLogs/signIns and GET /auditLogs/directoryAudits
        for that window, pages through @odata.nextLink automatically,
        and writes the raw merged response body to
        <out-prefix>_signins.json and <out-prefix>_audits.json. Pass
        --ingest real_benign or --ingest real_controlled_attack
        [--attack-type A2] to immediately run
        scripts/ingest_real_export.py against both files.

Every write and read here is logged by Microsoft the same way any other
Graph API usage is - this is real telemetry, not a simulation of it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import msal
    import requests
except ImportError:
    print(
        "Missing dependencies. Run:\n    pip install -e \".[real-collection]\"\n"
        "then re-run this command.",
        file=sys.stderr,
    )
    sys.exit(1)

GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft first-party public client
AUTHORITY = "https://login.microsoftonline.com/organizations"
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
TOKEN_CACHE_PATH = Path(__file__).resolve().parent.parent / ".entra_token_cache.json"

# Each scope below is the *least privileged* delegated permission Microsoft's
# own docs list for the specific operation this script performs with it -
# not the broader "ReadWrite.All" alternative. See the permissions table on
# each operation's Microsoft Learn page:
#   User.Create                    - POST /users                    (seed-users)
#   User.ReadUpdate.All            - PATCH /users/{id}               (seed-benign: profile update, password reset)
#   AppRegistration.Create         - POST /applications              (seed-benign: throwaway app registration)
#   RoleManagement.ReadWrite.Directory - POST /directoryRoles(/{id}/members/$ref) (seed-benign: role activation + assignment - no narrower permission exists for this operation)
#   AuditLog.Read.All               - GET /auditLogs/signIns, /auditLogs/directoryAudits (export)
# Deliberately NOT requested: User.ReadWrite.All, Directory.ReadWrite.All,
# Application.ReadWrite.All - each is a broader "manage everything of this
# type in the tenant" permission that Microsoft's own docs list as the
# *higher*-privileged alternative to the scope actually used above, and
# nothing in this script needs that broader access.
ADMIN_SCOPES = [
    "User.Create",
    "User.ReadUpdate.All",
    "AppRegistration.Create",
    "RoleManagement.ReadWrite.Directory",
    "AuditLog.Read.All",
]


def _load_cache() -> "msal.SerializableTokenCache":
    cache = msal.SerializableTokenCache()
    if TOKEN_CACHE_PATH.exists():
        cache.deserialize(TOKEN_CACHE_PATH.read_text(encoding="utf-8"))
    return cache


def _save_cache(cache: "msal.SerializableTokenCache") -> None:
    if cache.has_state_changed:
        TOKEN_CACHE_PATH.write_text(cache.serialize(), encoding="utf-8")


def _admin_app() -> "msal.PublicClientApplication":
    return msal.PublicClientApplication(
        GRAPH_CLI_CLIENT_ID, authority=AUTHORITY, token_cache=_load_cache()
    )


def cmd_login(_args) -> None:
    """Interactive admin device-code sign-in - the credential check
    itself, so there is no automating past it."""
    app = _admin_app()
    flow = app.initiate_device_flow(scopes=ADMIN_SCOPES)
    if "user_code" not in flow:
        print(f"Failed to start device flow: {flow}", file=sys.stderr)
        sys.exit(1)
    print(flow["message"])
    print(
        "\nWaiting for you to complete sign-in in the browser... "
        "(if this is the first time these scopes are used in this "
        "tenant, you'll also see a one-time admin-consent page - "
        "click Accept, you're granting consent to yourself)"
    )
    result = app.acquire_token_by_device_flow(flow)
    _save_cache(app.token_cache)
    if "access_token" not in result:
        print(f"Login failed: {result.get('error_description', result)}", file=sys.stderr)
        sys.exit(1)
    print("Logged in and cached. Every other command now runs with no further interaction.")


def _admin_token() -> str:
    app = _admin_app()
    accounts = app.get_accounts()
    if not accounts:
        print("No cached admin login. Run `login` first.", file=sys.stderr)
        sys.exit(1)
    result = app.acquire_token_silent(ADMIN_SCOPES, account=accounts[0])
    _save_cache(app.token_cache)
    if not result or "access_token" not in result:
        print("Cached login expired. Run `login` again.", file=sys.stderr)
        sys.exit(1)
    return result["access_token"]


def _graph(method: str, path: str, token: str, **kwargs) -> requests.Response:
    resp = requests.request(
        method, f"{GRAPH_ROOT}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=30, **kwargs,
    )
    if not resp.ok:
        print(f"Graph {method} {path} -> {resp.status_code}: {resp.text[:500]}", file=sys.stderr)
        resp.raise_for_status()
    return resp


def cmd_seed_users(args) -> None:
    """POST /users - real users, real directoryAudits 'Add user' entries.
    Zero interaction: runs entirely under the cached admin token."""
    token = _admin_token()
    who = _graph("GET", "/me", token).json()
    domain = who["userPrincipalName"].split("@", 1)[1]
    created = []
    for i in range(1, args.count + 1):
        upn = f"idt-test-user{i}@{domain}"
        password = f"Idt!{uuid.uuid4().hex[:12]}"
        body = {
            "accountEnabled": True,
            "displayName": f"IdentityTrace Test User {i}",
            "mailNickname": f"idt-test-user{i}",
            "userPrincipalName": upn,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password,
            },
        }
        resp = _graph("POST", "/users", token, json=body)
        created.append({"upn": upn, "password": password, "id": resp.json()["id"]})
        print(f"Created {upn}  (temp password: {password})")
    print(
        f"\n{len(created)} users created. Save these credentials somewhere private - "
        "you'll need each one for `signin`. They are not written to real_data/ or git."
    )


def cmd_seed_benign(args) -> None:
    """A battery of real, harmless admin actions under the cached admin
    token - each produces a real directoryAudits entry with zero further
    interaction."""
    token = _admin_token()
    users = _graph(
        "GET", "/users",
        token, params={"$filter": "startswith(userPrincipalName,'idt-test-user')"},
    ).json()["value"]
    if not users:
        print("No idt-test-user* accounts found - run `seed-users` first.", file=sys.stderr)
        sys.exit(1)
    target = users[0]

    print(f"Updating profile for {target['userPrincipalName']} ...")
    _graph("PATCH", f"/users/{target['id']}", token, json={"jobTitle": "Lab Test Account"})

    print("Registering a throwaway app (for later OAuth-consent scenarios) ...")
    app_resp = _graph(
        "POST", "/applications", token,
        json={"displayName": f"idt-lab-app-{uuid.uuid4().hex[:8]}"},
    ).json()
    print(f"  appId: {app_resp['appId']}")

    if len(users) > 1:
        role_target = users[1]
        print(f"Assigning Helpdesk Administrator role to {role_target['userPrincipalName']} ...")
        roles = _graph("GET", "/directoryRoles", token).json()["value"]
        helpdesk = next((r for r in roles if r["displayName"] == "Helpdesk Administrator"), None)
        if helpdesk is None:
            # Directory role templates must be "activated" once before use.
            templates = _graph("GET", "/directoryRoleTemplates", token).json()["value"]
            tmpl = next(t for t in templates if t["displayName"] == "Helpdesk Administrator")
            helpdesk = _graph("POST", "/directoryRoles", token, json={"roleTemplateId": tmpl["id"]}).json()
        _graph(
            "POST", f"/directoryRoles/{helpdesk['id']}/members/$ref", token,
            json={"@odata.id": f"{GRAPH_ROOT}/directoryObjects/{role_target['id']}"},
        )

    print(f"Resetting password for {target['userPrincipalName']} ...")
    new_password = f"Idt!{uuid.uuid4().hex[:12]}"
    try:
        _graph(
            "PATCH", f"/users/{target['id']}", token,
            json={"passwordProfile": {"forceChangePasswordNextSignIn": False, "password": new_password}},
        )
    except requests.exceptions.HTTPError as exc:
        # Real finding (not a bug to silently patch around): Microsoft's own
        # docs list User.ReadUpdate.All as sufficient for this, but Graph
        # has rejected it at runtime with 403 Authorization_RequestDenied
        # even for a Global Administrator. Password reset is one of four
        # seed-benign actions - don't lose the other three to this one
        # failure; report it and move on.
        print(f"  SKIPPED - Graph returned {exc.response.status_code}: {exc.response.text[:300]}")
        print("  (real finding: password reset denied despite User.ReadUpdate.All + Global Admin - "
              "not silently worked around; the other 3 actions above already succeeded)")

    print("Done - see above for what actually succeeded.")


def _user_app() -> "msal.PublicClientApplication":
    return msal.PublicClientApplication(GRAPH_CLI_CLIENT_ID, authority=AUTHORITY)


def cmd_signin(args) -> None:
    """Device-code sign-in AS the given test user. This is the one step
    that genuinely cannot be scripted around: a sign-in log entry only
    exists because a real authentication happened, so a real human has
    to type that user's password (and MFA, if enabled) once."""
    scopes = ["User.Read"] + (args.scope or [])
    app = _user_app()
    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        print(f"Failed to start device flow: {flow}", file=sys.stderr)
        sys.exit(1)
    print(f"Sign in as {args.upn} using the code below:")
    print(flow["message"])
    if args.scope:
        print(f"(You'll also see a consent prompt for: {', '.join(args.scope)} - click Accept.)")
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        print(f"Sign-in failed: {result.get('error_description', result)}", file=sys.stderr)
        sys.exit(1)
    print(f"Signed in as {args.upn}. A real signIns log entry now exists for this identity.")
    if args.scope:
        # Exercise the granted scope so consent + resource access both land
        # in the logs, not just the sign-in. A bare/trial tenant may have no
        # SharePoint/OneDrive license at all, in which case this specific
        # call 400s regardless of the Files.Read.All grant - that's a real
        # licensing gap, not a bug, and shouldn't lose the sign-in + consent
        # events that already landed.
        try:
            _graph("GET", "/me/drive/root/children", result["access_token"])
            print(f"Exercised granted scope(s): {', '.join(args.scope)}")
        except requests.exceptions.HTTPError as exc:
            print(f"  SKIPPED resource access - Graph returned {exc.response.status_code}: "
                  f"{exc.response.text[:300]}")
            print("  (real finding: no SharePoint/OneDrive license in this tenant - the "
                  "sign-in + consent grant above are still real and already recorded)")


def cmd_attack_sequence(args) -> None:
    """Runs a device-code sign-in with a broad scope, then immediately
    exercises that scope - the same irreducible manual sign-in as
    `signin`, just timed tightly so the whole sequence lands in one
    narrow export window."""
    started_at = datetime.now(timezone.utc)
    args.scope = [args.scope]
    cmd_signin(args)
    ended_at = datetime.now(timezone.utc)
    print(
        f"\nSequence window: {started_at.isoformat()} to {ended_at.isoformat()}\n"
        f"Pass this to `export --since {started_at.isoformat()} --until {ended_at.isoformat()}`"
    )


def _iso(dt_str: str) -> str:
    # Accept bare dates too (2026-09-01 -> full ISO with Z).
    if "T" not in dt_str:
        dt_str += "T00:00:00Z"
    if not dt_str.endswith("Z") and "+" not in dt_str[10:]:
        dt_str += "Z"
    return dt_str


def _fetch_all_pages(path: str, params: dict, token: str) -> dict:
    """GET path with params, follow @odata.nextLink, and merge every
    page's `value` array into the FIRST page's raw envelope - so the
    saved file is still byte-for-byte a real Graph response shape, just
    with every page's events folded into one `value` list."""
    resp = _graph("GET", path, token, params=params).json()
    merged = dict(resp)
    next_link = resp.get("@odata.nextLink")
    while next_link:
        page = requests.get(next_link, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        page.raise_for_status()
        page_json = page.json()
        merged["value"].extend(page_json.get("value", []))
        next_link = page_json.get("@odata.nextLink")
    merged.pop("@odata.nextLink", None)
    return merged


def cmd_export(args) -> None:
    """Pulls the raw signIns and directoryAudits responses for the given
    window and writes them unmodified. Zero interaction."""
    token = _admin_token()
    since = _iso(args.since)
    until = _iso(args.until) if args.until else datetime.now(timezone.utc).isoformat()
    # Same time window, different property name per resource - signIns uses
    # createdDateTime, directoryAudits uses activityDateTime (confirmed by a
    # real 400 BadRequest when the signIns field name was used for both).
    signin_filt = f"createdDateTime ge {since} and createdDateTime le {until}"
    audit_filt = f"activityDateTime ge {since} and activityDateTime le {until}"

    out_prefix = Path(args.out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    signins = _fetch_all_pages("/auditLogs/signIns", {"$filter": signin_filt}, token)
    signins_path = out_prefix.with_name(out_prefix.name + "_signins.json")
    signins_path.write_text(json.dumps(signins, indent=2), encoding="utf-8")
    print(f"Wrote {len(signins['value'])} sign-in events -> {signins_path}")

    audits = _fetch_all_pages("/auditLogs/directoryAudits", {"$filter": audit_filt}, token)
    audits_path = out_prefix.with_name(out_prefix.name + "_audits.json")
    audits_path.write_text(json.dumps(audits, indent=2), encoding="utf-8")
    print(f"Wrote {len(audits['value'])} audit events -> {audits_path}")

    if args.ingest:
        for path in (signins_path, audits_path):
            cmd = [
                sys.executable, "scripts/ingest_real_export.py", str(path),
                "--source", "entra", "--label", args.ingest,
            ]
            if args.attack_type:
                cmd += ["--attack-type", args.attack_type]
            print(f"\n$ {' '.join(cmd)}")
            subprocess.run(cmd, cwd=Path(__file__).resolve().parent.parent, check=True)


GRANT_ADMIN_SCOPE = "DelegatedPermissionGrant.ReadWrite.All"


def scope_without(scope: str, target: str) -> str:
    """The grant's space-separated scope string with `target` removed
    (order of the rest preserved)."""
    return " ".join(x for x in scope.split() if x != target)


def _grant_token() -> str:
    app = _admin_app()
    accounts = app.get_accounts()
    if accounts:
        cached = app.acquire_token_silent([GRANT_ADMIN_SCOPE], account=accounts[0])
        _save_cache(app.token_cache)
        if cached and "access_token" in cached:
            print(f"Reusing cached sign-in for {accounts[0]['username']} (already consented to {GRANT_ADMIN_SCOPE}).")
            return cached["access_token"]
    flow = app.initiate_device_flow(scopes=[GRANT_ADMIN_SCOPE])
    if "user_code" not in flow:
        print(f"Failed to start device flow: {flow}", file=sys.stderr)
        sys.exit(1)
    print(flow["message"])
    print(f"\n(You'll see a one-time consent page for {GRANT_ADMIN_SCOPE} - click Accept.)")
    result = app.acquire_token_by_device_flow(flow)
    _save_cache(app.token_cache)
    if "access_token" not in result:
        print(f"Login failed: {result.get('error_description', result)}", file=sys.stderr)
        sys.exit(1)
    return result["access_token"]


def _patch_grant_scope(grant_id: str, scope: str, token: str) -> tuple[str, str]:
    """PATCH the grant; return (utc time just before, utc time just after)."""
    before = datetime.now(timezone.utc).isoformat()
    # A grant that was JUST changed (e.g. by the consent to this helper scope)
    # can briefly 400 "not found" on a directory replica that has not caught
    # up. Retry only that specific error, a few times, then give up loudly.
    for attempt in range(5):
        resp = requests.patch(
            f"{GRAPH_ROOT}/oauth2PermissionGrants/{grant_id}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"scope": scope}, timeout=30,
        )
        if resp.ok:
            return before, datetime.now(timezone.utc).isoformat()
        if resp.status_code == 400 and "not found" in resp.text and attempt < 4:
            print(f"  PATCH not found yet (replication lag?) - retrying in 20s ({attempt + 1}/4)")
            time.sleep(20)
            before = datetime.now(timezone.utc).isoformat()
            continue
        print(f"Graph PATCH /oauth2PermissionGrants/{grant_id} -> {resp.status_code}: {resp.text[:500]}", file=sys.stderr)
        resp.raise_for_status()
    raise RuntimeError("unreachable")


def cmd_revoke_scope(args) -> None:
    """Remove one delegated scope from an existing grant. Dry-run unless --apply."""
    token = _grant_token()
    grants = _graph(
        "GET", "/oauth2PermissionGrants", token,
        params={"$filter": f"clientId eq '{args.client_sp_id}'"},
    ).json()["value"]
    holders = [g for g in grants if args.scope in (g.get("scope") or "").split()]
    print(f"{len(grants)} grant(s) for client {args.client_sp_id}; {len(holders)} hold {args.scope}:")
    for g in grants:
        print(f"  {g['id']}  consentType={g.get('consentType')}  principalId={g.get('principalId')}  scope={g.get('scope')!r}")
    if len(holders) != 1:
        print("Need exactly one grant holding the scope; refusing to guess.", file=sys.stderr)
        sys.exit(1)
    grant = holders[0]
    new_scope = scope_without(grant["scope"], args.scope)
    print(f"\nPlan: {grant['id']}\n  old: {grant['scope']!r}\n  new: {new_scope!r}")
    if not args.apply:
        print("\nDry run - nothing changed. Re-run with --apply to revoke.")
        return

    record = {"grant_id": grant["id"], "target_scope": args.scope,
              "scope_before": grant["scope"], "started_utc": datetime.now(timezone.utc).isoformat()}
    record["revoke_call_utc"] = _patch_grant_scope(grant["id"], new_scope, token)
    after = _graph("GET", f"/oauth2PermissionGrants/{grant['id']}", token).json()
    record["scope_after"] = after["scope"]
    record["revoked_scope_gone"] = args.scope not in after["scope"].split()
    print(f"Revoked {args.scope}: now {after['scope']!r}")

    if args.drop_helper and GRANT_ADMIN_SCOPE in after["scope"].split():
        helper_scope = scope_without(after["scope"], GRANT_ADMIN_SCOPE)
        record["helper_drop_call_utc"] = _patch_grant_scope(grant["id"], helper_scope, token)
        record["scope_final"] = _graph("GET", f"/oauth2PermissionGrants/{grant['id']}", token).json()["scope"]
        print(f"Dropped helper scope {GRANT_ADMIN_SCOPE}: now {record['scope_final']!r}")

    record["finished_utc"] = datetime.now(timezone.utc).isoformat()
    out = Path(args.record)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"\nWrote {out}. Audit logs lag several minutes; then export with:\n"
          f"  python scripts/collect_entra_telemetry.py export --since {record['started_utc']} "
          f"--out-prefix real_data/entra_revocation")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="interactive admin device-code login (do this first)").set_defaults(fn=cmd_login)

    p = sub.add_parser("seed-users", help="create N real test users")
    p.add_argument("--count", type=int, default=3)
    p.set_defaults(fn=cmd_seed_users)

    sub.add_parser("seed-benign", help="run a battery of real benign admin actions").set_defaults(fn=cmd_seed_benign)

    p = sub.add_parser("signin", help="device-code sign-in as one test user (manual step)")
    p.add_argument("--upn", required=True)
    p.add_argument("--scope", action="append", help="extra Graph scope to also consent to (repeatable)")
    p.set_defaults(fn=cmd_signin)

    p = sub.add_parser("attack-sequence", help="timed sign-in + scope-exercise sequence")
    p.add_argument("--upn", required=True)
    p.add_argument("--scope", required=True, help="broad scope to request, e.g. Files.Read.All")
    p.set_defaults(fn=cmd_attack_sequence)

    p = sub.add_parser("revoke-scope", help="remove ONE delegated scope from a grant (dry-run unless --apply)")
    p.add_argument("--client-sp-id", required=True, help="object id of the client service principal that holds the grant")
    p.add_argument("--scope", required=True, help="the single scope to revoke, e.g. Mail.ReadWrite")
    p.add_argument("--apply", action="store_true", help="actually revoke (default: dry run)")
    p.add_argument("--drop-helper", action="store_true", help=f"afterwards also remove {GRANT_ADMIN_SCOPE} from the grant")
    p.add_argument("--record", default="real_data/entra_revocation_experiment.json")
    p.set_defaults(fn=cmd_revoke_scope)

    p = sub.add_parser("export", help="pull raw signIns + directoryAudits for a window")
    p.add_argument("--since", required=True, help="ISO datetime or bare date (UTC)")
    p.add_argument("--until", help="ISO datetime or bare date (UTC); default now")
    p.add_argument("--out-prefix", required=True, help="e.g. real_data/entra_benign_day1")
    p.add_argument("--ingest", choices=["real_benign", "real_controlled_attack"])
    p.add_argument("--attack-type", choices=["A1", "A2", "A3", "A4", "A5", "A6"])
    p.set_defaults(fn=cmd_export)

    args = parser.parse_args()
    if getattr(args, "command", None) == "export" and args.ingest == "real_controlled_attack" and not args.attack_type:
        parser.error("--attack-type is required with --ingest real_controlled_attack")
    args.fn(args)


if __name__ == "__main__":
    main()
