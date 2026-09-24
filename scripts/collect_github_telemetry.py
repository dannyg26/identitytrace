#!/usr/bin/env python
"""Automate real GitHub telemetry collection for Phase 9B - run on YOUR
machine against repos/accounts YOU own.

Uses the GitHub CLI (`gh`) so there is no separate app registration or
manual token minting: `gh auth login` is a one-time OAuth device/web
flow (you click "Authorize" once in your browser), and every command
below then runs non-interactively using gh's own cached credential.
Every "seed" action is a real API write against your own account/repo -
it happens, so it is real telemetry, not a simulation of it. `export`
saves GitHub's raw response body unmodified.

What CANNOT be automated, and why:
  - `gh auth login` needs one click of "Authorize" in a browser popup.
    That's the credential check itself.
  - GitHub does not expose a REST/CLI endpoint for the *personal*
    security log (Settings > Security log) - only a UI "Export" button
    exists for it. If you want that source, `export --personal` prints
    the exact manual steps.
  - The org audit-log REST API requires GitHub Enterprise Cloud
    (confirmed via GitHub's own docs) - a free or Team-tier org's audit
    log is UI-export-only, same limitation as the personal security
    log, regardless of `read:audit_log` scope. Creating a free org does
    NOT unlock API automation for this (an earlier version of this
    docstring claimed otherwise - it was wrong). `export --org` will
    404 and tell you this; use `export --personal`, or export the org's
    audit log manually from its Settings > Audit log > Export page.
  - GitHub does not expose an API to *create* a personal access token
    (by design - you can't mint new credentials using existing ones).
    This project doesn't need one: every seed/attack action below rides
    on gh's own OAuth token. A manually-created PAT is optional, only
    for extra fidelity on the "stolen developer token" scenario - see
    `seed-attack --help`.

One-time environment setup (once per machine):
    winget install --id GitHub.cli
    gh auth login --scopes "repo,read:audit_log"

That --scopes flag matters: gh's own default login grants `repo` and
`read:org`. This project doesn't use `read:org` anywhere, and DOES need
`read:audit_log` (a real, separate OAuth scope - "Read audit log data")
for `export --org`, which gh doesn't request by default. Passing
--scopes explicitly gets exactly what's used and nothing else. If
you've already run a plain `gh auth login`, add the missing scope
without a full re-login: `gh auth refresh -h github.com -s read:audit_log`.
`check` (below) verifies this for you.

Subcommands:
    check
        Verifies gh is installed and authenticated; prints the exact
        fix command for whichever part is missing, then stops.

    seed-benign --prefix idt-lab
        Creates a repo, commits a file to it via the API, invites a
        collaborator (if you pass --collaborator), toggles visibility,
        and adds a topic - all real, all via `gh api`/`gh repo`, zero
        further interaction.

    seed-attack --prefix idt-lab
        Creates a decoy repo named like a secrets store
        (idt-lab-secret-vault), accesses it and downloads its contents
        with the same credential used for seed-benign, all within a
        few minutes - modeling a compromised-token access pattern.
        Optional --pat "<token>" to run this with a manually-created
        PAT instead of gh's own OAuth token (see the module docstring).

    export --org my-org --since 2026-09-01 [--until ...] --out real_data/github_audit.json
        Pulls GET /orgs/{org}/audit-log for the window via `gh api
        --paginate` and writes the raw merged array unmodified.
        Requires the org to already exist (see module docstring).

    export --personal --out real_data/github_security_log.json
        Prints the manual steps for the personal security log export -
        the one GitHub source with no API at all.

Pass --ingest real_benign or --ingest real_controlled_attack
[--attack-type A4] to `export` to immediately run
scripts/ingest_real_export.py against the written file.
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parent.parent


def _gh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    if shutil.which("gh") is None:
        print(
            "gh CLI is not installed. Install it with:\n"
            "    winget install --id GitHub.cli\n"
            "then run `gh auth login` and re-run this command.",
            file=sys.stderr,
        )
        sys.exit(1)
    result = subprocess.run(["gh", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"gh {' '.join(args)} failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result


def cmd_check(_args) -> None:
    if shutil.which("gh") is None:
        print("gh CLI: NOT installed.")
        print("Fix:  winget install --id GitHub.cli")
        sys.exit(1)
    print("gh CLI: installed.")
    status = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if status.returncode != 0:
        print("gh auth: NOT logged in.")
        print(
            "Fix:  gh auth login --scopes \"repo,read:audit_log\"\n"
            "      (opens a browser - click Authorize once. This requests only what\n"
            "      this project uses: `repo` for seed-benign/seed-attack, `read:audit_log`\n"
            "      for the org export - deliberately narrower than gh's own default\n"
            "      scope set, which also includes `read:org` unused here.)"
        )
        sys.exit(1)
    print("gh auth: logged in.")
    output = status.stderr + status.stdout
    print(output.strip())

    scopes_line = next((ln for ln in output.splitlines() if "Token scopes" in ln), "")
    if "repo" not in scopes_line:
        print(
            "\nWARNING: token has no 'repo' scope - seed-benign/seed-attack (repo "
            "create/write) will fail.\nFix:  gh auth refresh -h github.com -s repo"
        )
    if "read:audit_log" not in scopes_line:
        print(
            "\nNote: token has no 'read:audit_log' scope - only needed for "
            "`export --org` (not seed-benign/seed-attack).\n"
            "Fix if you plan to use it:  gh auth refresh -h github.com -s read:audit_log"
        )
    print("\nReady for seed-benign / seed-attack. See notes above for `export --org`.")


def cmd_seed_benign(args) -> None:
    """Real, harmless repo actions via `gh`/`gh api` - zero interaction
    beyond the one-time `gh auth login`."""
    who = json.loads(_gh("api", "user").stdout)["login"]
    repo_name = f"{args.prefix}-repo1"
    full = f"{who}/{repo_name}"

    print(f"Creating {full} ...")
    _gh("repo", "create", full, "--private", "--description", "IdentityTrace lab benign activity")

    print("Committing a file via the API ...")
    content_b64 = base64.b64encode(b"IdentityTrace lab benign commit\n").decode()
    _gh(
        "api", f"repos/{full}/contents/README.md", "-X", "PUT",
        "-f", "message=lab: initial commit",
        "-f", f"content={content_b64}",
    )

    print("Adding a topic ...")
    _gh("api", f"repos/{full}/topics", "-X", "PUT", "-f", "names[]=identitytrace-lab", "-H", "Accept: application/vnd.github+json")

    if args.collaborator:
        print(f"Inviting collaborator {args.collaborator} ...")
        _gh("api", f"repos/{full}/collaborators/{args.collaborator}", "-X", "PUT", check=False)

    print("Toggling visibility private -> public -> private ...")
    _gh("api", f"repos/{full}", "-X", "PATCH", "-f", "private=false")
    time.sleep(2)
    _gh("api", f"repos/{full}", "-X", "PATCH", "-f", "private=true")

    print(f"\nDone. {full} now has real, queryable audit/security-log activity.")


def cmd_seed_attack(args) -> None:
    """A decoy-repo access sequence, timed tightly, to model a
    compromised-credential access pattern - real API activity against a
    repo you own, using either gh's own token or a manually-created
    PAT (--pat) if you want closer 'stolen developer token' fidelity.

    Chases the full A4 correlation chain (IDT-CORR-005: repo_access ->
    sensitive_resource_access -> bulk_data_access), not just the middle
    step - a real Phase 9B run found `gh api` reads by the repo owner
    generate NO repo.access log entry at all (a confirmed GitHub personal
    security log limitation), so this uses the one action already proven
    (this session) to produce a real repo.access entry: toggling
    visibility. First on a "normal" repo (--normal-repo, if you already
    have one from seed-benign) to get repo_access on ordinary-looking
    activity, then on the decoy repo itself to get repo_access AND
    sensitive_resource_access together. --clone additionally attempts a
    real `git clone` for the bulk_data_access signal - experimental,
    since whether GitHub's personal log exposes a byte-transfer figure
    for it at all is not yet confirmed against real data."""
    env = None
    if args.pat:
        import os
        env = dict(os.environ, GH_TOKEN=args.pat)

    def gh_env(*cli_args, check=True):
        result = subprocess.run(["gh", *cli_args], capture_output=True, text=True, env=env)
        if check and result.returncode != 0:
            print(f"gh {' '.join(cli_args)} failed:\n{result.stderr}", file=sys.stderr)
            sys.exit(1)
        return result

    who = json.loads(gh_env("api", "user").stdout)["login"]

    if args.normal_repo:
        normal_full = f"{who}/{args.normal_repo}"
        print(f"Accessing normal repo {normal_full} first (repo_access signal) ...")
        gh_env("api", f"repos/{normal_full}", "-X", "PATCH", "-f", "private=false", check=False)
        time.sleep(2)
        gh_env("api", f"repos/{normal_full}", "-X", "PATCH", "-f", "private=true", check=False)
    else:
        print("No --normal-repo given - skipping the repo_access-on-ordinary-repo step "
              "(run seed-benign first and pass --normal-repo <name> for the fuller chain).")

    repo_name = f"{args.prefix}-secret-vault"
    full = f"{who}/{repo_name}"

    print(f"Creating decoy repo {full} ...")
    gh_env("repo", "create", full, "--private", "--description", "decoy - looks like a credential store")
    content_b64 = base64.b64encode(f"placeholder-{uuid.uuid4().hex}\n".encode()).decode()
    gh_env(
        "api", f"repos/{full}/contents/credentials.txt", "-X", "PUT",
        "-f", "message=seed", "-f", f"content={content_b64}",
    )

    print("Accessing repo metadata and contents rapidly (simulated exfil pattern) ...")
    gh_env("api", f"repos/{full}")
    gh_env("api", f"repos/{full}/contents/credentials.txt")
    gh_env("api", f"repos/{full}/commits")

    print(f"Toggling visibility on {full} (repo_access + sensitive_resource_access together) ...")
    gh_env("api", f"repos/{full}", "-X", "PATCH", "-f", "private=false", check=False)
    time.sleep(2)
    gh_env("api", f"repos/{full}", "-X", "PATCH", "-f", "private=true", check=False)

    if args.clone:
        print(f"Attempting a real `git clone` of {full} (bulk_data_access signal - experimental) ...")
        clone_url = f"https://github.com/{full}.git"
        result = subprocess.run(
            ["git", "clone", clone_url, str(Path.cwd() / f".{repo_name}-clone-tmp")],
            capture_output=True, text=True, env=env,
        )
        if result.returncode != 0:
            print(f"  clone failed (non-fatal): {result.stderr[:300]}")
        else:
            print("  cloned. Check the next export for whether this produced a distinct log "
                  "entry with a byte-transfer figure, or nothing at all like the API reads did.")

    print(f"\nDone. Sequence completed in one tight window against {full}.")


def _parse_paginated_json_arrays(text: str) -> list:
    """`gh api ... --paginate` on a bare-array endpoint like the org
    audit-log concatenates each page's JSON array back to back with no
    separator (e.g. `[...][...][...]`) rather than producing one valid
    JSON document. Decode each array in sequence and flatten them - the
    individual event objects are untouched, only the page boundaries
    are being resolved."""
    text = text.strip()
    events: list = []
    if not text:
        return events
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx] in " \n\r\t":
            idx += 1
        if idx >= len(text):
            break
        obj, end = decoder.raw_decode(text, idx)
        events.extend(obj if isinstance(obj, list) else [obj])
        idx = end
    return events


def cmd_export(args) -> None:
    if args.personal:
        print(
            "GitHub has no API for the personal security log - manual steps:\n"
            "  1. Go to https://github.com/settings/security-log\n"
            "  2. (optional) filter by date\n"
            "  3. Click Export -> JSON\n"
            f"  4. Save the downloaded file as {args.out}\n"
        )
        return

    if not args.org:
        print("Pass --org <org> or --personal.", file=sys.stderr)
        sys.exit(1)

    phrase = f"created:{args.since}"
    if args.until:
        phrase += f"..{args.until}"
    print(f"Pulling audit log for org '{args.org}', phrase='{phrase}' ...")
    result = _gh(
        "api", f"orgs/{args.org}/audit-log", "--paginate",
        "-f", f"phrase={phrase}",
        check=False,
    )
    if result.returncode != 0:
        if "404" in result.stderr:
            print(
                "404 Not Found - confirmed via GitHub's own docs: the org audit-log\n"
                "REST API requires GitHub Enterprise Cloud. A free (or Team-tier) org's\n"
                "audit log is UI-export-only, same limitation as the personal security\n"
                "log. Use `export --personal` instead, or export this org's audit log\n"
                f"manually from https://github.com/organizations/{args.org}/settings/audit-log\n"
                "(Export -> JSON) and save it to the path you passed to --out.",
                file=sys.stderr,
            )
        else:
            print(f"gh api orgs/{args.org}/audit-log failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    events = _parse_paginated_json_arrays(result.stdout)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(events, indent=2), encoding="utf-8")
    print(f"Wrote {len(events)} audit-log events -> {out_path}")

    if args.ingest:
        cmd = [
            sys.executable, "scripts/ingest_real_export.py", str(out_path),
            "--source", "github", "--label", args.ingest,
        ]
        if args.attack_type:
            cmd += ["--attack-type", args.attack_type]
        print(f"\n$ {' '.join(cmd)}")
        subprocess.run(cmd, cwd=REPO_ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="verify gh is installed and authenticated").set_defaults(fn=cmd_check)

    p = sub.add_parser("seed-benign", help="real benign repo activity")
    p.add_argument("--prefix", default="idt-lab")
    p.add_argument("--collaborator", help="username to invite as a collaborator")
    p.set_defaults(fn=cmd_seed_benign)

    p = sub.add_parser("seed-attack", help="timed decoy-repo access sequence")
    p.add_argument("--prefix", default="idt-lab")
    p.add_argument("--pat", help="optional manually-created PAT for closer 'stolen token' fidelity")
    p.add_argument("--normal-repo", help="an existing repo (e.g. from seed-benign) to access first, for the repo_access-on-ordinary-activity chain step")
    p.add_argument("--clone", action="store_true", help="also attempt a real git clone for the bulk_data_access signal (experimental)")
    p.set_defaults(fn=cmd_seed_attack)

    p = sub.add_parser("export", help="pull raw org audit-log, or print personal-log manual steps")
    p.add_argument("--org")
    p.add_argument("--personal", action="store_true")
    p.add_argument("--since", help="e.g. 2026-09-01 (required with --org)")
    p.add_argument("--until")
    p.add_argument("--out", required=True)
    p.add_argument("--ingest", choices=["real_benign", "real_controlled_attack"])
    p.add_argument("--attack-type", choices=["A1", "A2", "A3", "A4", "A5", "A6"])
    p.set_defaults(fn=cmd_export)

    args = parser.parse_args()
    if getattr(args, "command", None) == "export" and args.org and not args.since:
        parser.error("--since is required with --org")
    if getattr(args, "command", None) == "export" and args.ingest == "real_controlled_attack" and not args.attack_type:
        parser.error("--attack-type is required with --ingest real_controlled_attack")
    args.fn(args)


if __name__ == "__main__":
    main()
