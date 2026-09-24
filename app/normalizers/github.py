"""Normalize GitHub organization audit log-shaped raw events into the common
NormalizedEvent schema.

Modeled on the real GitHub organization audit log export shape (the fields
returned by the audit-log REST/export API), covering the actions the
blueprint's developer-token and repository scenarios (A4, A6) depend on:
token creation/use, repository clone/access, and secret-oriented paths.

Field names checked against GitHub's documented enterprise audit log
schema and its "Authentication Metadata for Git Events" feature - see
docs/normalizer-fidelity.md. `actor_location.country_name` (not
`country_code`, which this module used before that check) is GitHub's
actual documented field; note it's a country *name* ("United States"),
unlike Entra's `location.countryOrRegion`, which is a 2-letter code - the
two sources aren't directly comparable without extra normalization this
project doesn't do yet (a real limitation for any future cross-source
"same country" baseline comparison).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.event import NormalizedEvent

# GitHub audit "action" strings that represent bulk/clone-style data access.
_CLONE_ACTIONS = {"git.clone", "repo.clone", "repo.download_zip"}
_TOKEN_ACTIONS_PREFIX = "personal_access_token."


def _event_id(raw: dict[str, Any]) -> str:
    doc_id = raw.get("_document_id") or raw.get("id")
    return str(doc_id) if doc_id else str(uuid.uuid4())


def _stringify(value: Any) -> str | None:
    return str(value) if value is not None else None


def _parse_ts(raw: dict[str, Any]) -> datetime:
    if "created_at" in raw:
        value = raw["created_at"]
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    if "@timestamp" in raw:
        return datetime.fromtimestamp(raw["@timestamp"] / 1000, tz=timezone.utc)
    raise ValueError("GitHub raw event missing created_at/@timestamp")


def _event_type(action: str) -> str:
    if action in _CLONE_ACTIONS or action.startswith("git."):
        return "repo_clone"
    if action.startswith(_TOKEN_ACTIONS_PREFIX) or action.startswith("oauth_"):
        return "token_event"
    if action == "repo.access":
        return "repo_access"
    # Real telemetry (Phase 9B): GitHub's real audit action namespace has
    # ~20 distinct repo.* actions (create, destroy, change_merge_setting,
    # set_default_workflow_permissions, add_topic, rename, ...) - only
    # "repo.access" itself is a genuine read/view action. Classifying
    # every repo.* action as repo_access made IDT-GITHUB-001 (PAT used for
    # repository access) fire on every token-authenticated repo config
    # change, not just actual access - confirmed by a real false-positive
    # run: 8 of 8 real repo.* events matched, only 1 was a real access.
    return "audit"


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    action = raw.get("action", "unknown")
    location = raw.get("actor_location") or {}
    is_token_actor = bool(raw.get("token_id") or raw.get("hashed_token"))

    return NormalizedEvent(
        event_id=_event_id(raw),
        timestamp=_parse_ts(raw),
        source="github",
        event_type=_event_type(action),
        action=action,
        result="failure" if action.endswith(("_fail", ".failed")) else "success",
        actor_id=raw.get("actor") or str(raw.get("actor_id") or "unknown"),
        actor_type="token" if is_token_actor else "user",
        session_id=None,
        device_id=None,
        ip_address=raw.get("actor_ip"),
        geo_country=location.get("country_name"),
        user_agent=raw.get("user_agent"),
        auth_protocol="PAT" if is_token_actor else None,
        mfa_result=None,
        # Real telemetry (Phase 9B): oauth_application_id comes back as a
        # real int (e.g. 5479418713) in GitHub's own security-log export,
        # not a string - NormalizedEvent.app_id requires str.
        app_id=_stringify(raw.get("token_id") or raw.get("oauth_application_id")),
        permissions=list(raw.get("token_scopes") or []),
        resource_id=raw.get("repo") or raw.get("org"),
        resource_type="repo" if raw.get("repo") else ("org" if raw.get("org") else None),
        bytes_transferred=raw.get("transfer_size_bytes"),
        raw_event_ref=raw,
    )
