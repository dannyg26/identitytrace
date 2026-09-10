"""Normalize Entra ID-shaped raw events into the common NormalizedEvent schema.

Modeled loosely on the two Entra log categories analysts actually work with
(Azure Monitor table names): "signInLogs" for authentication events and
"auditLogs" for directory/consent/role-assignment events. Real Entra export
schemas are larger; this covers the fields the blueprint's attack scenarios
(A1-A3, A5) depend on. Extend here, not in the API layer, as more fields are
needed - this module is the seam Phase 6 revisits.

Field names checked against Microsoft's real Graph API resource docs
(learn.microsoft.com/en-us/graph/api/resources/{signin,directoryaudit,
devicedetail,signinlocation,targetresource,auditactivityinitiator}) -
see docs/normalizer-fidelity.md. One real finding from that check:
`mfaDetail` is a documented-deprecated field on the real `signIn` resource;
its replacement is the top-level `authenticationRequirement` string
(`singleFactorAuthentication` / `multiFactorAuthentication`). Both are
supported here - `mfaDetail` is still commonly present in real payloads
(and in every fixture this project's own generators produce), so it's
checked first, falling back to the modern field.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.event import NormalizedEvent


def _event_id(raw: dict[str, Any]) -> str:
    return str(raw["id"]) if raw.get("id") else str(uuid.uuid4())


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc)


def _extract_consent_permissions(target_resources: list[dict]) -> list[str]:
    perms: list[str] = []
    for resource in target_resources or []:
        for prop in resource.get("modifiedProperties", []) or []:
            if "Permissions" not in (prop.get("displayName") or ""):
                continue
            raw_value = prop.get("newValue")
            if not raw_value:
                continue
            try:
                parsed = json.loads(raw_value)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, list):
                perms.extend(str(p) for p in parsed)
    return perms


def _mfa_result(raw: dict[str, Any]) -> str | None:
    mfa = raw.get("mfaDetail") or {}
    if mfa.get("result"):
        return mfa["result"]
    # mfaDetail is documented-deprecated on the real signIn resource; the
    # modern replacement is the top-level authenticationRequirement string.
    requirement = raw.get("authenticationRequirement")
    if requirement == "multiFactorAuthentication":
        return "success"
    if requirement == "singleFactorAuthentication":
        return "not_present"
    return None


def _normalize_signin(raw: dict[str, Any]) -> NormalizedEvent:
    status = raw.get("status") or {}
    device = raw.get("deviceDetail") or {}
    location = raw.get("location") or {}
    result = "success" if status.get("errorCode", 0) == 0 else "failure"

    return NormalizedEvent(
        event_id=_event_id(raw),
        timestamp=_parse_ts(raw["createdDateTime"]),
        source="entra",
        event_type="signin",
        action="login",
        result=result,
        actor_id=raw.get("userPrincipalName") or raw.get("userId") or "unknown",
        actor_type="user",
        session_id=raw.get("sessionId"),
        device_id=device.get("deviceId"),
        ip_address=raw.get("ipAddress"),
        geo_country=location.get("countryOrRegion"),
        user_agent=device.get("browser") or raw.get("userAgent"),
        # authenticationRequirement is deliberately NOT a fallback here -
        # it's an MFA-strength signal ("singleFactorAuthentication" etc.),
        # not a protocol/grant type, and folding it in here was a latent
        # bug (harmless by accident: it never matched any rule's
        # auth_protocol enum checks, but was semantically wrong).
        auth_protocol=raw.get("authenticationProtocol"),
        mfa_result=_mfa_result(raw),
        app_id=raw.get("appId"),
        permissions=[],
        resource_id=raw.get("resourceId") or raw.get("resourceDisplayName"),
        resource_type="app" if raw.get("resourceDisplayName") else None,
        bytes_transferred=None,
        raw_event_ref=raw,
    )


def _normalize_audit(raw: dict[str, Any]) -> NormalizedEvent:
    initiated_by = (raw.get("initiatedBy") or {}).get("user") or {}
    targets = raw.get("targetResources") or []
    activity = raw.get("activityDisplayName") or "audit_event"
    is_consent = "consent" in activity.lower()
    app_target = next((t for t in targets if t.get("type") == "Application"), None)

    return NormalizedEvent(
        event_id=_event_id(raw),
        timestamp=_parse_ts(raw["activityDateTime"]),
        source="entra",
        event_type="oauth_consent" if is_consent else "audit",
        action=activity,
        result=(raw.get("result") or "success").lower(),
        actor_id=initiated_by.get("userPrincipalName") or initiated_by.get("id") or "unknown",
        actor_type="user",
        session_id=None,
        device_id=None,
        ip_address=(raw.get("initiatedBy") or {}).get("user", {}).get("ipAddress"),
        geo_country=None,
        user_agent=None,
        auth_protocol=None,
        mfa_result=None,
        app_id=(app_target or {}).get("id"),
        permissions=_extract_consent_permissions(targets) if is_consent else [],
        resource_id=(app_target or {}).get("displayName") if app_target else None,
        resource_type="app" if app_target else None,
        bytes_transferred=None,
        raw_event_ref=raw,
    )


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    """Dispatch between the two real Entra log shapes.

    Keyed on `activityDateTime` (present only on the real `directoryAudit`
    resource) vs. `createdDateTime` (the real `signIn` resource's
    timestamp field) - a prior version of this dispatch used an invented
    `category: "auditLogs"/"signInLogs"` marker, which collided with
    `directoryAudit`'s own real `category` field (real values like
    `"ApplicationManagement"`, `"RoleManagement"` - nothing to do with
    picking a parser) and would have broken on genuine audit payloads. See
    docs/normalizer-fidelity.md.
    """
    if "activityDateTime" in raw:
        return _normalize_audit(raw)
    return _normalize_signin(raw)
