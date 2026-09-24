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


def _parse_scope_string(raw_value: Any) -> list[str] | None:
    """A JSON-quoted, space-separated scope string -> its scopes, in order
    and de-duplicated. None when the value is absent or not that shape."""
    if not raw_value:
        return None
    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, str):
        return None
    return list(dict.fromkeys(parsed.split()))


def _extract_consent_permissions(target_resources: list[dict]) -> list[str]:
    perms: list[str] = []
    for resource in target_resources or []:
        for prop in resource.get("modifiedProperties", []) or []:
            name = prop.get("displayName") or ""
            raw_value = prop.get("newValue")
            if not raw_value:
                continue

            if name == "DelegatedPermissionGrant.Scope":
                # Real shape found via Phase 9B telemetry: the property that
                # actually carries a newly-granted scope like Files.Read.All
                # when an admin consents is one space-separated string
                # (JSON-quoted), not an array. It is the CUMULATIVE scope of
                # the grant: newValue repeats everything already granted
                # (e.g. offline_access from an earlier event), so only
                # newValue minus oldValue is what THIS event added. Scoring
                # the cumulative list re-fires on permissions this event did
                # not grant (see docs/evaluation.md, "A2 Benign Twin -
                # Detection vs Intent"). The full cumulative value stays
                # available in raw_event_ref.
                new_scopes = _parse_scope_string(raw_value)
                if new_scopes is None:
                    continue
                already_granted = set(_parse_scope_string(prop.get("oldValue")) or [])
                perms.extend(s for s in new_scopes if s not in already_granted)
                continue

            if "Permissions" not in name:
                continue
            # ConsentAction.Permissions (on "Consent to application" events)
            # is documented/tested against a clean JSON array, but real
            # telemetry showed it can also be Entra's internal
            # "[[Id: ..., Scope: ...]] => [[...]]" object-dump text - not
            # valid JSON, and not safe to whitespace-split (that produces
            # junk tokens like "ClientId:" alongside real scope names).
            # Left unparsed rather than guessed at - a known, honest gap,
            # not silently worked around. DelegatedPermissionGrant.Scope
            # above already carries the same information cleanly whenever
            # this shape shows up paired with it.
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


_NIL_GUID = "00000000-0000-0000-0000-000000000000"


def _clean_entity_id(value: Any) -> str | None:
    """Normalize a GUID-like entity identifier for exact-match linking.

    Real telemetry (Phase 9B): browser/portal sign-ins carry
    `servicePrincipalId == 00000000-0000-0000-0000-000000000000` - a
    placeholder, not an entity. Treating it as one would make every such
    event "share" a service principal with every other. Empty/nil -> None,
    so a correlation constraint on this field fails closed. Lower-cased so a
    case difference can never silently break an exact match.
    """
    if not isinstance(value, str):
        return None
    cleaned = value.strip().strip('"').strip().lower()
    if not cleaned or cleaned == _NIL_GUID:
        return None
    return cleaned


def _audit_service_principal_id(target_resources: list[dict]) -> str | None:
    """The *client* application's service principal on an audit event.

    Only the explicit `ServicePrincipal.ObjectID` modified property is
    used. Do NOT fall back to "the first ServicePrincipal target": on real
    `Add/Remove delegated permission grant` events, targetResources[0] is
    the *resource* service principal (Microsoft Graph, 806e4a74...), and
    the client application is the second entry - taking the first would
    silently link on the wrong entity. Absent -> None (fails closed).
    """
    for target in target_resources or []:
        for prop in target.get("modifiedProperties") or []:
            if prop.get("displayName") != "ServicePrincipal.ObjectID":
                continue
            raw_value = prop.get("newValue")
            try:
                parsed = json.loads(raw_value) if isinstance(raw_value, str) else raw_value
            except ValueError:
                parsed = raw_value
            cleaned = _clean_entity_id(parsed)
            if cleaned:
                return cleaned
    return None


def _native_client_auth_protocol(raw: dict[str, Any]) -> str | None:
    """Real telemetry (Phase 9B, 2026-09): `authenticationProtocol` is
    documented on the signIn resource but was never once populated across
    37 real sign-ins inspected in this tenant - benign and controlled-
    attack, success and failure alike - confirmed by direct field-by-field
    inspection, not assumed. `clientAppUsed` IS reliably populated and
    perfectly separates native/desktop/CLI clients from browser sign-ins
    (0 exceptions in all 37) - but that's a broader real-world category
    than "device-code" specifically (it also covers other native flows:
    mobile apps, Windows-integrated auth, ROPC). Returning a distinctly-
    named value here, rather than "deviceCode", is deliberate: it's honest
    about detecting "native/CLI-style sign-in", not the specific protocol
    the field's absence makes unprovable. See IDT-ENTRA-003 and
    docs/evaluation.md's Real-World Observability Findings section for
    the full investigation and the original (deviceCode-only) behavior
    this replaces."""
    if raw.get("clientAppUsed") == "Mobile Apps and Desktop clients":
        return "nativeClient"
    return None


def _normalize_signin(raw: dict[str, Any]) -> NormalizedEvent:
    status = raw.get("status") or {}
    device = raw.get("deviceDetail") or {}
    location = raw.get("location") or {}
    result = "success" if status.get("errorCode", 0) == 0 else "failure"
    # Real telemetry (Phase 9B, 2026-09): AADSTS90094 ("Admin consent is
    # required for the permissions requested by this application") is a
    # specific, narrow failure reason - present in the one real controlled
    # attempt that requested an approval-requiring scope, and in 0 of 34
    # real benign sign-ins. The detection engine only resolves top-level
    # NormalizedEvent fields (no nested raw_event_ref access), so this is
    # surfaced into `action`, which was otherwise a constant "login" for
    # every signin - not overloading a field that carried real information
    # elsewhere. See IDT-ENTRA-007 and docs/evaluation.md's A2 End-to-End
    # Real Validation section.
    action = "admin_consent_required" if status.get("errorCode") == 90094 else "login"

    return NormalizedEvent(
        event_id=_event_id(raw),
        timestamp=_parse_ts(raw["createdDateTime"]),
        source="entra",
        event_type="signin",
        action=action,
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
        auth_protocol=raw.get("authenticationProtocol") or _native_client_auth_protocol(raw),
        mfa_result=_mfa_result(raw),
        app_id=raw.get("appId"),
        service_principal_id=_clean_entity_id(raw.get("servicePrincipalId")),
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
    activity_lower = activity.lower()
    # Real telemetry (Phase 9B): an admin consent grant actually shows up as
    # a correlated trio of audit events - "Consent to application" plus a
    # "Remove/Add delegated permission grant" pair (an update = Add + Remove of
    # the same resulting state; the Add is the one that grants). Only the last
    # two contain "delegated permission grant", not
    # "consent" - "Consent to application" alone was too narrow.
    is_consent = "consent" in activity_lower or "delegated permission grant" in activity_lower
    # Entra logs an update to an existing grant as an Add plus a Remove within
    # milliseconds (same correlationId, actor, targets and, byte for byte, the
    # same old/new scope values - the Remove is NOT a reduction). The Add
    # carries the grant; a Remove/Unassign record cannot grant anything, so it
    # contributes no permissions. Otherwise one consent action is scored twice.
    # See docs/evaluation.md, "Remove delegated permission grant".
    is_grant_removal = activity_lower.startswith("remove") and "delegated permission grant" in activity_lower
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
        ip_address=initiated_by.get("ipAddress"),
        geo_country=None,
        user_agent=None,
        auth_protocol=None,
        mfa_result=None,
        app_id=(app_target or {}).get("id"),
        service_principal_id=_audit_service_principal_id(targets),
        permissions=_extract_consent_permissions(targets) if is_consent and not is_grant_removal else [],
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
