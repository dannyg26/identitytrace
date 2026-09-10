"""Normalize Microsoft 365 unified audit log-shaped raw events (the Office
365 Management Activity API schema real tenants export) into the common
NormalizedEvent schema.

This is the blueprint's suggested third telemetry domain (§6.1, §10.1.1) -
distinct from app/normalizers/entra.py, which already covers Azure AD
sign-in/audit/OAuth-consent events (those also flow through the same
unified log in a real tenant, but this project keeps that path on the
entra normalizer since it's already built and tested; m365.py covers the
SharePoint/OneDrive/Exchange workload events Entra's normalizer doesn't).
Feeds A6 (SaaS data theft) most directly - file access/download volume and
mailbox persistence (forwarding rules, a classic BEC technique) are exactly
the evidence that scenario needs.

Field names checked against Microsoft's documented Office 365 Management
Activity API common schema (CreationTime, Operation, Workload, UserId,
ClientIP, ResultStatus, ObjectId) - see docs/normalizer-fidelity.md. That
check is also why `ResultStatus: "PartiallySucceeded"` maps to this
project's `result="partial"` (already a valid NormalizedEvent value,
previously unused by any normalizer) instead of being folded into
"failure" - a real, documented status this API returns, not a guess.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.event import NormalizedEvent

_FILE_OPERATIONS = {"FileDownloaded", "FileAccessed", "FileSyncDownloadedFull"}
_MAILBOX_RULE_OPERATIONS = {"New-InboxRule", "Set-Mailbox", "UpdateInboxRules"}
_MAILBOX_ACCESS_OPERATIONS = {"MailItemsAccessed"}

_WORKLOAD_RESOURCE_TYPE = {
    "SharePoint": "file",
    "OneDrive": "file",
    "Exchange": "mailbox",
}


def _event_id(raw: dict[str, Any]) -> str:
    return str(raw["Id"]) if raw.get("Id") else str(uuid.uuid4())


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _event_type(operation: str) -> str:
    if operation in _MAILBOX_RULE_OPERATIONS:
        return "mailbox_rule_change"
    if operation in _MAILBOX_ACCESS_OPERATIONS:
        return "mailbox_access"
    if operation in _FILE_OPERATIONS:
        return "file_download" if operation != "FileAccessed" else "file_access"
    return "audit"


def _result(raw: dict[str, Any]) -> str:
    # Real ResultStatus values (Microsoft's documented schema): Succeeded,
    # PartiallySucceeded, Failed. "Partial" maps to this project's own
    # dedicated `partial` result value rather than being lumped in with
    # outright failures.
    status = (raw.get("ResultStatus") or "Succeeded").lower()
    if status in ("succeeded", "success"):
        return "success"
    if status == "partiallysucceeded":
        return "partial"
    return "failure"


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    operation = raw.get("Operation", "unknown")
    workload = raw.get("Workload")

    return NormalizedEvent(
        event_id=_event_id(raw),
        timestamp=_parse_ts(raw["CreationTime"]),
        source="m365",
        event_type=_event_type(operation),
        action=operation,
        result=_result(raw),
        actor_id=raw.get("UserId") or "unknown",
        actor_type="user",
        session_id=None,
        device_id=raw.get("DeviceId"),
        ip_address=raw.get("ClientIP"),
        geo_country=None,
        user_agent=raw.get("UserAgent"),
        auth_protocol=None,
        mfa_result=None,
        app_id=raw.get("ApplicationId"),
        permissions=[],
        resource_id=raw.get("ObjectId") or raw.get("SiteUrl"),
        resource_type=_WORKLOAD_RESOURCE_TYPE.get(workload),
        bytes_transferred=raw.get("SizeInBytes") or raw.get("FileSizeBytes"),
        raw_event_ref=raw,
    )
