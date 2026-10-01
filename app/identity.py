"""Resolve only administrator-approved source/alias pairs; never guess links."""

from app.models.event import NormalizedEvent
from app.models.operations import IdentityLink


def resolve_identity(db, event: NormalizedEvent) -> NormalizedEvent:
    original = event.source_actor_id or event.actor_id
    link = db.get(IdentityLink, (event.source, original))
    if link is None:
        return event
    return event.model_copy(update={"actor_id": link.canonical_id, "source_actor_id": original})
