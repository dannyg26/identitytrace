"""Identity graph (blueprint §5.1 "NetworkX for MVP" + §8.1's relationship
vocabulary): typed entities and relationships, built per-incident from its
evidence events.

Deliberately NOT a persistent, incrementally-maintained global graph - the
blueprint explicitly recommends NetworkX over a graph database for the MVP
specifically to avoid that complexity. Each incident's graph is rebuilt
on demand from the same `EventRecord` rows already used everywhere else
(matches, deviations, correlation), so there's no second copy of identity
relationships to keep in sync.
"""

from __future__ import annotations

import networkx as nx
from sqlalchemy.orm import Session

from app.models.event import EventRecord


def _node_id(kind: str, key: str) -> str:
    return f"{kind}:{key}"


def build_incident_graph(db: Session, incident: dict) -> nx.MultiDiGraph:
    """A directed multigraph of every entity touched by `incident`'s
    evidence events, connected per the blueprint's §8.1 relationships
    (adapted to what this project's normalized schema actually tracks -
    e.g. Session is a bare session_id, not yet a modeled entity with its
    own start/end).
    """
    graph = nx.MultiDiGraph()

    incident_node = _node_id("incident", incident["incident_id"])
    graph.add_node(incident_node, kind="incident", label=incident["correlation_rule_title"])

    identity_node = _node_id("identity", incident["identity_id"])
    graph.add_node(identity_node, kind="identity", label=incident["identity_id"])

    records = (
        db.query(EventRecord)
        .filter(EventRecord.event_id.in_(incident["evidence_ids"]))
        .all()
    )
    events_by_id = {r.event_id: r for r in records}

    for event_id in incident["evidence_ids"]:
        event = events_by_id.get(event_id)
        if event is None:
            continue

        event_node = _node_id("event", event.event_id)
        graph.add_node(
            event_node, kind="event", label=f"{event.event_type}: {event.action}"
        )
        graph.add_edge(identity_node, event_node, relation="TRIGGERED")
        graph.add_edge(event_node, incident_node, relation="EVIDENCE_FOR")

        if event.session_id:
            session_node = _node_id("session", event.session_id)
            graph.add_node(session_node, kind="session", label=event.session_id)
            graph.add_edge(identity_node, session_node, relation="AUTHENTICATED_VIA")
            graph.add_edge(event_node, session_node, relation="VIA")
            ip_or_device_anchor = session_node
            anchor_relation_ip = "FROM"
            anchor_relation_device = "ON"
        else:
            # No session context on this event - anchor IP/device directly
            # off the event so the evidence still shows up in the graph.
            ip_or_device_anchor = event_node
            anchor_relation_ip = "FROM"
            anchor_relation_device = "ON"

        if event.ip_address:
            ip_node = _node_id("ip", event.ip_address)
            graph.add_node(ip_node, kind="ip", label=event.ip_address)
            graph.add_edge(ip_or_device_anchor, ip_node, relation=anchor_relation_ip)

        if event.device_id:
            device_node = _node_id("device", event.device_id)
            graph.add_node(device_node, kind="device", label=event.device_id)
            graph.add_edge(ip_or_device_anchor, device_node, relation=anchor_relation_device)

        if event.app_id:
            app_node = _node_id("app", event.app_id)
            app_label = event.resource_id if event.event_type == "oauth_consent" else event.app_id
            graph.add_node(app_node, kind="app", label=app_label)
            if event.event_type == "oauth_consent":
                graph.add_edge(identity_node, app_node, relation="CONSENTED_TO")
                for permission in event.permissions or []:
                    permission_node = _node_id("permission", permission)
                    graph.add_node(permission_node, kind="permission", label=permission)
                    graph.add_edge(app_node, permission_node, relation="GRANTED")
            else:
                graph.add_edge(event_node, app_node, relation="USED_APP")

        if event.resource_id and event.event_type != "oauth_consent":
            resource_node = _node_id("resource", event.resource_id)
            graph.add_node(resource_node, kind="resource", label=event.resource_id)
            graph.add_edge(identity_node, resource_node, relation="ACCESSED")
            graph.add_edge(event_node, resource_node, relation="ON_RESOURCE")

        if "role" in (event.action or "").lower():
            privilege_node = _node_id("privilege", event.action)
            graph.add_node(privilege_node, kind="privilege", label=event.action)
            graph.add_edge(identity_node, privilege_node, relation="ASSIGNED")
            graph.add_edge(event_node, privilege_node, relation="GRANTED_PRIVILEGE")

    return graph
