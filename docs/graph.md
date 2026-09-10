# Identity Graph (Phase 5)

Per-incident evidence graphs, built with NetworkX per the blueprint's
explicit MVP stack choice (§5.1: "NetworkX for MVP; Neo4j optional later").

## Why per-incident, not a persistent global graph

The blueprint's §8.1 relationships (`AUTHENTICATED_VIA`, `CONSENTED_TO`,
`ACCESSED`, `ASSIGNED`, `EVIDENCE_FOR`, ...) describe entities and edges,
but nothing about *when* to materialize them. Building one global,
incrementally-maintained graph would mean a second copy of identity
relationships to keep in sync with the events/matches/deviations tables -
exactly the kind of premature complexity the blueprint repeatedly warns
against (§5.1: "Avoid premature complexity. Add only when ... requires
it."). Instead, `app/graph/build.py`'s `build_incident_graph()` rebuilds a
small, scoped graph on demand from one incident's `evidence_ids` - cheap at
this project's scale, and by construction never drifts from the
events table.

## Relationships built

| Blueprint relationship | When it's added |
|---|---|
| `(Identity)-[:TRIGGERED]->(Event)` | Always, for every evidence event |
| `(Event)-[:EVIDENCE_FOR]->(Incident)` | Always |
| `(Identity)-[:AUTHENTICATED_VIA]->(Session)` | Event has a `session_id` |
| `(Session)-[:FROM]->(IP)` / `(Event)-[:FROM]->(IP)` | Event has `ip_address` (anchored to the session if one exists, else directly to the event) |
| `(Session)-[:ON]->(Device)` / `(Event)-[:ON]->(Device)` | Event has `device_id` (same anchoring) |
| `(Identity)-[:CONSENTED_TO]->(OAuthApp)` | `event_type == "oauth_consent"` and `app_id` present |
| `(OAuthApp)-[:GRANTED]->(Permission)` | One edge per scope in the consent event's `permissions` |
| `(Identity)-[:ACCESSED]->(Resource)` | `resource_id` present on a non-consent event |
| `(Identity)-[:ASSIGNED]->(Privilege)` | The event's `action` mentions "role" (Phase 2's `IDT-ENTRA-006` heuristic, reused here) |

Session isn't yet a modeled entity with its own start/end/auth-method
(that's a real gap vs. the blueprint's Session entity, §6.3) - it's just
the bare `session_id` string an event happens to carry, per this project's
current schema.

## Rendering

`app/graph/svg.py` renders the graph as inline SVG using
`nx.spring_layout()` for node positions (seeded, so a given incident's
graph looks the same every time it's viewed) - no client-side JS graph
library, no CDN dependency. `app/graph/serialize.py` produces the same
graph as plain node/edge JSON for the API. Both consume the identical
`build_incident_graph()` output, so the dashboard's picture and the API's
JSON are guaranteed to agree.

## API & dashboard

- `GET /api/incidents/{id}/graph` - `{"nodes": [...], "edges": [...]}`.
- The incident detail page (`/incidents/{id}`) renders the SVG directly
  above the evidence timeline.

## Testing

- `tests/unit/test_graph_build.py` - every relationship rule above, plus
  edge cases: no session (IP/device anchor to the event instead), a
  missing evidence event (skipped, not a crash), multiple events all
  linking to the same incident.
- `tests/unit/test_graph_serialize_and_svg.py` - JSON shape, SVG label
  escaping (a label can't inject markup), long-label truncation, empty
  graph.
- `tests/integration/test_incidents.py` - `GET /api/incidents/{id}/graph`
  against a real correlated incident (checks the OAuth app's display-name
  labeling and every relationship type actually appears), and the
  dashboard's incident detail page actually contains a rendered `<svg>`.
