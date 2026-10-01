"""Render a built graph as inline SVG for the dashboard - no client-side
JS graph library, no CDN dependency, so the app stays fully self-contained
(consistent with the "reproducible local deployment" ethos of the
blueprint's stack choices, §5.1).
"""

from __future__ import annotations

import html

import networkx as nx

NODE_COLORS = {
    "identity": "#8fb3ff",
    "session": "#6fcf7a",
    "device": "#e0c341",
    "ip": "#e0913f",
    "app": "#c792ea",
    "permission": "#e05f5f",
    "resource": "#5fd0e0",
    "privilege": "#ff8fa3",
    "event": "#9aa3bd",
    "incident": "#ffffff",
}
NODE_RADIUS = {"incident": 22, "identity": 20}
DEFAULT_RADIUS = 14
MAX_LABEL_LEN = 22


def _esc(value: object) -> str:
    return html.escape(str(value))


def render_svg(graph: nx.MultiDiGraph, width: int = 1040, height: int = 360) -> str:
    if graph.number_of_nodes() == 0:
        return f'<svg width="{width}" height="{height}"></svg>'

    # Stable columns avoid spring-layout label collisions and visual movement
    # between investigations. Relationships remain available as tooltips.
    columns = [[], [], [], []]
    for node, data in sorted(graph.nodes(data=True), key=lambda item: str(item[0])):
        kind = data.get("kind", "event")
        column = (3 if kind == "incident" else 1 if kind == "event" else
                  0 if kind in {"identity", "session", "device", "ip"} else 2)
        columns[column].append(node)
    width = max(width, 1040)
    height = max(height, 100 * max(map(len, columns)) + 80)
    scaled = {node: (130 + column * (width - 260) / 3, 60 + row * 100)
              for column, nodes in enumerate(columns) for row, node in enumerate(nodes)}

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Incident evidence relationships" style="min-width:{width}px;background:#0f1420;border-radius:10px;">'
    ]

    seen_edges: set[tuple[str, str, str]] = set()
    for u, v, data in graph.edges(data=True):
        relation = data.get("relation", "")
        key = (u, v, relation)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        x1, y1 = scaled[u]
        x2, y2 = scaled[v]
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#333c58" stroke-width="1.5"><title>{_esc(relation)}</title></line>'
        )

    for node, (x, y) in scaled.items():
        data = graph.nodes[node]
        kind = data.get("kind", "event")
        color = NODE_COLORS.get(kind, "#9aa3bd")
        radius = NODE_RADIUS.get(kind, DEFAULT_RADIUS)
        label = str(data.get("label", node))
        parts.append(f'<g tabindex="0"><title>{_esc(kind)}: {_esc(label)}</title>')
        if len(label) > MAX_LABEL_LEN:
            label = label[: MAX_LABEL_LEN - 3] + "..."
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{color}" '
            f'stroke="#0f1420" stroke-width="2" />'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y + radius + 12:.1f}" font-size="11" fill="#e6e9f0" '
            f'text-anchor="middle">{_esc(label)}</text>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{y + 4:.1f}" font-size="9" fill="#0f1420" '
            f'text-anchor="middle">{_esc(kind[:3])}</text>'
        )
        parts.append('</g>')

    parts.append("</svg>")
    return "".join(parts)
