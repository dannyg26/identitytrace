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


def render_svg(graph: nx.MultiDiGraph, width: int = 900, height: int = 560) -> str:
    if graph.number_of_nodes() == 0:
        return f'<svg width="{width}" height="{height}"></svg>'

    k = 1.4 / max(1, graph.number_of_nodes() ** 0.5)
    pos = nx.spring_layout(graph, seed=42, k=k)

    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    pad = 60

    def scale(x: float, y: float) -> tuple[float, float]:
        sx = pad + (x - min_x) / (max_x - min_x or 1) * (width - 2 * pad)
        sy = pad + (y - min_y) / (max_y - min_y or 1) * (height - 2 * pad)
        return sx, sy

    scaled = {node: scale(x, y) for node, (x, y) in pos.items()}

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'xmlns="http://www.w3.org/2000/svg" style="background:#0f1420;border-radius:10px;">'
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
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#333c58" stroke-width="1.5" />'
        )
        parts.append(
            f'<text x="{mx:.1f}" y="{my:.1f}" font-size="9" fill="#7d87a8" '
            f'text-anchor="middle">{_esc(relation)}</text>'
        )

    for node, (x, y) in scaled.items():
        data = graph.nodes[node]
        kind = data.get("kind", "event")
        color = NODE_COLORS.get(kind, "#9aa3bd")
        radius = NODE_RADIUS.get(kind, DEFAULT_RADIUS)
        label = str(data.get("label", node))
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

    parts.append("</svg>")
    return "".join(parts)
