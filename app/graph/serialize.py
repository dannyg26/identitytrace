"""Serialize a built graph to plain JSON-able node/edge lists (for the API;
see app/graph/svg.py for the dashboard's visual rendering)."""

from __future__ import annotations

import networkx as nx


def graph_to_dict(graph: nx.MultiDiGraph) -> dict:
    nodes = [{"id": node_id, **data} for node_id, data in graph.nodes(data=True)]
    edges = [
        {"source": source, "target": target, "relation": data.get("relation")}
        for source, target, data in graph.edges(data=True)
    ]
    return {"nodes": nodes, "edges": edges}
