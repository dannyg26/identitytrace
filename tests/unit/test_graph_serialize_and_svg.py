import networkx as nx

from app.graph.serialize import graph_to_dict
from app.graph.svg import render_svg


def _sample_graph() -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    g.add_node("identity:alice", kind="identity", label="alice")
    g.add_node("event:evt-1", kind="event", label="signin: login")
    g.add_edge("identity:alice", "event:evt-1", relation="TRIGGERED")
    return g


def test_graph_to_dict_shape():
    data = graph_to_dict(_sample_graph())
    assert {"id": "identity:alice", "kind": "identity", "label": "alice"} in data["nodes"]
    assert {"id": "event:evt-1", "kind": "event", "label": "signin: login"} in data["nodes"]
    assert {"source": "identity:alice", "target": "event:evt-1", "relation": "TRIGGERED"} in data["edges"]


def test_graph_to_dict_empty_graph():
    data = graph_to_dict(nx.MultiDiGraph())
    assert data == {"nodes": [], "edges": []}


def test_render_svg_contains_labels_and_relations():
    svg = render_svg(_sample_graph())
    assert svg.startswith("<svg")
    assert "alice" in svg
    assert "TRIGGERED" in svg


def test_render_svg_empty_graph_does_not_crash():
    svg = render_svg(nx.MultiDiGraph())
    assert "<svg" in svg


def test_render_svg_escapes_labels():
    g = nx.MultiDiGraph()
    g.add_node("a", kind="identity", label='<script>alert(1)</script>')
    svg = render_svg(g)
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_render_svg_truncates_long_labels():
    g = nx.MultiDiGraph()
    long_label = "a" * 50
    g.add_node("a", kind="resource", label=long_label)
    svg = render_svg(g)
    assert f"<title>resource: {long_label}</title>" in svg
    assert "..." in svg
