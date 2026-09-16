"""Turn an extracted model into a directed graph suited to reachability analysis.

Node identity is the component **prototype** path, never the component type. A
type instantiated twice (two doors, four wheel sensors) must remain two nodes;
collapsing them onto the type would let a BFS walk from one instance to its
sibling through a path that does not exist in the vehicle.

Edge direction encodes *influence* rather than wiring, because that is the
question a reachability query actually asks — "what can this component affect?":

* **Sender-receiver** — data flows provider to requester, so influence follows
  the wiring and the connector yields one edge.
* **Client-server** — the client drives the request (requester to provider) and
  the server's reply drives the client (provider to requester), so one connector
  yields *two* edges. Modelling client-server as a single provider-to-requester
  edge is the easiest way to miss an attack path in a service-oriented design,
  since it hides the client's ability to reach into the server.

A MultiDiGraph is used deliberately: two components commonly share several
connectors, and each must stay separately attributable back to its ARXML element.
"""

from __future__ import annotations

import networkx as nx

from . import ecu as ecu_mod
from .model import CLIENT_SERVER, Model


def build(model: Model) -> nx.MultiDiGraph:
    """Build the influence graph for one ARXML snapshot."""
    graph = nx.MultiDiGraph()

    for proto in model.prototypes.values():
        component = model.component_types.get(proto.type_ref)
        provided, required = (), ()
        if component is not None:
            provided = tuple(
                sorted(p.short_name for p in component.ports.values() if p.kind in ("P", "PR"))
            )
            required = tuple(
                sorted(p.short_name for p in component.ports.values() if p.kind in ("R", "PR"))
            )
        graph.add_node(
            proto.path,
            kind="prototype",
            short_name=proto.short_name,
            type_ref=proto.type_ref,
            category=component.category if component is not None else None,
            composition=proto.composition,
            provided_ports=provided,
            required_ports=required,
            # None when the snapshot carries no SWC-TO-ECU-MAPPING, which is the
            # normal case for an ECU extract. ecu.assume_single_host() can fill it.
            host=ecu_mod.host_of(model, proto.path),
        )

    _add_assembly_edges(graph, model)
    _add_delegation_edges(graph, model)
    return graph


def _ensure_node(graph: nx.MultiDiGraph, path: str, **attrs) -> None:
    """Add a placeholder node so an edge to an out-of-set target is not lost."""
    if path not in graph:
        graph.add_node(path, short_name=path.rsplit("/", 1)[-1], host=None, **attrs)


def _add_assembly_edges(graph: nx.MultiDiGraph, model: Model) -> None:
    for conn in model.assembly_connectors.values():
        provider, requester = conn.provider_component, conn.requester_component
        if not provider or not requester:
            continue
        _ensure_node(graph, provider, kind="unresolved")
        _ensure_node(graph, requester, kind="unresolved")

        interface = model.interface_of(conn.provider_port) or model.interface_of(
            conn.requester_port
        )
        attrs = {
            "connector": conn.path,
            "connector_kind": "ASSEMBLY",
            "interface": interface.path if interface else None,
            "interface_kind": interface.kind if interface else None,
            "provider_port": conn.provider_port,
            "requester_port": conn.requester_port,
            # True = traverses a bus (and so *can* carry SecOC), False = RTE-local
            # (and so cannot), None = at least one endpoint is unmapped.
            "cross_ecu": ecu_mod.is_cross_ecu(model, provider, requester),
        }

        if interface is not None and interface.kind == CLIENT_SERVER:
            graph.add_edge(
                requester, provider, key=f"{conn.path}#request", influence="request", **attrs
            )
            graph.add_edge(
                provider, requester, key=f"{conn.path}#response", influence="response", **attrs
            )
        else:
            graph.add_edge(
                provider, requester, key=f"{conn.path}#data", influence="data", **attrs
            )


def _add_delegation_edges(graph: nx.MultiDiGraph, model: Model) -> None:
    """Wire composition boundary ports to their inner prototypes.

    The composition itself becomes a node so boundary-crossing paths have an
    endpoint. In an ECU extract the root composition's outer ports are the ECU
    boundary, which makes these nodes the natural place to seed entry points.
    """
    for conn in model.delegation_connectors.values():
        inner, outer = conn.inner_component, conn.composition
        if not inner or not outer:
            continue
        boundary = model.component_types.get(outer)
        _ensure_node(
            graph,
            outer,
            kind="composition",
            category=boundary.category if boundary is not None else None,
        )
        _ensure_node(graph, inner, kind="unresolved")

        interface = model.interface_of(conn.inner_port)
        attrs = {
            "connector": conn.path,
            "connector_kind": "DELEGATION",
            "interface": interface.path if interface else None,
            "interface_kind": interface.kind if interface else None,
            "inner_port": conn.inner_port,
            "outer_port": conn.outer_port,
        }
        if conn.inner_kind == "P":
            # Inner component provides outward: influence leaves the composition.
            graph.add_edge(
                inner, outer, key=f"{conn.path}#out", influence="delegate-out", **attrs
            )
        else:
            # Inner component requires from outside: influence enters.
            graph.add_edge(
                outer, inner, key=f"{conn.path}#in", influence="delegate-in", **attrs
            )


def to_json(graph: nx.MultiDiGraph) -> dict:
    """Serialise to a stable, diffable JSON structure."""
    return {
        "nodes": [
            {"id": n, **{k: _plain(v) for k, v in attrs.items()}}
            for n, attrs in sorted(graph.nodes(data=True))
        ],
        "edges": [
            {"source": u, "target": v, "key": k, **{ak: _plain(av) for ak, av in attrs.items()}}
            for u, v, k, attrs in sorted(graph.edges(keys=True, data=True), key=lambda e: (e[0], e[1], e[2]))
        ],
    }


def _plain(value):
    return list(value) if isinstance(value, tuple) else value


# -- Export: Graphviz DOT --------------------------------------------------------


def to_dot(
    graph: nx.MultiDiGraph,
    entry: tuple[str, ...] = (),
    critical: tuple[str, ...] = (),
    highlight_edges: frozenset[tuple[str, str]] = frozenset(),
) -> str:
    """Render as Graphviz DOT text.

    No external binary is required to produce this — it is plain text. Rendering it
    to an image (``dot -Tpng graph.dot -o graph.png``) requires Graphviz to be
    installed separately; :func:`render_png` below does not have that dependency.

    Colour is used to answer the two questions a reviewer actually has: "where could
    an attacker start, and what must never be reached" (node colour), and "is this
    hop actually authenticated" (edge colour). ``highlight_edges`` lets a caller mark
    the specific hops that make up a reported attack path, keyed on
    ``(source, target)`` node pairs.
    """
    lines = ["digraph arxml_secdiff {", '  rankdir="LR";', "  node [shape=box, style=filled, fontname=Helvetica];"]

    entry_set, critical_set = set(entry), set(critical)
    for node, attrs in sorted(graph.nodes(data=True)):
        label = node.rsplit("/", 1)[-1]
        if node in critical_set:
            fill = "#f4b6b6"  # red-ish: safety-critical target
        elif node in entry_set:
            fill = "#b6d7f4"  # blue-ish: attacker entry point
        else:
            fill = "#e8e8e8"
        lines.append(f'  "{node}" [label="{label}", fillcolor="{fill}"];')

    for u, v, _key, attrs in graph.edges(keys=True, data=True):
        authenticated = attrs.get("authenticated")
        if authenticated is True:
            color = "#2e7d32"  # green: protected
        elif authenticated is False:
            color = "#c62828"  # red: applicable and missing
        else:
            color = "#9e9e9e"  # gray: not applicable / RTE-local

        # Width, not colour, marks a highlighted attack-path hop — colour must stay
        # true to authentication status even for a protected hop that sits on a
        # reported route, or the diagram would misreport the one thing that matters.
        on_path = (u, v) in highlight_edges
        width = 3.0 if on_path else 1.0
        style = "bold" if on_path else "solid" if authenticated is not None else "dashed"

        influence = attrs.get("influence", "")
        lines.append(
            f'  "{u}" -> "{v}" [label="{influence}", color="{color}", penwidth={width}, style="{style}"];'
        )

    lines.append("}")
    return "\n".join(lines)


# -- Export: rendered image (matplotlib, no external binary needed) -------------


def render_png(
    graph: nx.MultiDiGraph,
    path: str,
    entry: tuple[str, ...] = (),
    critical: tuple[str, ...] = (),
    highlight_edges: frozenset[tuple[str, str]] = frozenset(),
    title: str | None = None,
) -> None:
    """Render a visual PNG of the graph using matplotlib.

    Deliberately does not depend on the Graphviz binary — `to_dot` covers that path
    for anyone who has Graphviz and wants its layout engine instead. This uses
    networkx's own spring layout, which is enough to see structure, entry/critical
    nodes, and which hops are unauthenticated without installing anything beyond the
    project's own dependencies.
    """
    import matplotlib

    matplotlib.use("Agg")  # no display needed; safe in CI and headless environments
    import matplotlib.pyplot as plt

    entry_set, critical_set = set(entry), set(critical)
    node_colors = [
        "#f4b6b6" if n in critical_set else "#b6d7f4" if n in entry_set else "#e8e8e8"
        for n in graph.nodes()
    ]
    labels = {n: n.rsplit("/", 1)[-1] for n in graph.nodes()}

    # Colour always reflects authentication status, never the highlight — a protected
    # hop that happens to sit on a reported attack path is still protected, and
    # recolouring it to look unauthenticated would misreport the one thing this tool
    # exists to get right. The highlight is conveyed by width and z-order only.
    edge_colors, edge_widths = [], []
    for u, v, _k, attrs in graph.edges(keys=True, data=True):
        authenticated = attrs.get("authenticated")
        on_path = (u, v) in highlight_edges
        if authenticated is True:
            edge_colors.append("#2e7d32")
        elif authenticated is False:
            edge_colors.append("#c62828")
        else:
            edge_colors.append("#9e9e9e")
        edge_widths.append(3.0 if on_path else 1.0)

    fig, ax = plt.subplots(figsize=(12, 9))
    pos = nx.spring_layout(graph, seed=0, k=0.9)
    nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_shape="s", node_size=1400, ax=ax)
    nx.draw_networkx_labels(graph, pos, labels=labels, font_size=7, ax=ax)
    nx.draw_networkx_edges(
        graph, pos, edge_color=edge_colors, width=edge_widths, arrows=True,
        connectionstyle="arc3,rad=0.08", ax=ax,
    )

    legend = [
        plt.Line2D([0], [0], marker="s", color="w", markerfacecolor="#b6d7f4", markersize=12, label="entry point"),
        plt.Line2D([0], [0], marker="s", color="w", markerfacecolor="#f4b6b6", markersize=12, label="critical node"),
        plt.Line2D([0], [0], color="#2e7d32", lw=2, label="authenticated hop"),
        plt.Line2D([0], [0], color="#c62828", lw=2, label="unauthenticated / attack-path hop"),
        plt.Line2D([0], [0], color="#9e9e9e", lw=2, label="SecOC not applicable (RTE-local)"),
    ]
    # Placed below the plot rather than inside it: an in-plot legend box can sit
    # directly on top of an isolated node (one with no edges, e.g. a component the
    # architecture never wires up), silently hiding it from the reviewer.
    ax.legend(
        handles=legend, loc="upper center", bbox_to_anchor=(0.5, -0.02),
        ncol=3, fontsize=8, framealpha=0.9,
    )
    ax.set_title(title or "ARXML architecture graph")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)