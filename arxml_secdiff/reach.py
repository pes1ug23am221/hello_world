"""Reachability from attacker entry points to safety-critical nodes.

The finding this module exists to produce is *newly reachable*: a path that did not
exist in the before and does exist in the update. That is strictly stronger than
"a connector was added", because most added connectors are harmless and the
dangerous ones are usually harmless-looking in isolation — the gateway-to-chassis
link in `veh_v2.arxml` is properly authenticated and still completes a chain from a
cellular modem to a brake actuator.

Two ideas do the work:

* **Paths are compared, not just endpoints.** A pair already reachable in the
  before can still be a regression if the update opens a *shorter* or otherwise
  different route, so `PathChange` keeps the actual node sequence.
* **The weakest hop is the finding's real severity.** A five-hop path where every
  hop is SecOC-protected is a very different risk from the same path with one
  unauthenticated bus hop, so every path carries its unprotected hops.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from . import roles as roles_mod


@dataclass(frozen=True)
class Hop:
    """One edge on a path, with the attributes that decide how bad it is."""

    source: str
    target: str
    key: str
    influence: str | None = None
    bus_visible: bool | None = None
    authenticated: bool | None = None
    unprotected_pdus: tuple[str, ...] = ()

    @property
    def connector(self) -> str:
        return self.key.rsplit("#", 1)[0]

    @property
    def unprotected(self) -> bool:
        """Crosses a bus with nothing authenticating it.

        `authenticated is False` only, never falsy: None means SecOC does not apply,
        which is not a weakness.
        """
        return self.authenticated is False

    def __str__(self) -> str:
        return f"{self.source} -{self.influence}-> {self.target}"


@dataclass(frozen=True)
class Path:
    """One entry-to-critical route."""

    nodes: tuple[str, ...]
    hops: tuple[Hop, ...]

    @property
    def entry(self) -> str:
        return self.nodes[0]

    @property
    def target(self) -> str:
        return self.nodes[-1]

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def unprotected_hops(self) -> tuple[Hop, ...]:
        return tuple(h for h in self.hops if h.unprotected)

    @property
    def bus_hops(self) -> tuple[Hop, ...]:
        return tuple(h for h in self.hops if h.bus_visible)

    @property
    def fully_protected(self) -> bool:
        """Every bus hop on the route is authenticated.

        A fully protected path is still a reachability finding — authentication stops
        an off-bus attacker, not a compromised legitimate sender — but it is a much
        weaker one, and the scorer treats it as such.
        """
        return not self.unprotected_hops

    def __str__(self) -> str:
        return " -> ".join(n.rsplit("/", 1)[-1] for n in self.nodes)


@dataclass
class Reachability:
    """All entry-to-critical paths in one snapshot."""

    paths: tuple[Path, ...] = ()
    entry: tuple[str, ...] = ()
    critical: tuple[str, ...] = ()
    #: Why the query was unanswerable, when it was. Empty on a real analysis.
    gaps: tuple[str, ...] = ()

    @property
    def analysed(self) -> bool:
        """False when there were no seeds to search between.

        `paths == ()` is ambiguous on its own — it means either "searched and found
        nothing" or "never searched". Only the first is a clean bill of health.
        """
        return not self.gaps

    @property
    def pairs(self) -> frozenset[tuple[str, str]]:
        return frozenset((p.entry, p.target) for p in self.paths)

    def to(self, target: str) -> tuple[Path, ...]:
        return tuple(p for p in self.paths if p.target == target)

    def shortest_to(self, target: str) -> Path | None:
        return min(self.to(target), key=lambda p: p.length, default=None)

    @property
    def unprotected_paths(self) -> tuple[Path, ...]:
        return tuple(p for p in self.paths if not p.fully_protected)


def analyse(
    graph: nx.MultiDiGraph,
    node_roles: roles_mod.Roles | None = None,
    cutoff: int | None = 12,
) -> Reachability:
    """Enumerate simple paths from every entry point to every critical node.

    `cutoff` bounds path length. Real graphs are dense enough that unbounded simple
    path enumeration is exponential, and a 12-hop attack chain is not a finding
    anyone acts on anyway. Raise it deliberately if a snapshot needs it.
    """
    node_roles = node_roles if node_roles is not None else roles_mod.classify(graph)
    entry = tuple(n for n in node_roles.entry if n in graph)
    critical = tuple(n for n in node_roles.critical if n in graph)

    # Gaps are computed from the filtered sets, not the raw config: a critical node
    # named in config but absent from this snapshot leaves the query just as
    # unanswerable as one that was never named.
    gaps = []
    if not entry:
        gaps.append("no entry point present in this snapshot")
    if not critical:
        gaps.append("no safety-critical node present in this snapshot")

    # Collapse to a simple digraph for the search, then map each step back to the
    # best-attested parallel edge. Enumerating over the MultiDiGraph directly
    # multiplies identical node sequences by every parallel-edge combination.
    simple = nx.DiGraph()
    simple.add_nodes_from(graph.nodes)
    simple.add_edges_from((u, v) for u, v, _ in graph.edges(keys=True))

    found: list[Path] = []
    for source in entry:
        for target in critical:
            if source == target or target not in simple:
                continue
            for nodes in nx.all_simple_paths(simple, source, target, cutoff=cutoff):
                hops = tuple(
                    _worst_hop(graph, u, v) for u, v in zip(nodes, nodes[1:])
                )
                found.append(Path(tuple(nodes), hops))

    found.sort(key=lambda p: (p.length, p.nodes))
    return Reachability(tuple(found), entry, critical, tuple(gaps))


def _worst_hop(graph: nx.MultiDiGraph, u: str, v: str) -> Hop:
    """Pick the parallel edge that represents the greatest exposure.

    When two components are joined by several connectors, the attacker only needs
    the weakest, so an unprotected bus hop is reported ahead of a protected one.
    """
    candidates = [(k, d) for k, d in graph[u][v].items()]
    key, attrs = max(
        candidates,
        key=lambda kd: (
            kd[1].get("authenticated") is False,
            bool(kd[1].get("bus_visible")),
            kd[0],
        ),
    )
    return Hop(
        source=u,
        target=v,
        key=key,
        influence=attrs.get("influence"),
        bus_visible=attrs.get("bus_visible"),
        authenticated=attrs.get("authenticated"),
        unprotected_pdus=tuple(attrs.get("unprotected_pdus") or ()),
    )


@dataclass(frozen=True)
class PathChange:
    """A route that appeared, disappeared, or got shorter between snapshots."""

    kind: str
    path: Path
    before: Path | None = None

    @property
    def entry(self) -> str:
        return self.path.entry

    @property
    def target(self) -> str:
        return self.path.target

    def __str__(self) -> str:
        return f"{self.kind}: {self.path}"


NEW_PAIR = "new-pair"
NEW_PATH = "new-path"
SHORTER = "shorter"
REMOVED_PAIR = "removed-pair"


@dataclass
class ReachDiff:
    """Change in reachability between two snapshots."""

    before: Reachability
    updated: Reachability
    changes: tuple[PathChange, ...] = ()
    seeds_changed: tuple[str, ...] = field(default=(), repr=False)

    def by(self, kind: str) -> tuple[PathChange, ...]:
        return tuple(c for c in self.changes if c.kind == kind)

    @property
    def newly_reachable(self) -> tuple[PathChange, ...]:
        """Critical nodes an entry point could not reach at all before.

        The headline finding: this is the one that should block a release.
        """
        return self.by(NEW_PAIR)

    @property
    def newly_reachable_unprotected(self) -> tuple[PathChange, ...]:
        return tuple(c for c in self.newly_reachable if not c.path.fully_protected)

    def summary(self) -> dict[str, int]:
        return {
            "before_paths": len(self.before.paths),
            "updated_paths": len(self.updated.paths),
            "new_pairs": len(self.by(NEW_PAIR)),
            "new_paths": len(self.by(NEW_PATH)),
            "shorter": len(self.by(SHORTER)),
            "removed_pairs": len(self.by(REMOVED_PAIR)),
        }


def compare(before: Reachability, updated: Reachability) -> ReachDiff:
    """Diff two reachability results.

    A pair newly reachable is reported once, via its shortest path, rather than once
    per route: twelve variations on the same chain is not twelve findings.
    """
    changes: list[PathChange] = []
    before_pairs, after_pairs = before.pairs, updated.pairs
    before_routes = {p.nodes for p in before.paths}

    for pair in sorted(after_pairs - before_pairs):
        shortest = min(
            (p for p in updated.paths if (p.entry, p.target) == pair),
            key=lambda p: p.length,
        )
        changes.append(PathChange(NEW_PAIR, shortest))

    for pair in sorted(before_pairs - after_pairs):
        shortest = min(
            (p for p in before.paths if (p.entry, p.target) == pair),
            key=lambda p: p.length,
        )
        changes.append(PathChange(REMOVED_PAIR, shortest))

    for pair in sorted(after_pairs & before_pairs):
        old_best = min(
            (p for p in before.paths if (p.entry, p.target) == pair),
            key=lambda p: p.length,
        )
        for path in sorted(
            (p for p in updated.paths if (p.entry, p.target) == pair),
            key=lambda p: (p.length, p.nodes),
        ):
            if path.nodes in before_routes:
                continue
            kind = SHORTER if path.length < old_best.length else NEW_PATH
            changes.append(PathChange(kind, path, before=old_best))

    seeds = tuple(
        sorted(
            set(updated.entry) ^ set(before.entry)
            | (set(updated.critical) ^ set(before.critical))
        )
    )
    return ReachDiff(before, updated, tuple(changes), seeds)
