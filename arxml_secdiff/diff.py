"""Diff two snapshots of the same architecture.

Identity is what makes a diff useful, so both sides are keyed on values that
survive an unrelated edit:

* a node is its **prototype path** — so re-ordering ``<COMPONENTS>`` or renaming a
  connector never looks like a component was replaced;
* an edge is ``(source, target, connector#influence)`` — so a connector re-pointed
  at a different component shows up as one edge removed and one added, which is
  what actually happened, rather than as a quiet field change.

Keying edges on the connector path costs one thing back, and `_pair_renames` pays it:
a *renamed* connector wires the same hop between the same ports, but its edge key
changes, so the diff would see a removal and an addition where the architecture did
not move at all. `HOP_FIELDS` identifies the hop independently of the connector's
name so those two halves can be stitched back into one `MODIFIED` edge.

Only fields in `NODE_FIELDS` / `EDGE_FIELDS` are compared. That list is deliberate:
a diff that reports every attribute the graph builder happens to attach becomes
noise the moment the builder grows a field, and noise is what stops people reading
regression reports.

The security-relevant views (`newly_unprotected`, `newly_bus_visible`) are derived
from the same edge diff rather than computed separately, so a finding can always be
traced back to the connector and the field that moved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from . import secoc
from .model import Model

ADDED = "added"
REMOVED = "removed"
MODIFIED = "modified"

#: Node attributes worth comparing. `short_name` is excluded because it is derived
#: from the path, so it cannot change without the node's identity changing too.
NODE_FIELDS = (
    "kind",
    "type_ref",
    "category",
    "composition",
    "provided_ports",
    "required_ports",
    "host",
)

#: Edge attributes worth comparing. The SecOC block is only populated once
#: `secoc.annotate` has run; on a bare graph those fields are absent on both sides
#: and so contribute nothing.
EDGE_FIELDS = (
    "influence",
    "connector_kind",
    "interface",
    "interface_kind",
    "provider_port",
    "requester_port",
    "inner_port",
    "outer_port",
    "cross_ecu",
    "bus_visible",
    "authenticated",
    "secoc_source",
    "pdus",
    "unprotected_pdus",
)

_MISSING = object()

#: Pseudo-field name used to report a connector rename. Not an attribute of the edge
#: — the connector path lives in the edge key — so `_pair_renames` synthesises it.
CONNECTOR = "connector"

#: Attributes that pin down *which architectural hop* an edge is, independent of the
#: name of the connector implementing it. Two edges between the same pair of
#: components agreeing on all of these are the same hop wired by two differently
#: named connectors. Deliberately excludes everything security-relevant
#: (`bus_visible`, `authenticated`, `pdus`, …): a rename that also strips SecOC must
#: still pair, because reporting that regression is the entire point.
HOP_FIELDS = (
    "influence",
    "interface",
    "interface_kind",
    "provider_port",
    "requester_port",
    "inner_port",
    "outer_port",
)


@dataclass(frozen=True)
class FieldChange:
    """One attribute that moved between snapshots."""

    field: str
    before: Any
    after: Any

    def __str__(self) -> str:
        return f"{self.field}: {self.before!r} -> {self.after!r}"


@dataclass(frozen=True)
class NodeChange:
    path: str
    change: str
    fields: tuple[FieldChange, ...] = ()
    attrs: dict = field(default_factory=dict, repr=False)

    @property
    def short_name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass(frozen=True)
class EdgeChange:
    source: str
    target: str
    key: str
    change: str
    fields: tuple[FieldChange, ...] = ()
    attrs: dict = field(default_factory=dict, repr=False)

    @property
    def connector(self) -> str:
        """The ARXML connector path, recoverable from the edge key."""
        return self.key.rsplit("#", 1)[0]

    @property
    def influence(self) -> str:
        return self.key.rsplit("#", 1)[-1]

    def moved(self, name: str) -> FieldChange | None:
        return next((f for f in self.fields if f.field == name), None)

    @property
    def renamed(self) -> FieldChange | None:
        """The connector rename this edge was stitched back together across, if any."""
        return self.moved(CONNECTOR)

    def __str__(self) -> str:
        return f"{self.source} -{self.influence}-> {self.target}"


@dataclass
class Diff:
    """Structural delta between a before and an updated snapshot."""

    nodes: tuple[NodeChange, ...] = ()
    edges: tuple[EdgeChange, ...] = ()
    before: nx.MultiDiGraph | None = field(default=None, repr=False, compare=False)
    updated: nx.MultiDiGraph | None = field(default=None, repr=False, compare=False)

    # -- plain structural views -------------------------------------------------

    def nodes_by(self, change: str) -> tuple[NodeChange, ...]:
        return tuple(n for n in self.nodes if n.change == change)

    def edges_by(self, change: str) -> tuple[EdgeChange, ...]:
        return tuple(e for e in self.edges if e.change == change)

    @property
    def empty(self) -> bool:
        return not self.nodes and not self.edges

    # -- security-relevant views ------------------------------------------------

    @property
    def newly_unprotected(self) -> tuple[EdgeChange, ...]:
        """Edges that lost authentication, or gained bus exposure without it.

        Covers both regressions that matter: an existing bus hop whose SecOC was
        removed (True -> False), and a hop that only just became applicable and
        arrived unprotected (None -> False).
        """
        out = []
        for edge in self.edges:
            if edge.change == ADDED:
                if edge.attrs.get("authenticated") is False:
                    out.append(edge)
                continue
            moved = edge.moved("authenticated")
            if moved is not None and moved.after is False:
                out.append(edge)
        return tuple(out)

    @property
    def newly_bus_visible(self) -> tuple[EdgeChange, ...]:
        """Traffic that used to stay inside an ECU and now crosses a bus.

        A real regression class on its own: moving a component to another ECU puts
        previously RTE-local data on a wire, whether or not anyone noticed.
        """
        return tuple(
            e
            for e in self.edges
            if e.change == MODIFIED
            and (m := e.moved("bus_visible")) is not None
            and m.after is True
        )

    @property
    def rehosted(self) -> tuple[NodeChange, ...]:
        """Components that changed ECU — the usual cause of new bus exposure."""
        return tuple(
            n
            for n in self.nodes
            if n.change == MODIFIED and any(f.field == "host" for f in n.fields)
        )

    @property
    def renames(self) -> tuple[EdgeChange, ...]:
        """Hops whose connector was renamed without the hop itself moving.

        Surfaced rather than swallowed: `_pair_renames` makes an inference, and an
        inference a report cannot show is one nobody can check.
        """
        return tuple(e for e in self.edges if e.renamed is not None)

    def summary(self) -> dict[str, int]:
        return {
            "nodes_added": len(self.nodes_by(ADDED)),
            "nodes_removed": len(self.nodes_by(REMOVED)),
            "nodes_modified": len(self.nodes_by(MODIFIED)),
            "edges_added": len(self.edges_by(ADDED)),
            "edges_removed": len(self.edges_by(REMOVED)),
            "edges_modified": len(self.edges_by(MODIFIED)),
            "newly_unprotected": len(self.newly_unprotected),
            "newly_bus_visible": len(self.newly_bus_visible),
            "rehosted": len(self.rehosted),
            "renamed_connectors": len(self.renames),
        }


def compare(before: nx.MultiDiGraph, updated: nx.MultiDiGraph) -> Diff:
    """Diff two influence graphs.

    Annotate both with `secoc.annotate` first if you want authentication changes
    reported; on bare graphs the SecOC fields are absent on both sides and are
    silently skipped rather than reported as changes.
    """
    return Diff(
        nodes=_diff_nodes(before, updated),
        edges=_diff_edges(before, updated),
        before=before,
        updated=updated,
    )


def _diff_nodes(before: nx.MultiDiGraph, updated: nx.MultiDiGraph) -> tuple[NodeChange, ...]:
    before, after = dict(before.nodes(data=True)), dict(updated.nodes(data=True))
    changes: list[NodeChange] = []

    for path in sorted(set(before) - set(after)):
        changes.append(NodeChange(path, REMOVED, attrs=dict(before[path])))
    for path in sorted(set(after) - set(before)):
        changes.append(NodeChange(path, ADDED, attrs=dict(after[path])))
    for path in sorted(set(before) & set(after)):
        moved = _field_changes(before[path], after[path], NODE_FIELDS)
        if moved:
            changes.append(NodeChange(path, MODIFIED, moved, attrs=dict(after[path])))
    return tuple(changes)


def _diff_edges(before: nx.MultiDiGraph, updated: nx.MultiDiGraph) -> tuple[EdgeChange, ...]:
    before = {(u, v, k): d for u, v, k, d in before.edges(keys=True, data=True)}
    after = {(u, v, k): d for u, v, k, d in updated.edges(keys=True, data=True)}

    gone = sorted(set(before) - set(after))
    fresh = sorted(set(after) - set(before))
    common = sorted(set(before) & set(after))

    renamed = _pair_renames(before, after, gone, fresh)
    was_renamed = {old for old in renamed.values()}

    removed = [EdgeChange(*i, REMOVED, attrs=dict(before[i])) for i in gone if i not in was_renamed]
    added = [EdgeChange(*i, ADDED, attrs=dict(after[i])) for i in fresh if i not in renamed]

    modified: list[EdgeChange] = []
    for ident in common:
        moved = _field_changes(before[ident], after[ident], EDGE_FIELDS)
        if moved:
            modified.append(EdgeChange(*ident, MODIFIED, moved, attrs=dict(after[ident])))
    for ident in fresh:
        old = renamed.get(ident)
        if old is None:
            continue
        moved = (FieldChange(CONNECTOR, _connector_of(old[2]), _connector_of(ident[2])),)
        moved += _field_changes(before[old], after[ident], EDGE_FIELDS)
        modified.append(EdgeChange(*ident, MODIFIED, moved, attrs=dict(after[ident])))

    return tuple(removed + added + modified)


def _connector_of(key: str) -> str:
    return key.rsplit("#", 1)[0]


def _pair_renames(
    before: dict,
    after: dict,
    gone: list[tuple],
    fresh: list[tuple],
) -> dict[tuple, tuple]:
    """Match a vanished edge to a new one that is the same hop under a new name.

    Renaming a connector is not an architectural change, but because an edge is keyed
    on the connector path it looks like one, and that costs three separate ways:

    * a hop that was **already** unprotected reappears as a brand-new unauthenticated
      edge, so `newly_unprotected` reports a regression that did not happen;
    * a hop renamed *while* its SecOC wrapper was stripped loses its
      ``authenticated: True -> False`` move, so the real regression is demoted from
      "authentication removed" to "new hop arrived unprotected";
    * a hop renamed *while* its component was rehosted loses its
      ``bus_visible: False -> True`` move, so `newly_bus_visible` misses it entirely.

    All three are the same bug. Pairing on `HOP_FIELDS` — endpoints, ports, interface,
    influence — fixes all three, and the security fields are excluded from that
    signature precisely so a rename that hides a regression still pairs and the
    regression still surfaces.

    Pairing is only accepted when the hop signature is unique on **both** sides. Two
    candidates means there is no evidence which renamed into which, and guessing would
    be worse than reporting the removal and the addition that were actually observed.
    """

    def signature(edges: dict, ident: tuple) -> tuple:
        attrs = edges[ident]
        return (ident[0], ident[1], tuple(attrs.get(f) for f in HOP_FIELDS))

    old_by: dict[tuple, list[tuple]] = {}
    for ident in gone:
        old_by.setdefault(signature(before, ident), []).append(ident)
    new_by: dict[tuple, list[tuple]] = {}
    for ident in fresh:
        new_by.setdefault(signature(after, ident), []).append(ident)

    pairs: dict[tuple, tuple] = {}
    for hop, olds in old_by.items():
        news = new_by.get(hop)
        if news is None or len(olds) != 1 or len(news) != 1:
            continue
        pairs[news[0]] = olds[0]
    return pairs


def _field_changes(before: dict, after: dict, fields: tuple[str, ...]) -> tuple[FieldChange, ...]:
    """Compare a fixed field list, skipping fields absent from both sides.

    Absent-from-both is how an un-annotated graph avoids reporting its missing
    SecOC fields as changes.
    """
    moved = []
    for name in fields:
        old, new = before.get(name, _MISSING), after.get(name, _MISSING)
        if old is _MISSING and new is _MISSING:
            continue
        if old != new:
            moved.append(
                FieldChange(
                    name,
                    None if old is _MISSING else old,
                    None if new is _MISSING else new,
                )
            )
    return tuple(moved)


@dataclass(frozen=True)
class ProfileChange:
    """A change in the authentication state of one payload PDU."""

    pdu: str
    change: str
    before: secoc.SecOcProfile | None = None
    after: secoc.SecOcProfile | None = None

    @property
    def lost_protection(self) -> bool:
        was = self.before is not None and self.before.authenticated
        now = self.after is not None and self.after.authenticated
        return bool(was and not now)


def compare_secoc(
    before: Model,
    updated: Model,
    before_overlay=None,
    updated_overlay=None,
) -> tuple[ProfileChange, ...]:
    """Diff SecOC at the PDU level, independent of the graph.

    Worth doing separately because a PDU can lose its ``SECURED-I-PDU`` wrapper
    without any connector changing, and because the payload may not be attached to
    any connector this snapshot happens to model.
    """
    before = secoc.profiles(before, before_overlay)
    after = secoc.profiles(updated, updated_overlay)
    changes: list[ProfileChange] = []

    for pdu in sorted(set(before) | set(after)):
        old, new = before.get(pdu), after.get(pdu)
        if old is None:
            changes.append(ProfileChange(pdu, ADDED, after=new))
        elif new is None:
            changes.append(ProfileChange(pdu, REMOVED, before=old))
        elif old != new:
            changes.append(ProfileChange(pdu, MODIFIED, before=old, after=new))
    return tuple(changes)
