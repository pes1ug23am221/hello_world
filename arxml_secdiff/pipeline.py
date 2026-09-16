"""Run the whole analysis: two snapshots in, one decision out.

Every stage is exposed separately elsewhere; this module exists so that the *order*
of the stages, and the objects handed between them, live in one auditable place
rather than being reassembled by each caller — including the CLI, the tests, and any
CI wrapper someone writes later.

`Analysis` keeps every intermediate result. That is deliberate: a verdict a reviewer
cannot drill into is a verdict they will eventually ignore, so the report layer needs
the graphs, the routes, and the raw diff, not just the number.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from . import diff as diff_mod
from . import findings as findings_mod
from . import gate as gate_mod
from . import graph as graph_mod
from . import model as model_mod
from . import parser as parser_mod
from . import reach as reach_mod
from . import roles as roles_mod
from . import secoc as secoc_mod
from . import severity as severity_mod


@dataclass
class Snapshot:
    """One release's ARXML, parsed and annotated."""

    label: str
    sources: tuple[Path, ...]
    model: model_mod.Model
    graph: nx.MultiDiGraph
    profiles: dict[str, secoc_mod.SecOcProfile] = field(default_factory=dict, repr=False)
    node_roles: roles_mod.Roles = field(default_factory=roles_mod.Roles)
    reachability: reach_mod.Reachability = field(default_factory=reach_mod.Reachability)

    @property
    def synthetic_secoc(self) -> tuple[str, ...]:
        """PDUs whose protection comes from the overlay rather than the ARXML.

        Worth naming in a report: an overlay is an assumption about the release, and a
        verdict resting on one is only as good as that assumption.
        """
        return tuple(
            sorted(
                pdu
                for pdu, profile in self.profiles.items()
                if profile.source == secoc_mod.FROM_OVERLAY
            )
        )

    def summary(self) -> dict[str, int]:
        return {
            "components": self.graph.number_of_nodes(),
            "connections": self.graph.number_of_edges(),
            "pdus": len(self.model.pdus),
            "secoc_profiles": len(self.profiles),
            "synthetic_secoc": len(self.synthetic_secoc),
            "entry_points": len(self.node_roles.entry),
            "critical_nodes": len(self.node_roles.critical),
            "attack_paths": len(self.reachability.paths),
        }


@dataclass
class Analysis:
    """Everything one run produced, from parse to verdict."""

    before: Snapshot
    updated: Snapshot
    structural: diff_mod.Diff
    secoc_changes: tuple[diff_mod.ProfileChange, ...]
    reach_diff: reach_mod.ReachDiff
    findings: tuple[findings_mod.Finding, ...]
    scored: tuple[severity_mod.Scored, ...]
    decision: gate_mod.Decision

    @property
    def verdict(self) -> str:
        return self.decision.verdict

    @property
    def exit_code(self) -> int:
        return self.decision.exit_code

    def summary(self) -> dict:
        return {
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "before": self.before.summary(),
            "updated": self.updated.summary(),
            "structural": self.structural.summary(),
            "reachability": self.reach_diff.summary(),
            "findings": len(self.findings),
            "gate": self.decision.summary(),
        }


def load(
    label: str,
    sources: list[str | Path],
    overlay: str | Path | None = None,
    roles_config: str | Path | dict | None = None,
    heuristics: bool = True,
    cutoff: int | None = 12,
) -> Snapshot:
    """Parse, build, annotate, classify, and search one snapshot."""
    model = parser_mod.parse(list(sources))
    profiles = secoc_mod.profiles(model, overlay)
    graph = secoc_mod.annotate(graph_mod.build(model), model, profiles)
    node_roles = roles_mod.classify(graph, roles_config, heuristics)
    reachability = reach_mod.analyse(graph, node_roles, cutoff)
    return Snapshot(
        label=label,
        sources=tuple(Path(s) for s in sources),
        model=model,
        graph=graph,
        profiles=profiles,
        node_roles=node_roles,
        reachability=reachability,
    )


def run(
    before_sources: list[str | Path],
    updated_sources: list[str | Path],
    roles_config: str | Path | dict | None = None,
    policy: gate_mod.Policy | None = None,
    before_overlay: str | Path | None = None,
    updated_overlay: str | Path | None = None,
    scorer: severity_mod.Scorer | None = None,
    heuristics: bool = True,
    cutoff: int | None = 12,
) -> Analysis:
    """Compare two releases and decide whether the second one may ship.

    The same `roles_config` is applied to both snapshots. Using different seeds either
    side would make the reachability diff meaningless — routes would appear and vanish
    because the question changed, not because the architecture did.

    The scorer defaults to `BuiltinScorer` over the *updated* snapshot's roles and
    routes, since the release under judgement is the one whose exposure matters.
    """
    before = load(
        "before", before_sources, before_overlay, roles_config, heuristics, cutoff
    )
    updated = load(
        "updated", updated_sources, updated_overlay, roles_config, heuristics, cutoff
    )

    structural = diff_mod.compare(before.graph, updated.graph)
    secoc_changes = diff_mod.compare_secoc(
        before.model, updated.model, before_overlay, updated_overlay
    )
    reach_diff = reach_mod.compare(before.reachability, updated.reachability)

    found = findings_mod.collect(structural, reach_diff)
    scorer = scorer or severity_mod.BuiltinScorer(
        node_roles=updated.node_roles, paths=updated.reachability
    )
    scored = severity_mod.score_all(found, scorer)
    decision = gate_mod.evaluate(scored, policy)

    return Analysis(
        before=before,
        updated=updated,
        structural=structural,
        secoc_changes=secoc_changes,
        reach_diff=reach_diff,
        findings=found,
        scored=scored,
        decision=decision,
    )
