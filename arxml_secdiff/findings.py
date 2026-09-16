"""Collect security findings from a diff and a reachability comparison.

This module is deliberately the only place that knows *what counts as a finding*.
The layers below it answer factual questions — what changed, what is reachable — and
the layer above scores what it is given. Keeping the judgement in one place is what
makes it reviewable, and lets a programme argue with a category without touching the
graph code.

Every finding carries a stable `id`, so a team can accept one and have it stay
accepted across releases. That matters more than it sounds: a gate that cannot be
befored gets switched off within two sprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import diff as diff_mod
from . import reach as reach_mod

# Categories, ordered roughly by how much they should worry a release manager.
NEWLY_REACHABLE = "newly-reachable"
NEW_ATTACK_PATH = "new-attack-path"
SECOC_REMOVED = "secoc-removed"
UNPROTECTED_NEW_HOP = "unprotected-new-hop"
NEWLY_BUS_VISIBLE = "newly-bus-visible"
REHOSTED = "rehosted-component"
COMPONENT_ADDED = "component-added"
COMPONENT_REMOVED = "component-removed"
NOT_ANALYSED = "not-analysed"

#: Categories that describe context rather than a defect. They belong in the report
#: — a reviewer wants to know a component moved — but must not be able to fail a
#: build on their own.
INFORMATIONAL = frozenset({REHOSTED, COMPONENT_ADDED, COMPONENT_REMOVED})


@dataclass(frozen=True)
class Finding:
    """One reportable observation about a release."""

    category: str
    subject: str
    title: str
    detail: str = ""
    #: Structured proof: connector paths, PDU paths, the attack path, changed fields.
    #: Everything a reviewer needs to confirm or dismiss the finding by hand.
    evidence: dict = field(default_factory=dict, compare=False)
    #: The safety-critical node this finding puts at risk, when there is one.
    target: str | None = None
    #: Attack path, when the finding is a reachability one.
    path: reach_mod.Path | None = field(default=None, compare=False)

    @property
    def id(self) -> str:
        """Stable across releases, so findings can be befored and accepted."""
        return f"{self.category}:{self.subject}"

    @property
    def informational(self) -> bool:
        return self.category in INFORMATIONAL

    def __str__(self) -> str:
        return f"[{self.category}] {self.title}"


def collect(
    structural: diff_mod.Diff,
    reachability: reach_mod.ReachDiff | None = None,
) -> tuple[Finding, ...]:
    """Turn a structural diff and a reachability diff into findings.

    `reachability` is optional so the structural half stays usable on a snapshot
    nobody has seeded roles for — but when it is absent, or was inconclusive, that
    fact is emitted as a finding of its own rather than passed over.
    """
    found: list[Finding] = []
    found.extend(_secoc_findings(structural))
    found.extend(_structural_findings(structural))
    if reachability is None:
        found.append(
            Finding(
                NOT_ANALYSED,
                "reachability",
                "Reachability analysis was not run",
                "Only structural and SecOC changes were examined. Whether this "
                "release lets an attacker reach a safety-critical component is "
                "unknown, not known to be unchanged.",
                {"gaps": ("reachability analysis was not run",)},
            )
        )
    else:
        found.extend(_reach_findings(reachability))
        found.extend(_inconclusive(reachability))
    return tuple(found)


def _secoc_findings(structural: diff_mod.Diff) -> list[Finding]:
    out: list[Finding] = []
    for edge in structural.newly_unprotected:
        pdus = tuple(edge.attrs.get("unprotected_pdus") or ())
        evidence = {
            "connector": edge.connector,
            "influence": edge.influence,
            "source": edge.source,
            "target": edge.target,
            "unprotected_pdus": pdus,
            "changed_fields": tuple(str(f) for f in edge.fields),
        }
        was_protected = (
            (m := edge.moved("authenticated")) is not None and m.before is True
        )
        if was_protected:
            out.append(
                Finding(
                    SECOC_REMOVED,
                    edge.key,
                    f"SecOC removed from {edge.source.rsplit('/', 1)[-1]} -> "
                    f"{edge.target.rsplit('/', 1)[-1]}",
                    "This hop crossed a bus with SecOC in the before and no longer "
                    "does. Any device on the bus can now forge it.",
                    evidence,
                )
            )
        else:
            out.append(
                Finding(
                    UNPROTECTED_NEW_HOP,
                    edge.key,
                    f"Unauthenticated bus traffic on {edge.connector.rsplit('/', 1)[-1]}",
                    "This hop is newly applicable for SecOC and arrived without it, "
                    "so it is on a wire with nothing authenticating it.",
                    evidence,
                )
            )

    for edge in structural.newly_bus_visible:
        out.append(
            Finding(
                NEWLY_BUS_VISIBLE,
                edge.key,
                f"{edge.connector.rsplit('/', 1)[-1]} moved from RTE-local to a bus",
                "Data that never left the ECU in the before is now on a network. "
                "Whether or not it is authenticated, its exposure changed.",
                {
                    "connector": edge.connector,
                    "pdus": tuple(edge.attrs.get("pdus") or ()),
                    "authenticated": edge.attrs.get("authenticated"),
                },
            )
        )
    return out


def _structural_findings(structural: diff_mod.Diff) -> list[Finding]:
    out: list[Finding] = []
    for node in structural.rehosted:
        moved = next(f for f in node.fields if f.field == "host")
        out.append(
            Finding(
                REHOSTED,
                node.path,
                f"{node.short_name} moved from {moved.before} to {moved.after}",
                "Rehosting changes which connectors cross a bus, so it is worth "
                "checking even when no connector was touched.",
                {"before": moved.before, "after": moved.after},
            )
        )
    for node in structural.nodes_by(diff_mod.ADDED):
        out.append(
            Finding(
                COMPONENT_ADDED,
                node.path,
                f"New component {node.short_name}",
                detail="",
                evidence={"host": node.attrs.get("host"), "type": node.attrs.get("type_ref")},
            )
        )
    for node in structural.nodes_by(diff_mod.REMOVED):
        out.append(
            Finding(
                COMPONENT_REMOVED,
                node.path,
                f"Component {node.short_name} removed",
                evidence={"host": node.attrs.get("host")},
            )
        )
    return out


def _reach_findings(reachability: reach_mod.ReachDiff) -> list[Finding]:
    out: list[Finding] = []
    for change in reachability.newly_reachable:
        path = change.path
        out.append(
            Finding(
                NEWLY_REACHABLE,
                f"{path.entry}->{path.target}",
                f"{path.entry.rsplit('/', 1)[-1]} can now reach "
                f"{path.target.rsplit('/', 1)[-1]}",
                "No path existed between these two in the before. Every connector "
                "on the new route may be individually reasonable; the chain is not.",
                {
                    "path": tuple(path.nodes),
                    "hops": tuple(str(h) for h in path.hops),
                    "unprotected_hops": tuple(h.key for h in path.unprotected_hops),
                    "bus_hops": tuple(h.key for h in path.bus_hops),
                    "fully_protected": path.fully_protected,
                },
                target=path.target,
                path=path,
            )
        )

    for change in reachability.by(reach_mod.SHORTER):
        path = change.path
        out.append(
            Finding(
                NEW_ATTACK_PATH,
                f"{path.entry}->{path.target}#{len(path.hops)}",
                f"Shorter route from {path.entry.rsplit('/', 1)[-1]} to "
                f"{path.target.rsplit('/', 1)[-1]}",
                f"Already reachable in {change.before.length} hops, now reachable in "
                f"{path.length}. Fewer hops means fewer things that have to go wrong.",
                {
                    "path": tuple(path.nodes),
                    "before_path": tuple(change.before.nodes),
                    "unprotected_hops": tuple(h.key for h in path.unprotected_hops),
                },
                target=path.target,
                path=path,
            )
        )
    return out


def _inconclusive(reachability: reach_mod.ReachDiff) -> list[Finding]:
    """Emit the absence of an analysis as a finding.

    Without this, a snapshot with no configured entry point produces an empty
    findings list that is indistinguishable from a clean one — the single most
    dangerous failure mode a gate can have.
    """
    out: list[Finding] = []
    for label, result in (("before", reachability.before), ("updated", reachability.updated)):
        if not result.analysed:
            out.append(
                Finding(
                    NOT_ANALYSED,
                    f"{label}-reachability",
                    f"Reachability not analysed for the {label} snapshot",
                    "; ".join(result.gaps)
                    + ". No conclusion about attack paths can be drawn from this run.",
                    {"gaps": tuple(result.gaps), "snapshot": label},
                )
            )
    return out
