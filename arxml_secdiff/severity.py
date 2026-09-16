"""Score findings, and keep the provenance of every score attached to it.

The scheme is modelled on the ISO/SAE 21434 Annex H worked example: an *impact*
rating and an *attack feasibility* rating combine through a matrix into a risk value
of 1 to 5. Two deliberate choices:

* **ASIL stands in for hazard severity.** 21434 wants a safety impact derived from
  the hazard analysis; what programmes actually have to hand per component is an
  ASIL. Mapping ASIL to impact is a simplification, and it is recorded in the
  rationale of every score that uses it rather than buried here.

* **A guessed input taints the score.** `Score.assumed` is true whenever any input
  came from a heuristic instead of a config. A risk of 5 derived from a name match on
  the string "brake" is not the same claim as one derived from a HARA, and a report
  that presents them identically is worse than no report.

`ExternalScorer` is the seam for a programme's own scorer — VERA or otherwise. It
speaks JSON over stdin/stdout, so wiring one in is a thin wrapper rather than a
rewrite, and the contract is small enough to implement in an afternoon.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Protocol

from . import findings as findings_mod
from . import reach as reach_mod
from . import roles as roles_mod

SEVERE = "severe"
MAJOR = "major"
MODERATE = "moderate"
NEGLIGIBLE = "negligible"

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
VERY_LOW = "very-low"

IMPACT_ORDER = (NEGLIGIBLE, MODERATE, MAJOR, SEVERE)
FEASIBILITY_ORDER = (VERY_LOW, LOW, MEDIUM, HIGH)

#: Risk value per (impact, feasibility), after the ISO/SAE 21434 Annex H example.
RISK_MATRIX = {
    (SEVERE, HIGH): 5,
    (SEVERE, MEDIUM): 4,
    (SEVERE, LOW): 3,
    (SEVERE, VERY_LOW): 2,
    (MAJOR, HIGH): 4,
    (MAJOR, MEDIUM): 3,
    (MAJOR, LOW): 2,
    (MAJOR, VERY_LOW): 1,
    (MODERATE, HIGH): 3,
    (MODERATE, MEDIUM): 2,
    (MODERATE, LOW): 2,
    (MODERATE, VERY_LOW): 1,
    (NEGLIGIBLE, HIGH): 1,
    (NEGLIGIBLE, MEDIUM): 1,
    (NEGLIGIBLE, LOW): 1,
    (NEGLIGIBLE, VERY_LOW): 1,
}

#: ASIL to impact. A simplification; see the module docstring.
ASIL_IMPACT = {
    "D": SEVERE,
    "C": MAJOR,
    "B": MODERATE,
    "A": MODERATE,
    "QM": NEGLIGIBLE,
}

#: Impact assumed for a critical node with no ASIL on record. Chosen high enough that
#: an unannotated safety-critical component is not quietly discounted.
UNKNOWN_ASIL_IMPACT = MAJOR

#: Categories whose impact is not about a safety target at all.
CATEGORY_IMPACT = {
    findings_mod.REHOSTED: MODERATE,
    findings_mod.COMPONENT_ADDED: NEGLIGIBLE,
    findings_mod.COMPONENT_REMOVED: NEGLIGIBLE,
    findings_mod.NEWLY_BUS_VISIBLE: MODERATE,
    # An un-run analysis has no impact of its own; the gate handles it separately,
    # because "we do not know" is a decision problem, not a severity one.
    findings_mod.NOT_ANALYSED: NEGLIGIBLE,
}


class ScorerError(RuntimeError):
    """An external scorer could not be reached, or gave an unusable answer."""


@dataclass(frozen=True)
class Score:
    impact: str
    feasibility: str
    risk: int
    rationale: tuple[str, ...] = ()
    scorer: str = "builtin-21434"
    #: True when any input to this score was heuristic rather than configured.
    assumed: bool = False

    def __str__(self) -> str:
        tail = " (assumed inputs)" if self.assumed else ""
        return f"risk {self.risk} [{self.impact}/{self.feasibility}]{tail}"


@dataclass(frozen=True)
class Scored:
    finding: findings_mod.Finding
    score: Score

    @property
    def risk(self) -> int:
        return self.score.risk

    def __str__(self) -> str:
        return f"{self.score} {self.finding}"


class Scorer(Protocol):
    name: str

    def score(self, finding: findings_mod.Finding) -> Score: ...


@dataclass
class BuiltinScorer:
    """Self-contained 21434-style scorer.

    Needs `node_roles` to resolve a target's ASIL. Without it every safety impact
    falls back to the unknown-ASIL default and every score is marked assumed, which
    is the correct behaviour but not a useful one — pass the roles in.

    `paths` is the updated snapshot's reachability result, and it is what stops the
    scorer from under-rating a hop. Judged on its own receiver, losing SecOC on a
    modem-to-gateway link looks moderate, because a gateway is not a safety function.
    Judged against the routes that run through it, the same hop is the first step to a
    brake actuator. An edge finding therefore inherits the worst impact reachable
    downstream of it, and the rationale says which target it borrowed.
    """

    node_roles: roles_mod.Roles | None = None
    paths: reach_mod.Reachability | None = None
    name: str = "builtin-21434"

    def score(self, finding: findings_mod.Finding) -> Score:
        rationale: list[str] = []
        impact, impact_assumed = self._impact(finding, rationale)
        feasibility, feas_assumed = self._feasibility(finding, rationale)
        risk = RISK_MATRIX[(impact, feasibility)]
        return Score(
            impact=impact,
            feasibility=feasibility,
            risk=risk,
            rationale=tuple(rationale),
            scorer=self.name,
            assumed=impact_assumed or feas_assumed,
        )

    # -- impact -----------------------------------------------------------------

    def _impact(self, finding: findings_mod.Finding, rationale: list[str]) -> tuple[str, bool]:
        fixed = CATEGORY_IMPACT.get(finding.category)
        if fixed is not None:
            rationale.append(f"category {finding.category} carries a fixed {fixed} impact")
            return fixed, False

        if finding.target:
            rated = self._rate_node(finding.target)
            if rated:
                impact, assumed, why = rated
                rationale.append(why)
                return impact, assumed

        inherited = self._worst_downstream(finding)
        if inherited:
            impact, assumed, why = inherited
            rationale.append(why)
            return impact, assumed

        receiver = finding.evidence.get("target")
        if receiver:
            rated = self._rate_node(receiver)
            if rated:
                impact, assumed, why = rated
                rationale.append(why)
                return impact, assumed
            rationale.append(f"{_leaf(receiver)} is not classified safety-critical")
            return MODERATE, True

        rationale.append("no safety-critical asset identified for this finding")
        return MODERATE, True

    def _rate_node(self, node: str) -> tuple[str, bool, str] | None:
        """Impact of harming one node, or None if it is not a known asset."""
        if self.node_roles is None:
            return None
        asil = self.node_roles.asil_of(node)
        if asil and asil in ASIL_IMPACT:
            return ASIL_IMPACT[asil], False, f"{_leaf(node)} is ASIL {asil} -> {ASIL_IMPACT[asil]} impact"
        if self.node_roles.role_of(node) == roles_mod.CRITICAL:
            source = next(
                (r.source for r in self.node_roles.why(node) if r.role == roles_mod.CRITICAL),
                roles_mod.HEURISTIC,
            )
            return (
                UNKNOWN_ASIL_IMPACT,
                source == roles_mod.HEURISTIC,
                f"{_leaf(node)} is critical with no ASIL on record (identified by "
                f"{source}) -> assumed {UNKNOWN_ASIL_IMPACT}",
            )
        return None

    def _worst_downstream(self, finding: findings_mod.Finding) -> tuple[str, bool, str] | None:
        """Worst asset reachable through this finding's hop.

        Keyed on the hop key rather than the connector path, so the two directions of
        a client-server connector are rated independently: a request reaching an
        actuator is not the same finding as its response coming back.
        """
        if self.paths is None or not finding.subject:
            return None
        downstream = {
            path.target
            for path in self.paths.paths
            if any(hop.key == finding.subject for hop in path.hops)
        }
        rated = [(self._rate_node(t), t) for t in sorted(downstream)]
        candidates = [(r, t) for r, t in rated if r]
        if not candidates:
            return None
        (impact, assumed, _), target = max(
            candidates, key=lambda pair: IMPACT_ORDER.index(pair[0][0])
        )
        return (
            impact,
            assumed,
            f"this hop lies on a route to {_leaf(target)}, so it inherits that "
            f"target's {impact} impact",
        )

    # -- feasibility ------------------------------------------------------------

    def _feasibility(self, finding: findings_mod.Finding, rationale: list[str]) -> tuple[str, bool]:
        if finding.path is not None:
            return self._path_feasibility(finding, rationale)

        authenticated = finding.evidence.get("authenticated")
        unprotected = finding.evidence.get("unprotected_pdus") or ()
        if unprotected or authenticated is False:
            rationale.append(
                "unauthenticated bus traffic: forging a frame needs bus access and "
                "commodity hardware, no keys"
            )
            return HIGH, False
        if authenticated is True:
            rationale.append("bus traffic is SecOC-protected: forgery needs key material")
            return LOW, False
        rationale.append("no bus exposure established for this finding")
        return VERY_LOW, True

    def _path_feasibility(self, finding: findings_mod.Finding, rationale: list[str]) -> tuple[str, bool]:
        path = finding.path
        assert path is not None
        if path.unprotected_hops:
            weakest = path.unprotected_hops[0]
            rationale.append(
                f"{len(path.unprotected_hops)} of {path.length} hops cross a bus "
                f"unauthenticated (weakest: {_leaf(weakest.connector)})"
            )
            base = HIGH
        elif path.bus_hops:
            rationale.append(
                f"all {len(path.bus_hops)} bus hops on the route are authenticated, so "
                "the attacker needs key material or a compromised legitimate sender"
            )
            base = LOW
        else:
            rationale.append(
                "route is entirely RTE-local, so it presupposes code execution on the ECU"
            )
            base = VERY_LOW

        assumed = False
        surface = self._entry_surface(path.entry)
        if surface and base != HIGH:
            rationale.append(f"entry point is remotely accessible ({surface}), raising feasibility")
            base = FEASIBILITY_ORDER[min(FEASIBILITY_ORDER.index(base) + 1, len(FEASIBILITY_ORDER) - 1)]
        if self.node_roles is not None and self.node_roles.heuristic_only:
            rationale.append("entry and critical seeds were heuristic, not configured")
            assumed = True
        return base, assumed

    def _entry_surface(self, entry: str) -> str | None:
        """Whether the entry point is remote, which raises feasibility.

        A cellular modem and an OBD connector are not the same adversary: one needs
        physical access to the vehicle and one does not.
        """
        if self.node_roles is None:
            return None
        reasons = " ".join(
            r.reason.lower() for r in self.node_roles.why(entry) if r.role == roles_mod.ENTRY
        )
        for needle in ("cellular", "telematics", "wi-fi", "wifi", "bluetooth", "v2x", "over-the-air", "radio"):
            if needle in reasons:
                return needle
        return None


@dataclass
class ExternalScorer:
    """Delegate scoring to an external tool, one finding per invocation.

    Contract, kept small on purpose. The tool receives one JSON object on stdin::

        {"category": "...", "subject": "...", "target": "...", "evidence": {...},
         "path": ["/V/Swc/Veh/tel", ...], "unprotected_hops": [...]}

    and writes one JSON object to stdout::

        {"impact": "severe", "feasibility": "high", "risk": 5,
         "rationale": ["..."]}

    `impact` and `feasibility` must use this module's vocabulary. `risk` is taken as
    given if present — an external scorer is presumed to own its own matrix — and
    otherwise derived from the impact/feasibility pair.
    """

    command: list[str]
    timeout: float = 30.0
    name: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"external:{self.command[0]}"

    def score(self, finding: findings_mod.Finding) -> Score:
        payload = {
            "category": finding.category,
            "subject": finding.subject,
            "target": finding.target,
            "evidence": _jsonable(finding.evidence),
            "path": list(finding.path.nodes) if finding.path else None,
            "unprotected_hops": (
                [h.key for h in finding.path.unprotected_hops] if finding.path else []
            ),
        }
        try:
            proc = subprocess.run(
                self.command,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScorerError(f"{self.name} failed on {finding.id}: {exc}") from exc

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScorerError(f"{self.name} returned invalid JSON for {finding.id}") from exc

        impact = str(data.get("impact", "")).lower()
        feasibility = str(data.get("feasibility", "")).lower()
        if impact not in IMPACT_ORDER or feasibility not in FEASIBILITY_ORDER:
            raise ScorerError(
                f"{self.name} returned impact={impact!r} feasibility={feasibility!r}, "
                f"which are not in this module's vocabulary"
            )
        risk = data.get("risk")
        if not isinstance(risk, int) or not 1 <= risk <= 5:
            risk = RISK_MATRIX[(impact, feasibility)]
        return Score(
            impact=impact,
            feasibility=feasibility,
            risk=risk,
            rationale=tuple(str(r) for r in data.get("rationale", ())),
            scorer=self.name,
            assumed=bool(data.get("assumed", False)),
        )


@dataclass
class FallbackScorer:
    """Try one scorer, fall back to another, and never hide that it happened.

    The fallback's provenance is stamped into `Score.scorer` and the reason into the
    rationale. A gate that silently degrades from a programme's own TARA to a generic
    heuristic is telling the reader something untrue about where the number came from.
    """

    primary: Scorer
    fallback: Scorer
    errors: list[str] = field(default_factory=list)
    name: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = f"{self.primary.name}+fallback"

    def score(self, finding: findings_mod.Finding) -> Score:
        try:
            return self.primary.score(finding)
        except ScorerError as exc:
            self.errors.append(str(exc))
            inner = self.fallback.score(finding)
            return Score(
                impact=inner.impact,
                feasibility=inner.feasibility,
                risk=inner.risk,
                rationale=inner.rationale + (f"{self.primary.name} unavailable: {exc}",),
                scorer=f"{self.fallback.name} (fallback from {self.primary.name})",
                assumed=True,
            )


def score_all(
    items: tuple[findings_mod.Finding, ...], scorer: Scorer
) -> tuple[Scored, ...]:
    """Score every finding, worst first."""
    scored = tuple(Scored(f, scorer.score(f)) for f in items)
    return tuple(sorted(scored, key=lambda s: (-s.risk, s.finding.category, s.finding.subject)))


def _jsonable(value):
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _leaf(path: str) -> str:
    """Short name from an AUTOSAR path, for rationale text a human will read."""
    return path.rsplit("/", 1)[-1]
