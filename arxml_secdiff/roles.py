"""Decide which nodes are attacker entry points and which are safety-critical.

This is the weakest link in any tool of this kind, so it is worth being blunt about
the epistemics: **criticality is not a property of the ARXML.** It comes from the
programme's HARA and TARA, which are documents, not files in the architecture. So:

* An explicit config is the only authoritative source, and it wins outright.
* Heuristics on short names and component categories exist so the tool produces
  something on a snapshot nobody has annotated yet. Every assignment records its
  `source`, and `Roles.heuristic_only` is true when nothing was configured, so a
  report can say "these seeds were guessed" instead of implying a safety analysis.

Config entries that match nothing are collected in `Roles.unmatched` rather than
ignored, because a typo in a critical-node path would otherwise silently disable the
very check the config was written to enable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import networkx as nx

ENTRY = "entry"
CRITICAL = "critical"

CONFIG = "config"
HEURISTIC = "heuristic"

#: Substrings suggesting an externally-reachable component, with the surface each
#: one implies. Matched case-insensitively against the node's short name and host.
ENTRY_HINTS = (
    ("telematic", "cellular telematics unit"),
    ("tcu", "telematics control unit"),
    ("obd", "OBD-II diagnostic port"),
    ("diag", "diagnostic service access"),
    ("dcm", "diagnostic communication manager"),
    ("bluetooth", "Bluetooth pairing surface"),
    ("wifi", "Wi-Fi interface"),
    ("wlan", "Wi-Fi interface"),
    ("usb", "USB host port"),
    ("infotain", "infotainment stack"),
    ("headunit", "head unit"),
    ("head_unit", "head unit"),
    ("ivi", "in-vehicle infotainment"),
    ("ota", "over-the-air update channel"),
    ("v2x", "V2X radio"),
    ("gnss", "GNSS receiver"),
    ("nfc", "NFC reader"),
    ("keyless", "keyless entry radio"),
    ("tpms", "TPMS radio"),
    ("charg", "charging interface"),
)

#: Substrings suggesting a safety- or security-critical target.
CRITICAL_HINTS = (
    ("brake", "service braking"),
    ("abs", "anti-lock braking"),
    ("esp", "stability control"),
    ("esc", "stability control"),
    ("steer", "steering"),
    ("eps", "electric power steering"),
    ("throttle", "throttle actuation"),
    ("torque", "torque request"),
    ("powertrain", "powertrain control"),
    ("engine", "engine control"),
    ("transmis", "transmission control"),
    ("gear", "gear selection"),
    ("airbag", "airbag deployment"),
    ("restraint", "occupant restraint"),
    ("srs", "supplemental restraint system"),
    ("aeb", "autonomous emergency braking"),
    ("adas", "driver assistance"),
    ("bms", "battery management"),
    ("immobil", "immobiliser"),
    ("lock", "central locking"),
    ("door", "door control"),
    ("light", "exterior lighting"),
    ("lamp", "exterior lighting"),
)

#: Component categories that physically actuate something. A structural signal,
#: and a better one than any name match, since it comes from the schema.
ACTUATING_CATEGORIES = ("SENSOR-ACTUATOR", "COMPLEX-DEVICE-DRIVER")


@dataclass(frozen=True)
class Role:
    """One node assigned one role, with the justification kept attached."""

    node: str
    role: str
    reason: str
    source: str
    attrs: dict = field(default_factory=dict, compare=False)

    @property
    def asil(self) -> str | None:
        """ASIL from the config, when the programme supplied one."""
        value = self.attrs.get("asil")
        return str(value).upper() if value else None


@dataclass
class Roles:
    """Entry and critical seeds for a reachability query."""

    assignments: tuple[Role, ...] = ()
    unmatched: tuple[tuple[str, str], ...] = ()

    @property
    def entry(self) -> tuple[str, ...]:
        return tuple(sorted({r.node for r in self.assignments if r.role == ENTRY}))

    @property
    def critical(self) -> tuple[str, ...]:
        return tuple(sorted({r.node for r in self.assignments if r.role == CRITICAL}))

    @property
    def heuristic_only(self) -> bool:
        """True when no assignment came from a config.

        Reports must say so: heuristic seeds are a starting point for triage, not a
        substitute for the programme's own hazard analysis.
        """
        return all(r.source == HEURISTIC for r in self.assignments)

    @property
    def seeded(self) -> bool:
        """Whether a reachability query is even answerable.

        With no entry point or no critical node there is nothing to search between,
        and `reach.analyse` will return zero paths. That is emptiness for want of a
        question, which must never be reported as "no attack paths found" - so
        callers check this and say "not analysed" instead.
        """
        return bool(self.entry) and bool(self.critical)

    def gaps(self) -> tuple[str, ...]:
        """Human-readable reasons the snapshot could not be analysed."""
        missing = []
        if not self.entry:
            missing.append("no entry point identified")
        if not self.critical:
            missing.append("no safety-critical node identified")
        return tuple(missing)

    def why(self, node: str) -> tuple[Role, ...]:
        return tuple(r for r in self.assignments if r.node == node)

    def role_of(self, node: str) -> str | None:
        """CRITICAL takes precedence, since it drives the severity of a finding."""
        roles = {r.role for r in self.why(node)}
        if CRITICAL in roles:
            return CRITICAL
        return ENTRY if ENTRY in roles else None

    def asil_of(self, node: str) -> str | None:
        return next((r.asil for r in self.why(node) if r.asil), None)


def load_config(path: str | Path) -> dict:
    """Load role config from YAML.

    Both a bare string and a mapping are accepted per entry, because the common case
    deserves the short form::

        entry_points:
          - /V/Swc/Veh/tel
          - "*Telematics*"          # globs match path or short name
        critical:
          - node: /V/Swc/Veh/brake
            asil: D
            reason: service brake actuation
    """
    import yaml

    return yaml.safe_load(Path(path).read_text()) or {}


def classify(
    graph: nx.MultiDiGraph,
    config: str | Path | dict | None = None,
    heuristics: bool = True,
) -> Roles:
    """Assign roles to nodes, preferring config over heuristics.

    Heuristics fill in a role the config did not cover at all, since a partial
    config is the normal state of a programme mid-analysis. They are skipped for a
    role the config *did* cover: someone who listed their critical nodes does not
    want guesses mixed in with them.

    Pass ``heuristics=False`` to forbid guessing entirely. A programme working from
    an authoritative TARA wants an empty result — reported as a gap — rather than a
    plausible one, and this is also the only way to tell a config typo apart from a
    role that was deliberately left out: with the fallback on, both end up populated.
    """
    if config is not None and not isinstance(config, dict):
        config = load_config(config)
    config = config or {}

    assignments: list[Role] = []
    unmatched: list[tuple[str, str]] = []

    for role, keys in ((ENTRY, ("entry_points", "entry")), (CRITICAL, ("critical", "safety_critical"))):
        entries = []
        for key in keys:
            entries.extend(config.get(key) or [])
        for entry in entries:
            spec = entry if isinstance(entry, dict) else {"node": entry}
            pattern = spec.get("node") or spec.get("pattern") or ""
            matches = _match(graph, pattern)
            if not matches:
                unmatched.append((role, pattern))
                continue
            reason = spec.get("reason") or f"listed in config as {role}"
            for node in matches:
                assignments.append(Role(node, role, reason, CONFIG, attrs=dict(spec)))

    if heuristics:
        configured = {r.role for r in assignments}
        if ENTRY not in configured:
            assignments.extend(_guess_entries(graph))
        if CRITICAL not in configured:
            assignments.extend(_guess_critical(graph))

    return Roles(tuple(sorted(assignments, key=lambda r: (r.role, r.node))), tuple(unmatched))


def _match(graph: nx.MultiDiGraph, pattern: str) -> list[str]:
    """Resolve one config entry to node paths.

    An exact path is tried first so that a literal entry never accidentally behaves
    like a glob; only then does pattern matching apply, against both the full path
    and the short name.
    """
    if not pattern:
        return []
    if pattern in graph:
        return [pattern]
    return sorted(
        n
        for n, attrs in graph.nodes(data=True)
        if fnmatch(n, pattern) or fnmatch(str(attrs.get("short_name", "")), pattern)
    )


def _guess_entries(graph: nx.MultiDiGraph) -> list[Role]:
    """Name-based guesses, plus the composition boundary as a structural fallback."""
    found: list[Role] = []
    for node, attrs in graph.nodes(data=True):
        hint = _hint(ENTRY_HINTS, attrs.get("short_name"), attrs.get("host"))
        if hint:
            found.append(Role(node, ENTRY, hint, HEURISTIC))

    if not found:
        # In an ECU extract the root composition's outer ports are the ECU boundary,
        # so anything influence enters through is the closest thing to an entry point
        # the file actually states.
        for node, attrs in graph.nodes(data=True):
            if attrs.get("kind") == "composition" and graph.out_degree(node):
                found.append(
                    Role(node, ENTRY, "composition boundary (no named surface found)", HEURISTIC)
                )
    return found


def _guess_critical(graph: nx.MultiDiGraph) -> list[Role]:
    found: list[Role] = []
    for node, attrs in graph.nodes(data=True):
        hint = _hint(CRITICAL_HINTS, attrs.get("short_name"), attrs.get("type_ref"))
        if hint:
            found.append(Role(node, CRITICAL, hint, HEURISTIC))
        elif attrs.get("category") in ACTUATING_CATEGORIES:
            found.append(
                Role(node, CRITICAL, f"{attrs['category']} component actuates hardware", HEURISTIC)
            )
    return found


def _hint(hints: tuple[tuple[str, str], ...], *haystacks) -> str | None:
    text = " ".join(str(h) for h in haystacks if h).lower()
    for needle, reason in hints:
        if needle in text:
            return reason
    return None
