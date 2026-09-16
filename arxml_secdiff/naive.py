"""Straw-man detectors, so the real analysis has to earn its place.

The claim this project makes is that a graph plus reachability plus three-valued SecOC
tells you something a diff cannot. That claim is worth nothing unmeasured, and it is
only interesting if the thing it beats is a *reasonable* alternative. A straw man that
flags every release is trivially beaten and proves nothing, so each detector here is
built to be the best version of its idea rather than the worst.

Three of them, in increasing sophistication:

`TextDiff` is what ``git diff --exit-code`` gives you, with the one concession that
makes it fair: both files are canonicalised first, so a reindent is not a change. Its
recall should be perfect and its specificity close to zero.

`ElementDiff` is what a diff tool taught to read ARXML would do — index every element
by its AUTOSAR path and report the paths that appeared, vanished or changed. It knows
the file is a tree of identified objects. It does not know what any of them mean.

`StructuralGrep` is the realistic one, and the one the comparison exists for. It
pattern-matches what a security reviewer greps for: connectors that appeared, secured
PDUs that vanished, ECU mappings that moved, connectors with no wrapper over them. It
is deliberately built with the two blind spots the real tool was designed to close —
no reachability filter, so it cannot tell a new connector that completes a route to
the brakes from one that goes nowhere; and boolean authentication, so a connector whose
data never leaves the ECU reads as unprotected rather than as not applicable. Both are
faithful to how the naive approach actually fails. Fixing either here would be cheating
the experiment.

On category mapping. Each detector reports `signals` in its own vocabulary, and maps
onto `findings` categories only where the correspondence is honest. Two of
`StructuralGrep`'s rules map cleanly: a vanished SECURED-I-PDU really is
``secoc-removed``-shaped, and a changed mapping really is ``rehosted-component``-shaped.
The other two do not. "A connector appeared" is not ``newly-reachable``: the detector
has no idea whether anything became reachable, and asserting the category would be
claiming an analysis it never ran. So those signals carry no category, and the
comparison in `evaluate` is drawn at the level these detectors can actually answer —
did you flag this release at all — with category agreement reported as the strictly
weaker question it is. That asymmetry is itself a result: the naive detectors can tell
you something changed, not what it means.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from lxml import etree

from . import findings as findings_mod

#: Collapses runs of whitespace, so indentation cannot register as a change.
_WS = re.compile(rb"\s+")


@dataclass(frozen=True)
class NaiveResult:
    """One detector's verdict on one before/after pair."""

    detector: str
    flagged: bool
    #: Human-readable, in the detector's own vocabulary: "connector added: /V/...".
    signals: tuple[str, ...] = ()
    #: `findings` categories, but only where the mapping is honest. Frequently empty
    #: even on a flagged pair, which is the point rather than an omission.
    categories: frozenset[str] = frozenset()
    #: Seconds spent comparing, for the like-for-like cost column.
    elapsed: float = 0.0

    @property
    def count(self) -> int:
        return len(self.signals)


class Detector:
    """Common shape, so `evaluate` can loop over detectors and the real pipeline alike."""

    name = "detector"
    #: One line for the results table, explaining what this detector can and cannot see.
    description = ""

    def compare(
        self, before: Sequence[str | Path], updated: Sequence[str | Path]
    ) -> NaiveResult:
        start = time.perf_counter()
        signals, categories = self._signals(_paths(before), _paths(updated))
        return NaiveResult(
            detector=self.name,
            flagged=bool(signals),
            signals=tuple(signals),
            categories=frozenset(categories),
            elapsed=time.perf_counter() - start,
        )

    def _signals(
        self, before: list[Path], updated: list[Path]
    ) -> tuple[list[str], set[str]]:  # pragma: no cover - overridden
        raise NotImplementedError


def _paths(sources: Sequence[str | Path]) -> list[Path]:
    """Accept one path or several, like `pipeline.run` does."""
    if isinstance(sources, (str, Path)):
        return [Path(sources)]
    return [Path(s) for s in sources]


# -- shared XML access ----------------------------------------------------------
#
# Local-name lookup throughout, because an R3.x file carries a different namespace URI
# and a detector that only worked on R4.x would be a straw man for the wrong reason.


def _parse(source: str | Path) -> etree._Element:
    parser = etree.XMLParser(remove_blank_text=True, remove_comments=True, huge_tree=True)
    return etree.parse(str(source), parser).getroot()


def _local(el: etree._Element) -> str:
    tag = el.tag
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _iter(root: etree._Element, *tags: str) -> list[etree._Element]:
    wanted = frozenset(tags)
    return [el for el in root.iter() if _local(el) in wanted]


def _short(el: etree._Element) -> str:
    for child in el:
        if _local(child) == "SHORT-NAME":
            return (child.text or "").strip()
    return ""


def _ar_path(el: etree._Element) -> str:
    """The SHORT-NAME chain, which is the only stable identity in an ARXML file."""
    parts: list[str] = []
    node: etree._Element | None = el
    while node is not None:
        name = _short(node)
        if name:
            parts.append(name)
        node = node.getparent()
    return "/" + "/".join(reversed(parts))


def _text(el: etree._Element, tag: str) -> str | None:
    for child in el:
        if _local(child) == tag:
            return (child.text or "").strip()
    return None


# -- TextDiff -------------------------------------------------------------------


class TextDiff(Detector):
    """Did any bytes change, ignoring layout?

    The canonicalisation is what keeps this honest. Without it every release that
    passed through a different serialiser would flag, and beating that would say
    nothing about the analysis. With it, the detector answers a real question — is this
    file materially different — and its failure is not sensitivity but silence about
    what the difference means.
    """

    name = "text-diff"
    description = "byte comparison after whitespace canonicalisation (git diff --exit-code)"

    def _signals(self, before: list[Path], updated: list[Path]):
        before = b"".join(_canonical(p) for p in before)
        after = b"".join(_canonical(p) for p in updated)
        if before == after:
            return [], set()
        delta = len(after) - len(before)
        return [f"file contents differ ({delta:+d} canonical bytes)"], set()


def _canonical(path: Path) -> bytes:
    """Strip the declaration and normalise whitespace, so a reindent is not a change."""
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    raw = re.sub(rb"<\?xml[^>]*\?>", b"", raw)
    # Between tags, whitespace is layout; inside text it may be meaningful, so it is
    # collapsed rather than dropped.
    raw = re.sub(rb">\s+<", b"><", raw)
    return _WS.sub(b" ", raw).strip()


# -- ElementDiff ----------------------------------------------------------------


class ElementDiff(Detector):
    """A structural set-diff over AUTOSAR paths, with no idea what any of them mean.

    This is the ceiling on what a schema-aware diff tool can tell you without a model:
    it names precisely which objects appeared, vanished and changed, which is genuinely
    useful for review and genuinely useless for a gate. Every change looks the same
    size.
    """

    name = "element-diff"
    description = "added / removed / changed AUTOSAR paths, no semantics"

    def _signals(self, before: list[Path], updated: list[Path]):
        before, after = _index(before), _index(updated)
        signals: list[str] = []
        for path in sorted(set(after) - set(before)):
            signals.append(f"element added: {path}")
        for path in sorted(set(before) - set(after)):
            signals.append(f"element removed: {path}")
        for path in sorted(set(before) & set(after)):
            if before[path] != after[path]:
                signals.append(f"element changed: {path}")
        return signals, set()


def _index(sources: list[Path]) -> dict[str, str]:
    """Every identified element by AUTOSAR path, mapped to a digest of its content.

    Keyed on the path because that is what survives reserialisation; valued on a
    normalised dump of the subtree's tags and text so a changed reference or a changed
    freshness length registers, and a reordering of unrelated siblings does not.
    """
    out: dict[str, str] = {}
    for source in sources:
        root = _parse(source)
        for el in root.iter():
            if not _short(el):
                continue
            out[_ar_path(el)] = _digest(el)
    return out


def _digest(el: etree._Element) -> str:
    parts: list[str] = []
    for node in el.iter():
        text = (node.text or "").strip()
        parts.append(f"{_local(node)}={text}" if text else _local(node))
    # Sorted, so sibling reordering is not reported as a content change. The order of
    # elements in an ARXML package carries no meaning, and a detector that claimed
    # otherwise would be a strictly worse straw man than the one being modelled.
    return "|".join(sorted(parts))


# -- StructuralGrep -------------------------------------------------------------

_CONNECTOR_TAGS = ("ASSEMBLY-SW-CONNECTOR", "ASSEMBLY-CONNECTOR-PROTOTYPE")
_MAPPING_TAGS = ("SWC-TO-ECU-MAPPING",)
_SECURED_TAGS = ("SECURED-I-PDU",)


class StructuralGrep(Detector):
    """What a security reviewer would grep for, with the two blind spots intact.

    The rules are the ones a competent reviewer applies by hand, and three of the four
    are right. What is missing is any notion of *reach*: rule 1 cannot distinguish a
    connector that completes a route from an entry point to an ASIL D function from one
    joining two leaf components, so it must either flag both or neither, and flagging
    both is what a reviewer does. And rule 4 treats authentication as a boolean, so a
    connector whose data never leaves the ECU — where SecOC does not apply and there is
    no PDU to wrap — reads identically to one crossing a bus in the clear.

    Those two are not oversights in this implementation. They are the measured cost of
    not building the graph, and the reason the real tool models `authenticated` with
    three values instead of two.
    """

    name = "structural-grep"
    description = (
        "connector / secured-PDU / ECU-mapping pattern match; no reachability, "
        "boolean authentication"
    )

    def _signals(self, before: list[Path], updated: list[Path]):
        before, after = _grep(before), _grep(updated)
        signals: list[str] = []
        categories: set[str] = set()

        for path in sorted(after["connectors"] - before["connectors"]):
            # No reachability filter: this may complete a route to a safety function or
            # join two leaves, and nothing here can tell the difference.
            signals.append(f"new connection: {path}")

        for path in sorted(before["secured"] - after["secured"]):
            signals.append(f"authentication removed: {path}")
            # Honest: a SECURED-I-PDU that vanished really is what the real tool calls
            # secoc-removed, even though the real one additionally checks the traffic
            # still crosses a bus.
            categories.add(findings_mod.SECOC_REMOVED)

        for component in sorted(set(before["hosts"]) | set(after["hosts"])):
            was, now = before["hosts"].get(component), after["hosts"].get(component)
            if was is not None and now is not None and was != now:
                signals.append(f"component rehosted: {component} {was} -> {now}")
                categories.add(findings_mod.REHOSTED)

        # Only newly-unwrapped connectors, not every standing one. A reviewer grepping a
        # release cares what this release broke; reporting the whole existing backlog
        # would flag every release including an empty one, which is a straw man too weak
        # to be worth beating.
        for path in sorted(after["unwrapped"] - before["unwrapped"]):
            # Boolean authentication. An RTE-local connector has no PDU to wrap, so it
            # lands here too, and this detector has no way to tell that apart from a
            # bus hop stripped of SecOC.
            signals.append(f"unauthenticated connection: {path}")

        return signals, categories


def _grep(sources: list[Path]) -> dict:
    """The four things the reviewer's grep would surface, per snapshot."""
    connectors: set[str] = set()
    secured: set[str] = set()
    hosts: dict[str, str] = {}
    unwrapped: set[str] = set()

    for source in sources:
        root = _parse(source)
        for tag in _SECURED_TAGS:
            secured.update(_ar_path(el) for el in _iter(root, tag))
        for mapping in _iter(root, *_MAPPING_TAGS):
            ecu = _ref_leaf(mapping, ("ECU-INSTANCE-REF", "ECU-REF"))
            for iref in _iter(mapping, "COMPONENT-IREF", "SW-COMPONENT-IREF"):
                target = _ref_leaf(iref, ("TARGET-COMPONENT-REF", "COMPONENT-PROTOTYPE-REF"))
                if target and ecu:
                    hosts[target] = ecu
        # Name matching, because a grep has no signal-to-PDU join to walk. This is what
        # a reviewer actually does — "is there a secured PDU that looks like this port?"
        # — and it is wrong in both directions, which is worth measuring.
        wrappers = {_short(el).lower() for el in _iter(root, *_SECURED_TAGS)}
        for conn in _iter(root, *_CONNECTOR_TAGS):
            path = _ar_path(conn)
            connectors.add(path)
            name = _short(conn).lower()
            if not any(name and name in w or w and w in name for w in wrappers):
                unwrapped.add(path)

    return {
        "connectors": connectors,
        "secured": secured,
        "hosts": hosts,
        "unwrapped": unwrapped,
    }


def _ref_leaf(el: etree._Element, tags: Sequence[str]) -> str | None:
    """The last segment of the first matching reference, which is the ECU or SWC name."""
    for tag in tags:
        for child in el.iter():
            if _local(child) == tag:
                ref = (child.text or "").strip()
                if ref:
                    return ref.rsplit("/", 1)[-1]
    return None


#: In increasing sophistication. `evaluate` prints them in this order, above the row
#: for the real pipeline, so the table reads as a progression.
DETECTORS: tuple[Detector, ...] = (TextDiff(), ElementDiff(), StructuralGrep())

BY_NAME: dict[str, Detector] = {d.name: d for d in DETECTORS}
