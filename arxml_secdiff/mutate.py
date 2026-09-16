"""Generate labelled before/after ARXML pairs by mutating a before.

A regression detector is only as trustworthy as the corpus it was measured on, and
three hand-written fixtures do not measure anything. This module turns one before
into many labelled pairs: each mutation declares the findings it is *supposed* to
produce, so detection can be counted rather than asserted.

Three kinds of mutation, and the third is the point:

* **regression** — injects a defect; the declared findings must appear.
* **benign** — a semantically neutral edit (reordering, renaming, whitespace, an
  unreferenced addition). *Any* non-informational finding is a false positive. A
  detector with perfect recall and no specificity gets switched off within a
  fortnight, so these carry as much weight as the regressions do.
* **known-gap** — a defect the tool does *not* currently catch, with the reason
  recorded. Declaring these is what stops a blind spot being read as a clean result,
  and the evaluation asserts they are still missed — so closing one makes the corpus
  fail until its label is updated, which is the correct way round.

Mutations operate on the XML tree rather than on the extracted model, so the output
is a real ARXML file that has to survive the real parser. Mutating the model instead
would test the detector against a model the parser might never produce. Elements are
addressed by local tag name and rebuilt in the root's own namespace, so an R3.x
before mutates as readily as an R4.x one.

Mutations compose, and that is where the corpus gets its discrimination. `rehost`
alone must **not** report unauthenticated traffic — the component moved, but its data
still never reaches a wire. `rehost` followed by `expose_on_bus` must report exactly
that. The pair pins down the distinction between "SecOC absent" and "SecOC not
applicable", which is the whole reason this tool is more than a grep.

Scale comes from three multipliers, not from writing more mutation code:

1. **Sites.** A `Family` enumerates every place in a before it could act — every
   SECURED-I-PDU, every unconnected compatible port pair, every (component, target
   ECU) rehost. One family yields as many labelled cases as the before has sites.
2. **Composition.** Named templates pair families whose interaction is the thing
   being measured, keeping the merged label honest via `combine`.
3. **Benign noise.** Every regression is also shipped alongside each cosmetic edit,
   because a real OTA release contains churn and the churn must not mask the defect.
   These carry the regression's label unchanged: the noise is not an excuse.

`expand` applies all three against a specific before; `CATALOGUE` is the fifteen
canonical single-site cases, kept by name because the write-up and the case study
refer to them.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from lxml import etree

from . import findings as findings_mod
from .parser import COMPONENT_CATEGORIES, PORT_KINDS

#: A mutation that injects a real defect. The declared findings must be reported.
REGRESSION = "regression"
#: A semantically neutral edit. Any non-informational finding is a false positive.
BENIGN = "benign"
#: A real defect this tool does not detect, declared so it is not mistaken for clean.
KNOWN_GAP = "known-gap"

#: Site key for a family that has exactly one place to act, or one chosen at apply time.
ONLY = "only"

_COMPONENT_TAGS = frozenset(COMPONENT_CATEGORIES)
_PORT_TAGS = frozenset(PORT_KINDS)
_PROVIDED_PORT_TAGS = ("P-PORT-PROTOTYPE", "PR-PORT-PROTOTYPE")
_REQUIRED_PORT_TAGS = ("R-PORT-PROTOTYPE", "PR-PORT-PROTOTYPE")
_INTERFACE_TREFS = (
    "PROVIDED-INTERFACE-TREF",
    "REQUIRED-INTERFACE-TREF",
    "PROVIDED-REQUIRED-INTERFACE-TREF",
)


class NotApplicable(Exception):
    """A mutation cannot be applied to this before.

    Raised rather than returned so a half-applied tree can never be written: the
    caller discards the tree and the case is recorded as skipped.
    """


# -- ground truth ---------------------------------------------------------------


@dataclass(frozen=True)
class Expectation:
    """One finding a mutation must produce.

    Deliberately coarse. A mutation knows it removed authentication from a PDU, but
    not which connector edge key the graph builder will derive for it, nor which
    safety-critical node the reachability stage will name — those depend on seeds the
    mutation never sees. Asserting the category, and optionally a substring of the
    subject, is the strongest claim that stays true across befores.
    """

    category: str
    subject_contains: str = ""
    min_count: int = 1

    def matches(self, finding) -> bool:
        return finding.category == self.category and (
            self.subject_contains in finding.subject
        )

    def count_in(self, found: Iterable) -> int:
        return sum(1 for f in found if self.matches(f))

    def satisfied_by(self, found: Iterable) -> bool:
        return self.count_in(found) >= self.min_count

    def __str__(self) -> str:
        out = self.category
        if self.subject_contains:
            out += f" (subject containing {self.subject_contains!r})"
        if self.min_count > 1:
            out += f" x{self.min_count}"
        return out


@dataclass(frozen=True)
class Mutation:
    """One edit to an ARXML tree, with the findings it is labelled to produce."""

    name: str
    kind: str
    description: str
    transform: Callable[[etree._Element], str] = field(repr=False, default=lambda root: "")
    expected: tuple[Expectation, ...] = ()
    #: Categories that must *not* appear. This is where the false-positive traps are
    #: pinned: a rehost with no PDU behind it must not report missing SecOC.
    forbidden: tuple[str, ...] = ()
    #: For KNOWN_GAP: what goes undetected and why.
    gap: str = ""
    #: False writes the mutant unindented, to prove formatting is not load-bearing.
    pretty: bool = True
    #: How many families were composed to make this case. Reported by the evaluation
    #: so accuracy can be broken down by how compound the change was.
    order: int = 1

    @property
    def benign(self) -> bool:
        return self.kind == BENIGN

    @property
    def known_gap(self) -> bool:
        return self.kind == KNOWN_GAP

    def __str__(self) -> str:
        return f"[{self.kind}] {self.name}: {self.description}"


def combine(name: str, description: str, *mutations: Mutation, **overrides) -> Mutation:
    """Apply several mutations as one case, merging their labels.

    Forbidden categories are unioned and then reduced by whatever the *final* expected
    set contains, because a category one half rules out is often exactly what the
    other half introduces. Resolving `expected` before subtracting matters: computing
    the union against the default and then accepting an `expected=` override would
    leave a label that forbids what it also demands.
    """
    kinds = {m.kind for m in mutations}

    def transform(root: etree._Element) -> str:
        return "; ".join(m.transform(root) for m in mutations)

    expected = overrides.get(
        "expected", tuple(dict.fromkeys(e for m in mutations for e in m.expected))
    )
    categories = {e.category for e in expected}
    forbidden = overrides.get(
        "forbidden", tuple(dict.fromkeys(c for m in mutations for c in m.forbidden))
    )
    return Mutation(
        name=overrides.get("name", name),
        kind=overrides.get(
            "kind",
            REGRESSION if REGRESSION in kinds else KNOWN_GAP if KNOWN_GAP in kinds else BENIGN,
        ),
        description=description,
        transform=transform,
        expected=expected,
        forbidden=tuple(c for c in forbidden if c not in categories),
        gap=overrides.get("gap", " ".join(m.gap for m in mutations if m.gap)),
        pretty=all(m.pretty for m in mutations),
        order=overrides.get("order", sum(m.order for m in mutations)),
    )


# -- sites and families ---------------------------------------------------------


@dataclass(frozen=True)
class Site:
    """One place in a before where a family can act.

    `args` holds AUTOSAR paths rather than elements, because a site is enumerated
    against one tree and applied against a freshly parsed one — and, in a composed
    case, against a tree an earlier mutation has already edited. Re-resolving the
    path at apply time is what lets a stale site raise `NotApplicable` instead of
    silently acting on the wrong element.
    """

    key: str
    args: tuple[str, ...] = ()
    label: str = ""


@dataclass(frozen=True)
class Family:
    """A mutation kind, plus every site in a given before where it applies."""

    name: str
    kind: str
    description: str
    sites: Callable[[etree._Element], list[Site]] = field(
        repr=False, default=lambda root: [Site(ONLY)]
    )
    edit: Callable[[etree._Element, Site], str] = field(
        repr=False, default=lambda root, site: ""
    )
    expected: tuple[Expectation, ...] = ()
    forbidden: tuple[str, ...] = ()
    gap: str = ""
    pretty: bool = True

    def at(self, site: Site, bare: bool = False) -> Mutation:
        """The concrete single-site mutation, with the site bound into its transform."""
        return Mutation(
            name=self.name if bare or site.key == ONLY else f"{self.name}__{site.key}",
            kind=self.kind,
            description=(
                f"{self.description} ({site.label})" if site.label else self.description
            ),
            transform=lambda root, _site=site: self.edit(root, _site),
            expected=self.expected,
            forbidden=self.forbidden,
            gap=self.gap,
            pretty=self.pretty,
        )

    def first(self) -> Mutation:
        """The family applied at whichever site comes first in document order.

        Site selection is deferred to apply time so this is a static object, which is
        what lets `CATALOGUE` name the canonical cases without holding a before.
        """

        def transform(root: etree._Element) -> str:
            found = self.sites(root)
            if not found:
                raise NotApplicable(f"no site in the before for {self.name}")
            return self.edit(root, found[0])

        return Mutation(
            name=self.name,
            kind=self.kind,
            description=self.description,
            transform=transform,
            expected=self.expected,
            forbidden=self.forbidden,
            gap=self.gap,
            pretty=self.pretty,
        )

    def mutations(self, root: etree._Element) -> list[Mutation]:
        """One mutation per site, named bare when the before offers only one."""
        found = _distinct(self.sites(root))
        if len(found) == 1:
            return [self.at(found[0], bare=True)]
        return [self.at(site) for site in found]


def _distinct(sites: Sequence[Site]) -> list[Site]:
    """Force site keys apart, since they become file names."""
    seen: dict[str, int] = {}
    out = []
    for site in sites:
        seen[site.key] = seen.get(site.key, 0) + 1
        count = seen[site.key]
        out.append(site if count == 1 else replace(site, key=f"{site.key}-{count}"))
    return out


# -- namespace-agnostic XML helpers ---------------------------------------------
#
# The tree keeps its namespace here, unlike everywhere else in the package: the
# output has to be a valid ARXML file, not merely one this parser can read. So
# elements are located by local name and created in the root's own namespace.


def _uri(root: etree._Element) -> str:
    tag = root.tag
    return tag.split("}", 1)[0][1:] if isinstance(tag, str) and tag.startswith("{") else ""


def _local(el: etree._Element) -> str:
    tag = el.tag
    if not isinstance(tag, str):
        return ""  # comment or processing instruction
    return tag.split("}", 1)[1] if "}" in tag else tag


def _iter(el: etree._Element, *tags: str) -> list[etree._Element]:
    """Every descendant (and `el` itself) whose local name is one of `tags`."""
    wanted = set(tags)
    return [d for d in el.iter() if _local(d) in wanted]


def _children(el: etree._Element | None, *tags: str) -> list[etree._Element]:
    if el is None:
        return []
    wanted = set(tags)
    return [c for c in el if _local(c) in wanted]


def _child(el: etree._Element | None, tag: str) -> etree._Element | None:
    return next(iter(_children(el, tag)), None)


def _text(el: etree._Element | None, tag: str) -> str | None:
    found = _child(el, tag)
    if found is None or found.text is None:
        return None
    return found.text.strip() or None


def _short(el: etree._Element | None) -> str | None:
    return _text(el, "SHORT-NAME")


def _ar_path(el: etree._Element) -> str:
    """The element's absolute AUTOSAR path, from the SHORT-NAMEs above it.

    Wrapper elements (AR-PACKAGES, ELEMENTS, PORTS) have no SHORT-NAME and so
    contribute no segment, which is exactly the AUTOSAR rule.
    """
    names: list[str] = []
    node: etree._Element | None = el
    while node is not None:
        name = _short(node)
        if name:
            names.append(name)
        node = node.getparent()
    return "/" + "/".join(reversed(names))


def _find(root: etree._Element, path: str, *tags: str) -> etree._Element | None:
    return next((el for el in _iter(root, *tags) if _ar_path(el) == path), None)


def _leaf(path: str | None) -> str:
    return (path or "").rsplit("/", 1)[-1] or "root"


def _slug(*parts: str | None) -> str:
    """A site key safe to use as a file name."""
    text = "-".join(_leaf(p) for p in parts if p)
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in text) or "site"


def _make(root: etree._Element, tag: str, text: str | None = None, **attrib) -> etree._Element:
    uri = _uri(root)
    el = etree.Element(f"{{{uri}}}{tag}" if uri else tag, attrib=attrib or None)
    if text is not None:
        el.text = text
    return el


def _identified(root: etree._Element, tag: str, short: str) -> etree._Element:
    el = _make(root, tag)
    el.append(_make(root, "SHORT-NAME", short))
    return el


def _reference(root: etree._Element, tag: str, dest: str, path: str) -> etree._Element:
    return _make(root, tag, path, DEST=dest)


def _ensure(parent: etree._Element, root: etree._Element, tag: str, index: int = -1):
    """Return `parent`'s child `tag`, creating it at `index` if absent."""
    found = _child(parent, tag)
    if found is not None:
        return found
    found = _make(root, tag)
    if index < 0:
        parent.append(found)
    else:
        parent.insert(index, found)
    return found


def _unique(root: etree._Element, base: str) -> str:
    """A SHORT-NAME not already used anywhere in the file."""
    taken = {name for el in root.iter() if (name := _short(el))}
    if base not in taken:
        return base
    for n in range(2, 100):
        if (candidate := f"{base}{n}") not in taken:
            return candidate
    raise NotApplicable(f"cannot find an unused name based on {base!r}")


# -- architecture queries -------------------------------------------------------


def _compositions(root: etree._Element) -> list[etree._Element]:
    return [
        c
        for c in _iter(root, "COMPOSITION-SW-COMPONENT-TYPE")
        if _child(c, "COMPONENTS") is not None
    ]


def _prototypes(composition: etree._Element) -> list[etree._Element]:
    return _children(_child(composition, "COMPONENTS"), "SW-COMPONENT-PROTOTYPE")


def _assembly_connectors(root: etree._Element) -> list[etree._Element]:
    return _iter(root, "ASSEMBLY-SW-CONNECTOR")


def _endpoints(conn: etree._Element) -> tuple[str, str, str, str] | None:
    """(provider prototype, provider port, requester prototype, requester port)."""
    provider, requester = _child(conn, "PROVIDER-IREF"), _child(conn, "REQUESTER-IREF")
    if provider is None or requester is None:
        return None
    parts = (
        _text(provider, "CONTEXT-COMPONENT-REF"),
        _text(provider, "TARGET-P-PORT-REF") or _text(provider, "TARGET-PR-PORT-REF"),
        _text(requester, "CONTEXT-COMPONENT-REF"),
        _text(requester, "TARGET-R-PORT-REF") or _text(requester, "TARGET-PR-PORT-REF"),
    )
    return parts if all(parts) else None  # type: ignore[return-value]


def _component_types(root: etree._Element) -> dict[str, etree._Element]:
    return {_ar_path(el): el for el in _iter(root, *_COMPONENT_TAGS)}


def _ports(type_el: etree._Element, tags: Sequence[str]) -> list[tuple[str, str]]:
    """(port path, interface path) for each port of `type_el` in `tags`."""
    holder = _child(type_el, "PORTS")
    out = []
    for port in _children(holder, *tags):
        interface = next(
            (ref for tref in _INTERFACE_TREFS if (ref := _text(port, tref))), None
        )
        if interface:
            out.append((_ar_path(port), interface))
    return out


def _hosts(root: etree._Element) -> dict[str, str]:
    """Prototype path -> ECU path, from SWC-TO-ECU-MAPPING."""
    out: dict[str, str] = {}
    for mapping in _iter(root, "SWC-TO-ECU-MAPPING"):
        ecu = _text(mapping, "ECU-INSTANCE-REF")
        if not ecu:
            continue
        for iref in _children(_child(mapping, "COMPONENT-IREFS"), "COMPONENT-IREF"):
            target = _text(iref, "TARGET-COMPONENT-REF")
            if target:
                out[target] = ecu
    return out


def _ecu_mappings(root: etree._Element) -> list[tuple[etree._Element, list[etree._Element]]]:
    """Each SWC-TO-ECU-MAPPING with its COMPONENT-IREF children, in document order."""
    out = []
    for mapping in _iter(root, "SWC-TO-ECU-MAPPING"):
        irefs = _children(_child(mapping, "COMPONENT-IREFS"), "COMPONENT-IREF")
        out.append((mapping, irefs))
    return out


def _mapped_ports(root: etree._Element) -> set[str]:
    """Ports that already reach a system signal, and so are already on a wire."""
    out = set()
    for mapping in _iter(root, "SENDER-RECEIVER-TO-SIGNAL-MAPPING"):
        iref = _child(mapping, "DATA-ELEMENT-IREF")
        port = _text(iref, "CONTEXT-PORT-REF") if iref is not None else None
        if port:
            out.add(port)
    return out


def _first_data_element(root: etree._Element, interface: str) -> str | None:
    """Path of the first VARIABLE-DATA-PROTOTYPE in a sender-receiver interface."""
    for el in _iter(root, "SENDER-RECEIVER-INTERFACE"):
        if _ar_path(el) != interface:
            continue
        member = next(
            iter(_children(_child(el, "DATA-ELEMENTS"), "VARIABLE-DATA-PROTOTYPE")), None
        )
        return _ar_path(member) if member is not None else None
    return None


def _interface_of_port(root: etree._Element, port: str) -> str | None:
    for el in _iter(root, *_PORT_TAGS):
        if _ar_path(el) != port:
            continue
        return next((ref for tref in _INTERFACE_TREFS if (ref := _text(el, tref))), None)
    return None


def _comm_package(root: etree._Element) -> etree._Element:
    """The ELEMENTS holder for signals and PDUs, created next to the SYSTEM if absent."""
    for tag in ("I-SIGNAL-I-PDU", "SYSTEM-SIGNAL", "I-SIGNAL"):
        existing = next(iter(_iter(root, tag)), None)
        if existing is not None:
            return existing.getparent()

    system = next(iter(_iter(root, "SYSTEM")), None)
    if system is None:
        raise NotApplicable("before has no SYSTEM to hang a communication package on")
    packages = system.getparent().getparent().getparent()  # ELEMENTS -> AR-PACKAGE -> AR-PACKAGES
    package = _identified(root, "AR-PACKAGE", _unique(root, "Comm"))
    elements = _make(root, "ELEMENTS")
    package.append(elements)
    packages.append(package)
    return elements


def _signal_mapping(
    root: etree._Element, port: str, element: str, signal: str
) -> etree._Element:
    mapping = _make(root, "SENDER-RECEIVER-TO-SIGNAL-MAPPING")
    iref = _make(root, "DATA-ELEMENT-IREF")
    composition = next(iter(_iter(root, "ROOT-SW-COMPOSITION-PROTOTYPE")), None)
    if composition is not None:
        iref.append(
            _reference(
                root,
                "CONTEXT-COMPOSITION-REF",
                "ROOT-SW-COMPOSITION-PROTOTYPE",
                _ar_path(composition),
            )
        )
    iref.append(_reference(root, "CONTEXT-PORT-REF", "P-PORT-PROTOTYPE", port))
    iref.append(
        _reference(root, "TARGET-DATA-PROTOTYPE-REF", "VARIABLE-DATA-PROTOTYPE", element)
    )
    mapping.append(iref)
    mapping.append(_reference(root, "SYSTEM-SIGNAL-REF", "SYSTEM-SIGNAL", signal))
    return mapping


# -- SecOC sites, shared by three families --------------------------------------


def _secured_sites(root: etree._Element) -> list[Site]:
    """One site per SECURED-I-PDU, plus an all-at-once site when there are several."""
    secured = _iter(root, "SECURED-I-PDU")
    sites = [
        Site(
            _slug(_ar_path(el)),
            (_ar_path(el),),
            f"payload {_text(el, 'PAYLOAD-REF') or _ar_path(el)}",
        )
        for el in secured
    ]
    if len(secured) > 1:
        # `args=()` means every wrapper. A release that drops protection wholesale is
        # a different change from one that drops it on a single PDU, and both happen.
        sites.append(Site("all", (), f"all {len(secured)} wrappers"))
    return sites


def _secured_elements(root: etree._Element, site: Site) -> list[etree._Element]:
    if not site.args:
        found = _iter(root, "SECURED-I-PDU")
        if not found:
            raise NotApplicable("before has no SECURED-I-PDU")
        return found
    el = _find(root, site.args[0], "SECURED-I-PDU")
    if el is None:
        raise NotApplicable(f"no SECURED-I-PDU at {site.args[0]}")
    return [el]


# -- regressions ----------------------------------------------------------------


def _edit_strip_secoc(root: etree._Element, site: Site) -> str:
    secured = _secured_elements(root, site)
    protected = []
    for el in secured:
        protected.append(_text(el, "PAYLOAD-REF") or _ar_path(el))
        el.getparent().remove(el)
    return (
        f"deleted {len(secured)} SECURED-I-PDU wrapper(s), "
        f"unprotecting {', '.join(protected)}"
    )


def _bypass_candidates(root: etree._Element) -> list[tuple[str, str, str, str]]:
    """Every (requester, requester port, provider, provider port) nobody wired.

    Sorted, so both site enumeration and the canonical `first()` case are stable
    across runs and across platforms.
    """
    types = _component_types(root)
    out: list[tuple[str, str, str, str]] = []
    for composition in _compositions(root):
        protos = {
            _ar_path(p): _text(p, "TYPE-TREF")
            for p in _prototypes(composition)
            if _text(p, "TYPE-TREF")
        }
        connected = set()
        for conn in _children(_child(composition, "CONNECTORS"), "ASSEMBLY-SW-CONNECTOR"):
            ends = _endpoints(conn)
            if ends:
                connected.add((ends[2], ends[3]))

        found: list[tuple[str, str, str, str]] = []
        for req_proto, req_type in sorted(protos.items()):
            req_el = types.get(req_type)
            if req_el is None:
                continue
            for req_port, interface in _ports(req_el, _REQUIRED_PORT_TAGS):
                if (req_proto, req_port) in connected:
                    continue
                for prov_proto, prov_type in sorted(protos.items()):
                    if prov_proto == req_proto:
                        continue  # a self-loop is not an attack path
                    prov_el = types.get(prov_type)
                    if prov_el is None:
                        continue
                    for prov_port, prov_iface in _ports(prov_el, _PROVIDED_PORT_TAGS):
                        if prov_iface == interface:
                            found.append((req_proto, req_port, prov_proto, prov_port))
        out.extend(sorted(found))
    return out


def _bypass_sites(root: etree._Element) -> list[Site]:
    return [
        Site(
            _slug(prov_proto, prov_port) + "-to-" + _slug(req_proto, req_port),
            (prov_proto, prov_port, req_proto, req_port),
            f"{prov_proto} -> {req_proto}",
        )
        for req_proto, req_port, prov_proto, prov_port in _bypass_candidates(root)
    ]


def _edit_bypass(root: etree._Element, site: Site) -> str:
    """Wire together a compatible port pair nobody connected.

    The canonical integration regression: every connector in the file is individually
    reasonable, and the one that completes a chain from the outside world to a safety
    function looks no different from the rest.
    """
    prov_proto, prov_port, req_proto, req_port = site.args
    composition = next(
        (
            c
            for c in _compositions(root)
            if any(_ar_path(p) == req_proto for p in _prototypes(c))
        ),
        None,
    )
    if composition is None:
        raise NotApplicable(f"{req_proto} is no longer in any composition")
    if _find(root, prov_proto, "SW-COMPONENT-PROTOTYPE") is None:
        raise NotApplicable(f"{prov_proto} is no longer in the before")
    for conn in _children(_child(composition, "CONNECTORS"), "ASSEMBLY-SW-CONNECTOR"):
        ends = _endpoints(conn)
        if ends and (ends[2], ends[3]) == (req_proto, req_port):
            raise NotApplicable(f"{req_port} on {req_proto} is already connected")

    name = _unique(root, f"{_leaf(prov_proto)}To{_leaf(req_proto).capitalize()}")
    conn = _identified(root, "ASSEMBLY-SW-CONNECTOR", name)
    provider = _make(root, "PROVIDER-IREF")
    provider.append(
        _reference(root, "CONTEXT-COMPONENT-REF", "SW-COMPONENT-PROTOTYPE", prov_proto)
    )
    provider.append(_reference(root, "TARGET-P-PORT-REF", "P-PORT-PROTOTYPE", prov_port))
    requester = _make(root, "REQUESTER-IREF")
    requester.append(
        _reference(root, "CONTEXT-COMPONENT-REF", "SW-COMPONENT-PROTOTYPE", req_proto)
    )
    requester.append(_reference(root, "TARGET-R-PORT-REF", "R-PORT-PROTOTYPE", req_port))
    conn.extend([provider, requester])
    _ensure(composition, root, "CONNECTORS").append(conn)
    return f"connected {prov_proto} -> {req_proto} via new connector {name}"


def _rehost_sites(root: etree._Element) -> list[Site]:
    """Every (component, destination ECU) move that leaves no mapping empty.

    Which destination is *plausible* is not what this measures, and there is no
    principled way to guess it, so every other mapped ECU counts as a site.
    """
    groups = [(m, irefs) for m, irefs in _ecu_mappings(root) if irefs]
    if len(groups) < 2:
        return []
    out = []
    for index, (_donor, irefs) in enumerate(groups):
        if len(irefs) < 2:
            continue  # moving the only component off an ECU would empty its mapping
        rotated = [groups[(index + 1 + n) % len(groups)] for n in range(len(groups) - 1)]
        for target, _ in rotated:
            ecu = _text(target, "ECU-INSTANCE-REF")
            if not ecu:
                continue
            for iref in irefs:
                component = _text(iref, "TARGET-COMPONENT-REF")
                if component:
                    out.append(
                        Site(
                            _slug(component) + "-to-" + _slug(ecu),
                            (component, ecu),
                            f"{component} to {ecu}",
                        )
                    )
    return out


def _edit_rehost(root: etree._Element, site: Site) -> str:
    """Move a component to another ECU, touching nothing else.

    The mutation a per-file review misses completely: the diff is a single
    ECU-INSTANCE-REF, and yet every connector the component owns may have changed
    from an RTE call into bus traffic.
    """
    component, ecu = site.args
    moved = donor = target = None
    for mapping, irefs in _ecu_mappings(root):
        if _text(mapping, "ECU-INSTANCE-REF") == ecu:
            target = mapping
        for iref in irefs:
            if _text(iref, "TARGET-COMPONENT-REF") == component:
                moved, donor = iref, mapping
    if moved is None or donor is None:
        raise NotApplicable(f"{component} is not mapped to any ECU")
    if target is None:
        raise NotApplicable(f"no SWC-TO-ECU-MAPPING for {ecu}")
    if donor is target:
        raise NotApplicable(f"{component} is already hosted on {ecu}")

    moved.getparent().remove(moved)
    _ensure(target, root, "COMPONENT-IREFS", index=1).append(moved)
    return f"moved {component} from {_text(donor, 'ECU-INSTANCE-REF')} to {ecu}"


def _edit_expose_on_bus(root: etree._Element, site: Site) -> str:
    """Give a cross-ECU connector the signal chain it needs, and no SecOC.

    Only applicable once a connector actually spans two ECUs, which is what makes it
    the natural second half of `rehost` and `bypass`: on its own it has nothing to
    act on, and that is the correct answer for a before whose buses are all
    already modelled. The site is therefore resolved here rather than enumerated —
    the eligible connector is usually one an earlier mutation in the same case just
    created.
    """
    hosts = _hosts(root)
    mapped = _mapped_ports(root)
    system_mapping = next(iter(_iter(root, "SYSTEM-MAPPING")), None)
    if system_mapping is None:
        raise NotApplicable("before has no SYSTEM-MAPPING to add a data mapping to")

    for conn in _assembly_connectors(root):
        ends = _endpoints(conn)
        if ends is None:
            continue
        prov_proto, prov_port, req_proto, _ = ends
        prov_host, req_host = hosts.get(prov_proto), hosts.get(req_proto)
        if not prov_host or not req_host or prov_host == req_host:
            continue  # RTE-local, or unmapped: nothing is on a wire to protect
        if prov_port in mapped:
            continue  # already carried by a PDU

        interface = _interface_of_port(root, prov_port)
        if interface is None:
            continue
        element = _first_data_element(root, interface)
        if element is None:
            continue  # client-server, or an interface with no data to map

        base = _short(conn) or "Bus"
        signal = _identified(root, "SYSTEM-SIGNAL", _unique(root, f"{base}SSig"))
        isignal = _identified(root, "I-SIGNAL", _unique(root, f"{base}ISig"))
        pdu = _identified(root, "I-SIGNAL-I-PDU", _unique(root, f"{base}IPdu"))
        mappings = _make(root, "I-SIGNAL-TO-PDU-MAPPINGS")
        entry = _identified(root, "I-SIGNAL-TO-I-PDU-MAPPING", _unique(root, f"{base}Map"))
        mappings.append(entry)
        pdu.append(mappings)

        comm = _comm_package(root)
        comm.extend([signal, isignal, pdu])
        # The refs go on after the elements have a home, because their targets are
        # derived from where they sit in the tree.
        isignal.append(
            _reference(root, "SYSTEM-SIGNAL-REF", "SYSTEM-SIGNAL", _ar_path(signal))
        )
        entry.append(_reference(root, "I-SIGNAL-REF", "I-SIGNAL", _ar_path(isignal)))

        data_mappings = _ensure(system_mapping, root, "DATA-MAPPINGS", index=1)
        data_mappings.append(_signal_mapping(root, prov_port, element, _ar_path(signal)))
        return (
            f"put {prov_port} on a bus as {_ar_path(pdu)} with no SECURED-I-PDU "
            f"({prov_host} -> {req_host})"
        )

    raise NotApplicable("no cross-ECU connector is missing its signal chain")


def _composition_sites(root: etree._Element) -> list[Site]:
    return [
        Site(_slug(_ar_path(c)), (_ar_path(c),), f"in {_ar_path(c)}")
        for c in _compositions(root)
    ]


def _edit_add_component(root: etree._Element, site: Site) -> str:
    composition = _find(root, site.args[0], "COMPOSITION-SW-COMPONENT-TYPE")
    if composition is None or _child(composition, "COMPONENTS") is None:
        raise NotApplicable(f"no composition at {site.args[0]}")

    types = _component_types(root)
    holder = next(
        (el.getparent() for el in types.values() if _local(el) in _COMPONENT_TAGS), None
    )
    if holder is None:
        raise NotApplicable("before has no component types")

    type_el = _identified(
        root, "APPLICATION-SW-COMPONENT-TYPE", _unique(root, "DiagnosticProbe")
    )
    holder.append(type_el)

    proto = _identified(root, "SW-COMPONENT-PROTOTYPE", _unique(root, "probe"))
    proto.append(
        _reference(root, "TYPE-TREF", "APPLICATION-SW-COMPONENT-TYPE", _ar_path(type_el))
    )
    _child(composition, "COMPONENTS").append(proto)

    mapping = next((m for m, irefs in _ecu_mappings(root) if irefs), None)
    if mapping is not None:
        iref = _make(root, "COMPONENT-IREF")
        iref.append(
            _reference(root, "TARGET-COMPONENT-REF", "SW-COMPONENT-PROTOTYPE", _ar_path(proto))
        )
        _ensure(mapping, root, "COMPONENT-IREFS", index=1).append(iref)
    return f"added component {_ar_path(proto)} with no ports and no connectors"


def _removable_sites(root: etree._Element) -> list[Site]:
    """Every prototype that can go without emptying its composition.

    Pure sinks come first, so the canonical `remove-component` case removes a leaf
    and measures one thing. Removing a provider is also enumerated, because a real
    release does that too and the tool should survive the upstream routes it breaks.
    """
    out = []
    for composition in _compositions(root):
        protos = _prototypes(composition)
        if len(protos) < 2:
            continue
        provides: set[str] = set()
        requires: set[str] = set()
        for conn in _assembly_connectors(root):
            ends = _endpoints(conn)
            if ends:
                provides.add(ends[0])
                requires.add(ends[2])
        paths = sorted(_ar_path(p) for p in protos)
        sinks = [p for p in paths if p in requires and p not in provides]
        ordered = sinks + [p for p in paths if p not in sinks]
        out.extend(
            Site(_slug(p), (p,), f"{'sink ' if p in sinks else ''}{p}") for p in ordered
        )
    return out


def _edit_remove_component(root: etree._Element, site: Site) -> str:
    """Delete a component, its connectors and its ECU mapping entry."""
    victim = site.args[0]
    element = _find(root, victim, "SW-COMPONENT-PROTOTYPE")
    if element is None:
        raise NotApplicable(f"{victim} is no longer in the before")
    holder = element.getparent()
    if len(holder) < 2:
        raise NotApplicable("refusing to empty the composition")

    holder.remove(element)
    dropped = 0
    for conn in _assembly_connectors(root):
        ends = _endpoints(conn)
        if ends and victim in (ends[0], ends[2]):
            conn.getparent().remove(conn)
            dropped += 1
    for _, irefs in _ecu_mappings(root):
        for iref in irefs:
            if _text(iref, "TARGET-COMPONENT-REF") == victim:
                iref.getparent().remove(iref)
    return f"removed component {victim} and {dropped} connector(s) referencing it"


def _edit_weaken_freshness(root: etree._Element, site: Site) -> str:
    """Keep the SecOC wrapper, gut its replay protection."""
    secured = _secured_elements(root, site)
    for el in secured:
        for tag, value in (
            ("FRESHNESS-VALUE-LENGTH", "0"),
            ("FRESHNESS-VALUE-ID", "0"),
            ("AUTH-INFO-TX-LENGTH", "8"),
        ):
            child = _child(el, tag)
            if child is None:
                el.insert(1, _make(root, tag, value))
            else:
                child.text = value
    return f"set freshness to 0 bits and the MAC to 8 bits on {len(secured)} SECURED-I-PDU(s)"


# -- benign edits ---------------------------------------------------------------


def _edit_reorder(root: etree._Element, site: Site) -> str:
    """Reverse every COMPONENTS and CONNECTORS list. Document order is not identity."""
    touched = 0
    for holder in _iter(root, "COMPONENTS", "CONNECTORS"):
        children = list(holder)
        if len(children) < 2:
            continue
        for child in reversed(children):
            holder.append(child)  # append moves, so this reverses in place
        touched += 1
    if not touched:
        raise NotApplicable("nothing in the before has two siblings to reorder")
    return f"reversed the child order of {touched} list(s)"


def _connector_sites(root: etree._Element) -> list[Site]:
    return [
        Site(_slug(_ar_path(c)), (_ar_path(c),), f"connector {_short(c)}")
        for c in _assembly_connectors(root)
    ]


def _edit_rename_connector(root: etree._Element, site: Site) -> str:
    conn = _find(root, site.args[0], "ASSEMBLY-SW-CONNECTOR")
    if conn is None:
        raise NotApplicable(f"no connector at {site.args[0]}")
    before = _short(conn)
    _child(conn, "SHORT-NAME").text = _unique(root, f"{before}Link")
    return f"renamed connector {before} to {_short(conn)}, endpoints untouched"


def _edit_rename_secured_pdu(root: etree._Element, site: Site) -> str:
    """Rename the wrapper, not the payload it points at.

    Checks that the SecOC join is keyed on PAYLOAD-REF. Keyed on the wrapper's own
    name instead, this edit would read as protection removed and re-added.
    """
    renamed = []
    for el in _secured_elements(root, site):
        before = _short(el)
        _child(el, "SHORT-NAME").text = _unique(root, f"{before}Rev2")
        renamed.append(f"{before} to {_short(el)}")
    return f"renamed {', '.join(renamed)}, PAYLOAD-REF untouched"


def _edit_add_uuids(root: etree._Element, site: Site) -> str:
    """Stamp UUIDs on identifiable elements. Derived from the path, so reproducible."""
    stamped = 0
    for el in root.iter():
        if not isinstance(el.tag, str) or _short(el) is None or el.get("UUID"):
            continue
        digest = hashlib.md5(_ar_path(el).encode()).hexdigest()
        el.set(
            "UUID",
            f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}",
        )
        stamped += 1
    if not stamped:
        raise NotApplicable("every identifiable element already carries a UUID")
    return f"stamped a UUID on {stamped} element(s)"


def _edit_add_unrelated_package(root: etree._Element, site: Site) -> str:
    packages = _child(root, "AR-PACKAGES")
    if packages is None:
        raise NotApplicable("before has no AR-PACKAGES")
    package = _identified(root, "AR-PACKAGE", _unique(root, "Unreferenced"))
    elements = _make(root, "ELEMENTS")
    interface = _identified(root, "SENDER-RECEIVER-INTERFACE", _unique(root, "SpareIf"))
    data = _make(root, "DATA-ELEMENTS")
    data.append(_identified(root, "VARIABLE-DATA-PROTOTYPE", _unique(root, "spare")))
    interface.append(data)
    elements.append(interface)
    package.append(elements)
    packages.append(package)
    return f"added package {_ar_path(package)}, referenced by nothing"


def _edit_keep_whitespace_only(root: etree._Element, site: Site) -> str:
    """No tree change: the mutant is written unindented instead.

    Byte-different, semantically identical — which is the only interesting property
    here, and it needs no edit at all.
    """
    return "reserialised without indentation, content unchanged"


# -- the families ---------------------------------------------------------------

STRIP_SECOC = Family(
    name="strip-secoc",
    kind=REGRESSION,
    description="Delete a SECURED-I-PDU, leaving its payload on the bus unauthenticated",
    sites=_secured_sites,
    edit=_edit_strip_secoc,
    expected=(Expectation(findings_mod.SECOC_REMOVED),),
    forbidden=(
        findings_mod.NEWLY_REACHABLE,
        findings_mod.NEWLY_BUS_VISIBLE,
        findings_mod.REHOSTED,
        findings_mod.NOT_ANALYSED,
    ),
)

BYPASS = Family(
    name="bypass",
    kind=REGRESSION,
    description="Connect a compatible port pair nobody had wired, completing a new route",
    sites=_bypass_sites,
    edit=_edit_bypass,
    expected=(Expectation(findings_mod.NEWLY_REACHABLE),),
    forbidden=(
        findings_mod.SECOC_REMOVED,
        # The new hop carries no PDU, so calling it unauthenticated would be wrong.
        findings_mod.UNPROTECTED_NEW_HOP,
        findings_mod.NEWLY_BUS_VISIBLE,
        findings_mod.NOT_ANALYSED,
    ),
)

REHOST = Family(
    name="rehost",
    kind=REGRESSION,
    description="Move a component to another ECU without touching the software architecture",
    sites=_rehost_sites,
    edit=_edit_rehost,
    expected=(Expectation(findings_mod.REHOSTED),),
    forbidden=(
        # The moved component's connectors now cross an ECU boundary, but no data
        # mapping puts them on a wire, so SecOC remains inapplicable. Reporting
        # missing authentication here is the false positive this tool exists to
        # avoid, and it is the reason `authenticated` is three-valued.
        findings_mod.UNPROTECTED_NEW_HOP,
        findings_mod.SECOC_REMOVED,
        findings_mod.NEWLY_BUS_VISIBLE,
        findings_mod.NOT_ANALYSED,
    ),
)

EXPOSE_ON_BUS = Family(
    name="expose-on-bus",
    kind=REGRESSION,
    description="Give a cross-ECU connector a signal, an I-PDU and no SecOC wrapper",
    edit=_edit_expose_on_bus,
    expected=(Expectation(findings_mod.UNPROTECTED_NEW_HOP),),
    forbidden=(findings_mod.SECOC_REMOVED, findings_mod.NOT_ANALYSED),
)

ADD_COMPONENT = Family(
    name="add-component",
    kind=REGRESSION,
    description="Add an isolated component with no ports and no connectors",
    sites=_composition_sites,
    edit=_edit_add_component,
    expected=(Expectation(findings_mod.COMPONENT_ADDED),),
    forbidden=(
        # Nothing is wired to it, so it cannot create a route or a bus hop.
        findings_mod.NEWLY_REACHABLE,
        findings_mod.UNPROTECTED_NEW_HOP,
        findings_mod.SECOC_REMOVED,
        findings_mod.NOT_ANALYSED,
    ),
)

REMOVE_COMPONENT = Family(
    name="remove-component",
    kind=REGRESSION,
    description="Delete a component along with its connectors and ECU mapping",
    sites=_removable_sites,
    edit=_edit_remove_component,
    expected=(Expectation(findings_mod.COMPONENT_REMOVED),),
    forbidden=(
        findings_mod.NEWLY_REACHABLE,
        findings_mod.UNPROTECTED_NEW_HOP,
        findings_mod.SECOC_REMOVED,
    ),
)

WEAKEN_FRESHNESS = Family(
    name="weaken-freshness",
    kind=KNOWN_GAP,
    description="Keep the SECURED-I-PDU but cut freshness to 0 bits and the MAC to 8",
    sites=_secured_sites,
    edit=_edit_weaken_freshness,
    gap=(
        "SecOC is read as a boolean: the presence of a SECURED-I-PDU wrapper makes the "
        "PDU authenticated regardless of its parameters, so a replayable 8-bit MAC "
        "scores the same as a sound configuration. The parameter change does reach the "
        "SecOC profile diff and is printed in the report, but it produces no finding "
        "and so can neither be scored nor gated on. Closing this needs a strength "
        "judgement in severity.py, not a parser change."
    ),
)

REORDER = Family(
    name="reorder",
    kind=BENIGN,
    description="Reverse the order of every COMPONENTS and CONNECTORS list",
    edit=_edit_reorder,
)

RENAME_CONNECTOR = Family(
    name="rename-connector",
    kind=BENIGN,
    description="Rename a connector without moving either endpoint",
    sites=_connector_sites,
    edit=_edit_rename_connector,
)

RENAME_SECURED_PDU = Family(
    name="rename-secured-pdu",
    kind=BENIGN,
    description="Rename a SECURED-I-PDU, leaving PAYLOAD-REF pointing at the same payload",
    sites=_secured_sites,
    edit=_edit_rename_secured_pdu,
)

ADD_UUIDS = Family(
    name="add-uuids",
    kind=BENIGN,
    description="Stamp UUID attributes on every identifiable element",
    edit=_edit_add_uuids,
)

ADD_UNRELATED_PACKAGE = Family(
    name="add-unrelated-package",
    kind=BENIGN,
    description="Add a package holding an interface nothing references",
    edit=_edit_add_unrelated_package,
)

REFORMAT = Family(
    name="reformat",
    kind=BENIGN,
    description="Reserialise the same content without indentation",
    edit=_edit_keep_whitespace_only,
    pretty=False,
)

#: Every family, regressions first. `expand` walks this in order.
FAMILIES: tuple[Family, ...] = (
    STRIP_SECOC,
    BYPASS,
    REHOST,
    EXPOSE_ON_BUS,
    ADD_COMPONENT,
    REMOVE_COMPONENT,
    WEAKEN_FRESHNESS,
    REORDER,
    RENAME_CONNECTOR,
    RENAME_SECURED_PDU,
    ADD_UUIDS,
    ADD_UNRELATED_PACKAGE,
    REFORMAT,
)

BY_FAMILY = {f.name: f for f in FAMILIES}

#: Benign families, used as the noise layer over every regression.
NOISE: tuple[Family, ...] = tuple(f for f in FAMILIES if f.kind == BENIGN)


# -- composition templates ------------------------------------------------------
#
# Each entry names the families to apply in order and the label the pair carries.
# The overrides are the interesting part: a category one half forbids is often
# exactly what the other half introduces, and `combine` needs telling which.

_TEMPLATES: tuple[dict, ...] = (
    {
        "name": "rehost-onto-bus",
        "description": (
            "Move a component to another ECU and put its previously RTE-local data "
            "on the wire"
        ),
        "families": ("rehost", "expose-on-bus"),
        "expected": (
            Expectation(findings_mod.REHOSTED),
            Expectation(findings_mod.NEWLY_BUS_VISIBLE),
            Expectation(findings_mod.UNPROTECTED_NEW_HOP),
        ),
    },
    {
        "name": "bypass-on-bus",
        "description": "Add a new route and carry it over an unauthenticated bus",
        "families": ("bypass", "expose-on-bus"),
        "expected": (
            Expectation(findings_mod.NEWLY_REACHABLE),
            Expectation(findings_mod.UNPROTECTED_NEW_HOP),
        ),
        # A brand-new connector is added, not modified, so it is new exposure rather
        # than *newly* bus-visible. Keeping the two apart is what makes the categories
        # actionable.
        "forbidden": (findings_mod.NEWLY_BUS_VISIBLE, findings_mod.SECOC_REMOVED),
    },
    {
        "name": "bypass-and-strip-secoc",
        "description": (
            "Two independent regressions in one release, as an OTA update plausibly "
            "ships them"
        ),
        "families": ("bypass", "strip-secoc"),
        "expected": (
            Expectation(findings_mod.NEWLY_REACHABLE),
            Expectation(findings_mod.SECOC_REMOVED),
        ),
    },
    {
        "name": "rehost-and-strip-secoc",
        "description": "Move a component and drop protection from an existing bus PDU",
        "families": ("rehost", "strip-secoc"),
        "expected": (
            Expectation(findings_mod.REHOSTED),
            Expectation(findings_mod.SECOC_REMOVED),
        ),
    },
    {
        "name": "bypass-and-rehost",
        "description": "Add a route and move one of its components to another ECU",
        "families": ("bypass", "rehost"),
        "expected": (
            Expectation(findings_mod.NEWLY_REACHABLE),
            Expectation(findings_mod.REHOSTED),
        ),
    },
    {
        "name": "remove-and-strip-secoc",
        "description": "Delete a component while dropping protection elsewhere",
        "families": ("remove-component", "strip-secoc"),
        "expected": (
            Expectation(findings_mod.COMPONENT_REMOVED),
            Expectation(findings_mod.SECOC_REMOVED),
        ),
    },
    {
        "name": "add-and-bypass",
        "description": "Add a component and wire a new route in the same release",
        "families": ("add-component", "bypass"),
        "expected": (
            Expectation(findings_mod.COMPONENT_ADDED),
            Expectation(findings_mod.NEWLY_REACHABLE),
        ),
    },
    {
        "name": "bypass-on-bus-and-strip-secoc",
        "description": (
            "A new unauthenticated bus route shipped alongside protection removed "
            "from an old one"
        ),
        "families": ("bypass", "expose-on-bus", "strip-secoc"),
        "expected": (
            Expectation(findings_mod.NEWLY_REACHABLE),
            Expectation(findings_mod.UNPROTECTED_NEW_HOP),
            Expectation(findings_mod.SECOC_REMOVED),
        ),
        "forbidden": (findings_mod.NEWLY_BUS_VISIBLE,),
    },
    {
        "name": "rehost-onto-bus-and-bypass",
        "description": "A rehost that exposes a bus, plus an unrelated new route",
        "families": ("rehost", "expose-on-bus", "bypass"),
        "expected": (
            Expectation(findings_mod.REHOSTED),
            Expectation(findings_mod.NEWLY_BUS_VISIBLE),
            Expectation(findings_mod.UNPROTECTED_NEW_HOP),
            Expectation(findings_mod.NEWLY_REACHABLE),
        ),
    },
    {
        "name": "weaken-and-reorder",
        "description": "Gut replay protection under cosmetic churn",
        "families": ("weaken-freshness", "reorder"),
    },
    {
        "name": "strip-and-rename",
        "description": "Drop one wrapper and rename another, so the diff looks like churn",
        "families": ("strip-secoc", "rename-connector"),
        "expected": (Expectation(findings_mod.SECOC_REMOVED),),
    },
)

#: Combinations generated per template. A cross product over sites grows fast, and
#: past a couple of dozen the extra pairs measure the same interaction again.
_PER_TEMPLATE = 24


# -- expansion ------------------------------------------------------------------


def _shorten(name: str, limit: int = 96) -> str:
    """Keep case names usable as file names without losing uniqueness."""
    if len(name) <= limit:
        return name
    digest = hashlib.md5(name.encode()).hexdigest()[:8]
    return f"{name[: limit - 9]}-{digest}"


def _named(mutations: Iterable[Mutation]) -> list[Mutation]:
    """Shorten names and force them apart, since each becomes a file."""
    out: list[Mutation] = []
    taken: set[str] = set()
    for mutation in mutations:
        name = _shorten(mutation.name)
        if name in taken:
            for n in range(2, 1000):
                if (candidate := _shorten(f"{name}-{n}")) not in taken:
                    name = candidate
                    break
        taken.add(name)
        out.append(mutation if name == mutation.name else replace(mutation, name=name))
    return out


def _template_cases(single: dict[str, list[Mutation]]) -> list[Mutation]:
    """Every template, over the cross product of its families' sites."""
    out: list[Mutation] = []
    for spec in _TEMPLATES:
        pools = [single.get(f, []) for f in spec["families"]]
        if not all(pools):
            continue  # a family with no site in this before cancels its templates
        overrides = {k: v for k, v in spec.items() if k in ("expected", "forbidden", "gap")}
        combos = [()]
        for pool in pools:
            combos = [combo + (m,) for combo in combos for m in pool][: _PER_TEMPLATE * 4]
        for combo in combos[:_PER_TEMPLATE]:
            suffix = "__".join(
                m.name.split("__", 1)[1] for m in combo if "__" in m.name
            )
            out.append(
                combine(
                    f"{spec['name']}__{suffix}" if suffix else spec["name"],
                    spec["description"],
                    *combo,
                    **overrides,
                )
            )
    return out


def _noise_cases(targets: Sequence[Mutation], single: dict[str, list[Mutation]]) -> list[Mutation]:
    """Every target shipped alongside one benign edit, keeping the target's label.

    Sites are cycled rather than crossed: pairing the i-th regression site with the
    i-th benign site covers every regression site without multiplying the corpus by
    the benign ones, which would add length without adding discrimination.
    """
    out: list[Mutation] = []
    for family in NOISE:
        pool = single.get(family.name, [])
        if not pool:
            continue
        for index, target in enumerate(targets):
            noise = pool[index % len(pool)]
            out.append(
                combine(
                    f"{target.name}+{family.name}",
                    f"{target.description}, shipped with cosmetic churn: {family.description}",
                    target,
                    noise,
                    expected=target.expected,
                    forbidden=target.forbidden,
                    gap=target.gap,
                    kind=target.kind,
                )
            )
    return out


def _benign_combos(single: dict[str, list[Mutation]]) -> list[Mutation]:
    """Several cosmetic edits at once. Still benign, and still must report nothing.

    Generated to depth three, and across every site, because the false-positive rate
    is measured on these and a handful of controls cannot measure a rate. A release
    that only renames, reorders and reformats is the commonest kind there is, and the
    combinations are where a detector keyed on the wrong thing gives itself away.
    """
    out: list[Mutation] = []
    pools = [(f, single.get(f.name, [])) for f in NOISE]
    pools = [(f, pool) for f, pool in pools if pool]
    for i, (first, left) in enumerate(pools):
        for j in range(i + 1, len(pools)):
            second, mid = pools[j]
            for a in left:
                for b in mid:
                    out.append(
                        combine(
                            f"{a.name}+{b.name}",
                            f"{first.description}; {second.description}",
                            a,
                            b,
                        )
                    )
            for third, right in pools[j + 1 :]:
                out.append(
                    combine(
                        f"{left[0].name}+{mid[0].name}+{right[0].name}",
                        f"{first.description}; {second.description}; {third.description}",
                        left[0],
                        mid[0],
                        right[0],
                    )
                )
    return out


def _fill(base: list[Mutation], extra: list[Mutation], target: int | None, seed: int):
    """Take `target` cases without letting one kind crowd the others out.

    Single-site cases are never dropped: they are the coverage claim, and a corpus
    that hit its size by discarding the benign controls would report a false-positive
    rate of zero for the wrong reason. The remainder is filled round-robin by kind
    from a seeded shuffle, so the same seed gives the same corpus.
    """
    if target is None:
        return base + extra
    if len(base) >= target:
        return base
    buckets: dict[str, list[Mutation]] = {}
    for mutation in extra:
        buckets.setdefault(mutation.kind, []).append(mutation)
    rng = random.Random(seed)
    for group in buckets.values():
        rng.shuffle(group)

    out = list(base)
    order = (REGRESSION, BENIGN, KNOWN_GAP)
    while len(out) < target and any(buckets.get(k) for k in order):
        for kind in order:
            if len(out) >= target:
                break
            if buckets.get(kind):
                out.append(buckets[kind].pop())
    return out


def expand(
    root: etree._Element,
    target: int | None = None,
    seed: int = 0,
    families: Sequence[Family] = FAMILIES,
    noise: bool = True,
    compose: bool = True,
) -> list[Mutation]:
    """Every labelled mutation this before supports, up to `target` of them.

    `target` is a ceiling, not a quota: a four-component before cannot be stretched
    to five hundred distinct cases, and padding it with repeats would inflate the
    denominator of every metric computed from it.
    """
    single = {f.name: f.mutations(root) for f in families}
    base = [m for f in families for m in single[f.name]]

    extra: list[Mutation] = []
    if compose:
        extra.extend(_template_cases(single))
    if noise:
        regressions = [m for m in base if m.kind != BENIGN]
        extra.extend(_noise_cases(regressions + list(extra), single))
        extra.extend(_benign_combos(single))

    return _named(_fill(base, extra, target, seed))


# -- applying and generating ----------------------------------------------------


def _parse(source: str | Path) -> etree._ElementTree:
    parser = etree.XMLParser(remove_blank_text=True, remove_comments=False, huge_tree=True)
    return etree.parse(str(source), parser)


#: The fifteen canonical single-site cases, named. The write-up, the case study and
#: the naive-diff comparison all refer to these by name, so they keep their names
#: even as `expand` generates hundreds more around them.
CATALOGUE: tuple[Mutation, ...] = (
    STRIP_SECOC.first(),
    BYPASS.first(),
    REHOST.first(),
    ADD_COMPONENT.first(),
    REMOVE_COMPONENT.first(),
    combine(
        "rehost-onto-bus",
        _TEMPLATES[0]["description"],
        REHOST.first(),
        EXPOSE_ON_BUS.first(),
        expected=_TEMPLATES[0]["expected"],
    ),
    combine(
        "bypass-on-bus",
        _TEMPLATES[1]["description"],
        BYPASS.first(),
        EXPOSE_ON_BUS.first(),
        expected=_TEMPLATES[1]["expected"],
        forbidden=_TEMPLATES[1]["forbidden"],
    ),
    combine(
        "bypass-and-strip-secoc",
        _TEMPLATES[2]["description"],
        BYPASS.first(),
        STRIP_SECOC.first(),
        expected=_TEMPLATES[2]["expected"],
    ),
    REORDER.first(),
    RENAME_CONNECTOR.first(),
    RENAME_SECURED_PDU.first(),
    ADD_UUIDS.first(),
    ADD_UNRELATED_PACKAGE.first(),
    REFORMAT.first(),
    WEAKEN_FRESHNESS.first(),
)

BY_NAME = {m.name: m for m in CATALOGUE}


def apply(
    mutation: Mutation | Sequence[Mutation], source: str | Path, destination: str | Path
) -> tuple[str, ...]:
    """Apply `mutation` to `source` and write the result to `destination`.

    Returns each mutation's note. Raises `NotApplicable` without writing anything,
    so a partly-mutated tree can never reach the corpus.
    """
    mutations = (mutation,) if isinstance(mutation, Mutation) else tuple(mutation)
    tree = _parse(source)
    root = tree.getroot()
    notes = tuple(m.transform(root) for m in mutations)
    pretty = all(m.pretty for m in mutations)

    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tree.write(str(dest), xml_declaration=True, encoding="UTF-8", pretty_print=pretty)
    return notes


@dataclass(frozen=True)
class Case:
    """One labelled before/after pair on disk."""

    name: str
    kind: str
    description: str
    before: Path
    updated: Path
    expected: tuple[Expectation, ...] = ()
    forbidden: tuple[str, ...] = ()
    gap: str = ""
    notes: tuple[str, ...] = ()
    order: int = 1

    @property
    def benign(self) -> bool:
        return self.kind == BENIGN

    @property
    def known_gap(self) -> bool:
        return self.kind == KNOWN_GAP

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "order": self.order,
            "description": self.description,
            "before": str(self.before),
            "updated": str(self.updated),
            "expected": [str(e) for e in self.expected],
            "forbidden": list(self.forbidden),
            "gap": self.gap,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class Corpus:
    """Generated cases, plus the mutations that did not fit this before."""

    before: Path
    cases: tuple[Case, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()

    def __len__(self) -> int:
        return len(self.cases)

    def by_kind(self, kind: str) -> tuple[Case, ...]:
        return tuple(c for c in self.cases if c.kind == kind)

    def as_dict(self) -> dict:
        return {
            "before": str(self.before),
            "counts": {
                kind: len(self.by_kind(kind)) for kind in (REGRESSION, BENIGN, KNOWN_GAP)
            },
            "cases": [c.as_dict() for c in self.cases],
            # Recorded, never silent: a mutation that could not be applied is
            # coverage this run did not have, and reads as a pass if it is hidden.
            "skipped": [{"mutation": n, "reason": r} for n, r in self.skipped],
        }


def generate(
    source: str | Path,
    out_dir: str | Path,
    mutations: Sequence[Mutation] | None = None,
    manifest: bool = True,
    target: int | None = None,
    seed: int = 0,
    **expand_kwargs,
) -> Corpus:
    """Write a labelled corpus derived from one before.

    The before is reparsed and rewritten rather than copied, so both sides of every
    pair share one formatting convention and no diff can be an artefact of layout.

    With `mutations` left unset the catalogue is expanded against this before —
    every site of every family, the composition templates, and each regression under
    benign churn. Pass an explicit sequence (`CATALOGUE`, say) to pin the corpus.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    before = out / "before.arxml"
    tree = _parse(source)
    tree.write(str(before), xml_declaration=True, encoding="UTF-8", pretty_print=True)

    if mutations is None:
        mutations = expand(_parse(before).getroot(), target=target, seed=seed, **expand_kwargs)

    cases: list[Case] = []
    skipped: list[tuple[str, str]] = []
    for mutation in mutations:
        updated = out / f"{mutation.name}.arxml"
        try:
            notes = apply(mutation, before, updated)
        except NotApplicable as exc:
            skipped.append((mutation.name, str(exc)))
            continue
        cases.append(
            Case(
                name=mutation.name,
                kind=mutation.kind,
                description=mutation.description,
                before=before,
                updated=updated,
                expected=mutation.expected,
                forbidden=mutation.forbidden,
                gap=mutation.gap,
                notes=notes,
                order=mutation.order,
            )
        )

    corpus = Corpus(before=before, cases=tuple(cases), skipped=tuple(skipped))
    if manifest:
        (out / "manifest.json").write_text(json.dumps(corpus.as_dict(), indent=2) + "\n")
    return corpus
