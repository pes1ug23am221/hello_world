"""Extract the AUTOSAR software architecture from a set of ARXML files.

Two things drive the design here:

1. **The unit of work is a package set, not a file.**  References cross file
   boundaries as a matter of course (a port's ``TYPE-TREF`` routinely resolves
   into a vendor platform-types file), so every file is folded into one shared
   ``path -> element`` index before anything is interpreted.  Refs that still do
   not resolve are recorded rather than raised.

2. **Paths are built by generic recursion.**  Any element carrying a SHORT-NAME
   contributes a segment, whether it is a package, a component type, a port, or
   a connector.  That is exactly how AUTOSAR forms the absolute paths used by
   ``*-REF`` elements, so the index keys match reference bodies verbatim.
"""

from __future__ import annotations

from pathlib import Path

from lxml import etree

from . import ecu, signals, xmlutil
from .model import (
    AssemblyConnector,
    ComponentType,
    DelegationConnector,
    Model,
    Port,
    PortInterface,
    Prototype,
)

COMPONENT_CATEGORIES = {
    "APPLICATION-SW-COMPONENT-TYPE": "APPLICATION",
    "SERVICE-SW-COMPONENT-TYPE": "SERVICE",
    "COMPOSITION-SW-COMPONENT-TYPE": "COMPOSITION",
    "SENSOR-ACTUATOR-SW-COMPONENT-TYPE": "SENSOR-ACTUATOR",
    "COMPLEX-DEVICE-DRIVER-SW-COMPONENT-TYPE": "COMPLEX-DEVICE-DRIVER",
    "ECU-ABSTRACTION-SW-COMPONENT-TYPE": "ECU-ABSTRACTION",
    "NV-BLOCK-SW-COMPONENT-TYPE": "NV-BLOCK",
    "PARAMETER-SW-COMPONENT-TYPE": "PARAMETER",
    "SERVICE-PROXY-SW-COMPONENT-TYPE": "SERVICE-PROXY",
}

PORT_KINDS = {
    "P-PORT-PROTOTYPE": "P",
    "R-PORT-PROTOTYPE": "R",
    "PR-PORT-PROTOTYPE": "PR",
}

# Which TREF names the interface, per port kind.
INTERFACE_TREF = {
    "P": "PROVIDED-INTERFACE-TREF",
    "R": "REQUIRED-INTERFACE-TREF",
    "PR": "PROVIDED-REQUIRED-INTERFACE-TREF",
}

INTERFACE_KINDS = {
    "SENDER-RECEIVER-INTERFACE": "SENDER-RECEIVER",
    "CLIENT-SERVER-INTERFACE": "CLIENT-SERVER",
    "MODE-SWITCH-INTERFACE": "MODE-SWITCH",
    "NV-DATA-INTERFACE": "NV-DATA",
    "PARAMETER-INTERFACE": "PARAMETER",
    "TRIGGER-INTERFACE": "TRIGGER",
}

INTERFACE_MEMBERS = {
    "SENDER-RECEIVER": "DATA-ELEMENTS/VARIABLE-DATA-PROTOTYPE",
    "CLIENT-SERVER": "OPERATIONS/CLIENT-SERVER-OPERATION",
}


def build_index(
    element: etree._Element,
    index: dict[str, etree._Element] | None = None,
    prefix: str = "",
) -> dict[str, etree._Element]:
    """Map every identifiable element to its absolute AUTOSAR path."""
    if index is None:
        index = {}
    for child in element:
        if not isinstance(child.tag, str) or child.tag == "SHORT-NAME":
            continue
        name = xmlutil.short_name(child)
        if name:
            path = f"{prefix}/{name}"
            index[path] = child
            build_index(child, index, path)
        else:
            # Wrapper elements (AR-PACKAGES, ELEMENTS, PORTS, ...) add no segment.
            build_index(child, index, prefix)
    return index


def parse(sources: list[str | Path]) -> Model:
    """Parse an explicit list of ARXML files into one model."""
    index: dict[str, etree._Element] = {}
    for _, root in xmlutil.load_paths(list(sources)):
        build_index(root, index)
    return from_index(index)


def parse_dir(directory: str | Path) -> Model:
    """Parse every .arxml under `directory` into one model."""
    return parse(list(xmlutil.discover(directory)))


def from_index(index: dict[str, etree._Element]) -> Model:
    """Interpret a prebuilt path index."""
    model = Model()

    for path, el in index.items():
        if el.tag in COMPONENT_CATEGORIES:
            model.component_types[path] = _component_type(path, el)
        elif el.tag in INTERFACE_KINDS:
            model.interfaces[path] = _interface(path, el)

    # Prototypes and connectors only exist inside compositions, so this pass
    # runs after component types are known.
    for path, el in index.items():
        if el.tag == "COMPOSITION-SW-COMPONENT-TYPE":
            _composition_contents(path, el, model)

    model.index = index
    ecu.extract(index, model)
    signals.extract(index, model)
    _record_unresolved(model)
    return model


def _component_type(path: str, el: etree._Element) -> ComponentType:
    component = ComponentType(
        path=path,
        short_name=xmlutil.short_name(el) or "",
        category=COMPONENT_CATEGORIES[el.tag],
    )
    for port_el in el.findall("PORTS/*"):
        kind = PORT_KINDS.get(port_el.tag)
        name = xmlutil.short_name(port_el)
        if kind is None or not name:
            continue
        tref = INTERFACE_TREF[kind]
        port_path = f"{path}/{name}"
        component.ports[port_path] = Port(
            path=port_path,
            short_name=name,
            kind=kind,
            interface_ref=xmlutil.ref(port_el, tref),
            interface_dest=xmlutil.ref_dest(port_el, tref),
            owner=path,
        )
    return component


def _interface(path: str, el: etree._Element) -> PortInterface:
    kind = INTERFACE_KINDS[el.tag]
    member_xpath = INTERFACE_MEMBERS.get(kind)
    members: tuple[str, ...] = ()
    if member_xpath:
        members = tuple(
            name
            for name in (xmlutil.short_name(m) for m in el.findall(member_xpath))
            if name
        )
    return PortInterface(
        path=path,
        short_name=xmlutil.short_name(el) or "",
        kind=kind,
        members=members,
    )


def _composition_contents(comp_path: str, el: etree._Element, model: Model) -> None:
    for proto_el in el.findall("COMPONENTS/SW-COMPONENT-PROTOTYPE"):
        name = xmlutil.short_name(proto_el)
        if not name:
            continue
        proto_path = f"{comp_path}/{name}"
        model.prototypes[proto_path] = Prototype(
            path=proto_path,
            short_name=name,
            type_ref=xmlutil.ref(proto_el, "TYPE-TREF") or "",
            composition=comp_path,
        )

    for conn_el in el.findall("CONNECTORS/*"):
        name = xmlutil.short_name(conn_el)
        if not name:
            continue
        conn_path = f"{comp_path}/{name}"
        if conn_el.tag == "ASSEMBLY-SW-CONNECTOR":
            model.assembly_connectors[conn_path] = _assembly(
                conn_path, name, comp_path, conn_el
            )
        elif conn_el.tag == "DELEGATION-SW-CONNECTOR":
            model.delegation_connectors[conn_path] = _delegation(
                conn_path, name, comp_path, conn_el
            )


def _assembly(
    path: str, name: str, comp_path: str, el: etree._Element
) -> AssemblyConnector:
    provider = el.find("PROVIDER-IREF")
    requester = el.find("REQUESTER-IREF")
    return AssemblyConnector(
        path=path,
        short_name=name,
        composition=comp_path,
        provider_component=(
            xmlutil.ref(provider, "CONTEXT-COMPONENT-REF")
            if provider is not None
            else None
        ),
        provider_port=(
            xmlutil.ref(provider, "TARGET-P-PORT-REF") if provider is not None else None
        ),
        requester_component=(
            xmlutil.ref(requester, "CONTEXT-COMPONENT-REF")
            if requester is not None
            else None
        ),
        requester_port=(
            xmlutil.ref(requester, "TARGET-R-PORT-REF")
            if requester is not None
            else None
        ),
    )


def _delegation(
    path: str, name: str, comp_path: str, el: etree._Element
) -> DelegationConnector:
    inner = el.find("INNER-PORT-IREF")
    inner_component = inner_port = inner_kind = None
    if inner is not None:
        # The inner endpoint is wrapped in a kind-specific instance ref.
        for tag, kind, target in (
            ("P-PORT-IN-COMPOSITION-INSTANCE-REF", "P", "TARGET-P-PORT-REF"),
            ("R-PORT-IN-COMPOSITION-INSTANCE-REF", "R", "TARGET-R-PORT-REF"),
        ):
            wrapper = inner.find(tag)
            if wrapper is None:
                continue
            inner_kind = kind
            inner_component = xmlutil.ref(wrapper, "CONTEXT-COMPONENT-REF")
            inner_port = xmlutil.ref(wrapper, target)
            break
    return DelegationConnector(
        path=path,
        short_name=name,
        composition=comp_path,
        inner_component=inner_component,
        inner_port=inner_port,
        inner_kind=inner_kind,
        outer_port=xmlutil.ref(el, "OUTER-PORT-REF"),
    )


def _record_unresolved(model: Model) -> None:
    """Note references that point outside this package set.

    Dangling refs are expected (platform types live in vendor files), so they are
    reported for triage instead of aborting the parse.
    """
    for proto in model.prototypes.values():
        if proto.type_ref and proto.type_ref not in model.component_types:
            model.unresolved_refs.append((proto.path, proto.type_ref))
    for component in model.component_types.values():
        for port in component.ports.values():
            if port.interface_ref and port.interface_ref not in model.interfaces:
                model.unresolved_refs.append((port.path, port.interface_ref))
    for conn in model.assembly_connectors.values():
        for endpoint in (conn.provider_component, conn.requester_component):
            if endpoint and endpoint not in model.prototypes:
                model.unresolved_refs.append((conn.path, endpoint))
