"""Typed view of the ARXML elements this tool cares about.

Everything is keyed by AUTOSAR path (the absolute slash-delimited form used by
``*-REF`` elements, e.g. ``/Demo/EDC/EDC/DoorLeft``) so that references resolve
across the whole package set rather than within a single file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Interface kinds whose data flow direction we model explicitly.
SENDER_RECEIVER = "SENDER-RECEIVER"
CLIENT_SERVER = "CLIENT-SERVER"


@dataclass(frozen=True)
class Port:
    """A P-/R-/PR-PORT-PROTOTYPE declared on a component *type*."""

    path: str
    short_name: str
    kind: str  # "P" (provided), "R" (required), "PR" (provided-required)
    interface_ref: str | None
    interface_dest: str | None
    owner: str  # component type path


@dataclass(frozen=True)
class PortInterface:
    path: str
    short_name: str
    kind: str  # SENDER_RECEIVER, CLIENT_SERVER, MODE-SWITCH, ...
    members: tuple[str, ...] = ()  # data element / operation short names


@dataclass(frozen=True)
class EcuInstance:
    """A physical ECU from the topology description.

    Absent from an ECU extract by construction: that artifact is already scoped
    to a single ECU, so it has no reason to name one. Populating `host` therefore
    requires a System Description or System Extract.
    """

    path: str
    short_name: str
    comm_connectors: tuple[str, ...] = ()  # this ECU's communication connectors


@dataclass
class ComponentType:
    """An *-SW-COMPONENT-TYPE: the reusable definition, not an instance."""

    path: str
    short_name: str
    category: str  # APPLICATION, SERVICE, COMPOSITION, SENSOR-ACTUATOR, ...
    ports: dict[str, Port] = field(default_factory=dict)  # keyed by port path

    @property
    def is_composition(self) -> bool:
        return self.category == "COMPOSITION"


@dataclass(frozen=True)
class Prototype:
    """A SW-COMPONENT-PROTOTYPE: one *instance* of a type inside a composition.

    This — not the type — is the unit of graph identity.  A type instantiated
    twice (two doors, four wheels) must stay two nodes, or reachability analysis
    invents paths between siblings that share nothing in the real vehicle.
    """

    path: str
    short_name: str
    type_ref: str
    composition: str


@dataclass(frozen=True)
class AssemblyConnector:
    """Wires a provided port on one prototype to a required port on another.

    The IREFs are asymmetric in a way worth remembering: the *context* points at
    the component prototype (the instance), while the *target* points at the port
    owned by the component type.
    """

    path: str
    short_name: str
    composition: str
    provider_component: str | None
    provider_port: str | None
    requester_component: str | None
    requester_port: str | None


@dataclass(frozen=True)
class DelegationConnector:
    """Wires a composition's own boundary port to a port on an inner prototype.

    Ignoring these breaks every reachability path that crosses a composition
    boundary, which in an ECU extract includes the ECU boundary itself.
    """

    path: str
    short_name: str
    composition: str
    inner_component: str | None
    inner_port: str | None
    inner_kind: str | None  # "P" or "R"
    outer_port: str | None


@dataclass(frozen=True)
class SystemSignal:
    path: str
    short_name: str


@dataclass(frozen=True)
class ISignal:
    path: str
    short_name: str
    system_signal: str | None


@dataclass(frozen=True)
class Pdu:
    path: str
    short_name: str
    kind: str  # I-SIGNAL-I-PDU, SECURED-I-PDU, NM-PDU, ...
    isignals: tuple[str, ...] = ()
    payload_ref: str | None = None  # SECURED-I-PDU -> the authentic I-PDU it wraps


@dataclass(frozen=True)
class DataMapping:
    """Binds a port's data element (or a CS operation) to a system signal.

    Presence of a mapping is what makes a signal leave the ECU at all: an
    unmapped connector is RTE-internal, gets no PDU, and therefore can never
    carry SecOC.
    """

    system_signal: str
    port: str | None = None
    data_prototype: str | None = None
    operation: str | None = None
    kind: str = SENDER_RECEIVER  # or CLIENT-SERVER-CALL / CLIENT-SERVER-RETURN


@dataclass(frozen=True)
class SignalRoute:
    """One fully resolved hop chain from a port down to the PDU on the wire."""

    port: str | None
    data_prototype: str | None
    system_signal: str
    isignal: str | None
    pdu: str | None
    kind: str


@dataclass
class Model:
    """Everything extracted from one ARXML package set."""

    component_types: dict[str, ComponentType] = field(default_factory=dict)
    prototypes: dict[str, Prototype] = field(default_factory=dict)
    interfaces: dict[str, PortInterface] = field(default_factory=dict)
    assembly_connectors: dict[str, AssemblyConnector] = field(default_factory=dict)
    delegation_connectors: dict[str, DelegationConnector] = field(default_factory=dict)
    ecus: dict[str, EcuInstance] = field(default_factory=dict)
    swc_to_ecu: dict[str, str] = field(default_factory=dict)  # prototype -> ECU path
    system_signals: dict[str, SystemSignal] = field(default_factory=dict)
    isignals: dict[str, ISignal] = field(default_factory=dict)
    pdus: dict[str, Pdu] = field(default_factory=dict)
    data_mappings: list[DataMapping] = field(default_factory=list)
    routes: list[SignalRoute] = field(default_factory=list)
    unresolved_refs: list[tuple[str, str]] = field(default_factory=list)
    # Raw path -> lxml element index, kept so later passes (ECU mapping, signal
    # and PDU chains, SecOC join) can re-walk the tree without reparsing.
    index: dict = field(default_factory=dict, repr=False, compare=False)

    def port(self, port_path: str | None) -> Port | None:
        """Resolve a port path without needing to know its owning type."""
        if port_path is None:
            return None
        for component in self.component_types.values():
            hit = component.ports.get(port_path)
            if hit is not None:
                return hit
        return None

    def interface_of(self, port_path: str | None) -> PortInterface | None:
        """Resolve the port interface a port is typed by, if it is known."""
        port = self.port(port_path)
        if port is None or port.interface_ref is None:
            return None
        return self.interfaces.get(port.interface_ref)
