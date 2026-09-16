"""Extraction tests: do we pull the right elements out of ARXML?"""

from arxml_secdiff import graph as graph_mod
from arxml_secdiff.model import CLIENT_SERVER, SENDER_RECEIVER

from .conftest import CTRL, DL, DR, TOP


class TestSenderReceiver:
    def test_counts(self, sr):
        # Sensor, Brake, and the Top composition are all component types.
        assert len(sr.component_types) == 3
        assert len(sr.prototypes) == 2
        assert len(sr.interfaces) == 1
        assert len(sr.assembly_connectors) == 1
        assert not sr.delegation_connectors
        assert not sr.unresolved_refs

    def test_index_paths_match_reference_bodies(self, sr):
        """Index keys must equal the strings *-REF elements actually contain."""
        assert "/T/Swc/Sensor/Out" in sr.index
        assert "/T/Swc/Top/s" in sr.index
        assert "/T/If/Speed" in sr.index

    def test_port_extraction(self, sr):
        port = sr.port("/T/Swc/Sensor/Out")
        assert port is not None
        assert port.kind == "P"
        assert port.short_name == "Out"
        assert port.interface_ref == "/T/If/Speed"
        assert port.interface_dest == "SENDER-RECEIVER-INTERFACE"
        assert port.owner == "/T/Swc/Sensor"

    def test_required_port_uses_required_tref(self, sr):
        port = sr.port("/T/Swc/Brake/In")
        assert port.kind == "R"
        assert port.interface_ref == "/T/If/Speed"

    def test_interface_members(self, sr):
        iface = sr.interfaces["/T/If/Speed"]
        assert iface.kind == SENDER_RECEIVER
        assert iface.members == ("value",)

    def test_connector_endpoints(self, sr):
        conn = sr.assembly_connectors["/T/Swc/Top/c1"]
        # Context is the prototype (instance); target is the port on the type.
        assert conn.provider_component == "/T/Swc/Top/s"
        assert conn.provider_port == "/T/Swc/Sensor/Out"
        assert conn.requester_component == "/T/Swc/Top/b"
        assert conn.requester_port == "/T/Swc/Brake/In"

    def test_interface_resolves_from_port(self, sr):
        iface = sr.interface_of("/T/Swc/Sensor/Out")
        assert iface is not None and iface.kind == SENDER_RECEIVER


class TestClientServer:
    def test_interface_kind_and_operations(self, cs):
        iface = cs.interfaces["/T/If/Unlock"]
        assert iface.kind == CLIENT_SERVER
        assert iface.members == ("doUnlock",)

    def test_server_provides_client_requires(self, cs):
        assert cs.port("/T/Swc/LockActuator/Svc").kind == "P"
        assert cs.port("/T/Swc/Telematics/Call").kind == "R"


class TestPrototypeIdentity:
    """The correction that matters most: nodes are prototypes, not types."""

    def test_one_type_two_prototypes(self, multi):
        assert len(multi.component_types) == 3  # Door, Ctrl, Top
        assert len(multi.prototypes) == 3  # dl, dr, ctrl

    def test_siblings_share_a_type_but_not_an_identity(self, multi):
        dl, dr = multi.prototypes[DL], multi.prototypes[DR]
        assert dl.type_ref == dr.type_ref == "/T/Swc/Door"
        assert dl.path != dr.path

    def test_keying_on_type_would_collapse_them(self, multi):
        """Guard against regressing to type-keyed identity."""
        by_type = {p.type_ref for p in multi.prototypes.values()}
        assert len(by_type) == 2  # Door, Ctrl
        assert len(multi.prototypes) == 3  # but three instances
        assert len(multi.prototypes) > len(by_type)

    def test_prototypes_know_their_composition(self, multi):
        assert multi.prototypes[CTRL].composition == TOP


class TestDelegation:
    def test_delegation_connector_shape(self, multi):
        conn = multi.delegation_connectors["/T/Swc/Top/sumOut"]
        assert conn.inner_kind == "P"
        assert conn.inner_component == CTRL
        assert conn.inner_port == "/T/Swc/Ctrl/Sum"
        assert conn.outer_port == "/T/Swc/Top/Sum"

    def test_assembly_and_delegation_kept_separate(self, multi):
        assert len(multi.assembly_connectors) == 4
        assert len(multi.delegation_connectors) == 1


class TestMultiFileIndex:
    def test_refs_resolve_across_files(self, mapped):
        """Topology in one file, software in another, one merged index."""
        assert len(mapped.component_types) == 3
        assert len(mapped.prototypes) == 3
        assert len(mapped.ecus) == 2
        assert not mapped.unresolved_refs

    def test_unresolved_refs_are_recorded_not_raised(self, parse_dangling):
        model = parse_dangling
        assert model.unresolved_refs
        assert any("/Nowhere/Missing" in ref for _, ref in model.unresolved_refs)


class TestNamespaceAgnostic:
    def test_alt_namespace_yields_identical_graph(self, sr, alt_ns, build):
        """A different xmlns must not change the extracted architecture."""
        a, b = build(sr), build(alt_ns)
        assert set(a.nodes) == set(b.nodes)
        assert set(a.edges(keys=True)) == set(b.edges(keys=True))

    def test_namespaces_are_stripped_from_tags(self, alt_ns):
        assert all("}" not in el.tag for el in alt_ns.index.values())


class TestRealEcuExtract:
    """Golden values for the upstream sample, to catch extraction regressions."""

    def test_counts(self, real):
        assert len(real.component_types) == 4
        assert len(real.prototypes) == 4
        assert len(real.interfaces) == 4
        assert len(real.assembly_connectors) == 5
        assert len(real.delegation_connectors) == 1

    def test_door_type_is_instantiated_twice(self, real):
        doors = [
            p for p in real.prototypes.values() if p.type_ref == "/Demo/Door/Door"
        ]
        assert len(doors) == 2
        assert {p.short_name for p in doors} == {"DoorLeft", "DoorRight"}

    def test_service_component_category_recognised(self, real):
        io = real.component_types["/Demo/Services/IoHwAb/IoHwAb"]
        assert io.category == "SERVICE"

    def test_ecu_extract_carries_no_ecu_instances(self, real):
        """An ECU extract is already scoped to one ECU, so it names none."""
        assert real.ecus == {}
        assert real.swc_to_ecu == {}
