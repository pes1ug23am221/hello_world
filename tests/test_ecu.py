"""ECU mapping tests: which host does each prototype run on, and which edges
therefore have to cross a bus?

This is the layer that makes cross-HPC questions answerable, and the layer that
decides whether SecOC is even applicable to a given connector.
"""

from arxml_secdiff import ecu

from .conftest import CTRL, DL, DR

BODY = "/T/Topology/BodyEcu"
DOOR_ECU = "/T/Topology/DoorEcu"


class TestEcuInstances:
    def test_both_ecus_extracted(self, mapped):
        assert set(mapped.ecus) == {BODY, DOOR_ECU}
        assert mapped.ecus[BODY].short_name == "BodyEcu"

    def test_comm_connectors_collected(self, mapped):
        assert mapped.ecus[BODY].comm_connectors == (f"{BODY}/CanConn",)


class TestSwcToEcuMapping:
    def test_prototypes_map_to_their_ecus(self, mapped):
        assert mapped.swc_to_ecu[CTRL] == BODY
        assert mapped.swc_to_ecu[DL] == DOOR_ECU
        assert mapped.swc_to_ecu[DR] == DOOR_ECU

    def test_one_mapping_can_carry_several_components(self, mapped):
        """ToDoor lists dl and dr under a single SWC-TO-ECU-MAPPING."""
        on_door = [p for p, e in mapped.swc_to_ecu.items() if e == DOOR_ECU]
        assert sorted(on_door) == [DL, DR]

    def test_host_of_returns_short_names(self, mapped):
        assert ecu.host_of(mapped, CTRL) == "BodyEcu"
        assert ecu.host_of(mapped, DL) == "DoorEcu"

    def test_host_of_is_none_for_unmapped(self, multi):
        assert ecu.host_of(multi, CTRL) is None


class TestCrossEcu:
    def test_controller_to_door_traverses_a_bus(self, mapped):
        assert ecu.is_cross_ecu(mapped, CTRL, DL) is True
        assert ecu.is_cross_ecu(mapped, CTRL, DR) is True

    def test_siblings_share_a_host(self, mapped):
        assert ecu.is_cross_ecu(mapped, DL, DR) is False

    def test_unknown_is_none_not_false(self, multi):
        """Treating unmapped as same-ECU would silently mark bus links local."""
        assert ecu.is_cross_ecu(multi, CTRL, DL) is None


class TestGraphAnnotation:
    def test_nodes_carry_host(self, mapped, build):
        g = build(mapped)
        assert g.nodes[CTRL]["host"] == "BodyEcu"
        assert g.nodes[DL]["host"] == "DoorEcu"

    def test_assembly_edges_marked_cross_ecu(self, mapped, build):
        g = build(mapped)
        assembly = [
            d for _, _, d in g.edges(data=True) if d["connector_kind"] == "ASSEMBLY"
        ]
        assert assembly and all(d["cross_ecu"] is True for d in assembly)

    def test_secoc_eligibility_follows_cross_ecu(self, mapped, build):
        """Only bus-traversing edges can carry SecOC; RTE-local ones cannot."""
        g = build(mapped)
        eligible = [
            (u, v)
            for u, v, d in g.edges(data=True)
            if d.get("cross_ecu") is True
        ]
        assert len(eligible) == 6  # 2 data + 2 request + 2 response


class TestAssumeSingleHost:
    def test_fills_an_unmapped_snapshot(self, multi):
        ecu.assume_single_host(multi, "/T/Topology/OnlyEcu")
        assert set(multi.swc_to_ecu) == set(multi.prototypes)
        assert ecu.host_of(multi, CTRL) == "OnlyEcu"

    def test_makes_everything_local(self, multi):
        ecu.assume_single_host(multi, "/T/Topology/OnlyEcu")
        assert ecu.is_cross_ecu(multi, CTRL, DL) is False

    def test_never_overwrites_a_real_mapping(self, mapped):
        ecu.assume_single_host(mapped, "/T/Topology/Bogus")
        assert mapped.swc_to_ecu[CTRL] == BODY
        assert mapped.swc_to_ecu[DL] == DOOR_ECU


class TestRealEcuExtract:
    def test_no_mapping_present(self, real):
        assert real.ecus == {}
        assert real.swc_to_ecu == {}

    def test_can_be_treated_as_one_host(self, real, build):
        ecu.assume_single_host(real, "/Demo/Topology/EdcEcu")
        g = build(real)
        assert g.nodes["/Demo/EDC/EDC/Control"]["host"] == "EdcEcu"
        assembly = [
            d for _, _, d in g.edges(data=True) if d["connector_kind"] == "ASSEMBLY"
        ]
        assert all(d["cross_ecu"] is False for d in assembly)
