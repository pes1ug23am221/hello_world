"""Diff tests against the veh_v1 / v2 / v3 trio.

Each pair isolates one regression class, so a failure here names the class rather
than just "the diff changed":

* v1 -> v2: a new connector, plus SecOC removed from an existing bus hop.
* v1 -> v3: a component rehosted, which puts previously RTE-local data on a bus.
"""

from arxml_secdiff import diff

from .conftest import ABS, BRAKE, GW, TEL

CMD_PDU = "/V/Comm/CmdIPdu"
SET_PDU = "/V/Comm/SetIPdu"
BRK_PDU = "/V/Comm/BrkIPdu"


class TestIdentity:
    def test_a_snapshot_against_itself_is_empty(self, veh1):
        """Re-parsing the same file must produce no changes at all.

        This is the test that catches non-determinism in the index or the graph,
        which would otherwise show up as phantom findings on every release.
        """
        _, g = veh1
        assert diff.compare(g, g).empty

    def test_reparsing_gives_an_identical_graph(self, veh1, veh1_again):
        _, first = veh1
        _, second = veh1_again
        assert diff.compare(first, second).empty


class TestNewConnector:
    def test_added_edge_is_reported_once(self, veh1, veh2):
        d = diff.compare(veh1[1], veh2[1])
        added = d.edges_by(diff.ADDED)
        assert len(added) == 1
        assert (added[0].source, added[0].target) == (GW, ABS)

    def test_added_edge_carries_its_connector(self, veh1, veh2):
        added = diff.compare(veh1[1], veh2[1]).edges_by(diff.ADDED)[0]
        assert added.connector == "/V/Swc/Veh/gwToAbs"
        assert added.influence == "data"

    def test_no_node_churn_when_only_a_connector_is_added(self, veh1, veh2):
        assert diff.compare(veh1[1], veh2[1]).nodes == ()

    def test_a_properly_authenticated_new_hop_is_not_a_finding(self, veh1, veh2):
        """gwToAbs is bus-visible but SecOC-protected, so it is not unprotected.

        Its danger is reachability, not authentication - a different finding, raised
        by a different module.
        """
        added = diff.compare(veh1[1], veh2[1]).edges_by(diff.ADDED)[0]
        assert added.attrs["authenticated"] is True
        assert added not in diff.compare(veh1[1], veh2[1]).newly_unprotected


class TestSecOcRemoved:
    def test_authentication_loss_is_a_field_change_not_a_replacement(self, veh1, veh2):
        """The connector did not move, so the edge must survive as MODIFIED."""
        modified = diff.compare(veh1[1], veh2[1]).edges_by(diff.MODIFIED)
        assert len(modified) == 1
        edge = modified[0]
        assert (edge.source, edge.target) == (TEL, GW)
        assert edge.moved("authenticated").before is True
        assert edge.moved("authenticated").after is False

    def test_the_affected_pdu_is_named(self, veh1, veh2):
        edge = diff.compare(veh1[1], veh2[1]).edges_by(diff.MODIFIED)[0]
        assert edge.moved("unprotected_pdus").after == (CMD_PDU,)

    def test_evidence_source_downgrades(self, veh1, veh2):
        edge = diff.compare(veh1[1], veh2[1]).edges_by(diff.MODIFIED)[0]
        assert edge.moved("secoc_source").before == "secured-i-pdu"
        assert edge.moved("secoc_source").after == "absent"

    def test_newly_unprotected_is_exactly_that_hop(self, veh1, veh2):
        found = diff.compare(veh1[1], veh2[1]).newly_unprotected
        assert [(e.source, e.target) for e in found] == [(TEL, GW)]

    def test_pdu_level_diff_sees_it_without_the_graph(self, veh1, veh2):
        changes = diff.compare_secoc(veh1[0], veh2[0])
        lost = [c for c in changes if c.lost_protection]
        assert [c.pdu for c in lost] == [CMD_PDU]

    def test_a_new_protected_pdu_is_not_a_loss(self, veh1, veh2):
        changes = {c.pdu: c for c in diff.compare_secoc(veh1[0], veh2[0])}
        assert changes[SET_PDU].change == diff.ADDED
        assert changes[SET_PDU].lost_protection is False


class TestRehost:
    def test_the_host_change_is_reported(self, veh1, veh3):
        d = diff.compare(veh1[1], veh3[1])
        assert [n.path for n in d.rehosted] == [ABS]
        assert d.nodes[0].fields[0].after == "GatewayEcu"

    def test_the_same_connector_becomes_a_bus_hop(self, veh1, veh3):
        d = diff.compare(veh1[1], veh3[1])
        edge = d.edges_by(diff.MODIFIED)[0]
        assert (edge.source, edge.target) == (ABS, BRAKE)
        assert edge.moved("cross_ecu").after is True
        assert edge.moved("bus_visible").after is True

    def test_not_applicable_becomes_applicable_and_absent(self, veh1, veh3):
        """None -> False is the whole point of keeping the third value.

        A two-valued flag would have shown this edge as unauthenticated in v1 too,
        burying the change in noise that was never actionable.
        """
        edge = diff.compare(veh1[1], veh3[1]).edges_by(diff.MODIFIED)[0]
        assert edge.moved("authenticated").before is None
        assert edge.moved("authenticated").after is False

    def test_it_is_both_newly_bus_visible_and_newly_unprotected(self, veh1, veh3):
        d = diff.compare(veh1[1], veh3[1])
        assert [(e.source, e.target) for e in d.newly_bus_visible] == [(ABS, BRAKE)]
        assert [(e.source, e.target) for e in d.newly_unprotected] == [(ABS, BRAKE)]

    def test_no_connector_was_added_or_removed(self, veh1, veh3):
        d = diff.compare(veh1[1], veh3[1])
        assert d.edges_by(diff.ADDED) == ()
        assert d.edges_by(diff.REMOVED) == ()

    def test_the_brake_pdu_appears_unprotected(self, veh1, veh3):
        changes = {c.pdu: c for c in diff.compare_secoc(veh1[0], veh3[0])}
        assert BRK_PDU not in changes  # unprotected PDUs get no profile at all

    def test_summary_counts(self, veh1, veh3):
        assert diff.compare(veh1[1], veh3[1]).summary() == {
            "nodes_added": 0,
            "nodes_removed": 0,
            "nodes_modified": 1,
            "edges_added": 0,
            "edges_removed": 0,
            "edges_modified": 1,
            "newly_unprotected": 1,
            "newly_bus_visible": 1,
            "rehosted": 1,
            "renamed_connectors": 0,
        }


class TestDirection:
    def test_the_diff_is_not_symmetric(self, veh1, veh2):
        """Reverting the release is not the same finding as shipping it."""
        forward = diff.compare(veh1[1], veh2[1])
        backward = diff.compare(veh2[1], veh1[1])
        assert len(forward.edges_by(diff.ADDED)) == 1
        assert len(backward.edges_by(diff.REMOVED)) == 1
        assert backward.newly_unprotected == ()


class TestUnannotatedGraphs:
    def test_missing_secoc_fields_are_not_reported_as_changes(self, veh1, build):
        """A bare graph has no SecOC attributes; absent on both sides is not a diff."""
        model, _ = veh1
        bare = build(model)
        assert diff.compare(bare, build(model)).empty

    def test_annotating_one_side_only_does_show_up(self, veh1, build):
        """And when one side is annotated, the asymmetry must not be silent."""
        model, annotated = veh1
        d = diff.compare(build(model), annotated)
        assert d.edges_by(diff.MODIFIED)
        assert any(e.moved("bus_visible") for e in d.edges)
