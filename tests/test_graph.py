"""Graph tests: is *influence* direction modelled correctly?

The client-server cases are the important ones. A model that only ever draws
provider-to-requester edges parses the same ARXML and produces a graph that looks
plausible but silently cannot answer "what can this client reach?".
"""

import json

import networkx as nx

from arxml_secdiff.graph import to_json

from .conftest import CTRL, DL, DR, TOP

LOCK = "/T/Swc/Top/lock"
TEL = "/T/Swc/Top/tel"
SENSOR = "/T/Swc/Top/s"
BRAKE = "/T/Swc/Top/b"


def _influences(g):
    """(influence, source, target) triples, for terse whole-graph assertions."""
    return {(d["influence"], u, v) for u, v, d in g.edges(data=True)}


class TestSenderReceiver:
    def test_single_edge_following_data_flow(self, sr, build):
        g = build(sr)
        assert g.number_of_nodes() == 2
        assert g.number_of_edges() == 1
        assert _influences(g) == {("data", SENSOR, BRAKE)}

    def test_edge_carries_provenance_back_to_arxml(self, sr, build):
        g = build(sr)
        _, _, attrs = next(iter(g.edges(data=True)))
        assert attrs["connector"] == "/T/Swc/Top/c1"
        assert attrs["connector_kind"] == "ASSEMBLY"
        assert attrs["interface"] == "/T/If/Speed"
        assert attrs["interface_kind"] == "SENDER-RECEIVER"
        assert attrs["provider_port"] == "/T/Swc/Sensor/Out"
        assert attrs["requester_port"] == "/T/Swc/Brake/In"

    def test_receiver_cannot_reach_sender(self, sr, build):
        """Sender-receiver influence is one-way; the reverse must not exist."""
        g = build(sr)
        assert not nx.has_path(g, BRAKE, SENSOR)


class TestClientServer:
    def test_one_connector_becomes_two_edges(self, cs, build):
        g = build(cs)
        assert g.number_of_nodes() == 2
        assert g.number_of_edges() == 2
        assert _influences(g) == {
            ("request", TEL, LOCK),
            ("response", LOCK, TEL),
        }

    def test_client_can_reach_server(self, cs, build):
        """The whole point: the client drives the server.

        Under a provider-to-requester-only model this path would not exist, and a
        reachability query from a telematics entry point to a lock actuator would
        come back clean.
        """
        g = build(cs)
        assert nx.has_path(g, TEL, LOCK)
        assert ("request", TEL, LOCK) in _influences(g)

    def test_request_and_response_share_a_connector_but_not_a_key(self, cs, build):
        g = build(cs)
        keys = {k for _, _, k in g.edges(keys=True)}
        assert keys == {"/T/Swc/Top/c1#request", "/T/Swc/Top/c1#response"}
        connectors = {d["connector"] for _, _, d in g.edges(data=True)}
        assert connectors == {"/T/Swc/Top/c1"}


class TestMultiInstance:
    def test_exact_graph_shape(self, multi, build):
        g = build(multi)
        assert g.number_of_nodes() == 4  # dl, dr, ctrl, Top (composition)
        assert g.number_of_edges() == 7
        assert _influences(g) == {
            ("data", DL, CTRL),
            ("data", DR, CTRL),
            ("request", CTRL, DL),
            ("request", CTRL, DR),
            ("response", DL, CTRL),
            ("response", DR, CTRL),
            ("delegate-out", CTRL, TOP),
        }

    def test_siblings_are_separate_nodes(self, multi, build):
        g = build(multi)
        assert DL in g and DR in g
        assert g.nodes[DL]["type_ref"] == g.nodes[DR]["type_ref"] == "/T/Swc/Door"
        assert g.nodes[DL]["short_name"] == "dl"
        assert g.nodes[DR]["short_name"] == "dr"

    def test_no_phantom_path_between_siblings(self, multi, build):
        """Type-keyed nodes would fuse dl and dr and invent this path."""
        g = build(multi)
        assert not nx.has_path(g, DL, DR) or nx.shortest_path(g, DL, DR) != [DL, DR]

    def test_multidigraph_keeps_parallel_edges(self, multi, build):
        """dl -> ctrl carries both a status data edge and a command response."""
        g = build(multi)
        assert g.number_of_edges(DL, CTRL) == 2
        influences = {d["influence"] for d in g[DL][CTRL].values()}
        assert influences == {"data", "response"}

    def test_node_port_summaries(self, multi, build):
        g = build(multi)
        assert g.nodes[DL]["provided_ports"] == ("Cmd", "Status")
        assert g.nodes[DL]["required_ports"] == ()
        assert g.nodes[CTRL]["required_ports"] == ("CmdL", "CmdR", "StatusL", "StatusR")
        assert g.nodes[CTRL]["provided_ports"] == ("Sum",)

    def test_composition_node_marks_the_boundary(self, multi, build):
        g = build(multi)
        assert g.nodes[TOP]["kind"] == "composition"
        assert g.nodes[CTRL]["kind"] == "prototype"

    def test_delegation_edge_carries_both_port_paths(self, multi, build):
        g = build(multi)
        attrs = g[CTRL][TOP]["/T/Swc/Top/sumOut#out"]
        assert attrs["connector_kind"] == "DELEGATION"
        assert attrs["inner_port"] == "/T/Swc/Ctrl/Sum"
        assert attrs["outer_port"] == "/T/Swc/Top/Sum"


class TestHostAndCrossEcu:
    def test_host_is_none_without_a_system_mapping(self, multi, build):
        g = build(multi)
        assert all(g.nodes[n]["host"] is None for n in (DL, DR, CTRL))

    def test_cross_ecu_is_none_not_false_when_unmapped(self, multi, build):
        """Unknown must stay distinguishable from same-ECU."""
        g = build(multi)
        assert all(d["cross_ecu"] is None for _, _, d in g.edges(data=True) if d["connector_kind"] == "ASSEMBLY")


class TestJsonExport:
    def test_is_serialisable_and_sorted(self, multi, build):
        payload = to_json(build(multi))
        assert json.dumps(payload)  # must not raise on tuple-valued attrs
        ids = [n["id"] for n in payload["nodes"]]
        assert ids == sorted(ids)

    def test_tuples_become_lists(self, multi, build):
        payload = to_json(build(multi))
        node = next(n for n in payload["nodes"] if n["id"] == DL)
        assert node["provided_ports"] == ["Cmd", "Status"]

    def test_edge_count_survives_export(self, multi, build):
        g = build(multi)
        assert len(to_json(g)["edges"]) == g.number_of_edges()


class TestRealEcuExtract:
    def test_golden_shape(self, real, build):
        g = build(real)
        assert g.number_of_nodes() == 5
        assert g.number_of_edges() == 9

    def test_client_server_doubling_accounts_for_the_edge_count(self, real, build):
        g = build(real)
        counts: dict[str, int] = {}
        for _, _, d in g.edges(data=True):
            counts[d["influence"]] = counts.get(d["influence"], 0) + 1
        # 3 client-server connectors -> 3 request + 3 response;
        # 2 sender-receiver -> 2 data; 1 delegation -> 1 delegate-out.
        assert counts == {
            "request": 3,
            "response": 3,
            "data": 2,
            "delegate-out": 1,
        }
        assert sum(counts.values()) == len(real.assembly_connectors) + len(
            real.delegation_connectors
        ) + 3

    def test_controller_reaches_every_door(self, real, build):
        """Only true because request edges exist."""
        g = build(real)
        ctrl = "/Demo/EDC/EDC/Control"
        for door in ("/Demo/EDC/EDC/DoorLeft", "/Demo/EDC/EDC/DoorRight"):
            assert nx.has_path(g, ctrl, door)
