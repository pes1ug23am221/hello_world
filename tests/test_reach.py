"""Reachability tests against the veh_v1 / v2 / v3 trio, plus the real ECU extract.

The headline assertion in each block is identical: some entry point could not reach a
critical node in the before, and can in the update. Everything else is the proof
that the path, the hop attributes, and the change-type are reported correctly.
"""

import pytest

from arxml_secdiff import reach, roles, secoc
from arxml_secdiff import graph as graph_mod

from .conftest import ABS, BRAKE, GW, TEL


# Fixed seeds for the diff tests, so no heuristic variation can flip an assertion.
def _roles():
    return {
        "entry": [{"node": TEL, "reason": "cellular telematics, external attack surface"}],
        "critical": [
            {"node": BRAKE, "asil": "D", "reason": "service braking"},
            {"node": ABS, "asil": "C", "reason": "anti-lock braking"},
        ],
    }


def _reach(model, graph):
    r = roles.classify(graph, _roles())
    return reach.analyse(graph, r)


class Testbefore:
    def test_tel_cannot_reach_brake_in_v1(self, veh1):
        r = _reach(*veh1)
        assert (TEL, BRAKE) not in r.pairs

    def test_no_entry_to_critical_path_at_all(self, veh1):
        r = _reach(*veh1)
        assert r.paths == ()

    def test_seeds_reflect_the_config(self, veh1):
        r = _reach(*veh1)
        assert r.entry == (TEL,)
        assert set(r.critical) == {BRAKE, ABS}

    def test_all_internal_paths_are_absent(self, veh1):
        """The abs -> brake connector is RTE-local, not an attack path."""
        r = _reach(*veh1)
        # abs can reach brake via the internal hop, but TEL cannot reach ABS
        # so no entry-to-critical chain exists.
        assert r.pairs == frozenset()


class TestNewConnectorAddsReachability:
    def test_tel_can_reach_brake_via_gw_in_v2(self, veh2):
        r = _reach(*veh2)
        assert (TEL, BRAKE) in r.pairs

    def test_the_path_traverses_the_gateway(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        assert GW in path.nodes

    def test_path_length_is_three_hops(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        assert path.length == 3

    def test_the_tel_gw_hop_is_unprotected(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        tel_gw = next(h for h in path.hops if h.source == TEL)
        assert tel_gw.authenticated is False

    def test_the_gw_abs_hop_is_authenticated(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        gw_abs = next(h for h in path.hops if h.source == GW)
        assert gw_abs.authenticated is True

    def test_path_is_not_fully_protected(self, veh2):
        assert not _reach(*veh2).shortest_to(BRAKE).fully_protected

    def test_tel_can_also_reach_abs_directly(self, veh2):
        r = _reach(*veh2)
        assert (TEL, ABS) in r.pairs

    def test_diff_flags_new_pair(self, veh1, veh2):
        d = reach.compare(_reach(*veh1), _reach(*veh2))
        new = d.by(reach.NEW_PAIR)
        assert any(c.target == BRAKE for c in new)

    def test_new_unprotected_pairs(self, veh1, veh2):
        d = reach.compare(_reach(*veh1), _reach(*veh2))
        assert d.newly_reachable_unprotected


class TestRehostAddsReachability:
    def test_tel_cannot_reach_brake_via_existing_connectors(self, veh3):
        """The rehost does not add any connector, so tel -> abs is not wired."""
        r = _reach(*veh3)
        assert (TEL, BRAKE) not in r.pairs

    def test_the_brake_hop_is_newly_unprotected(self, veh3):
        """abs -> brake became a bus hop with no SecOC after the rehost."""
        _, g = veh3
        edge_attrs = next(iter(g[ABS][BRAKE].values()))
        assert edge_attrs["authenticated"] is False

    def test_diff_sees_no_new_pair_only_a_changed_edge(self, veh1, veh3):
        d = reach.compare(_reach(*veh1), _reach(*veh3))
        assert d.by(reach.NEW_PAIR) == ()

    def test_empty_before_and_empty_updated_give_empty_diff(self, veh1):
        r = _reach(*veh1)
        assert reach.compare(r, r).summary()["new_pairs"] == 0


class TestPathAttributes:
    def test_unprotected_hops_subset_of_all_hops(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        assert set(path.unprotected_hops).issubset(set(path.hops))

    def test_bus_hops_subset_of_all_hops(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        assert set(path.bus_hops).issubset(set(path.hops))

    def test_connector_path_is_recoverable_from_hop(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        tel_gw = next(h for h in path.hops if h.source == TEL)
        assert tel_gw.connector == "/V/Swc/Veh/telToGw"

    def test_str_is_short_names(self, veh2):
        path = _reach(*veh2).shortest_to(BRAKE)
        assert str(path) == "tel -> gw -> abs -> brake"

    def test_cutoff_limits_path_length(self, veh2):
        m, g = veh2
        r = roles.classify(g, _roles())
        short = reach.analyse(g, r, cutoff=1)
        assert all(p.length <= 1 for p in short.paths)


class TestConfigRoles:
    def test_exact_path_resolves(self, veh1):
        _, g = veh1
        r = roles.classify(g, {"entry": [TEL], "critical": [BRAKE]})
        assert r.entry == (TEL,)
        assert r.critical == (BRAKE,)
        assert not r.heuristic_only

    def test_glob_resolves_to_all_matching_nodes(self, veh1):
        _, g = veh1
        r = roles.classify(g, {"critical": ["*/brake"]})
        assert BRAKE in r.critical

    def test_unmatched_pattern_is_recorded(self, veh1):
        _, g = veh1
        r = roles.classify(g, {"critical": ["/V/Swc/Veh/nonexistent"]})
        assert r.unmatched == ((roles.CRITICAL, "/V/Swc/Veh/nonexistent"),)

    def test_asil_is_accessible(self, veh1):
        _, g = veh1
        r = roles.classify(g, {"critical": [{"node": BRAKE, "asil": "D"}]})
        assert r.asil_of(BRAKE) == "D"

    def test_heuristic_only_is_true_when_no_config(self, veh1):
        _, g = veh1
        r = roles.classify(g)
        assert r.heuristic_only

    def test_heuristic_guesses_brake_as_critical_by_name(self, veh1):
        _, g = veh1
        r = roles.classify(g)
        assert BRAKE in r.critical

    def test_heuristic_guesses_telematic_as_entry_by_name(self, veh1):
        _, g = veh1
        r = roles.classify(g)
        assert TEL in r.entry


class TestDiffSummary:
    def test_v1_to_v2_summary(self, veh1, veh2):
        d = reach.compare(_reach(*veh1), _reach(*veh2))
        s = d.summary()
        assert s["before_paths"] == 0
        assert s["new_pairs"] == 2
        assert s["removed_pairs"] == 0


class TestUnanswerableQueries:
    """"No paths found" and "never searched" must never look the same."""

    def test_partial_config_is_completed_by_heuristics(self, veh1):
        """The default, and the right one: a half-written config still analyses."""
        _, g = veh1
        r = roles.classify(g, {"critical": [BRAKE]})
        assert r.critical == (BRAKE,)
        assert r.entry == (TEL,)  # guessed
        assert reach.analyse(g, r).analysed is True

    def test_heuristics_off_turns_a_missing_role_into_a_gap(self, veh1):
        _, g = veh1
        r = roles.classify(g, {"critical": [BRAKE]}, heuristics=False)
        result = reach.analyse(g, r)
        assert result.paths == ()
        assert result.analysed is False
        assert "no entry point present in this snapshot" in result.gaps

    def test_heuristics_off_with_no_critical_role_is_also_a_gap(self, veh1):
        _, g = veh1
        r = roles.classify(g, {"entry": [TEL]}, heuristics=False)
        assert reach.analyse(g, r).analysed is False

    def test_a_typod_config_path_is_reported_and_yields_a_gap(self, veh1):
        """With guessing off, a typo cannot hide behind a plausible fallback."""
        _, g = veh1
        r = roles.classify(
            g, {"entry": [TEL], "critical": ["/V/Swc/Veh/typo"]}, heuristics=False
        )
        assert r.unmatched == ((roles.CRITICAL, "/V/Swc/Veh/typo"),)
        assert reach.analyse(g, r).analysed is False

    def test_a_seed_named_but_absent_from_this_snapshot_is_a_gap(self, veh1):
        """The node exists in the config's world, just not in this graph."""
        _, g = veh1
        r = roles.Roles(
            assignments=(
                roles.Role(TEL, roles.ENTRY, "configured", roles.CONFIG),
                roles.Role("/Other/Swc/x", roles.CRITICAL, "configured", roles.CONFIG),
            )
        )
        assert r.seeded is True  # the config looks complete...
        assert reach.analyse(g, r).analysed is False  # ...but this snapshot cannot answer it

    def test_a_real_search_with_no_hits_is_analysed(self, veh1):
        result = _reach(*veh1)
        assert result.paths == ()
        assert result.analysed is True
        assert result.gaps == ()


class TestRealEcuExtract:
    def test_names_the_door_components_critical(self, real, build):
        """Heuristic on short names: `DoorLeft` / `DoorRight` match door control."""
        g = secoc.annotate(build(real), real)
        r = roles.classify(g)
        assert "/Demo/EDC/EDC/DoorLeft" in r.critical
        assert "/Demo/EDC/EDC/DoorRight" in r.critical

    def test_finds_no_entry_surface_and_says_so(self, real, build):
        """An ECU extract of a door demo has no named external attack surface.

        The delegation in this file is outbound only, so even the composition
        boundary fallback does not apply - influence leaves the ECU there, it does
        not enter. The correct output is "not analysed", not "no attack paths".
        """
        g = secoc.annotate(build(real), real)
        r = roles.classify(g)
        assert r.entry == ()
        assert r.seeded is False
        assert "no entry point identified" in r.gaps()

    def test_reachability_reports_the_gap_rather_than_a_clean_bill(self, real, build):
        g = secoc.annotate(build(real), real)
        result = reach.analyse(g, roles.classify(g))
        assert result.paths == ()
        assert result.analysed is False

    def test_an_explicit_entry_makes_the_query_answerable(self, real, build):
        """With a seed supplied, the same snapshot analyses cleanly.

        `Control` reaches both doors over internal connectors, which is a real
        influence path - it is simply not a *bus* one, so it carries no SecOC finding.
        """
        g = secoc.annotate(build(real), real)
        r = roles.classify(
            g, {"entry": ["/Demo/EDC/EDC/Control"], "critical": ["*/DoorLeft"]}
        )
        result = reach.analyse(g, r)
        assert result.analysed is True
        assert result.paths
        assert all(p.fully_protected for p in result.paths)
        assert all(h.bus_visible is False for p in result.paths for h in p.hops)
