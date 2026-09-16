"""Severity tests: the numbers, and the provenance attached to them.

Scores are asserted against the measured output of the veh trio. The point of most of
these is not the integer — it is that the integer is traceable: which ASIL it came
from, whether any input was guessed, and which scorer produced it.
"""

import json
import sys

import pytest

from arxml_secdiff import diff, findings, reach, roles, secoc, severity
from arxml_secdiff import graph as graph_mod

from .conftest import ABS, BRAKE, GW, TEL

TEL_TO_GW = "/V/Swc/Veh/telToGw#data"
ABS_TO_BRAKE = "/V/Swc/Veh/absToBrake#data"


def _seeds():
    return {
        "entry": [{"node": TEL, "reason": "cellular telematics, external attack surface"}],
        "critical": [
            {"node": BRAKE, "asil": "D", "reason": "service braking"},
            {"node": ABS, "asil": "C", "reason": "anti-lock braking"},
        ],
    }


def _pipeline(before, after, config=None, heuristics=True):
    """Everything from two annotated graphs to scored findings."""
    config = _seeds() if config is None else config
    rb = roles.classify(before[1], config, heuristics)
    ra = roles.classify(after[1], config, heuristics)
    reach_before, reach_after = reach.analyse(before[1], rb), reach.analyse(after[1], ra)
    found = findings.collect(
        diff.compare(before[1], after[1]), reach.compare(reach_before, reach_after)
    )
    scorer = severity.BuiltinScorer(node_roles=ra, paths=reach_after)
    return severity.score_all(found, scorer)


def _find(scored, finding_id):
    return next(s for s in scored if s.finding.id == finding_id)


@pytest.fixture
def stub(tmp_path):
    """Build an external scorer whose behaviour the test dictates."""

    def make(body: str, name="stub"):
        script = tmp_path / f"{name}.py"
        script.write_text(body)
        return severity.ExternalScorer([sys.executable, str(script)])

    return make


@pytest.fixture
def a_finding(veh1, veh2):
    found = findings.collect(diff.compare(veh1[1], veh2[1]))
    return next(f for f in found if f.category == findings.SECOC_REMOVED)


class TestRiskMatrix:
    def test_every_combination_is_covered(self):
        """A missing cell would be a KeyError at scoring time, not a wrong number."""
        for impact in severity.IMPACT_ORDER:
            for feasibility in severity.FEASIBILITY_ORDER:
                assert (impact, feasibility) in severity.RISK_MATRIX

    def test_all_values_are_in_range(self):
        assert all(1 <= v <= 5 for v in severity.RISK_MATRIX.values())

    def test_risk_never_falls_as_feasibility_rises(self):
        for impact in severity.IMPACT_ORDER:
            row = [severity.RISK_MATRIX[(impact, f)] for f in severity.FEASIBILITY_ORDER]
            assert row == sorted(row)

    def test_risk_never_falls_as_impact_rises(self):
        for feasibility in severity.FEASIBILITY_ORDER:
            column = [severity.RISK_MATRIX[(i, feasibility)] for i in severity.IMPACT_ORDER]
            assert column == sorted(column)

    def test_negligible_impact_is_never_worse_than_one(self):
        """Feasibility alone cannot make a harmless change into a finding."""
        assert {
            severity.RISK_MATRIX[(severity.NEGLIGIBLE, f)] for f in severity.FEASIBILITY_ORDER
        } == {1}

    def test_the_worst_cell_is_five(self):
        assert severity.RISK_MATRIX[(severity.SEVERE, severity.HIGH)] == 5


class TestConfiguredAsil:
    def test_the_brake_path_scores_five(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"newly-reachable:{TEL}->{BRAKE}")
        assert (s.score.impact, s.score.feasibility, s.risk) == (
            severity.SEVERE,
            severity.HIGH,
            5,
        )

    def test_the_asil_is_named_in_the_rationale(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"newly-reachable:{TEL}->{BRAKE}")
        assert any("ASIL D" in r for r in s.score.rationale)

    def test_a_configured_asil_is_not_an_assumption(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"newly-reachable:{TEL}->{BRAKE}")
        assert s.score.assumed is False

    def test_asil_c_scores_lower_than_asil_d_on_the_same_bus(self, veh1, veh2):
        scored = _pipeline(veh1, veh2)
        brake = _find(scored, f"newly-reachable:{TEL}->{BRAKE}")
        abs_ = _find(scored, f"newly-reachable:{TEL}->{ABS}")
        assert abs_.risk < brake.risk

    def test_the_unprotected_hop_is_named_in_the_rationale(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"newly-reachable:{TEL}->{BRAKE}")
        assert any("telToGw" in r for r in s.score.rationale)


class TestDownstreamInheritance:
    """A hop is only as safe as the worst thing reachable through it."""

    def test_secoc_removal_on_the_gateway_link_scores_five(self, veh1, veh2):
        """The receiver is a gateway, but the route ends at an ASIL D actuator."""
        s = _find(_pipeline(veh1, veh2), f"secoc-removed:{TEL_TO_GW}")
        assert s.score.impact == severity.SEVERE
        assert s.risk == 5

    def test_the_borrowed_target_is_named(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"secoc-removed:{TEL_TO_GW}")
        assert any("route to brake" in r for r in s.score.rationale)

    def test_without_the_paths_the_same_hop_scores_lower(self, veh1, veh2, a_finding):
        """Shows the inheritance is doing the work, not the ASIL table alone."""
        node_roles = roles.classify(veh2[1], _seeds())
        blind = severity.BuiltinScorer(node_roles=node_roles).score(a_finding)
        assert blind.impact == severity.MODERATE
        assert blind.risk == 3

    def test_a_hop_leading_nowhere_critical_is_not_inflated(self, veh1, veh2, a_finding):
        """Inheritance must not fire when no route runs through the hop."""
        node_roles = roles.classify(veh2[1], _seeds())
        empty = reach.Reachability()
        s = severity.BuiltinScorer(node_roles=node_roles, paths=empty).score(a_finding)
        assert s.impact == severity.MODERATE

    def test_the_receiving_end_is_used_when_it_is_itself_critical(self, veh1, veh3):
        """v3's new bus hop terminates at the brake actuator, no inheritance needed."""
        s = _find(_pipeline(veh1, veh3), f"unprotected-new-hop:{ABS_TO_BRAKE}")
        assert s.score.impact == severity.SEVERE
        assert s.risk == 5
        assert any("ASIL D" in r for r in s.score.rationale)


class TestHeuristicSeedsTaintTheScore:
    def test_guessed_seeds_mark_the_score_assumed(self, veh1, veh2):
        scored = _pipeline(veh1, veh2, config={})
        assert all(s.score.assumed for s in scored)

    def test_a_guessed_critical_node_scores_the_unknown_asil_default(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2, config={}), f"newly-reachable:{TEL}->{BRAKE}")
        assert s.score.impact == severity.UNKNOWN_ASIL_IMPACT

    def test_a_guessed_seed_scores_below_a_configured_asil_d(self, veh1, veh2):
        """Same architecture, weaker evidence, lower claim."""
        guessed = _find(_pipeline(veh1, veh2, config={}), f"newly-reachable:{TEL}->{BRAKE}")
        known = _find(_pipeline(veh1, veh2), f"newly-reachable:{TEL}->{BRAKE}")
        assert guessed.risk < known.risk

    def test_the_rationale_says_the_seeds_were_guessed(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2, config={}), f"newly-reachable:{TEL}->{BRAKE}")
        assert any("heuristic" in r for r in s.score.rationale)

    def test_no_roles_at_all_still_scores_and_still_flags_it(self, a_finding):
        s = severity.BuiltinScorer().score(a_finding)
        assert s.risk >= 1
        assert s.assumed is True


class TestFeasibility:
    def test_an_unauthenticated_bus_hop_is_high(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"secoc-removed:{TEL_TO_GW}")
        assert s.score.feasibility == severity.HIGH

    def test_a_fully_protected_route_is_not_high(self, real, build):
        """Internal-only routes presuppose code execution on the ECU."""
        g = secoc.annotate(build(real), real)
        node_roles = roles.classify(
            g, {"entry": ["/Demo/EDC/EDC/Control"], "critical": ["*/DoorLeft"]}
        )
        result = reach.analyse(g, node_roles)
        path = result.paths[0]
        f = findings.Finding(
            findings.NEWLY_REACHABLE, "x", "t", target=path.target, path=path
        )
        s = severity.BuiltinScorer(node_roles, result).score(f)
        assert s.feasibility == severity.VERY_LOW
        assert any("RTE-local" in r for r in s.rationale)

    def test_a_remote_entry_point_raises_feasibility(self, veh1):
        """Same internal route, but the chain starts at a cellular modem."""
        node_roles = roles.classify(
            veh1[1],
            {
                "entry": [{"node": ABS, "reason": "cellular telematics uplink"}],
                "critical": [{"node": BRAKE, "asil": "D"}],
            },
        )
        result = reach.analyse(veh1[1], node_roles)
        path = result.paths[0]
        f = findings.Finding(findings.NEWLY_REACHABLE, "x", "t", target=BRAKE, path=path)
        s = severity.BuiltinScorer(node_roles, result).score(f)
        assert s.feasibility == severity.LOW  # very-low, raised one step
        assert any("remotely accessible" in r for r in s.rationale)

    def test_a_local_entry_point_does_not_raise_feasibility(self, veh1):
        node_roles = roles.classify(
            veh1[1],
            {
                "entry": [{"node": ABS, "reason": "OBD-II diagnostic port"}],
                "critical": [{"node": BRAKE, "asil": "D"}],
            },
        )
        result = reach.analyse(veh1[1], node_roles)
        f = findings.Finding(
            findings.NEWLY_REACHABLE, "x", "t", target=BRAKE, path=result.paths[0]
        )
        assert severity.BuiltinScorer(node_roles, result).score(f).feasibility == severity.VERY_LOW

    def test_authenticated_bus_traffic_is_low(self):
        f = findings.Finding(
            findings.SECOC_REMOVED, "x", "t", evidence={"authenticated": True, "target": "/n"}
        )
        s = severity.BuiltinScorer().score(f)
        assert s.feasibility == severity.LOW

    def test_not_applicable_authentication_is_not_treated_as_missing(self):
        """`authenticated is None` means SecOC does not apply; it is not a weakness."""
        f = findings.Finding(
            findings.SECOC_REMOVED, "x", "t", evidence={"authenticated": None, "target": "/n"}
        )
        assert severity.BuiltinScorer().score(f).feasibility == severity.VERY_LOW


class TestFixedCategories:
    def test_a_rehost_scores_low_and_informationally(self, veh1, veh3):
        s = _find(_pipeline(veh1, veh3), f"rehosted-component:{ABS}")
        assert s.risk == 1
        assert s.finding.informational

    def test_a_rehost_cannot_inherit_a_severe_impact(self, veh1, veh3):
        """Context findings are pinned by category, so they never dominate a report."""
        s = _find(_pipeline(veh1, veh3), f"rehosted-component:{ABS}")
        assert s.score.impact == severity.MODERATE

    def test_not_analysed_scores_negligible_by_design(self, veh1, veh2):
        """Its risk is meaningless — the gate must act on the category, not the number."""
        found = findings.collect(diff.compare(veh1[1], veh2[1]))
        s = _find(
            severity.score_all(found, severity.BuiltinScorer()), "not-analysed:reachability"
        )
        assert s.risk == 1


class TestOrdering:
    def test_worst_first(self, veh1, veh2):
        scored = _pipeline(veh1, veh2)
        assert [s.risk for s in scored] == sorted((s.risk for s in scored), reverse=True)

    def test_ordering_is_deterministic(self, veh1, veh2):
        first = [s.finding.id for s in _pipeline(veh1, veh2)]
        second = [s.finding.id for s in _pipeline(veh1, veh2)]
        assert first == second

    def test_every_finding_is_scored(self, veh1, veh2):
        found = findings.collect(diff.compare(veh1[1], veh2[1]))
        assert len(severity.score_all(found, severity.BuiltinScorer())) == len(found)


class TestScoreRendering:
    def test_str_shows_risk_and_ratings(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"newly-reachable:{TEL}->{BRAKE}")
        assert str(s.score) == "risk 5 [severe/high]"

    def test_str_marks_assumed_inputs(self, a_finding):
        assert "(assumed inputs)" in str(severity.BuiltinScorer().score(a_finding))

    def test_scored_str_includes_the_finding(self, veh1, veh2):
        s = _find(_pipeline(veh1, veh2), f"secoc-removed:{TEL_TO_GW}")
        assert str(s).startswith("risk 5")
        assert "[secoc-removed]" in str(s)

    def test_every_score_carries_a_rationale(self, veh1, veh2):
        """A number with no explanation is not actionable and will not be trusted."""
        assert all(s.score.rationale for s in _pipeline(veh1, veh2))


class TestExternalScorer:
    ECHO = """
import json, sys
data = json.load(sys.stdin)
json.dump({"impact": "severe", "feasibility": "high", "risk": 5,
           "rationale": ["seen: " + data["category"]]}, sys.stdout)
"""

    def test_the_external_verdict_is_used_verbatim(self, stub, a_finding):
        s = stub(self.ECHO).score(a_finding)
        assert (s.impact, s.feasibility, s.risk) == ("severe", "high", 5)

    def test_provenance_names_the_external_tool(self, stub, a_finding):
        s = stub(self.ECHO).score(a_finding)
        assert s.scorer.startswith("external:")

    def test_the_finding_reaches_the_tool(self, stub, a_finding):
        s = stub(self.ECHO).score(a_finding)
        assert s.rationale == ("seen: secoc-removed",)

    def test_the_path_is_forwarded_when_there_is_one(self, stub, tmp_path, veh1, veh2):
        record = tmp_path / "payload.json"
        scorer = stub(
            f"""
import json, sys
data = json.load(sys.stdin)
open({str(record)!r}, "w").write(json.dumps(data))
json.dump({{"impact": "major", "feasibility": "medium"}}, sys.stdout)
"""
        )
        rb = roles.classify(veh1[1], _seeds())
        ra = roles.classify(veh2[1], _seeds())
        rd = reach.compare(reach.analyse(veh1[1], rb), reach.analyse(veh2[1], ra))
        f = next(
            f for f in findings.collect(diff.compare(veh1[1], veh2[1]), rd)
            if f.category == findings.NEWLY_REACHABLE and f.target == BRAKE
        )
        scorer.score(f)
        payload = json.loads(record.read_text())
        assert payload["path"] == [TEL, GW, ABS, BRAKE]
        assert payload["unprotected_hops"] == [TEL_TO_GW]
        assert payload["target"] == BRAKE

    def test_an_omitted_risk_is_derived_from_the_matrix(self, stub, a_finding):
        s = stub(
            'import json,sys; json.load(sys.stdin); '
            'json.dump({"impact":"major","feasibility":"medium"}, sys.stdout)'
        ).score(a_finding)
        assert s.risk == severity.RISK_MATRIX[("major", "medium")]

    def test_an_out_of_range_risk_is_replaced(self, stub, a_finding):
        s = stub(
            'import json,sys; json.load(sys.stdin); '
            'json.dump({"impact":"major","feasibility":"low","risk":99}, sys.stdout)'
        ).score(a_finding)
        assert s.risk == severity.RISK_MATRIX[("major", "low")]

    def test_an_unknown_vocabulary_is_rejected(self, stub, a_finding):
        scorer = stub(
            'import json,sys; json.load(sys.stdin); '
            'json.dump({"impact":"catastrophic","feasibility":"trivial"}, sys.stdout)'
        )
        with pytest.raises(severity.ScorerError, match="vocabulary"):
            scorer.score(a_finding)

    def test_invalid_json_is_rejected(self, stub, a_finding):
        scorer = stub('import sys; sys.stdin.read(); print("not json")')
        with pytest.raises(severity.ScorerError, match="invalid JSON"):
            scorer.score(a_finding)

    def test_a_nonzero_exit_is_reported(self, stub, a_finding):
        scorer = stub('import sys; sys.stdin.read(); sys.exit(3)')
        with pytest.raises(severity.ScorerError, match="failed on"):
            scorer.score(a_finding)

    def test_a_missing_command_is_reported(self, a_finding):
        scorer = severity.ExternalScorer(["/nonexistent/scorer"])
        with pytest.raises(severity.ScorerError):
            scorer.score(a_finding)

    def test_the_failing_finding_is_identified(self, stub, a_finding):
        scorer = stub('import sys; sys.stdin.read(); sys.exit(1)')
        with pytest.raises(severity.ScorerError, match=a_finding.id):
            scorer.score(a_finding)

    def test_an_external_scorer_may_declare_its_own_assumptions(self, stub, a_finding):
        s = stub(
            'import json,sys; json.load(sys.stdin); '
            'json.dump({"impact":"major","feasibility":"low","assumed":True}, sys.stdout)'
        ).score(a_finding)
        assert s.assumed is True


class TestFallbackScorer:
    def test_a_working_primary_is_left_alone(self, stub, a_finding):
        primary = stub(
            'import json,sys; json.load(sys.stdin); '
            'json.dump({"impact":"severe","feasibility":"high"}, sys.stdout)'
        )
        s = severity.FallbackScorer(primary, severity.BuiltinScorer()).score(a_finding)
        assert s.scorer == primary.name
        assert "fallback" not in s.scorer

    def test_a_broken_primary_falls_back(self, stub, a_finding):
        broken = stub('import sys; sys.stdin.read(); sys.exit(1)')
        s = severity.FallbackScorer(broken, severity.BuiltinScorer()).score(a_finding)
        assert s.risk >= 1

    def test_the_fallback_is_visible_in_the_provenance(self, stub, a_finding):
        """Silently degrading from a programme's TARA to a guess would be a lie."""
        broken = stub('import sys; sys.stdin.read(); sys.exit(1)')
        s = severity.FallbackScorer(broken, severity.BuiltinScorer()).score(a_finding)
        assert "fallback from" in s.scorer

    def test_a_fallback_score_is_always_assumed(self, stub, veh1, veh2):
        broken = stub('import sys; sys.stdin.read(); sys.exit(1)')
        node_roles = roles.classify(veh2[1], _seeds())
        found = findings.collect(diff.compare(veh1[1], veh2[1]))
        f = next(f for f in found if f.category == findings.SECOC_REMOVED)
        s = severity.FallbackScorer(broken, severity.BuiltinScorer(node_roles)).score(f)
        assert s.assumed is True

    def test_the_reason_is_appended_to_the_rationale(self, stub, a_finding):
        broken = stub('import sys; sys.stdin.read(); sys.exit(1)')
        s = severity.FallbackScorer(broken, severity.BuiltinScorer()).score(a_finding)
        assert any("unavailable" in r for r in s.rationale)

    def test_errors_are_collected_for_the_report(self, stub, a_finding):
        broken = stub('import sys; sys.stdin.read(); sys.exit(1)')
        scorer = severity.FallbackScorer(broken, severity.BuiltinScorer())
        scorer.score(a_finding)
        scorer.score(a_finding)
        assert len(scorer.errors) == 2

    def test_a_non_scorer_error_is_not_swallowed(self, a_finding):
        """Only ScorerError means "try the other one"; a bug must still surface."""

        class Exploding:
            name = "boom"

            def score(self, finding):
                raise ValueError("bug in the scorer")

        with pytest.raises(ValueError):
            severity.FallbackScorer(Exploding(), severity.BuiltinScorer()).score(a_finding)
