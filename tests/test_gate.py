"""Gate tests: the release decision, and the ways it must refuse to be convenient.

The scenario tests run the whole pipeline over the veh trio. The policy tests use
synthetic scored findings, because the behaviour under test is the rule, not the
architecture that produced it.
"""

import pytest

from arxml_secdiff import diff, findings, gate, reach, roles, secoc, severity
from arxml_secdiff import graph as graph_mod

from .conftest import ABS, BRAKE, GW, TEL


def _seeds():
    return {
        "entry": [{"node": TEL, "reason": "cellular telematics uplink"}],
        "critical": [
            {"node": BRAKE, "asil": "D", "reason": "service braking"},
            {"node": ABS, "asil": "C", "reason": "anti-lock braking"},
        ],
    }


def _decide(before, after, config=None, policy=None, with_reach=True, heuristics=True):
    config = _seeds() if config is None else config
    node_roles = roles.classify(after[1], config, heuristics)
    result = reach.analyse(after[1], node_roles)
    rd = (
        reach.compare(
            reach.analyse(before[1], roles.classify(before[1], config, heuristics)), result
        )
        if with_reach
        else None
    )
    found = findings.collect(diff.compare(before[1], after[1]), rd)
    scored = severity.score_all(found, severity.BuiltinScorer(node_roles, result))
    return gate.evaluate(scored, policy)


def _scored(risk, category=findings.NEWLY_REACHABLE, subject="/x", assumed=False):
    """A synthetic scored finding, for exercising policy rather than analysis."""
    finding = findings.Finding(category, subject, f"{category} at {subject}")
    score = severity.Score(
        impact=severity.SEVERE, feasibility=severity.HIGH, risk=risk, assumed=assumed
    )
    return severity.Scored(finding, score)


class TestScenarios:
    def test_a_new_route_to_the_brakes_blocks(self, veh1, veh2):
        assert _decide(veh1, veh2).verdict == gate.BLOCK

    def test_the_blocking_reason_names_the_worst_finding(self, veh1, veh2):
        d = _decide(veh1, veh2)
        assert "tel can now reach brake" in d.reasons[0]

    def test_an_unauthenticated_brake_hop_blocks(self, veh1, veh3):
        assert _decide(veh1, veh3).verdict == gate.BLOCK

    def test_an_unchanged_release_passes(self, veh1, veh1_again):
        assert _decide(veh1, veh1_again).verdict == gate.PASS

    def test_a_passing_release_gives_exit_zero(self, veh1, veh1_again):
        assert _decide(veh1, veh1_again).exit_code == 0

    def test_a_blocked_release_gives_a_nonzero_exit(self, veh1, veh2):
        assert _decide(veh1, veh2).exit_code != 0

    def test_guessed_seeds_flag_rather_than_block(self, veh1, veh2):
        """Same architecture, no TARA: the finding is real but the claim is weaker."""
        assert _decide(veh1, veh2, config={}).verdict == gate.FLAG

    def test_the_rehost_alone_does_not_decide_anything(self, veh1, veh3):
        d = _decide(veh1, veh3)
        assert d.informational
        assert all(s.finding.informational for s in d.informational)
        assert not any(s.finding.informational for s in d.considered)


class TestInconclusive:
    def test_a_missing_reachability_analysis_is_not_a_pass(self, veh1, veh1_again):
        """The load-bearing case for the whole module."""
        d = _decide(veh1, veh1_again, with_reach=False)
        assert d.verdict == gate.INCONCLUSIVE
        assert not d.passed

    def test_it_says_which_part_did_not_run(self, veh1, veh1_again):
        d = _decide(veh1, veh1_again, with_reach=False)
        assert "did not run" in " ".join(d.reasons)

    def test_an_unseeded_snapshot_is_inconclusive(self, veh1, veh1_again):
        d = _decide(veh1, veh1_again, config={"critical": [BRAKE]}, heuristics=False)
        assert d.verdict == gate.INCONCLUSIVE

    def test_inconclusive_exits_two_by_default(self, veh1, veh1_again):
        assert _decide(veh1, veh1_again, with_reach=False).exit_code == 2

    def test_a_strict_policy_makes_it_fatal(self, veh1, veh1_again):
        d = _decide(
            veh1, veh1_again, with_reach=False, policy=gate.Policy(inconclusive_blocks=True)
        )
        assert d.exit_code == gate.EXIT_CODES[gate.BLOCK]

    def test_the_verdict_stays_honest_under_a_strict_policy(self, veh1, veh1_again):
        """Escalating the consequence must not relabel the finding as a known defect."""
        d = _decide(
            veh1, veh1_again, with_reach=False, policy=gate.Policy(inconclusive_blocks=True)
        )
        assert d.verdict == gate.INCONCLUSIVE

    def test_a_real_blocking_finding_outranks_it(self, veh1, veh2):
        """You know enough to block, so say block."""
        d = _decide(veh1, veh2, with_reach=False)
        assert d.verdict == gate.BLOCK
        assert d.unanalysed  # still reported

    def test_it_outranks_a_mere_flag(self):
        d = gate.evaluate(
            (_scored(3), _scored(1, findings.NOT_ANALYSED, "reachability")),
        )
        assert d.verdict == gate.INCONCLUSIVE

    def test_its_own_risk_score_is_irrelevant(self):
        """not-analysed scores 1 by design; the category is what carries the weight."""
        d = gate.evaluate((_scored(1, findings.NOT_ANALYSED, "reachability"),))
        assert d.verdict == gate.INCONCLUSIVE


class TestThresholds:
    def test_risk_at_the_block_threshold_blocks(self):
        assert gate.evaluate((_scored(5),)).verdict == gate.BLOCK

    def test_risk_at_the_flag_threshold_flags(self):
        assert gate.evaluate((_scored(3),)).verdict == gate.FLAG

    def test_risk_below_the_flag_threshold_passes(self):
        assert gate.evaluate((_scored(2),)).verdict == gate.PASS

    def test_no_findings_at_all_passes(self):
        assert gate.evaluate(()).verdict == gate.PASS

    def test_thresholds_are_configurable(self):
        strict = gate.Policy(block_at=2, flag_at=1)
        assert gate.evaluate((_scored(2),), strict).verdict == gate.BLOCK

    def test_a_lenient_policy_can_demote_a_five(self):
        lenient = gate.Policy(block_at=6, flag_at=5)
        d = gate.evaluate((_scored(5),), lenient)
        assert d.verdict == gate.FLAG

    def test_a_flag_threshold_above_the_block_threshold_is_rejected(self):
        """It would hide every blocking finding from triage, so it cannot be a typo."""
        with pytest.raises(ValueError, match="invisible to triage"):
            gate.Policy(block_at=3, flag_at=5)

    def test_equal_thresholds_are_allowed(self):
        assert gate.Policy(block_at=4, flag_at=4).flag_at == 4

    def test_blocking_and_flagged_do_not_overlap(self):
        d = gate.evaluate((_scored(5, subject="/a"), _scored(3, subject="/b")))
        assert len(d.blocking) == 1
        assert len(d.flagged) == 1


class TestAssumedInputs:
    def test_an_assumed_finding_does_not_block_by_default(self):
        d = gate.evaluate((_scored(5, assumed=True),))
        assert d.verdict == gate.FLAG

    def test_the_downgrade_is_reported(self):
        """Quietly not blocking would be indistinguishable from not noticing."""
        d = gate.evaluate((_scored(5, assumed=True),))
        assert d.downgraded
        assert any("inputs were guessed" in r for r in d.reasons)

    def test_the_reason_names_the_setting_that_changes_it(self):
        d = gate.evaluate((_scored(5, assumed=True),))
        assert any("block_on_assumed" in r for r in d.reasons)

    def test_a_strict_policy_lets_it_block(self):
        d = gate.evaluate((_scored(5, assumed=True),), gate.Policy(block_on_assumed=True))
        assert d.verdict == gate.BLOCK
        assert not d.downgraded

    def test_a_confirmed_finding_is_unaffected(self):
        d = gate.evaluate((_scored(5, assumed=False),))
        assert d.verdict == gate.BLOCK
        assert not d.downgraded

    def test_an_assumed_finding_below_the_threshold_is_not_downgraded(self):
        d = gate.evaluate((_scored(3, assumed=True),))
        assert d.downgraded == ()


class TestAcceptance:
    def test_an_accepted_finding_does_not_block(self):
        policy = gate.Policy(accepted=frozenset({"newly-reachable:/x"}))
        assert gate.evaluate((_scored(5),), policy).verdict == gate.PASS

    def test_an_accepted_finding_is_still_reported(self):
        policy = gate.Policy(accepted=frozenset({"newly-reachable:/x"}))
        d = gate.evaluate((_scored(5),), policy)
        assert len(d.accepted) == 1
        assert d.considered == ()

    def test_acceptance_is_keyed_on_the_finding_id(self):
        policy = gate.Policy(accepted=frozenset({"newly-reachable:/other"}))
        assert gate.evaluate((_scored(5),), policy).verdict == gate.BLOCK

    def test_a_stale_acceptance_is_surfaced(self):
        """A waiver for something no longer present is a sign the config drifted."""
        policy = gate.Policy(accepted=frozenset({"newly-reachable:/gone"}))
        d = gate.evaluate((_scored(2),), policy)
        assert d.stale_acceptances == ("newly-reachable:/gone",)
        assert any("no longer present" in r for r in d.reasons)

    def test_a_used_acceptance_is_not_stale(self):
        policy = gate.Policy(accepted=frozenset({"newly-reachable:/x"}))
        assert gate.evaluate((_scored(5),), policy).stale_acceptances == ()

    def test_an_unanalysed_finding_cannot_be_waived(self):
        """Otherwise the first response to an inconclusive gate is to waive it."""
        policy = gate.Policy(accepted=frozenset({"not-analysed:reachability"}))
        d = gate.evaluate((_scored(1, findings.NOT_ANALYSED, "reachability"),), policy)
        assert d.verdict == gate.INCONCLUSIVE

    def test_the_refusal_is_explained(self):
        policy = gate.Policy(accepted=frozenset({"not-analysed:reachability"}))
        d = gate.evaluate((_scored(1, findings.NOT_ANALYSED, "reachability"),), policy)
        assert d.refused_acceptances == ("not-analysed:reachability",)
        assert any("cannot be waived" in r for r in d.reasons)

    def test_a_refused_acceptance_is_not_also_stale(self):
        policy = gate.Policy(accepted=frozenset({"not-analysed:reachability"}))
        d = gate.evaluate((_scored(1, findings.NOT_ANALYSED, "reachability"),), policy)
        assert d.stale_acceptances == ()

    def test_a_real_finding_can_be_accepted_end_to_end(self, veh1, veh3):
        """The rehost and the bus hop are known and signed off; the release proceeds."""
        blocked = _decide(veh1, veh3)
        policy = gate.Policy(accepted=frozenset(s.finding.id for s in blocked.considered))
        assert _decide(veh1, veh3, policy=policy).verdict == gate.PASS


class TestPolicyLoading:
    def test_defaults_are_the_documented_ones(self):
        p = gate.Policy()
        assert (p.block_at, p.flag_at) == (5, 3)
        assert p.block_on_assumed is False
        assert p.inconclusive_blocks is False

    def test_from_dict_reads_every_field(self):
        p = gate.Policy.from_dict(
            {
                "block_at": 4,
                "flag_at": 2,
                "block_on_assumed": True,
                "inconclusive_blocks": True,
                "accepted": ["a:b"],
            }
        )
        assert (p.block_at, p.flag_at) == (4, 2)
        assert p.block_on_assumed and p.inconclusive_blocks
        assert p.accepted == frozenset({"a:b"})

    def test_an_empty_dict_gives_defaults(self):
        assert gate.Policy.from_dict({}) == gate.Policy()

    def test_none_gives_defaults(self):
        assert gate.Policy.from_dict(None) == gate.Policy()

    def test_yaml_round_trips(self, tmp_path):
        path = tmp_path / "policy.yaml"
        path.write_text(
            "block_at: 4\nflag_at: 2\nblock_on_assumed: true\naccepted:\n  - 'rehosted-component:/V/Swc/Veh/abs'\n"
        )
        p = gate.load_policy(path)
        assert p.block_at == 4
        assert p.accepted == frozenset({"rehosted-component:/V/Swc/Veh/abs"})

    def test_an_empty_yaml_file_gives_defaults(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("")
        assert gate.load_policy(path) == gate.Policy()

    def test_an_invalid_yaml_policy_is_rejected_at_load(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("block_at: 2\nflag_at: 4\n")
        with pytest.raises(ValueError):
            gate.load_policy(path)


class TestReporting:
    def test_worst_is_the_highest_risk(self):
        d = gate.evaluate((_scored(2, subject="/a"), _scored(5, subject="/b")))
        assert d.worst.finding.subject == "/b"

    def test_worst_is_none_when_nothing_was_considered(self):
        assert gate.evaluate(()).worst is None

    def test_considered_is_ordered_worst_first(self, veh1, veh2):
        d = _decide(veh1, veh2)
        assert [s.risk for s in d.considered] == sorted(
            (s.risk for s in d.considered), reverse=True
        )

    def test_summary_covers_every_bucket(self, veh1, veh3):
        s = _decide(veh1, veh3).summary()
        assert set(s) == {
            "verdict",
            "exit_code",
            "blocking",
            "flagged",
            "unanalysed",
            "downgraded",
            "informational",
            "accepted",
        }

    def test_summary_counts_the_rehost_as_informational(self, veh1, veh3):
        assert _decide(veh1, veh3).summary()["informational"] == 1

    def test_str_leads_with_the_verdict(self, veh1, veh2):
        assert str(_decide(veh1, veh2)).startswith("BLOCK:")

    def test_a_pass_still_explains_itself(self, veh1, veh1_again):
        assert "no finding reached the flag threshold" in str(_decide(veh1, veh1_again))

    def test_every_verdict_has_an_exit_code(self):
        assert set(gate.EXIT_CODES) == set(gate.PRECEDENCE)

    def test_only_pass_exits_zero(self):
        assert [v for v, c in gate.EXIT_CODES.items() if c == 0] == [gate.PASS]
