"""Findings tests: the judgement layer, checked against the verified diff values.

Two things are under test here that matter more than the categories themselves:

* a `SecOC removed` finding and an `arrived without SecOC` finding are *different*,
  because `authenticated` moving True -> False is a regression while None -> False is
  a new hop that was never protected;
* an absent or unanswerable reachability analysis produces a finding, not silence.
"""

import pytest

from arxml_secdiff import diff, findings, reach, roles, secoc
from arxml_secdiff import graph as graph_mod

from .conftest import ABS, BRAKE, GW, TEL

TEL_TO_GW = "/V/Swc/Veh/telToGw#data"
GW_TO_ABS = "/V/Swc/Veh/gwToAbs#data"
ABS_TO_BRAKE = "/V/Swc/Veh/absToBrake#data"
CMD_PDU = "/V/Comm/CmdIPdu"
BRK_PDU = "/V/Comm/BrkIPdu"


def _seeds():
    return {
        "entry": [{"node": TEL, "reason": "cellular telematics, external attack surface"}],
        "critical": [
            {"node": BRAKE, "asil": "D", "reason": "service braking"},
            {"node": ABS, "asil": "C", "reason": "anti-lock braking"},
        ],
    }


def _reach(graph, config=None, heuristics=True):
    r = roles.classify(graph, config if config is not None else _seeds(), heuristics)
    return reach.analyse(graph, r)


def _collect(before, after, with_reach=True):
    """Full pipeline over two annotated snapshots."""
    structural = diff.compare(before[1], after[1])
    if not with_reach:
        return findings.collect(structural)
    rd = reach.compare(_reach(before[1]), _reach(after[1]))
    return findings.collect(structural, rd)


def _by(found, category):
    return tuple(f for f in found if f.category == category)


def _one(found, category):
    matches = _by(found, category)
    assert len(matches) == 1, f"expected exactly one {category}, got {len(matches)}"
    return matches[0]


class TestSecOcRemoved:
    """v1 -> v2 deletes CmdSecuredIPdu: authenticated moves True -> False."""

    def test_a_secoc_removed_finding_is_raised(self, veh1, veh2):
        assert _by(_collect(veh1, veh2), findings.SECOC_REMOVED)

    def test_it_names_the_connector_that_lost_protection(self, veh1, veh2):
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        assert f.subject == TEL_TO_GW

    def test_the_pdu_is_carried_as_evidence(self, veh1, veh2):
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        assert f.evidence["unprotected_pdus"] == (CMD_PDU,)

    def test_the_field_change_is_carried_as_evidence(self, veh1, veh2):
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        assert "authenticated: True -> False" in f.evidence["changed_fields"]

    def test_it_is_not_informational(self, veh1, veh2):
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        assert not f.informational

    def test_the_newly_added_authenticated_hop_raises_nothing(self, veh1, veh2):
        """gw -> abs arrived *with* SecOC, so it is not a SecOC finding at all."""
        found = _collect(veh1, veh2)
        assert not any(f.subject == GW_TO_ABS for f in found if "secoc" in f.category)
        assert not _by(found, findings.UNPROTECTED_NEW_HOP)


class TestUnprotectedNewHop:
    """v1 -> v3 rehosts abs: authenticated moves None -> False, which is not a removal."""

    def test_the_new_bus_hop_is_reported(self, veh1, veh3):
        f = _one(_collect(veh1, veh3), findings.UNPROTECTED_NEW_HOP)
        assert f.subject == ABS_TO_BRAKE

    def test_it_is_not_reported_as_a_removal(self, veh1, veh3):
        """Nothing was taken away — the hop was never on a bus before."""
        assert _by(_collect(veh1, veh3), findings.SECOC_REMOVED) == ()

    def test_the_pdu_is_carried_as_evidence(self, veh1, veh3):
        f = _one(_collect(veh1, veh3), findings.UNPROTECTED_NEW_HOP)
        assert f.evidence["unprotected_pdus"] == (BRK_PDU,)

    def test_bus_visibility_change_is_reported_separately(self, veh1, veh3):
        f = _one(_collect(veh1, veh3), findings.NEWLY_BUS_VISIBLE)
        assert f.subject == ABS_TO_BRAKE
        assert f.evidence["pdus"] == (BRK_PDU,)

    def test_the_rehost_is_reported_as_context(self, veh1, veh3):
        f = _one(_collect(veh1, veh3), findings.REHOSTED)
        assert f.subject == ABS
        assert f.evidence == {"before": "ChassisEcu", "after": "GatewayEcu"}

    def test_the_rehost_is_informational(self, veh1, veh3):
        """A component moving ECU is worth reading, but must not fail a build alone."""
        assert _one(_collect(veh1, veh3), findings.REHOSTED).informational


class TestNewlyReachable:
    def test_brake_becomes_reachable_from_the_modem(self, veh1, veh2):
        found = _by(_collect(veh1, veh2), findings.NEWLY_REACHABLE)
        assert any(f.target == BRAKE for f in found)

    def test_the_subject_is_the_entry_target_pair(self, veh1, veh2):
        found = _by(_collect(veh1, veh2), findings.NEWLY_REACHABLE)
        assert f"{TEL}->{BRAKE}" in {f.subject for f in found}

    def test_the_whole_path_is_carried_as_evidence(self, veh1, veh2):
        f = next(f for f in _by(_collect(veh1, veh2), findings.NEWLY_REACHABLE) if f.target == BRAKE)
        assert f.evidence["path"] == (TEL, GW, ABS, BRAKE)

    def test_the_path_object_is_attached_for_the_scorer(self, veh1, veh2):
        f = next(f for f in _by(_collect(veh1, veh2), findings.NEWLY_REACHABLE) if f.target == BRAKE)
        assert f.path is not None
        assert f.path.nodes == (TEL, GW, ABS, BRAKE)

    def test_the_route_is_not_fully_protected(self, veh1, veh2):
        f = next(f for f in _by(_collect(veh1, veh2), findings.NEWLY_REACHABLE) if f.target == BRAKE)
        assert f.evidence["fully_protected"] is False
        assert f.evidence["unprotected_hops"] == (TEL_TO_GW,)

    def test_abs_is_reported_as_well_as_brake(self, veh1, veh2):
        """Two critical nodes became reachable; both are findings."""
        found = _by(_collect(veh1, veh2), findings.NEWLY_REACHABLE)
        assert {f.target for f in found} == {ABS, BRAKE}

    def test_the_rehost_adds_no_reachability_finding(self, veh1, veh3):
        """v3 wires no new connector, so nothing new is reachable."""
        assert _by(_collect(veh1, veh3), findings.NEWLY_REACHABLE) == ()


class TestNoChange:
    def test_an_identical_pair_yields_no_findings(self, veh1, veh1_again):
        assert _collect(veh1, veh1_again) == ()

    def test_an_identical_pair_is_not_merely_quiet(self, veh1, veh1_again):
        """Empty here is a real result: the analysis ran and found nothing."""
        rd = reach.compare(_reach(veh1[1]), _reach(veh1_again[1]))
        assert rd.updated.analysed is True
        assert findings.collect(diff.compare(veh1[1], veh1_again[1]), rd) == ()


class TestInconclusive:
    def test_an_unseeded_snapshot_reports_a_gap_not_silence(self, veh1, veh2):
        """The load-bearing case: no entry seed must not look like a clean release."""
        d = diff.compare(veh1[1], veh2[1])
        no_entry = {"critical": [BRAKE]}
        rd = reach.compare(
            _reach(veh1[1], no_entry, heuristics=False),
            _reach(veh2[1], no_entry, heuristics=False),
        )
        found = findings.collect(d, rd)
        assert len(_by(found, findings.NOT_ANALYSED)) == 2

    def test_the_gap_reason_is_carried(self, veh1, veh2):
        no_entry = {"critical": [BRAKE]}
        rd = reach.compare(
            _reach(veh1[1], no_entry, heuristics=False),
            _reach(veh2[1], no_entry, heuristics=False),
        )
        f = _by(findings.collect(diff.compare(veh1[1], veh2[1]), rd), findings.NOT_ANALYSED)[0]
        assert f.evidence["gaps"] == ("no entry point present in this snapshot",)

    def test_both_snapshots_are_named_separately(self, veh1, veh2):
        no_entry = {"critical": [BRAKE]}
        rd = reach.compare(
            _reach(veh1[1], no_entry, heuristics=False),
            _reach(veh2[1], no_entry, heuristics=False),
        )
        found = _by(findings.collect(diff.compare(veh1[1], veh2[1]), rd), findings.NOT_ANALYSED)
        assert {f.evidence["snapshot"] for f in found} == {"before", "updated"}

    def test_omitting_reachability_entirely_is_also_reported(self, veh1, veh2):
        """A structural-only run must not imply reachability was checked and clean."""
        found = _collect(veh1, veh2, with_reach=False)
        f = _one(found, findings.NOT_ANALYSED)
        assert f.subject == "reachability"

    def test_a_structural_only_run_still_finds_the_secoc_regression(self, veh1, veh2):
        assert _by(_collect(veh1, veh2, with_reach=False), findings.SECOC_REMOVED)

    def test_not_analysed_is_not_informational(self, veh1, veh2):
        """It cannot be waved through: the gate has to act on it."""
        f = _one(_collect(veh1, veh2, with_reach=False), findings.NOT_ANALYSED)
        assert not f.informational


class TestIdentity:
    def test_id_combines_category_and_subject(self, veh1, veh2):
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        assert f.id == f"secoc-removed:{TEL_TO_GW}"

    def test_ids_are_unique_within_a_run(self, veh1, veh2):
        found = _collect(veh1, veh2)
        assert len({f.id for f in found}) == len(found)

    def test_ids_are_stable_across_repeated_runs(self, veh1, veh2):
        """A gate that cannot be befored gets switched off, so this is load-bearing."""
        first = [f.id for f in _collect(veh1, veh2)]
        second = [f.id for f in _collect(veh1, veh2)]
        assert first == second

    def test_evidence_does_not_affect_equality(self, veh1, veh2):
        """Two findings about the same thing compare equal even if proof differs."""
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        stripped = findings.Finding(f.category, f.subject, f.title, f.detail)
        assert stripped == f

    def test_str_leads_with_the_category(self, veh1, veh2):
        f = _one(_collect(veh1, veh2), findings.SECOC_REMOVED)
        assert str(f).startswith("[secoc-removed]")


class TestComponentLifecycle:
    def test_added_and_removed_components_are_informational(self):
        added = findings.Finding(findings.COMPONENT_ADDED, "/x", "New component x")
        removed = findings.Finding(findings.COMPONENT_REMOVED, "/x", "Component x removed")
        assert added.informational and removed.informational

    def test_reachability_findings_are_never_informational(self):
        for category in (
            findings.NEWLY_REACHABLE,
            findings.NEW_ATTACK_PATH,
            findings.SECOC_REMOVED,
            findings.UNPROTECTED_NEW_HOP,
            findings.NEWLY_BUS_VISIBLE,
            findings.NOT_ANALYSED,
        ):
            assert not findings.Finding(category, "/x", "t").informational


class TestRealEcuExtract:
    def test_an_unchanged_real_snapshot_yields_only_the_analysis_gap(self, real, build):
        """No diff, no seeds: the only honest output is "not analysed"."""
        g = secoc.annotate(build(real), real)
        d = diff.compare(g, g)
        rd = reach.compare(reach.analyse(g, roles.classify(g)), reach.analyse(g, roles.classify(g)))
        found = findings.collect(d, rd)
        assert d.empty
        assert len(_by(found, findings.NOT_ANALYSED)) == 2
        assert {f.category for f in found} == {findings.NOT_ANALYSED}
