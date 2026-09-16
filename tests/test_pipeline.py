"""Pipeline and report tests: the wiring, and what the output is obliged to disclose.

The pipeline is thin by design, so most of these check that it wired the stages
together in the right order and did not drop anything on the way. The report tests are
mostly about honesty: a limitation that the JSON records and the text omits would let a
reader draw a conclusion the tool cannot support.
"""

import json

import pytest

from arxml_secdiff import gate, pipeline, report, roles, secoc, severity

from .conftest import ABS, BRAKE, FIXTURES, GW, TEL, V1, V2, V3, VEH_ROLES

CMD_PDU = "/V/Comm/CmdIPdu"


def _run(before=V1, after=V2, **kwargs):
    kwargs.setdefault("roles_config", VEH_ROLES)
    return pipeline.run([before], [after], **kwargs)


class TestLoad:
    def test_a_snapshot_carries_every_stage(self):
        snap = pipeline.load("before", [V1], roles_config=VEH_ROLES)
        assert snap.graph.number_of_nodes() == 4
        assert snap.node_roles.entry == (TEL,)
        assert snap.reachability.analysed is True

    def test_the_label_is_kept_for_the_report(self):
        assert pipeline.load("before", [V1]).label == "before"

    def test_sources_are_kept_for_the_report(self):
        assert pipeline.load("before", [V1]).sources == (FIXTURES / "veh_v1.arxml",)

    def test_the_graph_is_secoc_annotated(self):
        """Loading must not hand back a bare graph; the diff depends on the attributes."""
        snap = pipeline.load("before", [V1])
        attrs = next(iter(snap.graph[TEL][GW].values()))
        assert attrs["authenticated"] is True
        assert attrs["secoc_source"] == secoc.FROM_ARXML

    def test_cutoff_is_honoured(self):
        snap = pipeline.load("updated", [V2], roles_config=VEH_ROLES, cutoff=1)
        assert all(p.length <= 1 for p in snap.reachability.paths)

    def test_heuristics_can_be_forbidden(self):
        snap = pipeline.load("before", [V1], roles_config={}, heuristics=False)
        assert snap.node_roles.assignments == ()
        assert snap.reachability.analysed is False

    def test_summary_counts_the_snapshot(self):
        s = pipeline.load("updated", [V2], roles_config=VEH_ROLES).summary()
        assert s["components"] == 4
        assert s["connections"] == 3
        assert s["attack_paths"] == 2


class TestRun:
    def test_it_reaches_a_verdict(self):
        assert _run().verdict == gate.BLOCK

    def test_the_exit_code_comes_from_the_gate(self):
        analysis = _run()
        assert analysis.exit_code == analysis.decision.exit_code

    def test_every_stage_is_retained(self):
        a = _run()
        assert a.structural.summary()["edges_added"] == 1
        assert a.reach_diff.summary()["new_pairs"] == 2
        assert len(a.findings) == 3
        assert len(a.scored) == 3

    def test_the_secoc_diff_is_run_on_models_not_the_graph(self):
        """PDU-level protection changes exist whether or not a connector changed."""
        changes = _run().secoc_changes
        lost = [c.pdu for c in changes if c.lost_protection]
        assert lost == [CMD_PDU]

    def test_the_same_seeds_are_applied_to_both_snapshots(self):
        """Different seeds either side would make the reachability diff meaningless."""
        a = _run()
        assert a.before.node_roles.entry == a.updated.node_roles.entry
        assert a.before.node_roles.critical == a.updated.node_roles.critical

    def test_the_default_scorer_sees_the_updated_routes(self):
        """Inheriting downstream impact needs the updated snapshot's paths."""
        secoc_finding = next(
            s for s in _run().scored if s.finding.category == "secoc-removed"
        )
        assert secoc_finding.risk == 5

    def test_an_identical_pair_passes(self):
        assert _run(V1, V1).verdict == gate.PASS

    def test_a_policy_is_applied(self):
        lenient = gate.Policy(block_at=6, flag_at=5)
        assert _run(policy=lenient).verdict == gate.FLAG

    def test_an_explicit_scorer_is_used(self):
        class Flat:
            name = "flat"

            def score(self, finding):
                return severity.Score("negligible", "very-low", 1, scorer="flat")

        a = _run(scorer=Flat())
        assert a.verdict == gate.PASS
        assert {s.score.scorer for s in a.scored} == {"flat"}

    def test_the_rehost_scenario_is_reported_too(self):
        a = _run(V1, V3)
        assert a.structural.summary()["rehosted"] == 1
        assert a.verdict == gate.BLOCK

    def test_a_missing_file_raises_oserror(self):
        with pytest.raises(OSError):
            pipeline.run(["/nonexistent.arxml"], [V2])

    def test_summary_is_json_serialisable(self):
        """The summary goes into CI output, so it must survive json.dumps."""
        json.dumps(_run().summary())


class TestOverlay:
    def test_an_overlay_supplies_protection_the_arxml_lacks(self, overlay_path):
        snap = pipeline.load("updated", [FIXTURES / "bus_signals.arxml"], overlay=overlay_path)
        assert snap.profiles

    def test_overlay_sourced_profiles_are_identified(self, overlay_path):
        snap = pipeline.load("updated", [FIXTURES / "bus_signals.arxml"], overlay=overlay_path)
        overlaid = snap.synthetic_secoc
        assert overlaid
        assert all(snap.profiles[p].source == secoc.FROM_OVERLAY for p in overlaid)

    def test_arxml_evidence_is_never_counted_as_synthetic(self):
        assert pipeline.load("before", [V1]).synthetic_secoc == ()


class TestLimitations:
    def test_a_clean_configured_run_records_none(self):
        assert report.limitations(_run()) == ()

    def test_guessed_seeds_are_disclosed(self):
        notes = report.limitations(_run(roles_config={}))
        assert any("guessed" in n for n in notes)
        assert any("HARA/TARA" in n for n in notes)

    def test_an_overlay_is_disclosed_as_an_assumption(self, overlay_path):
        a = pipeline.run(
            [FIXTURES / "bus_signals.arxml"],
            [FIXTURES / "bus_signals.arxml"],
            roles_config=VEH_ROLES,
            before_overlay=overlay_path,
            updated_overlay=overlay_path,
        )
        notes = report.limitations(a)
        assert any("YAML overlay" in n for n in notes)
        assert any("modelled assumptions" in n for n in notes)

    def test_an_unmatched_config_pattern_is_disclosed(self):
        a = _run(roles_config={"entry": [TEL], "critical": ["/V/Swc/Veh/typo"]})
        notes = report.limitations(a)
        assert any("matched no component" in n for n in notes)

    def test_an_unanalysed_snapshot_is_disclosed(self):
        a = _run(roles_config={"critical": [BRAKE]}, heuristics=False)
        assert any("was not analysed" in n for n in report.limitations(a))

    def test_a_downgraded_finding_is_disclosed(self):
        a = _run(roles_config={}, policy=gate.Policy(block_at=4))
        assert any("did not block" in n for n in report.limitations(a))

    def test_a_stale_acceptance_is_disclosed(self):
        a = _run(policy=gate.Policy(accepted=frozenset({"newly-reachable:/gone"})))
        assert any("not present in this release" in n for n in report.limitations(a))

    def test_a_refused_acceptance_is_disclosed(self):
        a = _run(
            V1,
            V1,
            roles_config={"critical": [BRAKE]},
            heuristics=False,
            policy=gate.Policy(accepted=frozenset({"not-analysed:before-reachability"})),
        )
        assert any("cannot be waived" in n for n in report.limitations(a))


class TestTextReport:
    def test_the_verdict_is_near_the_top(self):
        head = report.text(_run()).splitlines()[:10]
        assert any(line.startswith("VERDICT: BLOCK") for line in head)

    def test_both_source_files_are_named(self):
        text = report.text(_run())
        assert "veh_v1.arxml" in text and "veh_v2.arxml" in text

    def test_changed_snapshot_counts_are_marked(self):
        text = report.text(_run())
        assert "attack paths" in text
        assert any(line.rstrip().endswith("*") for line in text.splitlines())

    def test_every_finding_appears(self):
        a = _run()
        text = report.text(a)
        for item in a.scored:
            assert item.finding.id in text

    def test_the_rationale_appears(self):
        assert "because   brake is ASIL D" in report.text(_run())

    def test_the_route_is_drawn_hop_by_hop(self):
        text = report.text(_run())
        assert "tel -> gw -> abs -> brake" in text
        assert "UNAUTHENTICATED" in text

    def test_a_not_applicable_hop_is_not_called_a_weakness(self):
        """`authenticated is None` must read as inapplicable, not as missing SecOC."""
        assert "RTE-local (SecOC not applicable)" in report.text(_run())

    def test_the_secoc_profile_change_is_shown(self):
        assert "protection lost" in report.text(_run())

    def test_limitations_are_printed_with_the_verdict_not_hidden(self):
        text = report.text(_run(roles_config={}))
        assert "Limitations" in text
        assert "guessed" in text

    def test_a_clean_run_says_so_explicitly(self):
        assert "none recorded" in report.text(_run(V1, V1))

    def test_verbose_adds_evidence(self):
        plain, loud = report.text(_run()), report.text(_run(), verbose=True)
        assert len(loud) > len(plain)
        assert "unprotected_pdus" in loud

    def test_verbose_shows_zero_counts(self):
        assert "nodes added" in report.text(_run(), verbose=True)

    def test_a_no_findings_run_still_renders(self):
        assert "Findings (0)" in report.text(_run(V1, V1))


class TestJsonReport:
    def test_it_is_valid_json(self):
        json.loads(report.as_json(_run()))

    def test_the_verdict_and_exit_code_are_top_level(self):
        data = json.loads(report.as_json(_run()))
        assert data["verdict"] == "BLOCK"
        assert data["exit_code"] == 3

    def test_every_finding_carries_its_score_and_rationale(self):
        data = json.loads(report.as_json(_run()))
        for entry in data["findings"]:
            assert entry["risk"] >= 1
            assert entry["rationale"]
            assert entry["scorer"]

    def test_the_route_is_included(self):
        data = json.loads(report.as_json(_run()))
        entry = next(f for f in data["findings"] if f["target"] == BRAKE)
        assert entry["route"] == [TEL, GW, ABS, BRAKE]

    def test_a_non_path_finding_has_a_null_route(self):
        data = json.loads(report.as_json(_run()))
        entry = next(f for f in data["findings"] if f["category"] == "secoc-removed")
        assert entry["route"] is None

    def test_the_gate_buckets_are_reported_by_id(self):
        policy = gate.Policy(accepted=frozenset({"secoc-removed:/V/Swc/Veh/telToGw#data"}))
        data = json.loads(report.as_json(_run(policy=policy)))
        assert data["gate"]["accepted_ids"] == ["secoc-removed:/V/Swc/Veh/telToGw#data"]

    def test_the_seeds_used_are_recorded_per_snapshot(self):
        data = json.loads(report.as_json(_run()))
        assert data["roles"]["updated"]["entry"] == [TEL]
        assert data["roles"]["updated"]["heuristic_only"] is False

    def test_gaps_are_recorded_per_snapshot(self):
        a = _run(roles_config={"critical": [BRAKE]}, heuristics=False)
        data = json.loads(report.as_json(a))
        assert data["roles"]["before"]["gaps"]

    def test_the_limitations_match_the_text_report(self):
        """One list, two renderings — they must not drift apart."""
        a = _run(roles_config={})
        assert json.loads(report.as_json(a))["limitations"] == list(report.limitations(a))

    def test_evidence_survives_serialisation(self):
        data = json.loads(report.as_json(_run()))
        entry = next(f for f in data["findings"] if f["category"] == "secoc-removed")
        assert entry["evidence"]["unprotected_pdus"] == [CMD_PDU]

    def test_informational_findings_are_labelled(self):
        data = json.loads(report.as_json(_run(V1, V3)))
        rehost = next(f for f in data["findings"] if f["category"] == "rehosted-component")
        assert rehost["informational"] is True
