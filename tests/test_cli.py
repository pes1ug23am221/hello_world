"""CLI tests. The exit code is the product, so most of these assert on it.

`main()` is called in-process rather than through a subprocess: it is the documented
entry point, it returns the exit code, and testing it directly keeps the suite fast
enough to run on every save.
"""

import json
import sys

import pytest

from arxml_secdiff import cli, gate

from .conftest import ABS, BRAKE, TEL, V1, V2, V3, VEH_ROLES

BLOCK, FLAG, INCONCLUSIVE, PASS = 3, 1, 2, 0


def _argv(*extra, before=V1, after=V2, roles=None):
    args = ["--before", before, "--updated", after, *extra]
    if roles:
        args += ["--roles", roles]
    return args


class TestExitCodes:
    def test_a_new_route_to_the_brakes_exits_three(self, roles_file, capsys):
        assert cli.main(_argv(roles=roles_file)) == BLOCK

    def test_an_unchanged_release_exits_zero(self, roles_file, capsys):
        assert cli.main(_argv(before=V1, after=V1, roles=roles_file)) == PASS

    def test_the_rehost_scenario_exits_three(self, roles_file, capsys):
        assert cli.main(_argv(before=V1, after=V3, roles=roles_file)) == BLOCK

    def test_guessed_seeds_exit_one_rather_than_three(self, capsys):
        """No roles config: the finding is real, the claim is weaker, so it flags."""
        assert cli.main(_argv()) == FLAG

    def test_an_unanalysable_run_exits_two(self, capsys):
        assert cli.main(_argv("--no-heuristics", before=V1, after=V1)) == INCONCLUSIVE

    def test_inconclusive_can_be_made_fatal(self, capsys):
        argv = _argv("--no-heuristics", "--inconclusive-blocks", before=V1, after=V1)
        assert cli.main(argv) == BLOCK

    def test_zero_is_reserved_for_a_real_pass(self, capsys):
        """The one guarantee CI depends on: 0 means the analysis ran and was clean."""
        assert cli.main(_argv("--no-heuristics", before=V1, after=V1)) != PASS

    def test_every_documented_code_is_reachable(self, roles_file, capsys):
        seen = {
            cli.main(_argv(before=V1, after=V1, roles=roles_file)),
            cli.main(_argv()),
            cli.main(_argv("--no-heuristics", before=V1, after=V1)),
            cli.main(_argv(roles=roles_file)),
        }
        assert seen == {PASS, FLAG, INCONCLUSIVE, BLOCK}


class TestPolicyOverrides:
    def test_block_at_can_be_raised(self, roles_file, capsys):
        assert cli.main(_argv("--block-at", "6", "--flag-at", "5", roles=roles_file)) == FLAG

    def test_flag_at_can_be_raised_to_silence_a_run(self, roles_file, capsys):
        assert cli.main(_argv("--block-at", "6", "--flag-at", "6", roles=roles_file)) == PASS

    def test_an_inverted_threshold_pair_is_rejected(self, roles_file, capsys):
        assert cli.main(_argv("--block-at", "3", "--flag-at", "5", roles=roles_file)) == 2
        assert "invisible to triage" in capsys.readouterr().err

    def test_block_on_assumed_makes_guessed_findings_fatal(self, capsys):
        argv = _argv("--block-on-assumed", "--block-at", "4")
        assert cli.main(argv) == BLOCK

    def test_accept_suppresses_one_finding(self, roles_file, capsys):
        argv = _argv(
            "--accept",
            "newly-reachable:/V/Swc/Veh/tel->/V/Swc/Veh/brake",
            "--accept",
            "secoc-removed:/V/Swc/Veh/telToGw#data",
            roles=roles_file,
        )
        assert cli.main(argv) == FLAG

    def test_accept_is_repeatable_and_additive_with_a_file(self, tmp_path, roles_file, capsys):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "accepted:\n  - 'newly-reachable:/V/Swc/Veh/tel->/V/Swc/Veh/brake'\n"
        )
        argv = _argv(
            "--policy",
            str(policy),
            "--accept",
            "secoc-removed:/V/Swc/Veh/telToGw#data",
            roles=roles_file,
        )
        assert cli.main(argv) == FLAG

    def test_a_policy_file_is_honoured(self, tmp_path, roles_file, capsys):
        policy = tmp_path / "policy.yaml"
        policy.write_text("block_at: 6\nflag_at: 6\n")
        assert cli.main(_argv("--policy", str(policy), roles=roles_file)) == PASS

    def test_the_command_line_overrides_the_file(self, tmp_path, roles_file, capsys):
        policy = tmp_path / "policy.yaml"
        policy.write_text("block_at: 6\nflag_at: 6\n")
        argv = _argv("--policy", str(policy), "--block-at", "5", roles=roles_file)
        assert cli.main(argv) == BLOCK

    def test_lowering_only_block_at_pulls_flag_at_down_with_it(self, tmp_path):
        """Overriding one threshold in CI must not be able to build an invalid policy."""
        policy = tmp_path / "policy.yaml"
        policy.write_text("block_at: 6\nflag_at: 6\n")
        args = cli.build_parser().parse_args(
            _argv("--policy", str(policy), "--block-at", "4")
        )
        resolved = cli.resolve_policy(args)
        assert (resolved.block_at, resolved.flag_at) == (4, 4)

    def test_the_clamp_only_ever_reports_more_never_blocks_less(self, tmp_path):
        """Raising flag_at past the file's block_at must not raise block_at to match."""
        policy = tmp_path / "policy.yaml"
        policy.write_text("block_at: 3\nflag_at: 2\n")
        args = cli.build_parser().parse_args(
            _argv("--policy", str(policy), "--flag-at", "5")
        )
        resolved = cli.resolve_policy(args)
        assert resolved.block_at == 3
        assert resolved.flag_at == 3

    def test_a_lone_override_on_the_default_policy_still_clamps(self):
        args = cli.build_parser().parse_args(_argv("--block-at", "2"))
        resolved = cli.resolve_policy(args)
        assert (resolved.block_at, resolved.flag_at) == (2, 2)

    def test_naming_both_thresholds_inverted_is_still_an_error(self, tmp_path):
        """No intent left to infer, so this stays a reported mistake."""
        args = cli.build_parser().parse_args(_argv("--block-at", "3", "--flag-at", "5"))
        with pytest.raises(ValueError, match="invisible to triage"):
            cli.resolve_policy(args)

    def test_a_broken_policy_file_exits_two_without_analysing(self, tmp_path, capsys):
        policy = tmp_path / "policy.yaml"
        policy.write_text("block_at: 2\nflag_at: 4\n")
        assert cli.main(_argv("--policy", str(policy))) == 2

    def test_a_missing_policy_file_exits_two(self, capsys):
        assert cli.main(_argv("--policy", "/nonexistent.yaml")) == 2


class TestOutput:
    def test_the_text_report_goes_to_stdout(self, roles_file, capsys):
        cli.main(_argv(roles=roles_file))
        assert "VERDICT: BLOCK" in capsys.readouterr().out

    def test_text_is_the_default_format(self, roles_file, capsys):
        cli.main(_argv(roles=roles_file))
        out = capsys.readouterr().out
        assert out.startswith("ARXML security regression report")

    def test_json_format_is_parseable(self, roles_file, capsys):
        cli.main(_argv("--format", "json", roles=roles_file))
        data = json.loads(capsys.readouterr().out)
        assert data["verdict"] == "BLOCK"

    def test_output_writes_to_a_file(self, tmp_path, roles_file, capsys):
        out = tmp_path / "report.json"
        cli.main(_argv("--format", "json", "--output", str(out), roles=roles_file))
        assert json.loads(out.read_text())["exit_code"] == 3
        assert capsys.readouterr().out == ""

    def test_quiet_prints_nothing_but_still_decides(self, roles_file, capsys):
        code = cli.main(_argv("--quiet", roles=roles_file))
        assert code == BLOCK
        assert capsys.readouterr().out == ""

    def test_verbose_prints_more(self, roles_file, capsys):
        cli.main(_argv(roles=roles_file))
        plain = capsys.readouterr().out
        cli.main(_argv("--verbose", roles=roles_file))
        assert len(capsys.readouterr().out) > len(plain)

    def test_limitations_reach_stdout_on_a_guessed_run(self, capsys):
        cli.main(_argv())
        assert "guessed" in capsys.readouterr().out


class TestInputHandling:
    def test_a_missing_before_exits_two_with_a_message(self, capsys):
        assert cli.main(["--before", "/nonexistent.arxml", "--updated", V2]) == 2
        assert "arxml-secdiff:" in capsys.readouterr().err

    def test_several_files_merge_into_one_snapshot(self, capsys):
        from .conftest import FIXTURES

        multi = str(FIXTURES / "multi_instance.arxml")
        system = str(FIXTURES / "system_two_ecu.arxml")
        code = cli.main(["--before", multi, system, "--updated", multi, system, "--quiet"])
        assert code in (PASS, FLAG, INCONCLUSIVE, BLOCK)

    def test_cutoff_zero_means_unbounded(self, roles_file, capsys):
        assert cli.main(_argv("--cutoff", "0", roles=roles_file)) == BLOCK

    def test_before_and_updated_are_both_required(self):
        with pytest.raises(SystemExit):
            cli.main(["--before", V1])

    def test_the_help_text_documents_the_exit_codes(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        assert "0 pass, 1 flag, 2 inconclusive, 3 block" in capsys.readouterr().out


class TestExternalScorer:
    FLAT = 'import json,sys; json.load(sys.stdin); json.dump({"impact":"negligible","feasibility":"very-low"}, sys.stdout)'

    @pytest.fixture
    def script(self, tmp_path):
        def make(body):
            path = tmp_path / "scorer.py"
            path.write_text(body)
            return f"{sys.executable} {path}"

        return make

    def test_an_external_scorer_is_used(self, script, roles_file, capsys):
        """Everything scores negligible, so the same release now passes."""
        argv = _argv("--scorer-command", script(self.FLAT), roles=roles_file)
        assert cli.main(argv) == PASS

    def test_the_external_scorer_is_named_in_the_report(self, script, roles_file, capsys):
        cli.main(_argv("--scorer-command", script(self.FLAT), roles=roles_file))
        assert "external:" in capsys.readouterr().out

    def test_a_broken_scorer_falls_back_rather_than_crashing(self, script, roles_file, capsys):
        argv = _argv(
            "--scorer-command", script("import sys; sys.stdin.read(); sys.exit(1)"), roles=roles_file
        )
        assert cli.main(argv) in (PASS, FLAG, INCONCLUSIVE, BLOCK)

    def test_the_fallback_is_announced_on_stderr(self, script, roles_file, capsys):
        """A CI log tail may be all anyone reads, so this cannot live only in the report."""
        argv = _argv(
            "--scorer-command", script("import sys; sys.stdin.read(); sys.exit(1)"), roles=roles_file
        )
        cli.main(argv)
        err = capsys.readouterr().err
        assert "external scorer failed" in err
        assert "built-in scorer was used instead" in err

    def test_a_fallback_score_cannot_block(self, script, roles_file, capsys):
        """It is marked assumed, so the default policy downgrades it."""
        argv = _argv(
            "--scorer-command", script("import sys; sys.stdin.read(); sys.exit(1)"), roles=roles_file
        )
        assert cli.main(argv) == FLAG

    def test_a_missing_scorer_binary_falls_back(self, roles_file, capsys):
        argv = _argv("--scorer-command", "/nonexistent/scorer", roles=roles_file)
        assert cli.main(argv) == FLAG

    def test_an_empty_scorer_command_exits_two(self, roles_file, capsys):
        assert cli.main(_argv("--scorer-command", "   ", roles=roles_file)) == 2


class TestResolvers:
    def test_resolve_policy_defaults_to_the_builtin_policy(self):
        args = cli.build_parser().parse_args(_argv())
        assert cli.resolve_policy(args) == gate.Policy()

    def test_resolve_scorer_returns_none_without_a_command(self):
        args = cli.build_parser().parse_args(_argv())
        assert cli.resolve_scorer(args) is None

    def test_resolve_scorer_wraps_the_command_in_a_fallback(self):
        args = cli.build_parser().parse_args(_argv("--scorer-command", "cat"))
        scorer = cli.resolve_scorer(args)
        assert "fallback" in scorer.name

    def test_a_quoted_scorer_command_is_split_like_a_shell(self):
        args = cli.build_parser().parse_args(
            _argv("--scorer-command", "python -m scorer --strict")
        )
        assert cli.resolve_scorer(args).primary.command == [
            "python",
            "-m",
            "scorer",
            "--strict",
        ]
