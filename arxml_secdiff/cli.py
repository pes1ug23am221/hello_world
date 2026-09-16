"""Command-line entry point.

Exit codes are the product here, not the text: 0 pass, 1 flag, 2 inconclusive, 3
block. A CI job can treat 2 as fatal or not, which is the whole reason
``INCONCLUSIVE`` is a distinct code rather than being folded into 1 — "we could not
answer the question" and "a human should look at this" call for different pipelines.

The external-scorer flag deliberately wraps the command in a `FallbackScorer`. If a
programme's own scorer is unreachable in CI, the run still produces a verdict, and the
report says on every affected finding that the number came from the built-in fallback.
Failing the build on a missing scorer would be defensible too, but silently scoring
with the wrong tool and not saying so would not be.
"""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from . import gate as gate_mod
from . import graph as graph_mod
from . import pipeline as pipeline_mod
from . import report as report_mod
from . import severity as severity_mod


def export_graphs(analysis, out_dir: str) -> None:
    """Write before/updated graphs as JSON, DOT, and PNG into out_dir.

    Highlighted edges come from the updated snapshot's reported attack paths, since
    those are the hops a reviewer actually needs to see traced on the picture — the
    before graph is shown for comparison but has nothing to highlight against.
    """
    import json

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    updated_attack_edges = frozenset(
        pair for path in analysis.updated.reachability.paths for pair in zip(path.nodes, path.nodes[1:])
    )

    for label, snapshot in (("before", analysis.before), ("updated", analysis.updated)):
        g = snapshot.graph
        entry, critical = snapshot.node_roles.entry, snapshot.node_roles.critical
        highlight = updated_attack_edges if label == "updated" else frozenset()

        (directory / f"{label}_graph.json").write_text(json.dumps(graph_mod.to_json(g), indent=2) + "\n")
        (directory / f"{label}_graph.dot").write_text(
            graph_mod.to_dot(g, entry=entry, critical=critical, highlight_edges=highlight) + "\n"
        )
        graph_mod.render_png(
            g,
            str(directory / f"{label}_graph.png"),
            entry=entry,
            critical=critical,
            highlight_edges=highlight,
            title=f"{label} — {', '.join(str(s) for s in snapshot.sources)}",
        )

PROG = "arxml-secdiff"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Detect security regressions between two AUTOSAR ARXML snapshots.",
        epilog="exit codes: 0 pass, 1 flag, 2 inconclusive, 3 block",
    )
    parser.add_argument(
        "--before",
        nargs="+",
        required=True,
        metavar="ARXML",
        help="before snapshot; several files are merged into one model",
    )
    parser.add_argument(
        "--updated", nargs="+", required=True, metavar="ARXML", help="updated snapshot"
    )
    parser.add_argument(
        "--roles",
        metavar="YAML",
        help="entry-point and safety-critical node config (from the HARA/TARA)",
    )
    parser.add_argument("--policy", metavar="YAML", help="gate thresholds and acceptances")
    parser.add_argument(
        "--before-overlay",
        metavar="YAML",
        help="synthetic SecOC profiles for the before, used only where the ARXML has none",
    )
    parser.add_argument(
        "--updated-overlay", metavar="YAML", help="synthetic SecOC profiles for the update"
    )
    parser.add_argument(
        "--no-heuristics",
        action="store_true",
        help="never guess roles; report a gap instead. Use this once the config is authoritative",
    )
    parser.add_argument(
        "--cutoff",
        type=int,
        default=12,
        metavar="N",
        help="longest attack path to enumerate (default 12; 0 for unbounded)",
    )
    parser.add_argument(
        "--scorer-command",
        metavar="CMD",
        help="external scorer, one JSON finding on stdin and one JSON score on stdout",
    )
    parser.add_argument(
        "--export-graphs",
        metavar="DIR",
        help=(
            "write the before and updated influence graphs into DIR as JSON, "
            "Graphviz DOT, and a rendered PNG each (6 files total). Attack-path "
            "hops on the updated graph are highlighted in the PNG/DOT."
        ),
    )

    thresholds = parser.add_argument_group("policy overrides")
    thresholds.add_argument("--block-at", type=int, metavar="RISK")
    thresholds.add_argument("--flag-at", type=int, metavar="RISK")
    thresholds.add_argument(
        "--block-on-assumed",
        action="store_true",
        help="let findings built on guessed roles block a release",
    )
    thresholds.add_argument(
        "--inconclusive-blocks",
        action="store_true",
        help="exit 3 rather than 2 when the analysis could not run",
    )
    thresholds.add_argument(
        "--accept",
        action="append",
        default=[],
        metavar="FINDING_ID",
        help="suppress a reviewed finding; repeatable",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=("text", "json"), default="text")
    output.add_argument("--output", metavar="PATH", help="write the report here instead of stdout")
    output.add_argument("--verbose", action="store_true", help="include evidence and zero counts")
    output.add_argument(
        "--quiet", action="store_true", help="print nothing; the exit code is the result"
    )
    return parser


def resolve_policy(args: argparse.Namespace) -> gate_mod.Policy:
    """Merge the policy file with the command line, command line winning.

    A CI job overriding one threshold should not have to restate the whole file. That
    creates one wrinkle: lowering `--block-at` against a file with a higher `flag_at`
    would produce an inverted pair that `Policy` rejects. When only one of the two was
    given on the command line, `flag_at` is clamped down to `block_at` rather than
    failing — clamping in that direction only ever makes the gate report more, never
    block less, so it cannot turn a regression into a pass. Supplying both as an
    inverted pair is still an error, since there is no intent left to infer.
    """
    base = gate_mod.load_policy(args.policy) if args.policy else gate_mod.Policy()
    block_at = args.block_at if args.block_at is not None else base.block_at
    flag_at = args.flag_at if args.flag_at is not None else base.flag_at
    both_explicit = args.block_at is not None and args.flag_at is not None
    if flag_at > block_at and not both_explicit:
        flag_at = block_at
    return gate_mod.Policy(
        block_at=block_at,
        flag_at=flag_at,
        block_on_assumed=base.block_on_assumed or args.block_on_assumed,
        inconclusive_blocks=base.inconclusive_blocks or args.inconclusive_blocks,
        accepted=base.accepted | frozenset(args.accept),
    )


def resolve_scorer(args: argparse.Namespace) -> severity_mod.Scorer | None:
    """None means "let the pipeline build the default built-in scorer"."""
    if not args.scorer_command:
        return None
    command = shlex.split(args.scorer_command)
    if not command:
        raise ValueError("--scorer-command is empty")
    return severity_mod.FallbackScorer(
        primary=severity_mod.ExternalScorer(command),
        fallback=severity_mod.BuiltinScorer(),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        policy = resolve_policy(args)
        scorer = resolve_scorer(args)
    except (ValueError, OSError) as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2

    scorer_is_external = isinstance(scorer, severity_mod.FallbackScorer)

    try:
        analysis = pipeline_mod.run(
            before_sources=args.before,
            updated_sources=args.updated,
            roles_config=args.roles,
            policy=policy,
            before_overlay=args.before_overlay,
            updated_overlay=args.updated_overlay,
            scorer=scorer,
            heuristics=not args.no_heuristics,
            cutoff=args.cutoff or None,
        )
    except OSError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2

    if args.export_graphs:
        try:
            export_graphs(analysis, args.export_graphs)
        except OSError as exc:
            print(f"{PROG}: could not write graphs to {args.export_graphs}: {exc}", file=sys.stderr)
            return 2

    if scorer_is_external and scorer.errors:
        # Louder than the report, because a CI log tail may be all anyone reads.
        print(
            f"{PROG}: external scorer failed {len(scorer.errors)} time(s); the built-in "
            f"scorer was used instead. First error: {scorer.errors[0]}",
            file=sys.stderr,
        )

    if not args.quiet:
        rendered = (
            report_mod.as_json(analysis)
            if args.format == "json"
            else report_mod.text(analysis, verbose=args.verbose)
        )
        if args.output:
            Path(args.output).write_text(rendered + "\n")
        else:
            print(rendered)

    return analysis.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())