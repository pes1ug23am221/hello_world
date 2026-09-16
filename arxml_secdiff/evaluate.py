"""Measure the detector against its own labelled corpus, and against straw men.

This is the module that turns "it seems to work" into a number somebody can argue
with. It takes a corpus from `mutate`, runs the whole pipeline over every case, and
judges each result against the label the mutation declared *before* the run — which is
the only ordering under which the answer means anything.

Three things it is careful about, because each is a way an evaluation harness quietly
flatters its subject.

**The false-positive denominator.** A false-positive rate computed over every case is a
different and much prettier number than one computed over the benign controls, because
regressions dominate the corpus and a regression that reports findings is not a false
positive. Every rate here names its denominator, and any rate whose denominator is zero
is reported as `None` rather than as `0.0` — a corpus with no benign cases has an
unknown false-positive rate, not a perfect one.

**What counts as a false positive on a regression.** A regression case that reports an
extra category is usually not wrong: `bypass` declares `newly-reachable`, and the tool
may legitimately also notice a shorter route. So extra categories are recorded as
`unexpected` for triage but only `forbidden` categories — the traps each mutation pins
deliberately, like "a rehost with no PDU behind it must not report missing SecOC" —
count against precision. On a benign case the rule is stricter and simpler: any
non-informational finding at all is a false positive.

**Comparing unlike things.** The tool is judged on whether it produced the *right*
findings; a text differ has no findings to be right about. So the detector comparison
is drawn at the level all four can answer — did you flag this release — and computed
identically for the naive detectors and for the pipeline, with the tool's richer
label-based numbers reported separately. A comparison that scored the straw men on a
question only the real tool can answer would prove nothing.

Time-to-detect is `perf_counter` around `pipeline.run` alone. It excludes corpus
generation, process startup and imports, which means it is the marginal cost of
analysing one release in a job that is already warm — the number a CI owner cares
about. It is not the wall clock of the command.

A declared known gap that starts being *detected* is reported as `gap-closed`, loudly
and separately. That is neither a pass nor a failure: it means the corpus label is now
stale and someone must decide whether the gap really closed. Silently scoring it as a
win would let the register rot.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from . import findings as findings_mod
from . import gate as gate_mod
from . import mutate as mutate_mod
from . import naive as naive_mod
from . import pipeline as pipeline_mod
from . import roles as roles_mod

PROG = "arxml-secdiff-evaluate"

#: The tool's own name in the comparison table, alongside the straw men.
TOOL = "arxml-secdiff"

TRUE_POSITIVE = "true-positive"
FALSE_NEGATIVE = "false-negative"
TRUE_NEGATIVE = "true-negative"
FALSE_POSITIVE = "false-positive"
GAP_CONFIRMED = "gap-confirmed"
GAP_CLOSED = "gap-closed"
ERROR = "error"

#: Outcomes that mean the corpus label did not hold, and the run should not exit 0.
FAILURES = frozenset({FALSE_NEGATIVE, FALSE_POSITIVE})
#: Outcomes that mean the harness or the register is wrong, rather than the tool.
ALARMS = frozenset({ERROR, GAP_CLOSED})


def _rate(numerator: int, denominator: int) -> float | None:
    """None, not zero, when there is nothing to divide by.

    The whole point of the honesty discipline in this codebase: a metric with an empty
    denominator is unmeasured, and reporting it as 0.0 turns "we did not test this"
    into "we tested this and it was perfect".
    """
    return numerator / denominator if denominator else None


# -- one case -------------------------------------------------------------------


@dataclass(frozen=True)
class CaseResult:
    """What the tool did on one labelled pair, and whether the label held."""

    name: str
    kind: str
    order: int
    #: The mutation family or composition template this case came from, for breakdowns.
    family: str
    outcome: str
    verdict: str = ""
    exit_code: int = -1
    #: True when every declared expectation was satisfied.
    detected: bool = False
    #: True when any non-informational finding was reported at all. This is the column
    #: the naive detectors can be compared on.
    flagged: bool = False
    missing: tuple[str, ...] = ()
    #: Non-informational categories the label did not ask for. Recorded for triage; only
    #: counted against precision on a benign case, or when declared forbidden.
    unexpected: tuple[str, ...] = ()
    forbidden_hit: tuple[str, ...] = ()
    reported: tuple[str, ...] = ()
    worst_risk: int | None = None
    elapsed: float = 0.0
    gap: str = ""
    error: str = ""

    @property
    def false_positive(self) -> bool:
        """A benign case that reported anything, or any case that tripped a trap."""
        return self.outcome == FALSE_POSITIVE or bool(self.forbidden_hit)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "order": self.order,
            "family": self.family,
            "outcome": self.outcome,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "detected": self.detected,
            "flagged": self.flagged,
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "forbidden_hit": list(self.forbidden_hit),
            "reported": list(self.reported),
            "worst_risk": self.worst_risk,
            "elapsed_ms": round(self.elapsed * 1000, 3),
            "gap": self.gap,
            "error": self.error,
        }


def family_of(name: str) -> str:
    """The mutation family or template a generated case name came from.

    `mutate` names cases ``family__site``, ``template__sites`` and ``target+noise``, so
    the leading component before the first ``+`` and the first ``__`` is the thing being
    measured; anything after is the site or the cosmetic churn layered over it. Long
    names get an md5 suffix, but truncation happens at the end, so the leading component
    survives.
    """
    head = name.split("+", 1)[0]
    return head.split("__", 1)[0]


def evaluate_case(
    case: mutate_mod.Case,
    roles_config=None,
    policy: gate_mod.Policy | None = None,
    heuristics: bool = True,
    cutoff: int | None = 12,
    detectors: Sequence[naive_mod.Detector] = (),
) -> tuple[CaseResult, dict[str, naive_mod.NaiveResult]]:
    """Run the pipeline (and any straw men) over one case and judge the outcome."""
    naive_results = {
        d.name: d.compare([case.before], [case.updated]) for d in detectors
    }

    start = time.perf_counter()
    try:
        analysis = pipeline_mod.run(
            before_sources=[case.before],
            updated_sources=[case.updated],
            roles_config=roles_config,
            policy=policy,
            heuristics=heuristics,
            cutoff=cutoff,
        )
    except Exception as exc:  # noqa: BLE001 - an errored case is data, not a crash
        elapsed = time.perf_counter() - start
        return (
            CaseResult(
                name=case.name,
                kind=case.kind,
                order=case.order,
                family=family_of(case.name),
                outcome=ERROR,
                elapsed=elapsed,
                gap=case.gap,
                error=f"{type(exc).__name__}: {exc}",
            ),
            naive_results,
        )
    elapsed = time.perf_counter() - start

    found = analysis.findings
    substantive = [f for f in found if f.category not in findings_mod.INFORMATIONAL]
    reported_categories = {f.category for f in found}

    missing = tuple(str(e) for e in case.expected if not e.satisfied_by(found))
    detected = not missing and bool(case.expected)
    expected_categories = {e.category for e in case.expected}
    unexpected = tuple(
        sorted({f.category for f in substantive} - expected_categories)
    )
    forbidden_hit = tuple(sorted(reported_categories & set(case.forbidden)))

    if case.kind == mutate_mod.BENIGN:
        outcome = FALSE_POSITIVE if substantive else TRUE_NEGATIVE
    elif case.kind == mutate_mod.KNOWN_GAP:
        outcome = GAP_CLOSED if detected else GAP_CONFIRMED
    else:
        outcome = TRUE_POSITIVE if detected else FALSE_NEGATIVE

    risks = [s.score.risk for s in analysis.scored]
    return (
        CaseResult(
            name=case.name,
            kind=case.kind,
            order=case.order,
            family=family_of(case.name),
            outcome=outcome,
            verdict=analysis.verdict,
            exit_code=analysis.exit_code,
            detected=detected,
            flagged=bool(substantive),
            missing=missing,
            unexpected=unexpected,
            forbidden_hit=forbidden_hit,
            reported=tuple(sorted(f.id for f in found)),
            worst_risk=max(risks) if risks else None,
            elapsed=elapsed,
            gap=case.gap,
        ),
        naive_results,
    )


# -- metrics --------------------------------------------------------------------


@dataclass(frozen=True)
class Metrics:
    """Label-based accuracy over a set of case results.

    "Label-based" because a true positive here means the tool produced the findings the
    mutation declared, not merely that it said something. That is a strictly harder
    question than the one the straw men are scored on, and the two must not be printed
    in the same column without saying so.
    """

    total: int = 0
    regressions: int = 0
    benign: int = 0
    gaps: int = 0
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    #: Regression or gap cases that tripped a declared forbidden category. Counted in
    #: `false_positives` as well, but broken out because these are the deliberate traps.
    traps_tripped: int = 0
    gap_confirmed: int = 0
    gap_closed: int = 0
    errors: int = 0
    #: Seconds. `total_seconds` is the sum of per-case analysis time, not wall clock.
    mean: float | None = None
    median: float | None = None
    p95: float | None = None
    slowest: float | None = None
    total_seconds: float = 0.0

    @property
    def precision(self) -> float | None:
        return _rate(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float | None:
        return _rate(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def accuracy(self) -> float | None:
        judged = (
            self.true_positives
            + self.true_negatives
            + self.false_positives
            + self.false_negatives
        )
        return _rate(self.true_positives + self.true_negatives, judged)

    @property
    def false_positive_rate(self) -> float | None:
        """Over the benign controls only. The denominator is `benign`, stated in output."""
        return _rate(self.benign_false_positives, self.benign)

    @property
    def benign_false_positives(self) -> int:
        return self.false_positives - self.traps_tripped

    @property
    def false_negative_rate(self) -> float | None:
        return _rate(self.false_negatives, self.regressions)

    @classmethod
    def over(cls, results: Sequence[CaseResult]) -> Metrics:
        times = [r.elapsed for r in results if r.outcome != ERROR]
        by = {o: sum(1 for r in results if r.outcome == o) for o in
              (TRUE_POSITIVE, FALSE_NEGATIVE, TRUE_NEGATIVE, FALSE_POSITIVE,
               GAP_CONFIRMED, GAP_CLOSED, ERROR)}
        traps = sum(1 for r in results if r.forbidden_hit and r.kind != mutate_mod.BENIGN)
        return cls(
            total=len(results),
            regressions=sum(1 for r in results if r.kind == mutate_mod.REGRESSION),
            benign=sum(1 for r in results if r.kind == mutate_mod.BENIGN),
            gaps=sum(1 for r in results if r.kind == mutate_mod.KNOWN_GAP),
            true_positives=by[TRUE_POSITIVE],
            false_negatives=by[FALSE_NEGATIVE],
            true_negatives=by[TRUE_NEGATIVE],
            false_positives=by[FALSE_POSITIVE] + traps,
            traps_tripped=traps,
            gap_confirmed=by[GAP_CONFIRMED],
            gap_closed=by[GAP_CLOSED],
            errors=by[ERROR],
            mean=statistics.fmean(times) if times else None,
            median=statistics.median(times) if times else None,
            p95=_percentile(times, 95),
            slowest=max(times) if times else None,
            total_seconds=sum(times),
        )

    def as_dict(self) -> dict:
        return {
            "counts": {
                "total": self.total,
                "regressions": self.regressions,
                "benign": self.benign,
                "known_gaps": self.gaps,
                "true_positives": self.true_positives,
                "false_negatives": self.false_negatives,
                "true_negatives": self.true_negatives,
                "false_positives": self.false_positives,
                "traps_tripped": self.traps_tripped,
                "benign_false_positives": self.benign_false_positives,
                "gap_confirmed": self.gap_confirmed,
                "gap_closed": self.gap_closed,
                "errors": self.errors,
            },
            "rates": {
                "precision": self.precision,
                "recall": self.recall,
                "f1": self.f1,
                "accuracy": self.accuracy,
                "false_positive_rate": self.false_positive_rate,
                "false_positive_rate_denominator": self.benign,
                "false_negative_rate": self.false_negative_rate,
                "false_negative_rate_denominator": self.regressions,
            },
            "time_to_detect_ms": {
                "mean": _ms(self.mean),
                "median": _ms(self.median),
                "p95": _ms(self.p95),
                "max": _ms(self.slowest),
                "sum": _ms(self.total_seconds),
            },
        }


def _percentile(values: Sequence[float], pct: int) -> float | None:
    """Nearest-rank, so a short corpus still gives an answer rather than interpolating."""
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(pct / 100 * len(ordered)) - 1))
    return ordered[index]


def _ms(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds * 1000, 3)


@dataclass(frozen=True)
class Comparison:
    """Flag-based numbers for one detector, comparable across all of them.

    Positives are the regression cases, negatives the benign controls. Known gaps are
    excluded from precision and recall — a case declared undetectable cannot fairly
    count against the tool — and reported separately as `gaps_flagged`, which is where
    the straw men look deceptively good: a text differ "catches" the weak-MAC gap the
    real tool misses, without any idea that it is a weakness.
    """

    detector: str
    description: str = ""
    true_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    regressions: int = 0
    benign: int = 0
    gaps: int = 0
    gaps_flagged: int = 0
    median: float | None = None
    total_seconds: float = 0.0

    @property
    def precision(self) -> float | None:
        return _rate(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float | None:
        return _rate(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def false_positive_rate(self) -> float | None:
        return _rate(self.false_positives, self.benign)

    def as_dict(self) -> dict:
        return {
            "detector": self.detector,
            "description": self.description,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "regressions": self.regressions,
            "benign": self.benign,
            "known_gaps": self.gaps,
            "known_gaps_flagged": self.gaps_flagged,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "false_positive_rate_denominator": self.benign,
            "median_ms": _ms(self.median),
            "total_seconds": round(self.total_seconds, 3),
        }


def _comparison(
    detector: str, description: str, rows: Sequence[tuple[str, bool, float]]
) -> Comparison:
    """Score one detector on flagged-or-not, given (kind, flagged, seconds) per case."""
    times = [seconds for _, _, seconds in rows]
    regression = [flagged for kind, flagged, _ in rows if kind == mutate_mod.REGRESSION]
    benign = [flagged for kind, flagged, _ in rows if kind == mutate_mod.BENIGN]
    gaps = [flagged for kind, flagged, _ in rows if kind == mutate_mod.KNOWN_GAP]
    return Comparison(
        detector=detector,
        description=description,
        true_positives=sum(regression),
        false_negatives=len(regression) - sum(regression),
        true_negatives=len(benign) - sum(benign),
        false_positives=sum(benign),
        regressions=len(regression),
        benign=len(benign),
        gaps=len(gaps),
        gaps_flagged=sum(gaps),
        median=statistics.median(times) if times else None,
        total_seconds=sum(times),
    )


@dataclass(frozen=True)
class Breakdown:
    """One slice of the corpus — a family, or a composition order."""

    label: str
    total: int
    detected: int
    missed: int
    false_positives: int
    kinds: tuple[str, ...] = ()

    @property
    def detection_rate(self) -> float | None:
        return _rate(self.detected, self.detected + self.missed)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "total": self.total,
            "detected": self.detected,
            "missed": self.missed,
            "false_positives": self.false_positives,
            "detection_rate": self.detection_rate,
            "kinds": list(self.kinds),
        }


def _breakdown(results: Sequence[CaseResult], key) -> tuple[Breakdown, ...]:
    groups: dict[str, list[CaseResult]] = {}
    for result in results:
        groups.setdefault(str(key(result)), []).append(result)
    out = []
    for label in sorted(groups):
        rows = groups[label]
        out.append(
            Breakdown(
                label=label,
                total=len(rows),
                detected=sum(1 for r in rows if r.outcome == TRUE_POSITIVE),
                missed=sum(1 for r in rows if r.outcome == FALSE_NEGATIVE),
                false_positives=sum(1 for r in rows if r.false_positive),
                kinds=tuple(sorted({r.kind for r in rows})),
            )
        )
    return tuple(out)


# -- one before ---------------------------------------------------------------


@dataclass(frozen=True)
class Evaluation:
    """Everything one before's corpus produced, and what it reproduces from."""

    before: Path
    results: tuple[CaseResult, ...]
    metrics: Metrics
    comparisons: tuple[Comparison, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()
    corpus_size: int = 0
    corpus_counts: dict = field(default_factory=dict)
    seed: int = 0
    target: int | None = None
    roles_configured: bool = False
    generation_seconds: float = 0.0

    @property
    def by_family(self) -> tuple[Breakdown, ...]:
        return _breakdown(self.results, lambda r: r.family)

    @property
    def by_order(self) -> tuple[Breakdown, ...]:
        return _breakdown(self.results, lambda r: r.order)

    @property
    def failures(self) -> tuple[CaseResult, ...]:
        return tuple(r for r in self.results if r.outcome in FAILURES or r.false_positive)

    @property
    def alarms(self) -> tuple[CaseResult, ...]:
        return tuple(r for r in self.results if r.outcome in ALARMS)

    def as_dict(self) -> dict:
        return {
            "before": str(self.before),
            "corpus": {
                "size": self.corpus_size,
                "counts": self.corpus_counts,
                "seed": self.seed,
                "target": self.target,
                "generation_seconds": round(self.generation_seconds, 3),
                # Never omitted: a mutation that did not fit this before is coverage
                # the run did not have, and silence here reads as a clean sweep.
                "skipped": [{"mutation": n, "reason": r} for n, r in self.skipped],
            },
            "roles_configured": self.roles_configured,
            "metrics": self.metrics.as_dict(),
            "comparisons": [c.as_dict() for c in self.comparisons],
            "by_family": [b.as_dict() for b in self.by_family],
            "by_order": [b.as_dict() for b in self.by_order],
            "cases": [r.as_dict() for r in self.results],
        }


def run(
    before: str | Path,
    out_dir: str | Path | None = None,
    roles_config=None,
    target: int | None = None,
    seed: int = 0,
    policy: gate_mod.Policy | None = None,
    detectors: Sequence[naive_mod.Detector] = naive_mod.DETECTORS,
    mutations: Sequence[mutate_mod.Mutation] | None = None,
    heuristics: bool = True,
    cutoff: int | None = 12,
    **expand_kwargs,
) -> Evaluation:
    """Generate a corpus from one before, evaluate it, and score the straw men on it."""
    temporary = out_dir is None
    holder = tempfile.TemporaryDirectory(prefix="secdiff-corpus-") if temporary else None
    directory = Path(holder.name) if holder else Path(out_dir)  # type: ignore[arg-type]
    try:
        started = time.perf_counter()
        corpus = mutate_mod.generate(
            before, directory, mutations=mutations, target=target, seed=seed, **expand_kwargs
        )
        generation = time.perf_counter() - started

        results: list[CaseResult] = []
        naive_rows: dict[str, list[tuple[str, bool, float]]] = {d.name: [] for d in detectors}
        for case in corpus.cases:
            result, naive_results = evaluate_case(
                case,
                roles_config=roles_config,
                policy=policy,
                heuristics=heuristics,
                cutoff=cutoff,
                detectors=detectors,
            )
            results.append(result)
            for name, naive_result in naive_results.items():
                naive_rows[name].append((case.kind, naive_result.flagged, naive_result.elapsed))

        comparisons = [
            _comparison(d.name, d.description, naive_rows[d.name]) for d in detectors
        ]
        comparisons.append(
            _comparison(
                TOOL,
                "component graph, entry-point reachability, three-valued SecOC",
                [(r.kind, r.flagged, r.elapsed) for r in results],
            )
        )

        return Evaluation(
            before=Path(before),
            results=tuple(results),
            metrics=Metrics.over(results),
            comparisons=tuple(comparisons),
            skipped=corpus.skipped,
            corpus_size=len(corpus),
            corpus_counts={
                kind: len(corpus.by_kind(kind))
                for kind in (mutate_mod.REGRESSION, mutate_mod.BENIGN, mutate_mod.KNOWN_GAP)
            },
            seed=seed,
            target=target,
            roles_configured=roles_config is not None,
            generation_seconds=generation,
        )
    finally:
        if holder is not None:
            holder.cleanup()


# -- several befores ----------------------------------------------------------


@dataclass(frozen=True)
class Suite:
    """Several befores evaluated together, with pooled and per-before numbers.

    Pooling matters because no single fixture can carry a results chapter: a
    four-component synthetic file and a real vendor extract fail in different ways, and
    a number averaged over both without saying so hides that. Both views are reported.
    """

    evaluations: tuple[Evaluation, ...] = ()
    environment: dict = field(default_factory=dict)

    @property
    def results(self) -> tuple[CaseResult, ...]:
        return tuple(r for e in self.evaluations for r in e.results)

    @property
    def metrics(self) -> Metrics:
        return Metrics.over(self.results)

    @property
    def comparisons(self) -> tuple[Comparison, ...]:
        """Pooled per detector, in the order the detectors were declared."""
        names: list[str] = []
        descriptions: dict[str, str] = {}
        for evaluation in self.evaluations:
            for comparison in evaluation.comparisons:
                if comparison.detector not in descriptions:
                    names.append(comparison.detector)
                    descriptions[comparison.detector] = comparison.description
        out = []
        for name in names:
            merged: list[tuple[str, bool, float]] = []
            for evaluation in self.evaluations:
                source = next(
                    (c for c in evaluation.comparisons if c.detector == name), None
                )
                if source is None:
                    continue
                # Rebuilt from counts rather than kept per case, since the pooled table
                # only needs the tallies and the median of the medians would be wrong.
                merged.extend(
                    [(mutate_mod.REGRESSION, True, 0.0)] * source.true_positives
                    + [(mutate_mod.REGRESSION, False, 0.0)] * source.false_negatives
                    + [(mutate_mod.BENIGN, True, 0.0)] * source.false_positives
                    + [(mutate_mod.BENIGN, False, 0.0)] * source.true_negatives
                    + [(mutate_mod.KNOWN_GAP, True, 0.0)] * source.gaps_flagged
                    + [(mutate_mod.KNOWN_GAP, False, 0.0)]
                    * (source.gaps - source.gaps_flagged)
                )
            pooled = _comparison(name, descriptions[name], merged)
            medians = [
                c.median
                for e in self.evaluations
                for c in e.comparisons
                if c.detector == name and c.median is not None
            ]
            seconds = sum(
                c.total_seconds
                for e in self.evaluations
                for c in e.comparisons
                if c.detector == name
            )
            out.append(
                Comparison(
                    detector=pooled.detector,
                    description=pooled.description,
                    true_positives=pooled.true_positives,
                    false_negatives=pooled.false_negatives,
                    true_negatives=pooled.true_negatives,
                    false_positives=pooled.false_positives,
                    regressions=pooled.regressions,
                    benign=pooled.benign,
                    gaps=pooled.gaps,
                    gaps_flagged=pooled.gaps_flagged,
                    median=statistics.fmean(medians) if medians else None,
                    total_seconds=seconds,
                )
            )
        return tuple(out)

    @property
    def by_family(self) -> tuple[Breakdown, ...]:
        return _breakdown(self.results, lambda r: r.family)

    @property
    def by_order(self) -> tuple[Breakdown, ...]:
        return _breakdown(self.results, lambda r: r.order)

    @property
    def failures(self) -> tuple[CaseResult, ...]:
        return tuple(r for e in self.evaluations for r in e.failures)

    @property
    def alarms(self) -> tuple[CaseResult, ...]:
        return tuple(r for e in self.evaluations for r in e.alarms)

    @property
    def skipped(self) -> tuple[tuple[str, str, str], ...]:
        """(before, mutation, reason), so partial coverage is attributable."""
        return tuple(
            (e.before.name, name, reason) for e in self.evaluations for name, reason in e.skipped
        )

    @property
    def exit_code(self) -> int:
        if self.alarms:
            return 2
        if self.failures:
            return 1
        return 0

    def as_dict(self) -> dict:
        return {
            "environment": self.environment,
            "pooled": {
                "metrics": self.metrics.as_dict(),
                "comparisons": [c.as_dict() for c in self.comparisons],
                "by_family": [b.as_dict() for b in self.by_family],
                "by_order": [b.as_dict() for b in self.by_order],
                "failures": [r.as_dict() for r in self.failures],
                "alarms": [r.as_dict() for r in self.alarms],
                "skipped": [
                    {"before": b, "mutation": m, "reason": r} for b, m, r in self.skipped
                ],
            },
            "befores": [e.as_dict() for e in self.evaluations],
            "exit_code": self.exit_code,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, default=str)


def run_many(
    befores: Sequence[str | Path],
    roles: dict | None = None,
    out_dir: str | Path | None = None,
    **kwargs,
) -> Suite:
    """Evaluate several befores, pooling the results.

    `roles` maps a before's file name to its roles config, so the seeded fixtures get
    their programme's HARA/TARA extract and the rest fall back to the heuristics — which
    is itself worth measuring, since an unseeded run is what most first uses look like.
    """
    evaluations = []
    for before in befores:
        path = Path(before)
        directory = Path(out_dir) / path.stem if out_dir else None
        evaluations.append(
            run(
                path,
                out_dir=directory,
                roles_config=(roles or {}).get(path.name),
                **kwargs,
            )
        )
    return Suite(
        evaluations=tuple(evaluations),
        environment={
            "python": platform.python_version(),
            "platform": platform.platform(),
            "befores": [str(b) for b in befores],
            "timing": (
                "per-case pipeline.run only; excludes corpus generation, process "
                "startup and imports"
            ),
        },
    )


# -- rendering ------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _num(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _ms_text(seconds: float | None) -> str:
    return "n/a" if seconds is None else f"{seconds * 1000:.1f} ms"


def text(suite: Suite, verbose: bool = False) -> str:
    """Terminal rendering: the headline numbers and everything that did not hold."""
    m = suite.metrics
    lines = [
        "ARXML security regression detector - evaluation",
        "=" * 62,
        "",
        f"befores      {len(suite.evaluations)}",
        f"Cases          {m.total}  "
        f"({m.regressions} regression, {m.benign} benign, {m.gaps} known-gap)",
        "",
        "Detection (label-based: did the declared findings appear?)",
        f"  precision            {_num(m.precision)}   "
        f"({m.true_positives} TP / {m.true_positives + m.false_positives} flagged)",
        f"  recall               {_num(m.recall)}   "
        f"({m.true_positives} TP / {m.regressions} regressions)",
        f"  F1                   {_num(m.f1)}",
        f"  accuracy             {_num(m.accuracy)}",
        f"  false-positive rate  {_pct(m.false_positive_rate)}   "
        f"({m.benign_false_positives} of {m.benign} benign controls)",
        f"  false-negative rate  {_pct(m.false_negative_rate)}   "
        f"({m.false_negatives} of {m.regressions} regressions)",
        f"  traps tripped        {m.traps_tripped}   "
        "(forbidden categories on a non-benign case)",
        "",
        "Time to detect (per case, pipeline.run only)",
        f"  mean {_ms_text(m.mean)}   median {_ms_text(m.median)}   "
        f"p95 {_ms_text(m.p95)}   max {_ms_text(m.slowest)}",
        f"  {m.total_seconds:.1f} s of analysis across {m.total} cases",
        "",
        "Known gaps",
        f"  confirmed still missed  {m.gap_confirmed}",
        f"  CLOSED (label stale)    {m.gap_closed}",
        f"  errored cases           {m.errors}",
        "",
        "Naive before comparison (flag-based: did you flag this release at all?)",
        f"  {'detector':<18} {'precision':>9} {'recall':>7} {'F1':>6} {'FP rate':>8} {'median':>9}",
    ]
    for c in suite.comparisons:
        lines.append(
            f"  {c.detector:<18} {_num(c.precision, 2):>9} {_num(c.recall, 2):>7} "
            f"{_num(c.f1, 2):>6} {_pct(c.false_positive_rate):>8} {_ms_text(c.median):>9}"
        )

    if suite.alarms:
        lines += ["", f"ALARMS ({len(suite.alarms)}) - the harness or the register is wrong:"]
        for r in suite.alarms:
            detail = r.error or (r.gap or "declared gap now detected")
            lines.append(f"  [{r.outcome}] {r.name}: {detail}")

    if suite.failures:
        lines += ["", f"Labels that did not hold ({len(suite.failures)}):"]
        for r in suite.failures:
            if r.outcome == FALSE_NEGATIVE:
                lines.append(f"  [missed]  {r.name}: no {', '.join(r.missing)}")
            elif r.forbidden_hit:
                lines.append(f"  [trap]    {r.name}: reported {', '.join(r.forbidden_hit)}")
            else:
                lines.append(f"  [spurious] {r.name}: reported {', '.join(r.unexpected)}")
    else:
        lines += ["", "Every corpus label held."]

    if suite.skipped:
        lines += ["", f"Coverage not exercised - mutations that did not fit ({len(suite.skipped)}):"]
        for before, name, reason in suite.skipped:
            lines.append(f"  {before}: {name} - {reason}")

    if verbose:
        lines += ["", "By family:"]
        for b in suite.by_family:
            lines.append(
                f"  {b.label:<34} {b.total:>4} cases  "
                f"detected {_pct(b.detection_rate):>7}  fp {b.false_positives}"
            )
        lines += ["", "By composition order:"]
        for b in suite.by_order:
            lines.append(
                f"  order {b.label:<28} {b.total:>4} cases  "
                f"detected {_pct(b.detection_rate):>7}  fp {b.false_positives}"
            )
    return "\n".join(lines)


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return out


def markdown(suite: Suite) -> str:
    """The results tables the write-up needs, ready to paste."""
    m = suite.metrics
    env = suite.environment
    out = [
        "# Evaluation results",
        "",
        f"Python {env.get('python', '?')} on {env.get('platform', '?')}. "
        f"Timing: {env.get('timing', '')}.",
        "",
        "## Corpus",
        "",
    ]
    out += _table(
        ["before", "cases", "regression", "benign", "known-gap", "skipped", "seeded roles"],
        [
            [
                e.before.name,
                str(e.corpus_size),
                str(e.corpus_counts.get(mutate_mod.REGRESSION, 0)),
                str(e.corpus_counts.get(mutate_mod.BENIGN, 0)),
                str(e.corpus_counts.get(mutate_mod.KNOWN_GAP, 0)),
                str(len(e.skipped)),
                "yes" if e.roles_configured else "heuristic",
            ]
            for e in suite.evaluations
        ]
        + [
            [
                "**pooled**",
                f"**{m.total}**",
                f"**{m.regressions}**",
                f"**{m.benign}**",
                f"**{m.gaps}**",
                f"**{len(suite.skipped)}**",
                "",
            ]
        ],
    )

    out += ["", "## Headline metrics", "", "Label-based: a true positive means the tool "
            "produced the findings the mutation declared, not merely that it said "
            "something.", ""]
    out += _table(
        ["metric", "value", "denominator"],
        [
            ["precision", _num(m.precision), f"{m.true_positives + m.false_positives} flagged"],
            ["recall", _num(m.recall), f"{m.regressions} regressions"],
            ["F1", _num(m.f1), "-"],
            ["accuracy", _num(m.accuracy), f"{m.total - m.gaps - m.errors} judged"],
            ["false-positive rate", _pct(m.false_positive_rate), f"{m.benign} benign controls"],
            ["false-negative rate", _pct(m.false_negative_rate), f"{m.regressions} regressions"],
            ["traps tripped", str(m.traps_tripped), "forbidden categories declared"],
            ["known gaps confirmed", str(m.gap_confirmed), f"{m.gaps} declared"],
            ["known gaps closed", str(m.gap_closed), "label is stale if non-zero"],
            ["errored cases", str(m.errors), f"{m.total} cases"],
        ],
    )

    out += ["", "## Time to detect", "",
            "Per case, `pipeline.run` only.", ""]
    out += _table(
        ["mean", "median", "p95", "max", "total analysis time"],
        [[
            _ms_text(m.mean), _ms_text(m.median), _ms_text(m.p95), _ms_text(m.slowest),
            f"{m.total_seconds:.1f} s over {m.total} cases",
        ]],
    )

    out += ["", "## Naive before comparison", "",
            "Flag-based, computed identically for every row: positives are the "
            "regression cases, negatives the benign controls, known gaps excluded from "
            "precision and recall and reported separately.", ""]
    out += _table(
        ["detector", "precision", "recall", "F1", "FP rate", "gaps flagged", "median", "sees"],
        [
            [
                c.detector, _num(c.precision, 2), _num(c.recall, 2), _num(c.f1, 2),
                _pct(c.false_positive_rate), f"{c.gaps_flagged}/{c.gaps}",
                _ms_text(c.median), c.description,
            ]
            for c in suite.comparisons
        ],
    )

    out += ["", "## By mutation family", ""]
    out += _table(
        ["family", "cases", "kinds", "detected", "missed", "detection rate", "false positives"],
        [
            [
                b.label, str(b.total), ", ".join(b.kinds), str(b.detected), str(b.missed),
                _pct(b.detection_rate), str(b.false_positives),
            ]
            for b in suite.by_family
        ],
    )

    out += ["", "## By composition order", "",
            "How many mutation families were applied to make the case. A detector that "
            "only works on single-site changes shows up here.", ""]
    out += _table(
        ["order", "cases", "detected", "missed", "detection rate", "false positives"],
        [
            [b.label, str(b.total), str(b.detected), str(b.missed),
             _pct(b.detection_rate), str(b.false_positives)]
            for b in suite.by_order
        ],
    )

    if suite.alarms:
        out += ["", "## Alarms", "",
                "Neither a pass nor a failure of the tool: an errored case, or a declared "
                "gap that is now detected and whose label is therefore stale.", ""]
        out += _table(
            ["case", "outcome", "detail"],
            [[r.name, r.outcome, r.error or r.gap or "declared gap now detected"]
             for r in suite.alarms],
        )

    out += ["", "## Labels that did not hold", ""]
    if suite.failures:
        out += _table(
            ["case", "kind", "order", "outcome", "detail"],
            [
                [
                    r.name, r.kind, str(r.order), r.outcome,
                    ("missing " + ", ".join(r.missing)) if r.missing
                    else ("forbidden " + ", ".join(r.forbidden_hit)) if r.forbidden_hit
                    else ("reported " + ", ".join(r.unexpected)),
                ]
                for r in suite.failures
            ],
        )
    else:
        out += ["Every corpus label held: no false negatives, no false positives, no traps tripped."]

    out += ["", "## Known-gap register", "",
            "Defects declared undetectable, asserted still undetected. Closing one makes "
            "the corpus fail until its label is updated, which is the point.", ""]
    gaps = [r for r in suite.results if r.kind == mutate_mod.KNOWN_GAP]
    if gaps:
        seen: dict[str, CaseResult] = {}
        for r in gaps:
            seen.setdefault(r.gap or r.family, r)
        out += _table(
            ["family", "cases", "status", "what goes undetected"],
            [
                [
                    r.family,
                    str(sum(1 for g in gaps if g.family == r.family)),
                    "confirmed missed" if r.outcome == GAP_CONFIRMED else "**CLOSED**",
                    (r.gap or "-").replace("\n", " "),
                ]
                for r in seen.values()
            ],
        )
    else:
        out += ["No known-gap cases in this corpus."]

    out += ["", "## Coverage not exercised", "",
            "Mutations that found no site in a before. Recorded because partial "
            "coverage reads as a clean sweep when it is hidden.", ""]
    if suite.skipped:
        out += _table(
            ["before", "mutation", "reason"],
            [[b, n, r] for b, n, r in suite.skipped],
        )
    else:
        out += ["Every mutation applied to every before."]
    return "\n".join(out) + "\n"


# -- CLI ------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Evaluate the detector against a generated, labelled ARXML corpus.",
        epilog=(
            "exit codes: 0 every label held, 1 false positives or false negatives, "
            "2 a case errored or a declared gap closed"
        ),
    )
    parser.add_argument(
        "--before",
        nargs="+",
        required=True,
        metavar="ARXML",
        help="before files; each generates its own corpus and is scored separately",
    )
    parser.add_argument(
        "--roles",
        metavar="YAML",
        help="HARA/TARA seeds, applied to every before that has matching components",
    )
    parser.add_argument(
        "--out-dir",
        metavar="DIR",
        help="keep the generated corpus here (default: a temporary directory)",
    )
    parser.add_argument(
        "--target",
        type=int,
        metavar="N",
        help="ceiling on cases per before; a ceiling, not a quota",
    )
    parser.add_argument("--seed", type=int, default=0, help="corpus sampling seed")
    parser.add_argument(
        "--canonical",
        action="store_true",
        help="use the 15 named catalogue cases instead of the full expansion",
    )
    parser.add_argument(
        "--no-detectors", action="store_true", help="skip the naive before comparison"
    )
    parser.add_argument(
        "--cutoff", type=int, default=12, metavar="N", help="longest attack path (0 unbounded)"
    )
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--output", metavar="PATH", help="write here instead of stdout")
    parser.add_argument("--verbose", action="store_true", help="include the breakdowns in text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    roles = None
    if args.roles:
        # Via roles.load_config rather than yaml directly: that module owns the format,
        # so a schema change lands in one place.
        try:
            roles = roles_mod.load_config(args.roles)
        except Exception as exc:  # noqa: BLE001 - a bad config is a usage error, not a crash
            print(f"{PROG}: {exc}", file=sys.stderr)
            return 2

    try:
        suite = run_many(
            args.before,
            roles={Path(b).name: roles for b in args.before} if roles else None,
            out_dir=args.out_dir,
            target=args.target,
            seed=args.seed,
            mutations=mutate_mod.CATALOGUE if args.canonical else None,
            detectors=() if args.no_detectors else naive_mod.DETECTORS,
            cutoff=args.cutoff or None,
        )
    except OSError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return 2

    rendered = (
        suite.to_json()
        if args.format == "json"
        else markdown(suite)
        if args.format == "markdown"
        else text(suite, verbose=args.verbose)
    )
    if args.output:
        Path(args.output).write_text(rendered + "\n")
    else:
        print(rendered)
    return suite.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
