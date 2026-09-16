"""Render an analysis for a human and for a machine.

The text report has one rule behind its layout: the verdict is worthless without the
limitations, so they are printed together rather than the limitations being relegated
to a footnote nobody reads. If the SecOC evidence for a PDU came from a YAML overlay
rather than the ARXML, or the entry points were guessed from short names, the report
says so next to the number it affects.

`as_dict` is the machine form. It is a superset of the text: every finding carries its
score, its rationale, and its evidence, so a dashboard never has to re-derive
judgement the tool already made.
"""

from __future__ import annotations

import json

from . import pipeline as pipeline_mod

RISK_LABELS = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "informational"}


def limitations(analysis: pipeline_mod.Analysis) -> tuple[str, ...]:
    """Everything that weakens the verdict, in the reader's own interest.

    Kept as its own function so the CLI, the JSON, and any downstream report share one
    list. A limitation that appears in one output and not another is worse than none.
    """
    out: list[str] = []
    for snapshot in (analysis.before, analysis.updated):
        synthetic = snapshot.synthetic_secoc
        if synthetic:
            out.append(
                f"{snapshot.label}: SecOC status for {len(synthetic)} PDU(s) comes from "
                f"a YAML overlay, not from a SECURED-I-PDU in the ARXML "
                f"({', '.join(synthetic[:3])}{', ...' if len(synthetic) > 3 else ''}). "
                f"Those are modelled assumptions about the release."
            )
        if snapshot.node_roles.heuristic_only and snapshot.node_roles.assignments:
            out.append(
                f"{snapshot.label}: entry points and safety-critical nodes were guessed "
                f"from component names and categories. Criticality is not a property of "
                f"the ARXML — it comes from the programme's HARA/TARA — so these seeds "
                f"are a triage starting point, not a safety analysis."
            )
        for role, pattern in snapshot.node_roles.unmatched:
            out.append(
                f"{snapshot.label}: config pattern {pattern!r} for {role} matched no "
                f"component in this snapshot, so that check did not run."
            )
        for gap in snapshot.reachability.gaps:
            out.append(f"{snapshot.label}: {gap}; reachability was not analysed.")

    if analysis.reach_diff.seeds_changed:
        out.append(
            "the entry/critical seed set differs between the two snapshots, so some "
            "reachability changes may reflect the question changing rather than the "
            "architecture: " + ", ".join(analysis.reach_diff.seeds_changed)
        )
    for item in analysis.decision.downgraded:
        out.append(
            f"{item.finding.id} scored {item.risk} but rests on guessed inputs, so it "
            f"did not block."
        )
    for finding_id in analysis.decision.stale_acceptances:
        out.append(f"accepted finding {finding_id} is not present in this release.")
    for finding_id in analysis.decision.refused_acceptances:
        out.append(f"the acceptance of {finding_id} was refused; that category cannot be waived.")
    return tuple(out)


def text(analysis: pipeline_mod.Analysis, verbose: bool = False) -> str:
    lines: list[str] = []
    add = lines.append

    add("ARXML security regression report")
    add("=" * 31)
    add("")
    add(f"before : {', '.join(str(p) for p in analysis.before.sources)}")
    add(f"updated  : {', '.join(str(p) for p in analysis.updated.sources)}")
    add("")

    decision = analysis.decision
    add(f"VERDICT: {decision.verdict}   (exit {decision.exit_code})")
    for reason in decision.reasons:
        add(f"  - {reason}")
    add("")

    add("Snapshots")
    add(f"  {'':22}{'before':>10}{'updated':>10}")
    before, after = analysis.before.summary(), analysis.updated.summary()
    for key in before:
        marker = " *" if before[key] != after[key] else ""
        add(f"  {key.replace('_', ' '):22}{before[key]:>10}{after[key]:>10}{marker}")
    add("")

    add("Architecture changes")
    for key, value in analysis.structural.summary().items():
        if value or verbose:
            add(f"  {key.replace('_', ' '):22}{value:>10}")
    add("")

    if analysis.secoc_changes:
        add("SecOC profile changes")
        for change in analysis.secoc_changes:
            note = "  <- protection lost" if change.lost_protection else ""
            add(f"  {change.change:8} {change.pdu}{note}")
        add("")

    add(f"Findings ({len(analysis.scored)})")
    if not analysis.scored:
        add("  none")
    for item in analysis.scored:
        add("")
        add(f"  [{item.risk}/{RISK_LABELS[item.risk]}] {item.finding.title}")
        add(f"      id        {item.finding.id}")
        add(
            f"      score     {item.score.impact} impact / {item.score.feasibility} "
            f"feasibility"
            + ("   (assumed inputs)" if item.score.assumed else "")
        )
        add(f"      scorer    {item.score.scorer}")
        if item.finding.detail:
            add(f"      detail    {item.finding.detail}")
        for reason in item.score.rationale:
            add(f"      because   {reason}")
        if item.finding.path is not None:
            add(f"      route     {item.finding.path}")
            for hop in item.finding.path.hops:
                add(f"                {_hop_line(hop)}")
        if verbose and item.finding.evidence:
            for key, value in sorted(item.finding.evidence.items()):
                add(f"      {key:9} {value}")
    add("")

    buckets = (
        ("blocking", decision.blocking),
        ("flagged", decision.flagged),
        ("not analysed", decision.unanalysed),
        ("informational", decision.informational),
        ("accepted", decision.accepted),
    )
    add("Gate")
    for label, items in buckets:
        if items or verbose:
            add(f"  {label:14}{len(items):>4}")
    add("")

    notes = limitations(analysis)
    add(f"Limitations ({len(notes)})")
    if not notes:
        add("  none recorded")
    for note in notes:
        add(f"  - {note}")
    return "\n".join(lines)


def _hop_line(hop) -> str:
    if hop.authenticated is False:
        state = "on a bus, UNAUTHENTICATED"
    elif hop.authenticated is True:
        state = "on a bus, SecOC-protected"
    else:
        state = "RTE-local (SecOC not applicable)"
    return f"{hop.source.rsplit('/', 1)[-1]} -> {hop.target.rsplit('/', 1)[-1]}  [{state}]"


def as_dict(analysis: pipeline_mod.Analysis) -> dict:
    """Machine-readable form. Stable enough to assert against in CI."""
    decision = analysis.decision
    return {
        "verdict": decision.verdict,
        "exit_code": decision.exit_code,
        "reasons": list(decision.reasons),
        "sources": {
            "before": [str(p) for p in analysis.before.sources],
            "updated": [str(p) for p in analysis.updated.sources],
        },
        "summary": analysis.summary(),
        "secoc_changes": [
            {"pdu": c.pdu, "change": c.change, "lost_protection": c.lost_protection}
            for c in analysis.secoc_changes
        ],
        "findings": [_finding_dict(item) for item in analysis.scored],
        "gate": {
            **decision.summary(),
            "accepted_ids": sorted(s.finding.id for s in decision.accepted),
            "downgraded_ids": sorted(s.finding.id for s in decision.downgraded),
            "stale_acceptances": list(decision.stale_acceptances),
            "refused_acceptances": list(decision.refused_acceptances),
        },
        "roles": {
            snapshot.label: {
                "entry": list(snapshot.node_roles.entry),
                "critical": list(snapshot.node_roles.critical),
                "heuristic_only": snapshot.node_roles.heuristic_only,
                "unmatched": [list(u) for u in snapshot.node_roles.unmatched],
                "gaps": list(snapshot.reachability.gaps),
            }
            for snapshot in (analysis.before, analysis.updated)
        },
        "limitations": list(limitations(analysis)),
    }


def _finding_dict(item) -> dict:
    finding = item.finding
    return {
        "id": finding.id,
        "category": finding.category,
        "subject": finding.subject,
        "title": finding.title,
        "detail": finding.detail,
        "target": finding.target,
        "informational": finding.informational,
        "risk": item.risk,
        "risk_label": RISK_LABELS[item.risk],
        "impact": item.score.impact,
        "feasibility": item.score.feasibility,
        "assumed": item.score.assumed,
        "scorer": item.score.scorer,
        "rationale": list(item.score.rationale),
        "route": list(finding.path.nodes) if finding.path else None,
        "evidence": _jsonable(finding.evidence),
    }


def as_json(analysis: pipeline_mod.Analysis, indent: int | None = 2) -> str:
    return json.dumps(as_dict(analysis), indent=indent, sort_keys=False)


def _jsonable(value):
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
