# RUNBOOK — how to actually run this project, in order

This is not the reference README (see `README.md` for a file-by-file breakdown).
This is the *sequence*: what to run first, what that proves, what to run next, and
how each step builds on the last — mapped directly to the build-progress phases the
team tracked (parser → graph builder → diff/reachability → severity/gate → mutation
corpus → evaluation).

Every command below was actually executed against this checkout; the outputs shown
are real.

```
Phase 0   Setup
Phase 1   Parser                (weeks 1–2)
Phase 2   Graph builder         (weeks 3–4)
Phase 3   Diff + reachability   (weeks 5–6)
Phase 4   Severity + gate       (weeks 7–8)
Phase 5   Mutation corpus       (weeks 9–11)
Phase 6   End-to-end (the real command)
Phase 7   Full evaluation (the real measurement)
```

---

## Phase 0 — Setup

Do this once.

```bash
git clone https://github.com/CapstoneSDV/arxml-secdiff.git
cd arxml-secdiff

pip install -e ".[test]"     # installs the package + pytest
```

Sanity check the install:

```bash
arxml-secdiff --help
```
If that prints usage text, the console script and all runtime deps (`lxml`,
`networkx`, `PyYAML`) are wired correctly. If it fails, run
`pip install -e ".[test]"` again and check the error — it's almost always a missing
dependency.

---

## Phase 1 — Parser (weeks 1–2)

**What this phase is:** turning raw ARXML into typed components/ports/connectors.
**Files involved:** `arxml_secdiff/xmlutil.py`, `arxml_secdiff/parser.py`,
`arxml_secdiff/model.py`.
**Run this first** because everything else — graph, diff, reachability, severity —
is built on top of what the parser extracts. If this phase is broken, every later
phase fails for the wrong reason.

```bash
pytest tests/test_parser.py -v
```

**Verified output:**
```
tests/test_parser.py::TestSenderReceiver::test_counts PASSED
... (23 tests total)
======================= 23 passed in 0.05s =======================
```

What each test class is checking, if one fails:
- component/port/connector counts are right → the recursive path-builder in
  `parser.py` is walking `SHORT-NAME` elements correctly
- namespace-agnostic parsing → `xmlutil.py`'s strip-namespace step works on both
  R3.x and R4.x-style files (`tests/fixtures/alt_namespace.arxml`)
- dangling refs are recorded, not raised → a bad `*-REF` doesn't crash extraction

If this phase passes, you have confidence the tool can *read* an ARXML file
correctly — nothing about security yet, just correct extraction.

---

## Phase 2 — Graph builder (weeks 3–4)

**What this phase is:** turning the parsed model into a directed influence graph,
resolving which ECU each component runs on, walking port→signal→PDU, and resolving
SecOC (authenticated / not / not-applicable).
**Files involved:** `graph.py`, `ecu.py`, `signals.py`, `secoc.py`.
**Run this second**, after the parser is confirmed working, because this phase reads
the parser's output — it's meaningless to debug graph edges if the parser handed it
the wrong components.

```bash
pytest tests/test_graph.py tests/test_ecu.py tests/test_signals.py tests/test_secoc.py -v
```

**Verified output:**
```
92 passed in 0.30s
```

What each file is checking:
- `test_graph.py` — client-server connectors produce **two** edges (request +
  reply), not one; this is the single most important thing to get right here, since
  a graph that only draws one edge silently under-reports what a client can reach
- `test_ecu.py` — which host each component prototype resolves to (from
  `SWC-TO-ECU-MAPPING`), which decides which edges even *can* cross a bus
- `test_signals.py` — the port → SYSTEM-SIGNAL → I-SIGNAL → PDU chain, which is the
  join key SecOC resolution depends on
- `test_secoc.py` — the three-valued `authenticated` result (`None` = not
  applicable, `False` = applicable and missing, `True` = protected) stays
  three-valued from both ARXML and YAML-overlay sources

If this phase passes, the tool can now build a correct graph and correctly say
"this hop is/isn't authenticated" — the two ingredients reachability needs next.

---

## Phase 3 — Diff + reachability engine (weeks 5–6)

**What this phase is:** comparing before vs. updated graphs structurally, and
computing which entry-point → critical-node paths are newly reachable.
**Files involved:** `diff.py`, `reach.py`.
**Run this third** — reachability needs a correct graph (Phase 2) on both snapshots,
and diff needs correct node/edge identity from the same graph.

```bash
pytest tests/test_diff.py tests/test_reach.py -v
```

**Verified output:**
```
62 passed in 0.20s
```

What's actually being checked:
- `test_diff.py` — node identity survives reordering (keyed on prototype path, not
  position), and a *renamed* connector reads as one `MODIFIED` edge instead of a
  spurious remove+add
- `test_reach.py` — the headline case: something unreachable in the before that
  becomes reachable in the update, with the full path and its weakest hop reported —
  run against the `veh_v1/v2/v3` trio and the real `data/EcuExtract.arxml`

This is the phase that produces the tool's actual thesis: *is there a new or
newly-unauthenticated path from something an attacker can reach to something
safety-critical.* Everything before this was necessary plumbing to get here.

**See it, don't just read it:** once this phase passes, you can export the actual
graph instead of only reading path text in the report:

```bash
arxml-secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v2.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml \
  --export-graphs out/graphs --quiet
```
Produces `out/graphs/{before,updated}_graph.{json,dot,png}` — the PNG needs
nothing beyond the project's own dependencies (matplotlib), and highlights the exact
attack-path hops in bold, colour-coded by real authentication status (green =
protected, red = unauthenticated, gray dashed = not applicable). See the README's
"Example 5" for the full flag reference.

---

## Phase 4 — TARA severity scorer + gate (weeks 7–8)

**What this phase is:** turning a reachability/diff result into a scored finding
(impact × feasibility, ISO/SAE 21434-style) and turning scored findings into a
release decision (PASS / FLAG / BLOCK / INCONCLUSIVE).
**Files involved:** `findings.py`, `severity.py`, `gate.py`.
**Run this fourth** — scoring needs findings, which need a diff and reachability
result (Phase 3).

```bash
pytest tests/test_severity.py tests/test_gate.py -v
```

**Verified output:**
```
113 passed in 0.96s
```

What's checked:
- `test_severity.py` — scores are checked against the *measured* `veh` trio output,
  with emphasis on provenance: which ASIL a score used, whether any input was
  guessed (`Score.assumed`), which scorer produced it
- `test_gate.py` — both the end-to-end scenario (full pipeline on the `veh` trio)
  and policy-only rules against synthetic findings (assumed-input downgrade,
  `INCONCLUSIVE` handling, `--accept`)

**About the "VERA seam stubbed" note in your build table:** `severity.py` defines
`ExternalScorer` (speaks JSON over stdin/stdout to an external scorer command) and
`FallbackScorer` (wraps it, falls back to `BuiltinScorer` if the external one is
unreachable, and says so in the report). That seam is real and tested against a
scripted stub process in `test_severity.py` / `test_cli.py` — it does **not** require
an actual VERA installation on this machine, which is exactly why it shows as
"done (stubbed)" rather than "done." To point the CLI at a real external scorer
later:
```bash
arxml-secdiff --before <BASE> --updated <UPD> --scorer-command "python3 my_vera_wrapper.py"
```
The wrapper just needs to read one JSON finding on stdin and write one JSON score on
stdout — see the `ExternalScorer` docstring in `severity.py` for the exact contract.

If this phase passes, the tool can now produce an actual release verdict with an
exit code, not just a list of findings.

---

## Phase 5 — Mutation corpus generator (weeks 9–11)

**What this phase is:** generating labelled before/after ARXML pairs (regression /
benign / known-gap) from a real before, so the detector can be measured instead of
eyeballed.
**Files involved:** `mutate.py` (corpus generation), `evaluate.py` (runs the
pipeline over the corpus and scores it), `naive.py` (the straw-man detectors it's
compared against).
**Run this fifth** — evaluation needs a working pipeline (Phases 1–4) to run *over*
the generated corpus; there's nothing to evaluate before that.

This is the "15/15 canonical cases hold" line in your build table. Reproduce it
directly:

```bash
python -m arxml_secdiff.evaluate \
  --before tests/fixtures/veh_v1.arxml \
  --canonical
```

**Verified output:**
```
ARXML security regression detector - evaluation
==============================================================

befores      1
Cases          15  (8 regression, 6 benign, 1 known-gap)

Detection (label-based: did the declared findings appear?)
  precision            1.000   (8 TP / 8 flagged)
  recall               1.000   (8 TP / 8 regressions)
  F1                   1.000
  false-positive rate  0.0%   (0 of 6 benign controls)
  traps tripped        0   (forbidden categories on a non-benign case)

Known gaps
  confirmed still missed  1
  CLOSED (label stale)    0

Every corpus label held.
```
That's your literal "15/15 canonical cases, done" — 15 total cases (8 regression + 6
benign + 1 known-gap), zero false positives, zero false negatives, zero traps
tripped. Exit code `0` means every label held.

`--canonical` uses the 15 hand-named cases in `mutate.CATALOGUE` (list them
yourself with `python3 -c "from arxml_secdiff import mutate; print(mutate.CATALOGUE)"`).
Drop `--canonical` to run the full combinatorial expansion instead (many more cases,
useful once you want statistical numbers rather than named regression tests):

```bash
python -m arxml_secdiff.evaluate --before tests/fixtures/veh_v1.arxml --target 200 --seed 0
```

---

## Phase 6 — End-to-end: the actual command you'll run day to day

Everything above was building and verifying one layer at a time. This is the real
command, once all five phases pass — comparing two real ARXML snapshots and getting
a release verdict:

```bash
arxml-secdiff \
  --before <path/to/old.arxml> \
  --updated  <path/to/new.arxml> \
  --roles    <path/to/roles.yaml> \
  --policy   <path/to/policy.yaml> \
  --verbose
```

To see it work right now, against fixtures already in the repo:

```bash
# a real regression → exit 3, BLOCK
arxml-secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v2.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml \
  --verbose
```

Read the exit code, not just the text, if you're wiring this into CI:

| exit | verdict | meaning |
|---|---|---|
| 0 | PASS | nothing crossed a threshold |
| 1 | FLAG | a human should look before release |
| 2 | INCONCLUSIVE | couldn't answer (e.g. no `--roles` given) — never silently PASS |
| 3 | BLOCK | crossed the blocking threshold on real evidence |

---

## Phase 7 — Full test suite + full evaluation (final check before a demo or a commit)

Run both, in this order, before you present or merge anything:

```bash
# 1. everything still works at the unit level
pytest -q
```
**Verified output:**
```
401 passed in 2.56s
```

```bash
# 2. the detector still performs at the corpus level
python -m arxml_secdiff.evaluate --before tests/fixtures/veh_v1.arxml --canonical
```
**Verified output:** `Every corpus label held.` (exit code 0)

If both are green, you have end-to-end evidence the tool works — not just that no
exception was thrown, but that it correctly caught every planted regression and
raised zero false alarms on every planted benign change.

---

## Quick reference — "I just want to run it"

```bash
pip install -e ".[test]"                                    # once
pytest -q                                                    # confidence check
arxml-secdiff --before OLD.arxml --updated NEW.arxml \
  --roles roles.yaml --verbose                               # the actual analysis
```