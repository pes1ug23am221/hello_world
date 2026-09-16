# arxml-secdiff

Detect security regressions between two AUTOSAR ARXML snapshots.

Given a `--before` and an `--updated` architecture (one or more ARXML files each),
the tool parses both into a typed model, builds an influence graph, resolves SecOC
(AUTOSAR's message-authentication layer) for every bus-crossing connector, computes
attacker-entry-point → safety-critical-node reachability on both sides, diffs the two,
turns the diff into scored findings (ISO/SAE 21434-style impact × feasibility), and
gates a release decision from those scores. It answers one question a text or
element diff cannot: **did this change open a new, or newly unauthenticated, path
from something an attacker can reach to something that can hurt someone or the
vehicle?**

All commands below were run against this exact checkout to confirm they work; the
outputs shown are real, not illustrative.

---

## Table of contents

- [Setup](#setup)
- [Repository structure](#repository-structure)
- [Package: `arxml_secdiff/`](#package-arxml_secdiff)
- [Data: `data/`](#data-data)
- [Docs: `docs/`](#docs-docs)
- [Tests: `tests/`](#tests-tests)
- [Top-level config files](#top-level-config-files)
- [Running the main tool](#running-the-main-tool)
- [Running the evaluation harness](#running-the-evaluation-harness)
- [Running the tests](#running-the-tests)
- [Exit codes reference](#exit-codes-reference)

---

## Setup

```bash
git clone https://github.com/CapstoneSDV/arxml-secdiff.git
cd arxml-secdiff

# editable install, registers the `arxml-secdiff` console script
pip install -e .

# also pulls in pytest, for running/editing the test suite
pip install -e ".[test]"
```

Requires Python ≥ 3.10. Runtime dependencies: `lxml`, `networkx`, `PyYAML`,
`matplotlib` (see `requirements.txt` / `pyproject.toml`).

---

## Repository structure

```
arxml-secdiff/
├── arxml_secdiff/                 # the package — all analysis logic lives here
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── diff.py
│   ├── ecu.py
│   ├── evaluate.py
│   ├── findings.py
│   ├── gate.py
│   ├── graph.py
│   ├── model.py
│   ├── mutate.py
│   ├── naive.py
│   ├── parser.py
│   ├── pipeline.py
│   ├── reach.py
│   ├── report.py
│   ├── roles.py
│   ├── secoc.py
│   ├── severity.py
│   ├── signals.py
│   └── xmlutil.py
├── data/
│   └── EcuExtract.arxml           # real-world-shaped single-ECU sample
├── docs/
│   └── case_study.md              # worked example + naive-detector comparison
├── tests/
│   ├── conftest.py
│   ├── fixtures/                  # small synthetic ARXML/YAML used by the tests
│   │   ├── alt_namespace.arxml
│   │   ├── bus_signals.arxml
│   │   ├── dangling_ref.arxml
│   │   ├── minimal_cs.arxml
│   │   ├── minimal_sr.arxml
│   │   ├── multi_instance.arxml
│   │   ├── scenario_b_roles.yaml
│   │   ├── scenario_b_v1.arxml
│   │   ├── scenario_b_v2.arxml
│   │   ├── scenario_b_v3.arxml
│   │   ├── secoc_overlay.yaml
│   │   ├── system_two_ecu.arxml
│   │   ├── veh_v1.arxml
│   │   ├── veh_v2.arxml
│   │   └── veh_v3.arxml
│   ├── test_cli.py
│   ├── test_diff.py
│   ├── test_ecu.py
│   ├── test_findings.py
│   ├── test_gate.py
│   ├── test_graph.py
│   ├── test_parser.py
│   ├── test_pipeline.py
│   ├── test_reach.py
│   ├── test_secoc.py
│   ├── test_severity.py
│   └── test_signals.py
├── pyproject.toml
├── pytest.ini
├── requirements.txt
└── README.md                      # this file
```

---

## Package: `arxml_secdiff/`

The pipeline runs in this order — each module is a stage, and `pipeline.py` is the
only place that wires them together:

```
xmlutil → parser → model → graph → ecu → signals → secoc
        → reach (before & updated) → diff → findings → severity → gate → report
```

### `xmlutil.py`
**What:** Namespace-agnostic XML loading.
**Why it exists:** AUTOSAR schema revisions don't share an XML namespace (R3.x uses
`http://autosar.org/3.1.4`-style URIs, R4.x uses `http://autosar.org/schema/r4.0`).
Rather than thread a namespace map through every lookup, this strips namespaces once
at load time so everything downstream matches on plain local tag names, regardless of
AUTOSAR revision.

### `parser.py`
**What:** Extracts the software architecture (components, ports, connectors, PDUs,
signals, mappings) from a set of ARXML files.
**Why it exists:** The unit of work is a *package set*, not a single file — a port's
`TYPE-TREF` routinely resolves into a separate vendor platform-types file, so every
file is folded into one shared path→element index before anything is interpreted.
Paths are built by generic recursion over any element with a `SHORT-NAME`, which is
exactly how AUTOSAR forms the absolute paths used in `*-REF` elements — so the index
keys match reference bodies verbatim. Unresolved refs are recorded, not raised.

### `model.py`
**What:** Typed dataclass view of the ARXML elements the tool cares about
(components, ports, connectors, PDUs...), keyed by absolute AUTOSAR path.

### `graph.py`
**What:** Turns the extracted model into a `networkx.MultiDiGraph` suited to
reachability analysis.
**Why it exists:** Node identity is the component *prototype* path, never the
component type — two instances of the same type (two doors, four wheel sensors) stay
two distinct nodes, so a BFS can't "teleport" from one instance to a sibling through a
path that doesn't exist in the real vehicle. Edges encode *influence*, not wiring:
sender-receiver edges follow the data flow (provider→requester); client-server
connectors produce **two** edges (client→server request, server→client reply),
because collapsing that to one edge is the easiest way to miss an attacker's ability
to reach into a server from a client.

### `ecu.py`
**What:** Resolves which physical ECU each component prototype is deployed to (from
`SWC-TO-ECU-MAPPING`).
**Why it exists:** This is what turns the abstract software graph into something that
can answer cross-HPC questions — an edge between two prototypes on the *same* ECU is
RTE-internal, while an edge between prototypes on *different* ECUs must cross a bus,
and only the latter can carry SecOC. A single-ECU extract has no mapping at all;
`assume_single_host` covers that case explicitly rather than leaving every host `None`.

### `signals.py`
**What:** Walks `port + data element → SYSTEM-SIGNAL → I-SIGNAL → I-SIGNAL-I-PDU`.
**Why it exists:** SecOC is configured against PDUs; connectors are declared at the
software level. Nothing links a connector to its authentication config directly — this
chain is the join key. It's also a discriminator: a connector whose data element has
no signal mapping never reaches a PDU and can't carry SecOC at all, so its lack of
authentication is *correct*, not a finding.

### `secoc.py`
**What:** Decides whether a bus-visible connector is actually authenticated, from two
sources: a `SECURED-I-PDU` in the ARXML (hard evidence, preferred) or a YAML overlay
keyed by PDU path (for SecOC config that lives in vendor-confidential ECU
configuration outside the architecture files).
**Why it exists:** The three-valued result (`None` = not applicable / not on a wire,
`False` = applicable and missing, `True` = protected) is the whole point. Collapsing
`None` into `False` is the classic way to flood a report with false positives, since
most connectors in any real ECU extract are RTE-internal.

### `roles.py`
**What:** Decides which nodes are attacker entry points and which are
safety-critical.
**Why it exists:** Criticality isn't a property of the ARXML — it comes from a
programme's HARA/TARA documents. An explicit YAML config is the only authoritative
source and always wins; heuristics on short names/categories exist only so the tool
produces *something* on an unannotated snapshot, and every assignment records its
`source` so a report can say "these seeds were guessed" rather than implying a real
safety analysis happened. Config entries matching nothing land in `Roles.unmatched`
rather than being silently dropped.

### `reach.py`
**What:** Computes reachability from entry points to critical nodes on one snapshot,
and (via `pipeline.py`) compares before vs. updated to find *newly reachable* pairs
and *changed routes* between already-reachable pairs.
**Why it exists:** "Newly reachable" is strictly stronger than "a connector was
added" — most added connectors are harmless, and the dangerous ones usually look
harmless in isolation. Every path also carries its own weakest hop, because a
five-hop, fully-authenticated path is a very different risk from the same path with
one unauthenticated bus hop.

### `diff.py`
**What:** Diffs two architecture graphs. Nodes are keyed on prototype path (survives
reordering/connector renames); edges are keyed on
`(source, target, connector # influence)`, with a rename-pairing pass
(`_pair_renames`) so a renamed-but-otherwise-identical connector reads as one
`MODIFIED` edge instead of a spurious removal+addition.
**Why it exists:** Only fields in `NODE_FIELDS`/`EDGE_FIELDS` are compared — a diff
that reports every attribute the graph builder happens to attach becomes noise the
moment the builder grows a field, and noise is what stops people reading regression
reports. `newly_unprotected` / `newly_bus_visible` are derived from this same edge
diff so every finding traces back to a specific connector and field.

`graph.py` also exposes three export functions used by `cli.py`'s
`--export-graphs`: `to_json` (machine-readable, already covered above),
`to_dot` (Graphviz DOT text — no Graphviz install needed just to produce the text),
and `render_png` (a rendered image via matplotlib, no external binary dependency).
All three accept the entry/critical node sets and a set of attack-path edges to
highlight, so the exported picture matches what the text report says in prose.

### `findings.py`
**What:** The single place that decides *what counts as a security finding*, given a
diff and a reachability comparison.
**Why it exists:** Keeping "what is a finding" in one module (rather than scattered
across the graph/reach/diff layers) makes the rule set reviewable, and lets a
programme argue with a category without touching analysis code. Every finding has a
stable `id` so it can be `--accept`-ed and stay accepted across future releases.

### `severity.py`
**What:** Scores findings using an ISO/SAE 21434 Annex-H-style impact × feasibility
matrix (risk 1–5), and records where every input came from.
**Why it exists:** ASIL stands in for hazard-analysis-derived impact (a documented
simplification, noted in every score's rationale). `Score.assumed` is `True` whenever
any input was heuristic rather than configured — a risk of 5 from a name match on
"brake" is not the same claim as one from a real HARA, and this field is what lets the
gate and report tell the difference. `ExternalScorer`/`FallbackScorer` are the seam
for plugging in a programme's own scorer (e.g. VERA) over stdin/stdout JSON, falling
back to the built-in scorer (and saying so loudly) if it's unreachable.

### `gate.py`
**What:** Turns scored findings into one of four verdicts: `PASS`, `FLAG`, `BLOCK`,
`INCONCLUSIVE`.
**Why it exists:** `INCONCLUSIVE` is the verdict that justifies the module — a tool
with only PASS/FLAG/BLOCK has nowhere to put "no entry points were configured" except
PASS, making an unanalysed release look identical to a clean one. Two policy choices
are deliberately *not* the tool's to make: whether a guessed (heuristic) finding may
block a release (`block_on_assumed`, off by default — downgraded to FLAG instead, and
the downgrade is reported), and whether an inconclusive run should be fatal in CI
(`inconclusive_blocks`).

### `report.py`
**What:** Renders an `Analysis` as human-readable text or as a JSON dict.
**Why it exists:** The text report always prints limitations next to the verdict they
affect (never as a footnote), so a reader can't miss that a score came from a guessed
role or an overlay rather than the ARXML. `as_dict` is a superset of the text form —
every finding keeps its score, rationale and evidence, so a dashboard never has to
re-derive judgement the tool already made.

### `pipeline.py`
**What:** `pipeline.run(...)` — the single function that runs every stage above, in
order, and returns one `Analysis` object holding every intermediate result (both
graphs, both reachability sets, the raw diff, scored findings, the gate verdict).
**Why it exists:** So the *order* of stages and the objects passed between them live
in one auditable place, rather than being reassembled differently by the CLI, the
tests, and any future CI wrapper.

### `cli.py`
**What:** The `arxml-secdiff` command-line entry point (see
[Running the main tool](#running-the-main-tool) below).
**Why it exists:** Exit codes are the actual product here (0/1/2/3, see
[Exit codes reference](#exit-codes-reference)) — a CI job branches on them, not on the
text. `resolve_policy` merges a policy YAML with CLI overrides (CLI wins), clamping an
inverted `flag_at > block_at` down rather than failing, but only when just one side was
given on the command line — an explicitly inverted pair from a human is still an
error.

### `__main__.py`
**What:** Lets the package run as `python -m arxml_secdiff`, in addition to the
installed `arxml-secdiff` console script. Both invoke the exact same `cli.main`.

### `naive.py`
**What:** Three intentionally-strong "straw man" detectors used only for comparison
in `evaluate.py`:
- `TextDiff` — canonicalised text diff (what `git diff --exit-code` gives you, minus
  false alarms on reindents).
- `ElementDiff` — indexes every ARXML element by AUTOSAR path and reports
  appeared/vanished/changed paths; knows the file is a tree of identified objects,
  doesn't know what any of them *mean*.
- `StructuralGrep` — pattern-matches what a human security reviewer would grep for
  (new connectors, vanished secured PDUs, moved ECU mappings), with the same two blind
  spots a real grep-based check has: no reachability filter, and boolean (not
  three-valued) authentication.
**Why it exists:** The project's core claim — that graph + reachability + three-valued
SecOC finds things a diff can't — is worth nothing unmeasured, and only interesting if
what it beats is a genuinely reasonable alternative, not a detector built to lose.

### `mutate.py`
**What:** Generates labelled before/after ARXML pairs by mutating a real before —
`regression` (defect injected, must be detected), `benign` (cosmetic edit, must
**not** be flagged), and `known-gap` (a defect the tool is documented to miss).
Mutations operate on the raw XML tree (not the parsed model), so every generated file
has to survive the real parser, and compose (e.g. `rehost` + `expose_on_bus`) to test
specific distinctions such as "SecOC absent" vs. "SecOC not applicable."
**Why it exists:** Three hand-written fixtures don't measure a detector. This is the
corpus generator that lets `evaluate.py` report real precision/recall numbers instead
of "it seems to work." `CATALOGUE` holds the 15 canonical named single-site cases
referenced by `docs/case_study.md`.

### `evaluate.py`
**What:** Runs the whole pipeline over every case in a `mutate`-generated corpus, and
scores it against the label declared *before* the run. Has its own CLI (see
[Running the evaluation harness](#running-the-evaluation-harness)).
**Why it exists:** Reports precision/recall/F1/false-positive-rate with the
denominator always named (a corpus with zero benign cases reports `None` for FP rate,
not a flattering `0.0`), separates "extra finding category" (`unexpected`, doesn't
count against precision) from "forbidden category the mutation specifically pins"
(`traps tripped`, does), and reports a previously-declared `known-gap` that starts
being detected as `gap-closed` — loudly, because that means a corpus label is now
stale, not that the tool improved for free.

---

## Data: `data/`

### `EcuExtract.arxml`
A realistic single-ECU AUTOSAR extract (no `SWC-TO-ECU-MAPPING`, since an ECU extract
is already scoped to one ECU). Used as a real-world-shaped sanity check beyond the
synthetic test fixtures — e.g. to confirm `assume_single_host` behaves correctly on a
file shaped like something a real toolchain would export.

```bash
# sanity-check the parser/pipeline against a realistic single-ECU file
python -m arxml_secdiff --before data/EcuExtract.arxml --updated data/EcuExtract.arxml
```

---

## Docs: `docs/`

### `case_study.md`
A worked example (the "scenario B" fixtures) showing: an identical-pair control, a
real regression (a Bluetooth-reachable path to the brake actuator, with SecOC removed
on one hop), a benign control, a head-to-head comparison against the three naive
detectors in `naive.py` (recall/specificity table), and timing numbers. It ends with
the exact commands needed to reproduce every result in the document — those are the
commands this README's [Running the main tool](#running-the-main-tool) section is
built from and verified against.

---

## Tests: `tests/`

### `conftest.py`
Shared pytest fixtures: parses the `veh_v1/v2/v3` and `scenario_b_*` fixture files
once and exposes convenience path constants (`ABS`, `BRAKE`, `GW`, `TEL`, `V1`, `V2`,
`V3`, `VEH_ROLES`, etc.) used across the other test modules.

### `fixtures/`
Small, purpose-built ARXML/YAML inputs — never the full `data/EcuExtract.arxml` —
kept minimal so each test failure points at one specific behavior:

| file | used to test |
|---|---|
| `minimal_sr.arxml` / `minimal_cs.arxml` | sender-receiver vs. client-server edge direction |
| `multi_instance.arxml` | two instances of one component type stay distinct nodes |
| `alt_namespace.arxml` | namespace-agnostic parsing (R3.x-style namespace) |
| `dangling_ref.arxml` | unresolved `*-REF`s are recorded, not raised |
| `bus_signals.arxml` | port → signal → PDU chain resolution |
| `system_two_ecu.arxml` | `SWC-TO-ECU-MAPPING` / cross-ECU bus detection |
| `secoc_overlay.yaml` | YAML SecOC overlay when the ARXML has no `SECURED-I-PDU` |
| `veh_v1/v2/v3.arxml` | the main reachability/diff/severity/gate scenario trio |
| `scenario_b_v1/v2/v3.arxml` + `scenario_b_roles.yaml` | the CLI/case-study end-to-end scenario |

### `test_parser.py`
**Tests:** raw element extraction — are the right components, ports and connectors
pulled out of ARXML at all.

### `test_graph.py`
**Tests:** edge *direction* — specifically that client-server connectors produce two
edges (request + reply), not one, since that's the easiest way for a graph builder to
silently under-report what a client can reach.

### `test_ecu.py`
**Tests:** which host each prototype resolves to, and therefore which edges count as
bus-crossing vs. RTE-internal.

### `test_signals.py`
**Tests:** the port→signal→PDU chain, and that a connector with no signal mapping is
correctly treated as never reaching a PDU (not applicable, not a false negative).

### `test_secoc.py`
**Tests:** the three-valued `authenticated` result — `None` must stay distinct from
`False`, from both ARXML and overlay sources.

### `test_reach.py`
**Tests:** reachability against the `veh_v1/v2/v3` trio and the real ECU extract —
that a pair unreachable in the before and reachable in the update is reported
correctly, along with the path, hop attributes, and change type.

### `test_diff.py`
**Tests:** structural diffing on the `veh` trio — one pair isolating "new connector +
SecOC removed," the other isolating "component rehosted onto a different ECU."

### `test_findings.py`
**Tests:** the judgement layer against pre-verified diff values — in particular that
"SecOC removed" (`True → False`) and "arrived without SecOC" (`None → False`) are
reported as different finding categories, and that an unanswerable reachability
analysis produces a finding rather than silence.

### `test_severity.py`
**Tests:** the scored numbers against the measured `veh` trio output, with emphasis on
provenance — which ASIL a score came from, whether any input was assumed, which scorer
produced it.

### `test_gate.py`
**Tests:** the release-decision rules, both end-to-end (full pipeline on the `veh`
trio) and via synthetic scored findings for policy-only behaviour (assumed-input
downgrade, inconclusive handling, acceptance).

### `test_pipeline.py`
**Tests:** stage wiring (pipeline.run assembles/order stages correctly) and report
honesty (every limitation the JSON records also appears in the text form).

### `test_cli.py`
**Tests:** the actual command-line surface — argument parsing, policy merging,
`--scorer-command`, `--format`, `--output`, and above all, exit codes.

---

## Top-level config files

### `pyproject.toml`
Build metadata and the `arxml-secdiff = "arxml_secdiff.cli:main"` console-script entry
point (this is what `pip install -e .` registers). Also declares the `test` extra
(`pytest>=8.0`).

### `pytest.ini`
```ini
[pytest]
pythonpath = .
testpaths = tests
```
Means `pytest` run from the repo root needs no extra flags or `PYTHONPATH` setup.

### `requirements.txt`
Flat pinned-minimum list of the same dependencies as `pyproject.toml`
(`lxml`, `networkx`, `PyYAML`, `pytest`), for environments that prefer
`pip install -r requirements.txt` over an editable package install.

---

## Running the main tool

Both forms are equivalent (the console script and the module both call
`arxml_secdiff.cli:main`):

```bash
arxml-secdiff --before <ARXML...> --updated <ARXML...> [options]
python -m arxml_secdiff --before <ARXML...> --updated <ARXML...> [options]
```

### Key flags

| flag | purpose |
|---|---|
| `--before ARXML...` / `--updated ARXML...` | required; each accepts multiple files merged into one model |
| `--roles YAML` | HARA/TARA entry-point & critical-node config |
| `--policy YAML` | gate thresholds and pre-accepted finding IDs |
| `--before-overlay YAML` / `--updated-overlay YAML` | synthetic SecOC profiles where the ARXML has none |
| `--no-heuristics` | never guess roles from names; report a gap instead |
| `--cutoff N` | longest attack path to enumerate (default 12, 0 = unbounded) |
| `--scorer-command CMD` | external scorer (JSON finding in on stdin, JSON score out on stdout), falls back to the built-in scorer on failure |
| `--block-at RISK` / `--flag-at RISK` | override policy thresholds |
| `--block-on-assumed` | let heuristic-only findings actually block a release |
| `--inconclusive-blocks` | make an inconclusive analysis exit 3, not 2 |
| `--accept FINDING_ID` | suppress a reviewed finding (repeatable) |
| `--format text\|json` | output format |
| `--output PATH` | write report to a file instead of stdout |
| `--verbose` | include full evidence per finding, and zero-count rows |
| `--quiet` | print nothing; only the exit code matters |
| `--export-graphs DIR` | write the before and updated influence graphs into `DIR` as JSON, Graphviz DOT, and a rendered PNG each (6 files total) |

### Example 1 — identical pair (control)

```bash
python -m arxml_secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v1.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml
```

**Output (verified):**
```
ARXML security regression report
===============================

before : tests/fixtures/scenario_b_v1.arxml
updated  : tests/fixtures/scenario_b_v1.arxml

VERDICT: PASS   (exit 0)
  - no finding reached the flag threshold

Snapshots
                          before   updated
  components                     8         8
  connections                    6         6
  pdus                           5         5
  secoc profiles                 2         2
  synthetic secoc                0         0
  entry points                   2         2
  critical nodes                 3         3
  attack paths                   0         0

Findings (0)
  none

Gate

Limitations (0)
  none recorded
```
Exit code: **0**

### Example 2 — real regression (BLOCK)

```bash
python -m arxml_secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v2.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml \
  --verbose
```

**Output (verified, abridged — 8 findings total, 6 blocking):**
```
VERDICT: BLOCK   (exit 3)
  - 6 finding(s) at risk 5 or above, worst: btStack can now reach brakeAct

Snapshots
                          before   updated
  connections                    6         7 *
  pdus                           5         4 *
  secoc profiles                 2         1 *
  attack paths                   0         6 *

SecOC profile changes
  removed  /B/Comm/DecelIPdu  <- protection lost

Findings (8)

  [5/critical] btStack can now reach brakeAct
      id        newly-reachable:/B/Swc/ScenarioB/btStack->/B/Swc/ScenarioB/brakeAct
      because   brakeAct is ASIL D -> severe impact
      because   2 of 6 hops cross a bus unauthenticated (weakest: gwToAdas)
      route     btStack -> ivi -> gw -> adas -> trajGuard -> brakeCtl -> brakeAct
                gw -> adas  [on a bus, UNAUTHENTICATED]
                ...

  [5/critical] SecOC removed from trajGuard -> brakeCtl
      id        secoc-removed:/B/Swc/ScenarioB/guardToBrake#data
      detail    This hop crossed a bus with SecOC in the before and no longer does.
      changed_fields ('authenticated: True -> False', ...)

  [5/critical] Unauthenticated bus traffic on gwToAdas
      id        unprotected-new-hop:/B/Swc/ScenarioB/gwToAdas#data
      detail    This hop is newly applicable for SecOC and arrived without it.

  [3/medium] btStack can now reach adas
  [3/medium] ivi can now reach adas

Gate
  blocking         6
  flagged          2
  informational    0
```
Exit code: **3** (a new Bluetooth-reachable path to the brake actuator, with SecOC
dropped on one hop — this is the flagship scenario in `docs/case_study.md`)

### Example 3 — benign change (PASS with an informational finding)

```bash
python -m arxml_secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v3.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml
```

**Output (verified):**
```
VERDICT: PASS   (exit 0)
  - no finding reached the flag threshold

Findings (1)

  [1/informational] New component perfMon
      id        component-added:/B/Swc/ScenarioB/perfMon
      score     negligible impact / very-low feasibility   (assumed inputs)
      because   category component-added carries a fixed negligible impact

Gate
  informational    1
```
Exit code: **0** — a component was added but never wired into anything
reachability-relevant, so it's reported for a reviewer's awareness only and cannot
fail a build.

### Example 4 — machine-readable JSON output

```bash
python -m arxml_secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v1.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml \
  --format json
```

**Output (verified, abridged):**
```json
{
  "verdict": "PASS",
  "exit_code": 0,
  "reasons": ["no finding reached the flag threshold"],
  "sources": {
    "before": ["tests/fixtures/scenario_b_v1.arxml"],
    "updated": ["tests/fixtures/scenario_b_v1.arxml"]
  },
  "summary": {
    "verdict": "PASS",
    "exit_code": 0,
    "before": { "components": 8, "connections": 6, "pdus": 5, "attack_paths": 0 },
    "updated":  { "components": 8, "connections": 6, "pdus": 5, "attack_paths": 0 },
    "structural": { "nodes_added": 0, ... }
  }
}
```
Every field the text report shows (plus full per-finding evidence) is present here —
`as_dict`/`as_json` in `report.py` is a strict superset of the text form, so a CI
dashboard never has to re-derive a judgement the tool already made.

### Example 5 — exporting a visual, exportable graph

```bash
python -m arxml_secdiff \
  --before tests/fixtures/scenario_b_v1.arxml \
  --updated  tests/fixtures/scenario_b_v2.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml \
  --export-graphs out/graphs \
  --quiet
```

**Writes 6 files (verified):**
```
out/graphs/before_graph.json   # graph.to_json() — nodes + edges, machine-readable
out/graphs/before_graph.dot    # Graphviz DOT text — no Graphviz install needed to produce this
out/graphs/before_graph.png    # rendered image (matplotlib, no external binary needed)
out/graphs/updated_graph.json
out/graphs/updated_graph.dot
out/graphs/updated_graph.png
```

The PNG/DOT for the **updated** snapshot highlights (bold width) every hop that lies
on a reported attack path, while colour always reflects real authentication status:
green = authenticated, red = applicable and unauthenticated, gray dashed = SecOC not
applicable (RTE-local). A protected hop that happens to sit on an attack route stays
green — recoloring it red just because it's "on the path" would misreport the one
thing the tool exists to get right.

If you have Graphviz installed, the `.dot` file also renders with its own layout
engine:
```bash
dot -Tpng out/graphs/updated_graph.dot -o out/graphs/updated_graph_graphviz.png
```

### Example 6 — sanity check against a realistic file

```bash
python -m arxml_secdiff --before data/EcuExtract.arxml --updated data/EcuExtract.arxml
```
Runs the parser/pipeline against a real single-ECU extract (no `--roles` supplied, so
role assignment falls back to heuristics — expect `PASS`, identical snapshot, and a
report noting assumed inputs if any heuristic-based finding appears).

---

## Running the evaluation harness

`evaluate.py` is a second, separate CLI (`python -m arxml_secdiff.evaluate`) that
measures the detector's own precision/recall against a labelled, auto-generated
mutation corpus, and against the three naive detectors in `naive.py`.

```bash
python -m arxml_secdiff.evaluate \
  --before tests/fixtures/scenario_b_v1.arxml \
  --roles    tests/fixtures/scenario_b_roles.yaml \
  --canonical
```

| flag | purpose |
|---|---|
| `--before ARXML...` | required; each before generates and scores its own corpus |
| `--roles YAML` | HARA/TARA seeds applied to every matching before |
| `--canonical` | use the 15 named catalogue cases instead of the full combinatorial expansion |
| `--target N` | ceiling on generated cases per before (a ceiling, not a quota) |
| `--seed N` | corpus sampling seed (default 0, for reproducibility) |
| `--out-dir DIR` | keep the generated corpus on disk instead of a temp dir |
| `--no-detectors` | skip the naive-detector comparison |
| `--cutoff N` | longest attack path to enumerate |
| `--format text\|json\|markdown` | output format |
| `--output PATH` | write to a file instead of stdout |
| `--verbose` | include full label/coverage breakdowns |

**Output (verified):**
```
ARXML security regression detector - evaluation
==============================================================

befores      1
Cases          14  (7 regression, 6 benign, 1 known-gap)

Detection (label-based: did the declared findings appear?)
  precision            0.778   (7 TP / 9 flagged)
  recall               1.000   (7 TP / 7 regressions)
  F1                   0.875
  false-positive rate  0.0%   (0 of 6 benign controls)
  traps tripped        2   (forbidden categories on a non-benign case)

Time to detect (per case, pipeline.run only)
  mean 4.6 ms   median 4.4 ms   p95 5.3 ms   max 5.3 ms

Known gaps
  confirmed still missed  1
  CLOSED (label stale)    0

Naive before comparison (flag-based: did you flag this release at all?)
  detector           precision  recall     F1  FP rate    median
  text-diff               0.58    1.00   0.74    83.3%    0.8 ms
  element-diff            0.70    1.00   0.82    50.0%    4.2 ms
  structural-grep         0.71    0.71   0.71    33.3%    1.8 ms
  arxml-secdiff           1.00    0.57   0.73     0.0%    4.4 ms

Labels that did not hold (2):
  [trap]    bypass: reported unprotected-new-hop
  [trap]    bypass-and-strip-secoc: reported unprotected-new-hop
```
Exit codes: **0** every label held, **1** a false positive/negative occurred, **2** a
case errored or a declared known-gap unexpectedly closed.

---

## Running the tests

```bash
# full suite (pytest.ini already points at tests/ and sets pythonpath=.)
pytest

# a single module
pytest tests/test_secoc.py -q

# a single test
pytest tests/test_gate.py::TestScenario -q

# with coverage of what ran
pytest -v
```

**Output (verified, full suite):**
```
........................................................................ [ 17%]
........................................................................ [ 35%]
........................................................................ [ 53%]
........................................................................ [ 71%]
........................................................................ [ 89%]
.........................................                                [100%]
401 passed in 2.56s
```

**Output (verified, single module):**
```bash
$ pytest tests/test_secoc.py -q
..............                                                           [100%]
14 passed in 0.06s
```

Per-module test counts, if you want to target one area of behaviour:

| module | tests | what a failure here means |
|---|---|---|
| `test_cli.py` | 45 | argument parsing, policy merging, or an exit code changed |
| `test_gate.py` | 57 | a release-decision rule (PASS/FLAG/BLOCK/INCONCLUSIVE) broke |
| `test_pipeline.py` | 54 | stage wiring or report honesty broke |
| `test_severity.py` | 56 | a risk score or its provenance is wrong |
| `test_reach.py` | 40 | reachability/path-change detection broke |
| `test_findings.py` | 35 | the judgement layer misclassified a finding |
| `test_diff.py` | 22 | structural diffing (nodes/edges/renames) broke |
| `test_parser.py` | 23 | raw ARXML extraction broke |
| `test_graph.py` | 21 | edge direction (esp. client-server) broke |
| `test_ecu.py` | 17 | ECU/host resolution broke |
| `test_signals.py` | 17 | the port→signal→PDU join broke |
| `test_secoc.py` | 14 | the three-valued authenticated result broke |

---

## Exit codes reference

### `arxml-secdiff` (main tool)
| code | verdict | meaning |
|---|---|---|
| 0 | PASS | analysis ran; nothing crossed a threshold |
| 1 | FLAG | something needs a human before release |
| 2 | INCONCLUSIVE (default) | the analysis couldn't answer the question (e.g. no roles configured); never silently mapped to PASS |
| 3 | BLOCK | something crossed the blocking threshold on good evidence (or INCONCLUSIVE, if `--inconclusive-blocks` is set) |

### `arxml_secdiff.evaluate` (evaluation harness)
| code | meaning |
|---|---|
| 0 | every declared label held |
| 1 | a false positive or false negative occurred |
| 2 | a case errored, or a declared known-gap unexpectedly closed |