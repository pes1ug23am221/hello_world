# Case study: infotainment to brake actuator across a domain boundary

This is the detailed walkthrough of one release, mirroring the structure of VERA's
Scenario B. Everything below is measured output from the fixtures in
`tests/fixtures/`, not an illustration — the commands to reproduce each number are
given inline.

The claim under test is narrow and worth stating before the evidence:

> A component influence graph plus entry-point-to-critical-node reachability plus
> three-valued SecOC state tells a release manager something that a diff of the
> ARXML cannot, and it does so without flooding them with false positives.

The second half of that sentence is the hard part. A tool that flags every release is
easy to build and gets switched off in a fortnight. So this case study runs three
comparisons, not one: an identical pair, a genuine regression, and a **benign release
that must pass**. The benign case is where the naive befores fail and the interesting
result lives.

---

## 1. The system

Four ECUs, eight software component prototypes, six connectors.
`tests/fixtures/scenario_b_v1.arxml`.

| Hop | From ECU | To ECU | Wire | SecOC |
|---|---|---|---|---|
| `btStack -> ivi` | IviEcu | IviEcu | RTE-local | *not applicable* |
| `ivi -> gw` | IviEcu | GatewayEcu | **bus** | protected (`NavSecuredIPdu`) |
| `gw -> diagRouter` | GatewayEcu | GatewayEcu | RTE-local | *not applicable* |
| `adas -> trajGuard` | AdasEcu | AdasEcu | RTE-local | *not applicable* |
| `trajGuard -> brakeCtl` | AdasEcu | ChassisEcu | **bus** | protected (`DecelSecuredIPdu`) |
| `brakeCtl -> brakeAct` | ChassisEcu | ChassisEcu | RTE-local | *not applicable* |

Three of six hops cross a bus; four do not. That split is not annotated anywhere in
the file — it is derived, per hop, by walking

```
port -> data element -> SYSTEM-SIGNAL -> I-SIGNAL -> I-SIGNAL-I-PDU
```

and asking whether the chain terminates in a PDU at all. Only three of the seven
provider ports carry a `SENDER-RECEIVER-TO-SIGNAL-MAPPING`, so only three hops have
anything on a wire. The other four are RTE-internal, where SecOC is not merely absent
but *inapplicable*: there is no frame to authenticate.

**The before's security property is a topological one.** There is no `gw -> adas`
connector, so nothing the infotainment domain touches can influence the ADAS planner,
the brake controller or the brake actuator. Defence in depth is implemented as an
absent edge — which is exactly the kind of property a release can delete without any
single reviewer noticing.

### Role seeds

`tests/fixtures/scenario_b_roles.yaml`. These are assertions by the analyst, not facts
from the architecture, and the tool records them as `source: config` so a report can
say so. Criticality comes from the programme's HARA; the ARXML records no ASIL.

- **Entry points**: `btStack` (Bluetooth pairing and media parsing) and `ivi` (USB
  media import, Wi-Fi hotspot).
- **Critical**: `brakeAct` ASIL D, `brakeCtl` ASIL D, `adas` ASIL B.

Because both roles are configured, the name-matching heuristics are suppressed
entirely. No number in this case study depends on a substring match.

---

## 2. Control: the identical pair

```bash
python -m arxml_secdiff --before tests/fixtures/scenario_b_v1.arxml --updated tests/fixtures/scenario_b_v1.arxml --roles tests/fixtures/scenario_b_roles.yaml
```

`VERDICT: PASS (exit 0)`, zero findings. Worth running because it is the cheapest way
to catch a detector that flags on principle, and one of the naive befores below was
caught doing exactly that during development.

Note what the before summary reports: **0 attack paths**. Not "no findings" — the
reachability query genuinely returns nothing, because the graph has no route from
either entry point to any critical node.

---

## 3. The regression

`tests/fixtures/scenario_b_v2.arxml` differs from the before in exactly two
elements. Everything else is byte-identical, so nothing below can be blamed on
unrelated churn.

**Change 1 — one added connector.** `gwToAdas`, joining
`CentralGateway/ComfortOut` to `AdasPlanner/ComfortIn`. The stated purpose is a comfort
feature: let the driver's drive-mode selection reach the trajectory planner. The port
already had a data mapping to `ComfortIPdu`, and no `SECURED-I-PDU` wraps that PDU.

**Change 2 — one removed wrapper.** `DecelSecuredIPdu`, the SecOC wrapper over the
deceleration request from the ADAS domain to the chassis. The stated purpose is a
latency fix: the MAC and freshness bytes cost airtime on a hop with a hard deadline.

Neither is unreasonable in isolation. One is a feature; the other is a timing fix.
They would plausibly arrive in different change requests, reviewed by different people.

```bash
python -m arxml_secdiff --before tests/fixtures/scenario_b_v1.arxml --updated tests/fixtures/scenario_b_v2.arxml --roles tests/fixtures/scenario_b_roles.yaml --verbose
```

### Result: BLOCK, exit 3

| | before | updated |
|---|---|---|
| components | 8 | 8 |
| connections | 6 | 7 |
| PDUs | 5 | 4 |
| SecOC profiles | 2 | 1 |
| **attack paths** | **0** | **6** |

Eight findings: **6 at risk 5** (blocking) and 2 at risk 3 (flagged). Zero findings
carry assumed inputs, so nothing here rests on a heuristic.

The worst finding, verbatim:

```
[5/critical] btStack can now reach brakeAct
    score     severe impact / high feasibility
    because   brakeAct is ASIL D -> severe impact
    because   2 of 6 hops cross a bus unauthenticated (weakest: gwToAdas)
    route     btStack -> ivi -> gw -> adas -> trajGuard -> brakeCtl -> brakeAct
              btStack -> ivi          [RTE-local (SecOC not applicable)]
              ivi -> gw               [on a bus, SecOC-protected]
              gw -> adas              [on a bus, UNAUTHENTICATED]
              adas -> trajGuard       [RTE-local (SecOC not applicable)]
              trajGuard -> brakeCtl   [on a bus, UNAUTHENTICATED]
              brakeCtl -> brakeAct    [RTE-local (SecOC not applicable)]
```

Three things in that block are the whole point of the project.

**The chain, not the change.** Neither edit created a path by itself. Adding
`gwToAdas` alone would have exposed `adas` (ASIL B, risk 3). Stripping
`DecelSecuredIPdu` alone would have weakened a hop that no attacker could reach. It is
the composition that puts a Bluetooth radio six hops from an ASIL D actuator, and a
reviewer looking at either change request sees only its own half.

**Severity is inherited along the route, not attached to the element.** The
`secoc-removed` finding on `guardToBrake` scores 5, and its rationale says why: *"this
hop lies on a route to brakeAct, so it inherits that target's severe impact."* The same
wrapper removal on a hop that reached nothing critical would not block. Impact is a
property of what is downstream.

**Three-valued authentication, visible in the output.** Three of the six hops print
`[RTE-local (SecOC not applicable)]`. They are unauthenticated in the sense that no MAC
protects them, and reporting them as findings would be wrong — there is no frame to
protect, so there is nothing to fix. The distinction between `None` (inapplicable),
`False` (applicable and absent) and `True` (protected) is what keeps the finding list
at two unprotected hops instead of five.

The two risk-3 findings are the `adas` reachability pair — same root cause, lower
target severity. The gate's blocking set is driven by the ASIL D targets.

---

## 4. The benign control, and why it matters more

`tests/fixtures/scenario_b_v3.arxml` is a different release off the same before. It
deploys a `PerformanceMonitor` onto `AdasEcu` and feeds it health telemetry from the
planner over a new `adasToPerf` connector.

This is a real change — a new interface, a new port, a new component type, a new
prototype, a new connector, a new ECU mapping; **+987 canonical bytes and 16 changed
AUTOSAR paths.** It is also completely safe, and the tool has to know that:

- `adas` and `perfMon` are both mapped to `AdasEcu`, so the hop never leaves the ECU.
- `AdasPlanner/HealthOut` carries no data mapping, so it reaches no PDU. SecOC is
  inapplicable, not missing.
- `perfMon` is neither seeded as an entry point nor as critical, so no reachability
  relation between a seeded pair changes.

```bash
python -m arxml_secdiff --before tests/fixtures/scenario_b_v1.arxml --updated tests/fixtures/scenario_b_v3.arxml --roles tests/fixtures/scenario_b_roles.yaml
```

`VERDICT: PASS (exit 0)`. One finding, `component-added`, at risk 1, informational —
reported because a reviewer wants to know a component appeared, and structurally unable
to fail a build because it is in `findings.INFORMATIONAL`.

---

## 5. Naive before comparison

Three straw men, each built to be the best version of its idea rather than the worst.
Implementation and rationale in `arxml_secdiff/naive.py`.

- **`text-diff`** — `git diff --exit-code`, with the one concession that makes it fair:
  both files are whitespace-canonicalised first, so a reindent is not a change.
- **`element-diff`** — a diff tool taught to read ARXML: index every identified element
  by its AUTOSAR path, report what appeared, vanished or changed. Subtree digests are
  order-insensitive, so a sibling reorder is correctly not a change.
- **`structural-grep`** — what a security reviewer actually greps for: new connectors,
  vanished `SECURED-I-PDU`s, changed ECU mappings, connectors with no wrapper over them.
  Built with the two blind spots the real tool exists to close — no reachability filter,
  and boolean rather than three-valued authentication.

| detector | v1 vs v1 | v1 vs v2 (regression) | v1 vs v3 (benign) |
|---|---|---|---|
| `text-diff` | clean | flagged, 1 signal | **flagged — false positive** |
| `element-diff` | clean | flagged, 6 signals | **flagged — false positive** (16 signals) |
| `structural-grep` | clean | flagged, 3 signals | **flagged — false positive** (2 signals) |
| **`arxml-secdiff`** | **PASS** | **BLOCK, 6 blocking** | **PASS** |

All four agree the regression is worth flagging. All three naive detectors also flag
the benign release. On this pair of releases that is recall 1.0 and specificity 0.0 for
every before, against 1.0 and 1.0 for the analysis.

What each detector actually said about the regression:

```
text-diff        file contents differ (-44 canonical bytes)

element-diff     element added:   /B/Swc/ScenarioB/gwToAdas
                 element removed: /B/Comm/DecelSecuredIPdu
                 element changed: /B
                 element changed: /B/Comm
                 element changed: /B/Swc
                 element changed: /B/Swc/ScenarioB

structural-grep  new connection:              /B/Swc/ScenarioB/gwToAdas
                 authentication removed:      /B/Comm/DecelSecuredIPdu
                 unauthenticated connection:  /B/Swc/ScenarioB/gwToAdas
```

`element-diff` names both real changes and then four ancestor packages, because a
subtree digest propagates upward — six signals for a two-element change, with no
ranking to distinguish the wrapper removal from the package it lives in.

`structural-grep` does best, and its limits are precise. It finds both changed elements
and correctly labels one `secoc-removed`. What it cannot say is that they compose: it
reports a new connector without knowing whether anything became reachable, so it cannot
name a target, cannot assign an ASIL, and cannot rank the finding. Its category set for
the regression is `{secoc-removed}` against the analysis's
`{newly-reachable, secoc-removed, unprotected-new-hop}`.

And on the benign release its blind spots bite exactly as designed:
`unauthenticated connection: adasToPerf`. The connector is RTE-local and has no PDU to
wrap, so there is nothing to authenticate — but a boolean notion of authentication has
no way to express that.

This asymmetry is itself a result. The naive detectors can tell you something changed.
They cannot tell you what it means, and the two questions have different answers on
both of these releases.

### Time to detect

Median wall-clock over 25 runs per pair, single-threaded, on the four-ECU fixture.

| detector | v1 vs v2 | v1 vs v3 |
|---|---|---|
| `text-diff` | 1.07 ms | 0.93 ms |
| `structural-grep` | 2.54 ms | 2.32 ms |
| `element-diff` | 5.91 ms | 5.48 ms |
| `arxml-secdiff` | 12.63 ms | 11.51 ms |

The full analysis — parse, graph build, signal and PDU join, SecOC resolution,
reachability on both snapshots, diff, scoring, gate — costs roughly **2x an
element-diff and 5x a grep**, and lands at about 12 ms. Cost is not the reason to
prefer a diff. A JSON report for the regression pair is 15.9 KB.

---

## 6. Threats to validity

Stated plainly, because a case study that reads as advocacy is worth less than one that
names its own weaknesses.

**These fixtures are hand-built.** `scenario_b_v1.arxml` is not a vendor extract. It
was authored to make the bus/local split, the SecOC evidence and the topological
boundary all unambiguous, which means it is a demonstration that the analysis works on
a system with those properties — not evidence that real ARXML has them. The
project's one real input, `data/EcuExtract.arxml`, contains no `SECURED-I-PDU` elements
and no multi-ECU SWC mappings at all, which is why the corpus strategy is hybrid: real
topology, synthetic SecOC layer. See `docs/limitations.md`.

**The `limitations` section of this run is empty, and that is not a free pass.** It is
empty because SecOC state here comes from real `SECURED-I-PDU` evidence in the file
rather than from a YAML overlay, so no assumption is in play and every score has
`assumed=False`. On a snapshot where the overlay supplies the authentication layer, the
same report would carry a synthetic-SecOC limitation and the scores would be marked
assumed, which by default does not block.

**One scenario is one data point.** Recall 1.0 and specificity 0.0 for the befores
here are measured on a single regression and a single benign release. The population
numbers — detection accuracy and false positive rate over 327 labelled mutation pairs —
are in `docs/results.md`; this document exists to show the mechanism, not to establish
the rate.

**The role seeds are asserted.** Different ASIL assignments give different verdicts.
`brakeAct` at ASIL A rather than D would drop the worst finding from risk 5 to a lower
band and change BLOCK to FLAG. The tool makes the dependency explicit — every score
prints the ASIL it used in its rationale — but it cannot validate the assignment. That
is the programme's job, and the honest framing of this whole tool is that it propagates
a hazard analysis it did not perform.

**Reachability here is influence-based, not exploitability-based.** An edge means data
flows, so the target's behaviour can be affected. It does not mean the target's input
validation can be defeated. A `newly-reachable` finding says a control boundary moved,
which is a question for a human, not a proof that an attack works.

---

## Reproducing everything in this document

```bash
python -m arxml_secdiff --before tests/fixtures/scenario_b_v1.arxml --updated tests/fixtures/scenario_b_v2.arxml --roles tests/fixtures/scenario_b_roles.yaml --verbose
```

Identical-pair control, expect exit 0:

```bash
python -m arxml_secdiff --before tests/fixtures/scenario_b_v1.arxml --updated tests/fixtures/scenario_b_v1.arxml --roles tests/fixtures/scenario_b_roles.yaml
```

Benign control, expect exit 0 with one informational finding:

```bash
python -m arxml_secdiff --before tests/fixtures/scenario_b_v1.arxml --updated tests/fixtures/scenario_b_v3.arxml --roles tests/fixtures/scenario_b_roles.yaml
```
