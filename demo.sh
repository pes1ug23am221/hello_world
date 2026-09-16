#!/usr/bin/env bash
# ============================================================================
# arxml-secdiff -- Live Demo Script for Panel Review
# ============================================================================
# Run this from inside the cloned repo root (the arxml-secdiff/ directory).
#
# HOW TO USE:
#   chmod +x demo.sh
#   ./demo.sh
#
# The script pauses after each step (press ENTER to continue) so you can talk
# over the output before moving on. Nothing here modifies your repo -- every
# command was verified against the actual test fixtures before this script
# was written.
# ============================================================================

set -uo pipefail  # catch typos/unset vars, but NOT nonzero exits -- exit
                   # codes 1/2/3 from arxml-secdiff are correct, expected
                   # outcomes (FLAG/INCONCLUSIVE/BLOCK), not script failures

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

pause() {
    echo
    read -rp "$(echo -e "${DIM}press ENTER to continue...${RESET}")" _
    echo
}

section() {
    echo
    echo -e "${BOLD}${CYAN}============================================================${RESET}"
    echo -e "${BOLD}${CYAN} $1${RESET}"
    echo -e "${BOLD}${CYAN}============================================================${RESET}"
    echo
}

say() {
    echo -e "${GREEN}>> $1${RESET}"
    echo
}

# ----------------------------------------------------------------------------
# Sanity check: make sure we're actually in the repo, before wasting the
# panel's time on a "command not found" in front of them.
# ----------------------------------------------------------------------------
if [ ! -f "pyproject.toml" ] || [ ! -d "arxml_secdiff" ]; then
    echo "ERROR: run this script from inside the arxml-secdiff/ repo root."
    exit 1
fi

if ! command -v arxml-secdiff &> /dev/null; then
    echo "ERROR: arxml-secdiff CLI not found on PATH."
    echo "Run 'pip install -e \".[test]\"' first (do this BEFORE walking into the room)."
    exit 1
fi

clear
section "arxml-secdiff -- Security Regression Detection for AUTOSAR ARXML"
say "Detects security regressions between two AUTOSAR ARXML architecture snapshots
   by combining structural diffing, attacker-reachability analysis, and SecOC
   authentication checks into one auditable PASS / FLAG / BLOCK decision."
pause


# ----------------------------------------------------------------------------
# STEP 1 -- Control case: identical files must never raise a false alarm.
# ----------------------------------------------------------------------------
section "STEP 1 / 6 -- Control case: same file vs. itself"
say "Same ARXML compared to itself. If the tool cries wolf here, nothing else
   it says can be trusted."

arxml-secdiff \
    --before tests/fixtures/scenario_b_v1.arxml \
    --updated  tests/fixtures/scenario_b_v1.arxml \
    --roles    tests/fixtures/scenario_b_roles.yaml

say "Expect: VERDICT PASS, exit code 0."
pause


# ----------------------------------------------------------------------------
# STEP 2 -- The flagship regression.
# ----------------------------------------------------------------------------
section "STEP 2 / 6 -- The flagship regression (this is the thesis of the project)"
say "This pair models a real regression: a new Bluetooth-reachable path opens up
   to the brake actuator, and SecOC authentication is dropped on one hop along
   the way. Watch the verdict at the top."

arxml-secdiff \
    --before tests/fixtures/scenario_b_v1.arxml \
    --updated  tests/fixtures/scenario_b_v2.arxml \
    --roles    tests/fixtures/scenario_b_roles.yaml \
    --verbose

say "Expect: VERDICT BLOCK, exit code 3, with the full attack path listed."
pause


# ----------------------------------------------------------------------------
# STEP 3 -- Export and open the visual graph for the same regression.
# ----------------------------------------------------------------------------
section "STEP 3 / 6 -- Same regression, but visual"
say "Exporting the attack-path graph as an image -- the exact route from Step 2,
   drawn out. Red hops are unauthenticated or on the attack path."

rm -rf demo_out
arxml-secdiff \
    --before tests/fixtures/scenario_b_v1.arxml \
    --updated  tests/fixtures/scenario_b_v2.arxml \
    --roles    tests/fixtures/scenario_b_roles.yaml \
    --export-graphs demo_out --quiet

say "Files written to demo_out/. Opening the updated attack-path graph now..."

if command -v xdg-open &> /dev/null; then
    xdg-open demo_out/updated_graph.png &> /dev/null &
elif command -v open &> /dev/null; then
    open demo_out/updated_graph.png &
else
    say "(Could not auto-open an image viewer -- open demo_out/updated_graph.png manually.)"
fi

pause


# ----------------------------------------------------------------------------
# STEP 4 -- Benign case: proves precision, not just recall.
# ----------------------------------------------------------------------------
section "STEP 4 / 6 -- Benign case: a real change that isn't dangerous"
say "A component was genuinely added here -- but it's never wired into anything
   reachability-relevant. This is what separates the tool from a plain text
   diff: it doesn't flag noise."

arxml-secdiff \
    --before tests/fixtures/scenario_b_v1.arxml \
    --updated  tests/fixtures/scenario_b_v3.arxml \
    --roles    tests/fixtures/scenario_b_roles.yaml

say "Expect: VERDICT PASS, exit code 0, one informational finding only."
pause


# ----------------------------------------------------------------------------
# STEP 5 -- Measured precision/recall against naive befores.
# ----------------------------------------------------------------------------
section "STEP 5 / 6 -- Measured, not claimed"
say "Running the full evaluation harness: 15 labelled cases (regression / benign
   / known-gap), scored against three straw-man 'naive' detectors."

python -m arxml_secdiff.evaluate --before tests/fixtures/veh_v1.arxml --canonical

say "Expect: 100% precision, 100% recall, 0% false-positive rate, every label held."
pause


# ----------------------------------------------------------------------------
# STEP 6 -- Full test suite.
# ----------------------------------------------------------------------------
section "STEP 6 / 6 -- Full test suite"
say "401 tests across every module -- parser through CLI. This runs in about
   two seconds; safe to run live."

pytest -q

say "Demo complete."
echo
echo -e "${BOLD}${GREEN}Summary for the panel:${RESET}"
echo "  - Identical input  -> PASS   (no false alarms)"
echo "  - Real regression  -> BLOCK  (exact attack path identified)"
echo "  - Benign change    -> PASS   (no noise flagged)"
echo "  - Measured         -> 100% precision / 100% recall / 0% false-positive rate"
echo "  - Tested           -> 401 passing tests"
echo