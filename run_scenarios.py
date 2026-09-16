"""Run the 9 real-world-inspired ARXML test scenarios against this repo's own
arxml-secdiff pipeline, and print/save the results.

USAGE
-----
Drop this file, generate_scenarios.py, and scenario_defs.py into the repo's
root directory (next to arxml_secdiff/, tests/, pyproject.toml), then run:

    python run_scenarios.py

It writes each scenario's before.arxml / after.arxml / roles.yaml / NOTES.md /
cli_output.json into scenario_runs/<scenario_id>/, prints a live summary table
to the terminal, and writes scenario_runs/RESULTS.md + results.json.

No arguments, no setup beyond having the package installed the way the repo's
own README already tells you to (`pip install -e ".[test]"`).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "scenario_runs")

sys.path.insert(0, HERE)

from generate_scenarios import build_arxml, build_roles  # noqa: E402
from scenario_defs import SCENARIOS  # noqa: E402

# Same interpreter this script is running under -- works whether you invoke it
# as `python run_scenarios.py`, `python3 run_scenarios.py`, or from inside an
# activated venv. No hardcoded path to any particular .venv.
PYTHON = sys.executable

RANK = {"PASS": 0, "FLAG": 1, "INCONCLUSIVE": 1, "BLOCK": 2}


def run_one(scn) -> dict:
    d = os.path.join(OUT_DIR, scn.id)
    os.makedirs(d, exist_ok=True)

    before_path = os.path.join(d, "before.arxml")
    after_path = os.path.join(d, "after.arxml")
    roles_path = os.path.join(d, "roles.yaml")

    with open(before_path, "w", encoding="utf-8") as f:
        f.write(build_arxml(scn, scn.before_nodes, scn.before_edges))
    with open(after_path, "w", encoding="utf-8") as f:
        f.write(build_arxml(scn, scn.after_nodes, scn.after_edges))
    with open(roles_path, "w", encoding="utf-8") as f:
        f.write(build_roles(scn, scn.before_nodes))
    with open(os.path.join(d, "NOTES.md"), "w", encoding="utf-8") as f:
        f.write(
            f"# {scn.title}\n\n"
            f"**Source:** {scn.source}\n\n"
            f"**Summary:** {scn.summary}\n\n"
            f"**Expected verdict on the update (before -> after):** {scn.expected_after}\n"
        )

    cmd = [
        PYTHON, "-m", "arxml_secdiff.cli",
        "--before", before_path,
        "--updated", after_path,
        "--roles", roles_path,
        "--format", "json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)

    row = {
        "id": scn.id,
        "title": scn.title,
        "expected": scn.expected_after,
        "exit_code": proc.returncode,
    }
    try:
        data = json.loads(proc.stdout)
        row["verdict"] = data.get("verdict")
        findings = data.get("findings", [])
        row["n_findings"] = len(findings)
        row["categories"] = sorted({f.get("category") for f in findings})
    except Exception as e:  # noqa: BLE001
        row["verdict"] = f"ERROR: {e}"
        row["n_findings"] = None
        row["categories"] = []
        row["stderr"] = proc.stderr.strip()[-1500:]

    with open(os.path.join(d, "cli_output.json"), "w", encoding="utf-8") as f:
        f.write(proc.stdout)
    if proc.stderr:
        with open(os.path.join(d, "cli_stderr.txt"), "w", encoding="utf-8") as f:
            f.write(proc.stderr)

    return row


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = []
    print(f"Running {len(SCENARIOS)} scenarios against: {PYTHON}\n")
    print(f"{'scenario':30s} {'expected':10s} {'actual':14s} {'findings':9s} match")
    print("-" * 78)

    for scn in SCENARIOS:
        row = run_one(scn)
        act = str(row["verdict"])
        exp = row["expected"]
        match = "?"
        if act in RANK and exp in RANK:
            match = "yes" if act == exp or RANK[act] >= RANK[exp] else "no"
        print(f"{scn.id:30s} {exp:10s} {act:14s} {str(row['n_findings']):9s} {match}")
        row["match"] = match
        rows.append(row)

    with open(os.path.join(OUT_DIR, "results.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    lines = [
        "# Scenario test results",
        "",
        "| # | Scenario | Expected | Actual | Findings | Categories | Match |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, row in enumerate(rows, 1):
        cats = ", ".join(row["categories"]) if row["categories"] else "-"
        lines.append(
            f"| {i} | {row['title']} | {row['expected']} | {row['verdict']} | "
            f"{row['n_findings']} | {cats} | {row['match']} |"
        )
    with open(os.path.join(OUT_DIR, "RESULTS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    n_mismatch = sum(1 for r in rows if r["match"] == "no")
    print(f"\nWrote {OUT_DIR}/RESULTS.md and {OUT_DIR}/results.json")
    print(f"{len(rows) - n_mismatch}/{len(rows)} matched expectation.")
    return 1 if n_mismatch else 0


if __name__ == "__main__":
    raise SystemExit(main())
