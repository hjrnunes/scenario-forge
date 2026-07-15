#!/usr/bin/env python3
"""Run the parsimony pruning experiment against v16 output.

Loads all 103 scenarios from output/klarna-fs-isac-v16/scenarios/*.yaml,
runs enforce_parsimony(), and reports statistics.

Usage:
    python scripts/run_parsimony_experiment.py [--scenarios-dir PATH]
"""

from __future__ import annotations

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# Add src to path so we can import scenario_forge
src_dir = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(src_dir))

from scenario_forge.models.attack_tree import repair_attack_tree_dict  # noqa: E402
from scenario_forge.models.scenario import ScenarioEnvelope  # noqa: E402
from scenario_forge.pipeline.validation import (  # noqa: E402
    _collect_leaves,
    _collect_technique_ids,
    enforce_parsimony,
)


def load_scenarios(scenarios_dir: Path) -> list[ScenarioEnvelope]:
    """Load all YAML scenario envelopes from a directory."""
    scenarios: list[ScenarioEnvelope] = []
    for yaml_path in sorted(scenarios_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            if data and isinstance(data, dict):
                # Repair attack tree before validation
                if "attack_tree" in data and isinstance(data["attack_tree"], dict):
                    data["attack_tree"] = repair_attack_tree_dict(data["attack_tree"])
                scenario = ScenarioEnvelope.model_validate(data)
                scenarios.append(scenario)
        except Exception as exc:
            print(f"  WARNING: Failed to load {yaml_path.name}: {exc}")
    return scenarios


def print_report(
    scenarios: list[ScenarioEnvelope],
    result: object,
    max_representative: int = 5,
) -> None:
    """Print a detailed parsimony pruning report."""
    from scenario_forge.pipeline.validation import ParsimonyResult

    assert isinstance(result, ParsimonyResult)

    total = len(scenarios)
    compliant = len(result.compliant_scenarios)
    pruned = len(result.pruned_scenarios)
    unprunable = len(result.unprunable_scenarios)
    total_pruned_nodes = sum(len(pn) for _, pn in result.pruned_scenarios)

    print("=" * 72)
    print("PARSIMONY PRUNING EXPERIMENT — v16 OUTPUT")
    print("=" * 72)
    print()
    print(f"Total scenarios loaded:          {total}")
    print(f"Already compliant (within budget): {compliant} ({compliant*100//total}%)")
    print(f"Successfully pruned to budget:     {pruned} ({pruned*100//total}%)")
    print(f"Unprunable (still over budget):    {unprunable} ({unprunable*100//total}%)")
    print(f"Total leaf nodes pruned:           {total_pruned_nodes}")
    print()

    # Before/after leaf counts for pruned scenarios
    if result.pruned_scenarios:
        print("-" * 72)
        print("PRUNED SCENARIOS — before/after leaf counts")
        print("-" * 72)
        print(f"{'Scenario ID':<30} {'Before':>8} {'After':>8} {'Pruned':>8} {'Budget':>8}")
        print("-" * 72)

        for pruned_scenario, pruned_nodes in result.pruned_scenarios:
            after_leaves = len(_collect_leaves(pruned_scenario.attack_tree.root))
            before_leaves = after_leaves + len(pruned_nodes)
            tech_ids = _collect_technique_ids(pruned_scenario.attack_tree.root)
            tech_count = len(tech_ids)
            budget = 2 * tech_count + 1 if tech_count > 0 else 3
            print(
                f"{pruned_scenario.scenario_id:<30} "
                f"{before_leaves:>8} "
                f"{after_leaves:>8} "
                f"{len(pruned_nodes):>8} "
                f"{budget:>8}"
            )
        print()

    # Unprunable scenarios
    if result.unprunable_scenarios:
        print("-" * 72)
        print("UNPRUNABLE SCENARIOS — still over budget")
        print("-" * 72)
        print(f"{'Scenario ID':<30} {'Actual':>8} {'Budget':>8} {'Over by':>8}")
        print("-" * 72)
        for scenario, actual, budget in result.unprunable_scenarios:
            print(
                f"{scenario.scenario_id:<30} "
                f"{actual:>8} "
                f"{budget:>8} "
                f"{actual - budget:>8}"
            )
        print()

    # Representative pruned scenarios (detailed)
    if result.pruned_scenarios:
        print("=" * 72)
        print(f"REPRESENTATIVE PRUNED SCENARIOS (showing up to {max_representative})")
        print("=" * 72)

        for idx, (pruned_scenario, pruned_nodes) in enumerate(
            result.pruned_scenarios[:max_representative]
        ):
            after_leaves = len(_collect_leaves(pruned_scenario.attack_tree.root))
            before_leaves = after_leaves + len(pruned_nodes)
            tech_ids = _collect_technique_ids(pruned_scenario.attack_tree.root)

            print()
            print(f"--- [{idx + 1}] {pruned_scenario.scenario_id} ---")
            print(f"  Techniques: {sorted(tech_ids)}")
            print(f"  Leaves: {before_leaves} -> {after_leaves}")
            print("  Nodes pruned:")
            for pn in pruned_nodes:
                print(f"    - [{pn.node_id}] \"{pn.label}\"")
                print(f"      Parent gate: {pn.parent_gate}")
                print(f"      Reason: {pn.reason}")

            print("  Remaining tree structure:")
            _print_tree(pruned_scenario.attack_tree.root, indent=4)
            print()

    # Summary statistics
    if result.pruned_scenarios:
        before_total = sum(
            len(_collect_leaves(s.attack_tree.root)) + len(pn)
            for s, pn in result.pruned_scenarios
        )
        after_total = sum(
            len(_collect_leaves(s.attack_tree.root))
            for s, _ in result.pruned_scenarios
        )
        print("=" * 72)
        print("SUMMARY STATISTICS")
        print("=" * 72)
        print(f"Total leaves across pruned scenarios (before): {before_total}")
        print(f"Total leaves across pruned scenarios (after):  {after_total}")
        print(f"Total reduction: {before_total - after_total} leaves ({(before_total - after_total)*100//before_total}%)")
        print(f"Average leaves pruned per scenario: {total_pruned_nodes / pruned:.1f}")

    # Pre-pruning analysis: how many violated parsimony
    print()
    print("-" * 72)
    print("PRE-PRUNING PARSIMONY ANALYSIS")
    print("-" * 72)
    violating = 0
    for scenario in scenarios:
        tech_ids = _collect_technique_ids(scenario.attack_tree.root)
        tech_count = len(tech_ids)
        budget = 2 * tech_count + 1 if tech_count > 0 else 3
        leaf_count = len(_collect_leaves(scenario.attack_tree.root))
        if leaf_count > budget:
            violating += 1
    print(f"Scenarios violating parsimony before pruning: {violating}/{total}")
    print(f"Scenarios compliant after pruning: {compliant + pruned}/{total}")
    print()


def _print_tree(node, indent: int = 0) -> None:
    """Pretty-print a tree node recursively."""
    prefix = " " * indent
    tech = f" [{node.technique_id}]" if node.technique_id else ""
    print(f"{prefix}{node.id} ({node.gate.value}) \"{node.label}\"{tech}")
    if node.children:
        for child in node.children:
            _print_tree(child, indent + 2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run parsimony pruning experiment against v16 output."
    )
    parser.add_argument(
        "--scenarios-dir",
        type=Path,
        default=None,
        help="Path to scenarios directory. Defaults to output/klarna-fs-isac-v16/scenarios/",
    )
    args = parser.parse_args()

    if args.scenarios_dir:
        scenarios_dir = args.scenarios_dir
    else:
        # Try common locations
        candidates = [
            Path(__file__).resolve().parent.parent
            / "output"
            / "klarna-fs-isac-v16"
            / "scenarios",
            Path.cwd() / "output" / "klarna-fs-isac-v16" / "scenarios",
        ]
        scenarios_dir = None
        for c in candidates:
            if c.is_dir():
                scenarios_dir = c
                break
        if scenarios_dir is None:
            print("ERROR: Could not find scenarios directory. Use --scenarios-dir.")
            sys.exit(1)

    print(f"Loading scenarios from: {scenarios_dir}")
    scenarios = load_scenarios(scenarios_dir)
    print(f"Loaded {len(scenarios)} scenarios.")
    print()

    result = enforce_parsimony(scenarios)
    print_report(scenarios, result)


if __name__ == "__main__":
    main()
