"""Evaluation runner — orchestrates all Tier 1 metrics and produces a scorecard.

Loads scenario YAML files and Gherkin .feature files from an output directory,
runs all deterministic metrics, and produces a structured scorecard.
"""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import Any

import yaml

from scenario_forge.eval.consistency import score_consistency
from scenario_forge.eval.diversity import score_diversity
from scenario_forge.eval.gherkin import score_gherkin
from scenario_forge.eval.grounding import score_grounding
from scenario_forge.eval.plausibility import score_plausibility


def _load_scenarios(scenarios_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    """Load all scenario YAML files from a directory.

    Returns:
        List of (stem, parsed_dict) tuples, sorted by stem.
    """
    results: list[tuple[str, dict[str, Any]]] = []
    if not scenarios_dir.exists():
        return results

    for yaml_path in sorted(scenarios_dir.glob("*.yaml")):
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        if data and isinstance(data, dict):
            results.append((yaml_path.stem, data))

    return results


def _load_gherkin_files(scenarios_dir: Path) -> dict[str, str]:
    """Load all .feature files from a directory.

    Returns:
        Dict mapping file stem to Gherkin text content.
    """
    results: dict[str, str] = {}
    if not scenarios_dir.exists():
        return results

    for feature_path in sorted(scenarios_dir.glob("*.feature")):
        results[feature_path.stem] = feature_path.read_text(encoding="utf-8")

    return results


def run_evaluation(
    output_dir: Path,
    threats_path: Path | None = None,
) -> dict[str, Any]:
    """Run all Tier 1 evaluation metrics and produce a scorecard.

    Args:
        output_dir: Path to the pipeline output directory.
            Expects scenarios in output_dir/scenarios/.
        threats_path: Optional path to OWASP agentic threats YAML.

    Returns:
        Structured scorecard dict ready for YAML/JSON serialization.
    """
    scenarios_dir = output_dir / "scenarios"

    # Load data
    scenario_items = _load_scenarios(scenarios_dir)
    gherkin_files = _load_gherkin_files(scenarios_dir)

    scenarios = [data for _, data in scenario_items]
    scenario_ids = [stem for stem, _ in scenario_items]

    # --- Consistency (per-scenario) ---
    consistency_scores: dict[str, dict[str, Any]] = {}
    means: list[float] = []

    for stem, scenario in scenario_items:
        gherkin_text = gherkin_files.get(stem)
        scores = score_consistency(scenario, gherkin_text)
        consistency_scores[stem] = {
            "zone_alignment": scores["zone_alignment"],
            "entry_point_agreement": scores["entry_point_agreement"],
            "step_node_correspondence": scores["step_node_correspondence"],
        }
        means.append(scores["mean"])

    consistency_result: dict[str, Any] = {
        "mean": round(statistics.mean(means), 4) if means else 0.0,
    }
    if len(means) >= 2:
        consistency_result["stddev"] = round(statistics.stdev(means), 4)
    else:
        consistency_result["stddev"] = 0.0
    consistency_result["per_scenario"] = consistency_scores

    # --- Gherkin ---
    gherkin_texts = [
        gherkin_files[stem]
        for stem in scenario_ids
        if stem in gherkin_files
    ]
    # Include any feature files not matched to a scenario YAML
    for stem, text in gherkin_files.items():
        if stem not in scenario_ids:
            gherkin_texts.append(text)

    gherkin_result = score_gherkin(gherkin_texts)

    # --- Grounding ---
    grounding_result = score_grounding(scenarios, threats_path)

    # --- Diversity ---
    diversity_result = score_diversity(scenarios)

    # --- Plausibility ---
    plausibility_result = score_plausibility(scenarios)

    # --- Assemble scorecard ---
    scorecard: dict[str, Any] = {
        "evaluation": {
            "output_dir": str(output_dir),
            "scenario_count": len(scenarios),
            "feature_file_count": len(gherkin_texts),
            "consistency": consistency_result,
            "gherkin": gherkin_result,
            "grounding": grounding_result,
            "diversity": diversity_result,
            "plausibility": plausibility_result,
        }
    }

    return scorecard
