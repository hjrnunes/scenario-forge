"""Evaluation runner — orchestrates all Tier 1 metrics and produces a scorecard.

In cmps.1, scenario and feature discovery consumes **strict manifest inventory**
entries rather than globbing the filesystem.  Paths, hashes, and roles are
verified by the shared :class:`ManifestInventoryResolver`.

Internal (in-pipeline) callers pass an in-memory resolver via *resolver*.
Standalone callers pass a *run_dir* and the manifest must be authoritative
(``completed``) unless *allow_non_authoritative* is set.
"""

from __future__ import annotations

import statistics
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from scenario_forge.eval.consistency import score_consistency
from scenario_forge.eval.diversity import score_diversity
from scenario_forge.eval.gherkin import score_gherkin
from scenario_forge.eval.grounding import score_grounding, score_technique_agreement
from scenario_forge.eval.plausibility import score_plausibility
from scenario_forge.manifest import (
    ArtifactRole,
    ManifestInventoryResolver,
    find_run_dir,
    load_strict_resolver,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)


def run_evaluation(
    run_dir: Path | None = None,
    *,
    resolver: ManifestInventoryResolver | None = None,
    threats_path: Path | None = None,
    allow_non_authoritative: bool = False,
) -> dict[str, Any]:
    """Run all Tier 1 evaluation metrics and produce a scorecard.

    Args:
        run_dir: Path to a run directory (or collection with one run).
            Used for **standalone** evaluation.  The manifest must be
            authoritative (``completed``) unless *allow_non_authoritative*
            is set.
        resolver: Pre-built in-memory resolver for **internal** pipeline
            use.  When provided, *run_dir* is ignored.
        threats_path: Optional path to OWASP agentic threats YAML.
        allow_non_authoritative: When True (standalone only), accept
            non-``completed`` finalized manifests for forensic reading.

    Returns:
        Structured scorecard dict ready for YAML/JSON serialization.
    """
    if resolver is not None:
        actual_run_dir = resolver.run_dir
    else:
        actual_run_dir = find_run_dir(run_dir)
        resolver = load_strict_resolver(
            actual_run_dir,
            require_final=True,
            require_authoritative=not allow_non_authoritative,
        )

    # Load scenarios from manifest inventory
    scenario_items: list[tuple[str, dict[str, Any]]] = []
    for entry in resolver.scenario_yaml_entries():
        data = resolver.read_yaml(entry)
        if data and isinstance(data, dict):
            stem = Path(entry.path).stem
            scenario_items.append((stem, data))

    # Load Gherkin features from manifest inventory
    gherkin_files: dict[str, str] = {}
    for entry in resolver.scenario_feature_entries():
        stem = Path(entry.path).stem
        gherkin_files[stem] = resolver.read_text(entry)

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
        gherkin_files[stem] for stem in scenario_ids if stem in gherkin_files
    ]
    for stem, text in gherkin_files.items():
        if stem not in scenario_ids:
            gherkin_texts.append(text)

    gherkin_result = score_gherkin(gherkin_texts)

    # --- Grounding ---
    grounding_result = score_grounding(scenarios, threats_path)

    # --- Technique Agreement (cross-lens) ---
    gherkin_by_scenario_id: dict[str, str] = {}
    for stem, scenario in scenario_items:
        scenario_id = scenario.get("scenario_id", stem)
        if stem in gherkin_files:
            gherkin_by_scenario_id[scenario_id] = gherkin_files[stem]
    technique_agreement_result = score_technique_agreement(
        scenarios, gherkin_by_scenario_id
    )

    # --- Load capability profile from manifest inventory ---
    expected_entry_points: int | None = None
    active_zones: set[str] | None = None
    cap_profile: CapabilityProfile | None = None

    cap_entry = resolver.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    if cap_entry is not None:
        cap_data = resolver.read_yaml(cap_entry)
        if cap_data and isinstance(cap_data, dict):
            try:
                cap_profile = CapabilityProfile.model_validate(cap_data)
                active_zones_val = (
                    set(cap_profile.zones_active) if cap_profile.zones_active else set()
                )
                ingress_eps = [
                    ep
                    for ep in cap_profile.entry_points
                    if is_attacker_accessible_ingress(ep, active_zones_val)
                ]
                expected_entry_points = len(ingress_eps)
            except ValidationError:
                # A malformed profile must not produce attacker-accessibility
                # inferences from raw dicts — the validated profile is the
                # normative path (cmps.9 third review correction 2).
                cap_profile = None
            za_list = cap_data.get("zones_active")
            if isinstance(za_list, list):
                active_zones = {str(z) for z in za_list}

    # --- Diversity ---
    diversity_result = score_diversity(
        scenarios,
        expected_entry_points=expected_entry_points,
        active_zones=active_zones,
        profile=cap_profile,
    )

    # --- Plausibility ---
    plausibility_result = score_plausibility(scenarios)

    # --- Assemble scorecard ---
    scorecard: dict[str, Any] = {
        "evaluation": {
            "output_dir": str(actual_run_dir),
            "scenario_count": len(scenarios),
            "feature_file_count": len(gherkin_texts),
            "consistency": consistency_result,
            "gherkin": gherkin_result,
            "grounding": grounding_result,
            "technique_agreement": technique_agreement_result,
            "diversity": diversity_result,
            "plausibility": plausibility_result,
        }
    }

    return scorecard
