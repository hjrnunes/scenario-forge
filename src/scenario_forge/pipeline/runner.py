"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import logging
import math
from collections import Counter
from pathlib import Path

import yaml
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from scenario_forge.data.loaders import load_risk_extraction
from scenario_forge.data.validation import validate_risk_card_coherence
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import ACTOR_TYPES, ScenarioEnvelope
from scenario_forge.pipeline.generate import (
    assign_entry_point,
    compute_entry_point_affinity,
    extract_narrative_keywords,
    extract_structural_pattern,
    generate_scenario,
    get_overused_entry_points,
    get_overused_patterns,
    get_overused_structural_patterns,
    write_scenario_outputs,
)
from scenario_forge.pipeline.coverage import (
    CoverageGaps,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from scenario_forge.pipeline.profile import infer_capability_profile
from scenario_forge.pipeline.seeds import ScenarioSeed, expand_seeds
from scenario_forge.pipeline.threats import ThreatSurface, determine_threat_surface

_DEFAULT_CROSS_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "mappings"
    / "cross-taxonomy-mappings.yaml"
)


class PipelineResult(BaseModel):
    capability_profile: CapabilityProfile
    threat_surface: ThreatSurface
    seeds: list[ScenarioSeed]
    scenarios: list[ScenarioEnvelope]
    governance_only_count: int
    generation_notes: list[str]


def _pick_best_seed_for_entry_point(
    entry_point: str,
    seeds: list[ScenarioSeed],
    profile: CapabilityProfile,
) -> ScenarioSeed | None:
    """Select the seed whose threat zones best match a given entry point.

    Uses ``compute_entry_point_affinity`` to score how well the entry point
    feeds into the zones referenced by each seed's agentic threat IDs.
    Falls back to the first seed if no affinity signal is available.

    Returns ``None`` only when the seed list is empty.
    """
    if not seeds:
        return None
    if len(seeds) == 1:
        return seeds[0]

    best_seed = seeds[0]
    best_score = -1.0

    for seed in seeds:
        # Use the profile's active zones as a proxy for the seed's zone
        # affinity (consistent with the main generation loop).
        scores = compute_entry_point_affinity(
            [entry_point],
            profile.zones_active,
        )
        score = scores.get(entry_point, 0.0)
        if score > best_score:
            best_score = score
            best_seed = seed

    return best_seed


def _remediate_coverage_gaps(
    coverage_gaps: CoverageGaps,
    seeds: list[ScenarioSeed],
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    scenarios_dir: Path,
) -> tuple[list[ScenarioEnvelope], list[str]]:
    """Generate additional scenarios for entry points that received none.

    For each uncovered entry point identified by ``analyze_coverage_gaps``,
    this function selects the most relevant existing seed (by zone affinity)
    and calls ``generate_scenario`` with that entry point forced as the
    preferred entry point.

    Args:
        coverage_gaps: Result from ``analyze_coverage_gaps``.
        seeds: The scenario seeds from Stage 3.
        profile: The capability profile from Stage 1.
        client: LLM client for generation calls.
        use_case: Free-text description of the AI system under assessment.
        scenarios_dir: Directory for scenario output files.

    Returns:
        Tuple of (remediation_scenarios, generation_notes).
    """
    if not coverage_gaps.uncovered_entry_points:
        return [], []

    remediation_scenarios: list[ScenarioEnvelope] = []
    generation_notes: list[str] = []

    uncovered = coverage_gaps.uncovered_entry_points
    logger.info(
        "[Remediation] %d uncovered entry point(s) to remediate: %s",
        len(uncovered),
        uncovered,
    )

    for ep in uncovered:
        seed = _pick_best_seed_for_entry_point(ep, seeds, profile)
        if seed is None:
            note = f"Remediation skipped for entry point '{ep}': no seeds available"
            logger.warning("  %s", note)
            generation_notes.append(note)
            continue

        logger.info(
            "  Remediating entry point '%s' with seed %s (%s)...",
            ep,
            seed.seed_id,
            seed.mechanism_name,
        )

        try:
            envelope = generate_scenario(
                seed,
                profile,
                client,
                use_case,
                preferred_entry_point=ep,
            )
            write_scenario_outputs(envelope, scenarios_dir)
            remediation_scenarios.append(envelope)
            logger.info(
                "    Remediation scenario generated: %s (entry point: %s)",
                envelope.scenario_id,
                envelope.narrative.entry_point,
            )
        except Exception as exc:
            note = (
                f"Remediation generation failed for entry point '{ep}' "
                f"with seed {seed.seed_id}: {exc}"
            )
            logger.error("    %s", note)
            generation_notes.append(note)

    logger.info(
        "[Remediation] %d/%d uncovered entry points remediated",
        len(remediation_scenarios),
        len(uncovered),
    )

    return remediation_scenarios, generation_notes


def run_profile_only(
    use_case: str,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> tuple[CapabilityProfile, LLMResult]:
    """Run Stage 1 only: infer a capability profile from a use-case description."""
    client = LLMClient(base_url=base_url, api_key=api_key, model=model)
    return infer_capability_profile(use_case, client)


def run_pipeline(
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    output_dir: Path,
    cross_taxonomy_path: Path | None = None,
    threats_path: Path | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> PipelineResult:
    """Run the full scenario-forge pipeline (stages 1-4).

    Args:
        use_case: Free-text description of the AI system under assessment.
        risk_extraction_path: Path to policy-mapper risk-extraction.json.
        sssom_path: Path to SSSOM TSV mapping file.
        output_dir: Directory for all pipeline outputs.
        cross_taxonomy_path: Path to cross-taxonomy-mappings.yaml (defaults to bundled).
        threats_path: Path to OWASP agentic threats YAML (defaults to bundled).
        base_url: LLM endpoint URL override.
        api_key: LLM API key override.
        model: LLM model name override.

    Returns:
        PipelineResult with all artifacts from the pipeline run.
    """
    ct_path = cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY_PATH
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "use-case.txt").write_text(use_case)
    generation_notes: list[str] = []

    client = LLMClient(base_url=base_url, api_key=api_key, model=model)

    # --- Stage 1: Capability Profile Inference ---
    logger.info("[Stage 1] Inferring capability profile...")
    profile, _llm_result = infer_capability_profile(use_case, client)
    logger.info("  Zones active: %s", profile.zones_active)
    logger.info("  Entry points: %d", len(profile.entry_points))
    logger.info("  Confidence: %s", profile.confidence.value)

    profile_path = output_dir / "capability-profile.yaml"
    profile_data = profile.model_dump(mode="json", exclude_none=True)
    profile_path.write_text(
        yaml.dump(
            profile_data, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    logger.info("  Written to %s", profile_path)

    # --- Stage 2: Threat Surface Determination ---
    logger.info("[Stage 2] Determining threat surface...")
    risk_cards = load_risk_extraction(risk_extraction_path)

    # Validate causal chain coherence before proceeding.
    coherence_report = validate_risk_card_coherence(use_case, risk_cards)
    if coherence_report.has_warnings:
        for card_result in coherence_report.flagged_cards:
            generation_notes.append(
                f"Risk card {card_result.risk_id} ({card_result.risk_name}) "
                f"may describe a different system (0 keyword overlap with use case)."
            )

    threat_surface = determine_threat_surface(
        profile,
        risk_cards,
        sssom_path,
        ct_path,
        threats_path,
    )

    actionable_count = len(threat_surface.entries)
    governance_count = len(threat_surface.governance_only)
    in_scope_threats = set()
    for entry in threat_surface.entries:
        in_scope_threats.update(entry.agentic_threat_ids)

    ts_path = output_dir / "threat-surface.yaml"
    ts_data = threat_surface.model_dump(mode="json", exclude_none=True)
    ts_path.write_text(
        yaml.dump(
            ts_data, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    logger.info("  %d actionable risk cards", actionable_count)
    logger.info("  %d governance-only", governance_count)
    logger.info("  %d in-scope threats", len(in_scope_threats))
    logger.info("  Written to %s", ts_path)

    # --- Stage 3: Scenario Seed Expansion ---
    logger.info("[Stage 3] Expanding scenario seeds...")
    seeds = expand_seeds(threat_surface, threats_path)
    logger.info("  %d scenario seeds to generate", len(seeds))

    # --- Stage 4: Scenario Generation ---
    logger.info("[Stage 4] Generating %d scenarios...", len(seeds))
    scenarios_dir = output_dir / "scenarios"
    scenarios: list[ScenarioEnvelope] = []

    # Track entry point usage across the batch for diversity enforcement.
    entry_point_usage: Counter[str] = Counter()
    # Track attack pattern keywords for narrative diversity enforcement.
    pattern_usage: Counter[str] = Counter()
    # Track structural attack patterns for deep diversity enforcement.
    structural_usage: Counter[str] = Counter()
    # Track actor type usage for actor diversity enforcement.
    actor_type_usage: Counter[str] = Counter()
    # Track capability level usage for capability diversity enforcement.
    capability_level_usage: Counter[str] = Counter()
    total_seeds = len(seeds)
    num_actor_types = len(ACTOR_TYPES)

    for i, seed in enumerate(seeds, 1):
        label = f"{seed.seed_id}: {seed.mechanism_name}"
        logger.info("  [%d/%d] %s...", i, len(seeds), label)

        # Determine entry point hint for this seed based on affinity + diversity.
        # Use the seed's agentic_threat_ids zones as a proxy for zone_sequence.
        # Since we don't have the zone_sequence yet (it's generated by the LLM),
        # use the profile's active zones as a rough proxy.
        preferred_ep = assign_entry_point(
            profile.entry_points,
            profile.zones_active,
            entry_point_usage,
            total_seeds,
        )
        excluded_eps = get_overused_entry_points(
            profile.entry_points,
            entry_point_usage,
            total_seeds,
        )
        excluded_pats = get_overused_patterns(pattern_usage) or None
        excluded_structural = (
            get_overused_structural_patterns(structural_usage) or None
        )

        # Compute actor type diversity hints.
        # Pick the least-used actor type as preferred; exclude types over
        # their fair share (ceil(total_seeds / num_actor_types)).
        actor_fair_share = math.ceil(total_seeds / num_actor_types)
        preferred_actor = min(
            ACTOR_TYPES, key=lambda t: actor_type_usage.get(t, 0)
        )
        excluded_actors = [
            t for t in ACTOR_TYPES
            if actor_type_usage.get(t, 0) > actor_fair_share
        ] or None

        # Compute capability level diversity hint.
        # Pick the least-used capability level as preferred.
        _CAP_LEVELS = ("novice", "intermediate", "advanced", "expert")
        preferred_cap = min(
            _CAP_LEVELS, key=lambda c: capability_level_usage.get(c, 0)
        )

        try:
            envelope = generate_scenario(
                seed,
                profile,
                client,
                use_case,
                preferred_entry_point=preferred_ep,
                excluded_entry_points=excluded_eps or None,
                excluded_patterns=excluded_pats,
                excluded_structural_patterns=excluded_structural,
                preferred_actor_type=preferred_actor,
                excluded_actor_types=excluded_actors,
                preferred_capability_level=preferred_cap,
            )
            yaml_path, feature_path = write_scenario_outputs(envelope, scenarios_dir)
            scenarios.append(envelope)

            # Track which entry point was actually chosen by the LLM.
            entry_point_usage[envelope.narrative.entry_point] += 1

            # Track which actor type was generated for diversity enforcement.
            if envelope.actor_profile is not None:
                actor_type_usage[envelope.actor_profile.actor_type] += 1
                capability_level_usage[envelope.actor_profile.capability_level] += 1

            # Track attack pattern keywords for diversity enforcement.
            keywords = extract_narrative_keywords(envelope.narrative)
            pattern_usage.update(keywords)

            # Track structural attack pattern for deep diversity enforcement.
            structural_pattern = extract_structural_pattern(envelope.narrative)
            structural_usage[structural_pattern] += 1

            notes = envelope.generation.notes or []
            generation_notes.extend(notes)
        except Exception as exc:
            msg = f"Generation failed for {seed.seed_id}: {exc}"
            logger.error("    %s", msg)
            generation_notes.append(msg)

    logger.info("  %d/%d scenarios generated successfully", len(scenarios), len(seeds))
    if generation_notes:
        logger.info("  %d note(s) recorded", len(generation_notes))

    # --- Coverage Remediation Pass ---
    # Check for uncovered entry points and generate additional scenarios
    # to fill gaps, before running the final coverage analysis.
    pre_remediation_gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
    if pre_remediation_gaps.uncovered_entry_points:
        remediation_scenarios, remediation_notes = _remediate_coverage_gaps(
            pre_remediation_gaps,
            seeds,
            profile,
            client,
            use_case,
            scenarios_dir,
        )
        scenarios.extend(remediation_scenarios)
        generation_notes.extend(remediation_notes)

    # --- Coverage Analysis ---
    logger.info("[Post-Generation] Analyzing coverage gaps...")
    coverage_gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
    attacker_diversity = analyze_attacker_diversity(scenarios)
    write_coverage_report(coverage_gaps, output_dir, attacker_diversity)

    # --- Auto-generate HTML report ---
    try:
        from scenario_forge.report.generator import generate_report

        report_path = generate_report(output_dir)
        logger.info("Report written to %s", report_path)
    except Exception as exc:
        logger.warning("Report generation failed: %s", exc)

    return PipelineResult(
        capability_profile=profile,
        threat_surface=threat_surface,
        seeds=seeds,
        scenarios=scenarios,
        governance_only_count=governance_count,
        generation_notes=generation_notes,
    )
