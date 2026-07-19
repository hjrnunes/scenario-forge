"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import logging
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import BaseModel

from scenario_forge.data.loaders import load_risk_extraction
from scenario_forge.data.validation import validate_risk_card_coherence
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.capability_profile import ZONE_NAMES, CapabilityProfile
from scenario_forge.models.scenario import ACTOR_TYPES, ScenarioEnvelope
from scenario_forge.pipeline.candidates import (
    CandidateTriple,
    FilteredSeed,
    apply_rule_based_filter,
    cap_scenarios_per_pattern,
    expand_candidates,
    filter_candidates,
)
from scenario_forge.pipeline.generate import (
    GenerationError,
    compute_entry_point_affinity,
    extract_narrative_keywords,
    compute_compatible_goal_ids,
    extract_structural_pattern,
    filter_sub_goals_by_zones,
    generate_scenario,
    get_all_sub_goals,
    get_overused_patterns,
    get_overused_structural_patterns,
    load_attack_goals_taxonomy,
    select_attack_goal,
    write_call_log,
    write_scenario_outputs,
)
from scenario_forge.pipeline.coverage import (
    CoverageGaps,
    GapAttributions,
    _normalize_entry_point,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from scenario_forge.pipeline.profile import infer_capability_profile
from scenario_forge.pipeline.validation import (
    check_leaf_technique_provenance,
    validate_insider_access_floor,
    validate_phantom_capabilities,
    validate_scenario_semantics,
    validate_scenario_structure,
)
from scenario_forge.prompts import hash_prompt_templates
from scenario_forge.pipeline.seeds import ScenarioSeed, expand_seeds
from scenario_forge.pipeline.threats import ThreatSurface, determine_threat_surface

logger = logging.getLogger(__name__)

_DEFAULT_CROSS_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[3]
    / "data"
    / "taxonomies"
    / "mappings"
    / "cross-taxonomy-mappings.yaml"
)


def _write_pipeline_call_log(entries: list[dict], output_dir: Path) -> None:
    """Append call-log entries to the top-level ``calls.jsonl`` in *output_dir*.

    This file records non-scenario LLM calls (capability profile inference,
    candidate filtering) in the same JSON-per-line format used by
    ``scenarios/calls.jsonl``.
    """
    if not entries:
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    calls_path = output_dir / "calls.jsonl"
    with calls_path.open("a", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


class PipelineResult(BaseModel):
    capability_profile: CapabilityProfile
    threat_surface: ThreatSurface
    seeds: list[ScenarioSeed]
    filtered_seeds: list[FilteredSeed] | None = None
    scenarios: list[ScenarioEnvelope]
    governance_only_count: int
    generation_notes: list[str]


def _compute_gap_attributions(
    coverage_gaps: CoverageGaps,
    seeds: list[ScenarioSeed],
    candidates: list[CandidateTriple],
    filtered_seeds: list[FilteredSeed],
    scenarios: list[ScenarioEnvelope],
    phantom_seed_ids: set[str] | None = None,
) -> GapAttributions:
    """Attribute each coverage gap to the pipeline funnel stage where it fell out.

    For each uncovered threat/entry-point/zone, walks the funnel backwards
    to determine WHY it is uncovered:

      1. ``"no_seed"`` -- no seed was generated for this item
      2. ``"no_candidate"`` -- seed existed but candidate expansion produced nothing
      3. ``"rejected"`` -- candidate existed but the LLM filter rejected it
      4. ``"phantom_flagged"`` -- scenario was generated but marked invalid by
         phantom capability validation (scenarios still present in output)
      5. ``"generation_failed"`` -- filtered seed existed but scenario generation failed
      6. ``"out_of_scope"`` -- threat gated out before seed expansion

    Args:
        phantom_seed_ids: Scenario seed IDs (attack pattern IDs) of scenarios
            that were generated but flagged by phantom capability validation.
            When provided, the function can distinguish actual generation
            failures from phantom validation flags. This can be derived from
            scenarios with ``validation.phantom.valid == False``, or passed
            explicitly for backward compatibility.
    """
    # Derive phantom_seed_ids from scenario validation blocks if not provided.
    if phantom_seed_ids is None:
        _phantom_seed_ids: set[str] = set()
        for env in scenarios:
            if (
                env.validation is not None
                and not env.validation.phantom.valid
            ):
                _phantom_seed_ids.add(
                    env.faceting.taxonomy_chain.scenario_seed
                )
    else:
        _phantom_seed_ids = phantom_seed_ids

    seed_threat_ids: set[str] = {s.threat_id for s in seeds}
    candidate_threat_ids: set[str] = {c.threat_id for c in candidates}
    filtered_threat_ids: set[str] = {f.threat_id for f in filtered_seeds}
    scenario_threat_ids: set[str] = set()
    for env in scenarios:
        scenario_threat_ids.update(env.faceting.taxonomy_chain.agentic_threat_ids)

    # Attack pattern lookup sets (seed_id IS the attack pattern ID).
    seed_ap_ids: set[str] = {s.seed_id for s in seeds}
    candidate_ap_ids: set[str] = {c.seed_id for c in candidates}
    filtered_ap_ids: set[str] = {f.seed_id for f in filtered_seeds}
    # Normalized entry-point lookup sets.
    # Note: seeds don't carry entry points; candidates are the first stage
    # that pairs seeds with entry points.
    candidate_entry_points_norm: set[str] = {
        _normalize_entry_point(c.entry_point) for c in candidates
    }
    filtered_entry_points_norm: set[str] = {
        _normalize_entry_point(f.pinned_entry_point) for f in filtered_seeds
    }

    # Phantom-flagged lookup: build threat/AP/EP sets from the seed IDs of
    # scenarios that were flagged by phantom validation.
    phantom_threat_ids: set[str] = set()
    phantom_ap_ids: set[str] = _phantom_seed_ids
    phantom_entry_points_norm: set[str] = set()
    for fs in filtered_seeds:
        if fs.seed_id in _phantom_seed_ids:
            phantom_threat_ids.add(fs.threat_id)
            phantom_entry_points_norm.add(
                _normalize_entry_point(fs.pinned_entry_point)
            )

    # Zone lookup sets (zones only exist in generated scenarios).
    scenario_zones: set[str] = set()
    for env in scenarios:
        scenario_zones.update(env.narrative.zone_sequence)

    # --- Threat attribution ---
    threat_attrs: dict[str, str] = {}
    for tid in coverage_gaps.uncovered_threats:
        if tid not in seed_threat_ids:
            threat_attrs[tid] = "no_seed"
        elif tid not in candidate_threat_ids:
            threat_attrs[tid] = "no_candidate"
        elif tid not in filtered_threat_ids:
            threat_attrs[tid] = "rejected"
        elif tid in phantom_threat_ids:
            threat_attrs[tid] = "phantom_flagged"
        else:
            # Filtered seed existed but no scenario was produced
            threat_attrs[tid] = "generation_failed"

    # --- Attack pattern attribution ---
    ap_attrs: dict[str, str] = {}
    for ap_id in coverage_gaps.uncovered_attack_patterns:
        if ap_id not in seed_ap_ids:
            ap_attrs[ap_id] = "no_seed"
        elif ap_id not in candidate_ap_ids:
            ap_attrs[ap_id] = "no_candidate"
        elif ap_id not in filtered_ap_ids:
            ap_attrs[ap_id] = "rejected"
        elif ap_id in phantom_ap_ids:
            ap_attrs[ap_id] = "phantom_flagged"
        else:
            # Filtered seed existed but no scenario was produced
            ap_attrs[ap_id] = "generation_failed"

    # --- Entry-point attribution ---
    ep_attrs: dict[str, str] = {}
    for ep in coverage_gaps.uncovered_entry_points:
        ep_norm = _normalize_entry_point(ep)
        if ep_norm not in candidate_entry_points_norm:
            # Seeds don't track entry points; candidates are the first stage
            # that does. If no candidate has this entry point, it means all
            # seeds for this entry point were skipped (e.g. no ATLAS techniques).
            ep_attrs[ep] = "no_candidate"
        elif ep_norm not in filtered_entry_points_norm:
            ep_attrs[ep] = "rejected"
        elif ep_norm in phantom_entry_points_norm:
            ep_attrs[ep] = "phantom_flagged"
        else:
            ep_attrs[ep] = "generation_failed"

    # --- Zone attribution ---
    zone_attrs: dict[str, str] = {}
    for z in coverage_gaps.uncovered_zones:
        # Zones are only produced during scenario generation (zone_sequence).
        # Seeds/candidates don't track zone traversal. If scenarios exist but
        # none traversed this zone, the generation stage didn't target it.
        if not scenarios:
            zone_attrs[z] = "generation_failed"
        else:
            zone_attrs[z] = "no_seed"

    return GapAttributions(
        entry_points=ep_attrs,
        zones=zone_attrs,
        threats=threat_attrs,
        attack_patterns=ap_attrs,
    )


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
    available_goals: list[dict] | None = None,
    goal_usage: Counter | None = None,
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
        available_goals: Filtered attack goal sub-goals for diversity.
        goal_usage: Counter tracking goal usage across the batch.

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
            seed.attack_pattern_name,
        )

        selected_goal = None
        if available_goals and goal_usage is not None:
            seed_goals = compute_compatible_goal_ids(
                threat_id=seed.threat_id,
                sub_goals=available_goals,
                zones_active=profile.zones_active,
                kc_subcodes=profile.kc_subcodes,
            )
            try:
                selected_goal = select_attack_goal(
                    seed_goals,
                    goal_usage,
                    total_seeds=len(uncovered),
                    threat_id=seed.threat_id,
                )
            except ValueError:
                pass

        try:
            envelope, call_log_entries = generate_scenario(
                seed,
                profile,
                client,
                use_case,
                pinned_entry_point=ep,
                attack_goal=selected_goal,
            )
            write_scenario_outputs(envelope, scenarios_dir)
            write_call_log(call_log_entries, scenarios_dir)
            remediation_scenarios.append(envelope)
            if goal_usage is not None and envelope.actor_profile is not None:
                if envelope.actor_profile.goal_category is not None:
                    goal_usage[envelope.actor_profile.goal_category] += 1
            logger.info(
                "    Remediation scenario generated: %s (entry point: %s)",
                envelope.scenario_id,
                envelope.narrative.entry_point,
            )
        except GenerationError as exc:
            if exc.call_log_entries:
                write_call_log(exc.call_log_entries, scenarios_dir)
            note = (
                f"Remediation generation failed for entry point '{ep}' "
                f"with seed {seed.seed_id}: {exc}"
            )
            logger.error("    %s", note)
            generation_notes.append(note)
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
    profile_path: Path | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    max_techniques: int = 1,
    max_scenarios_per_pattern: int | None = None,
    zones: str | None = None,
    eval: bool = True,
) -> PipelineResult:
    """Run the full scenario-forge pipeline (stages 1-4).

    Args:
        use_case: Free-text description of the AI system under assessment.
        risk_extraction_path: Path to policy-mapper risk-extraction.json.
        sssom_path: Path to SSSOM TSV mapping file.
        output_dir: Directory for all pipeline outputs.
        cross_taxonomy_path: Path to cross-taxonomy-mappings.yaml (defaults to bundled).
        threats_path: Path to OWASP agentic threats YAML (defaults to bundled).
        profile_path: Path to a pre-built capability-profile.yaml (skips Stage 1 inference).
        base_url: LLM endpoint URL override.
        api_key: LLM API key override.
        model: LLM model name override.
        max_scenarios_per_pattern: Cap on scenarios per attack pattern (None = no cap).
        eval: Whether to run deterministic eval metrics after generation (default True).

    Returns:
        PipelineResult with all artifacts from the pipeline run.
    """
    ct_path = cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY_PATH
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "use-case.txt").write_text(use_case)
    generation_notes: list[str] = []

    client = LLMClient(base_url=base_url, api_key=api_key, model=model)

    # --- Write run manifest (start) ---
    manifest = {
        "version": importlib.metadata.version("scenario-forge"),
        "timestamp_start": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "use_case_hash": hashlib.sha256(use_case.encode()).hexdigest(),
            "risk_extraction_hash": hashlib.sha256(
                risk_extraction_path.read_bytes()
            ).hexdigest(),
            "sssom_hash": hashlib.sha256(sssom_path.read_bytes()).hexdigest(),
        },
        "config": {
            "model": client.model,
            "temperature": client.temperature,
            "max_completion_tokens": client.max_completion_tokens,
            "prompt_template_hashes": hash_prompt_templates(),
        },
    }
    manifest_path = output_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(manifest, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )

    # --- Stage 1: Capability Profile Inference ---
    if profile_path is not None:
        logger.info("[Stage 1] Loading capability profile from %s", profile_path)
        profile_data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        profile = CapabilityProfile(**profile_data)
    else:
        logger.info("[Stage 1] Inferring capability profile...")
        profile, profile_llm_result = infer_capability_profile(use_case, client)
        # Log the profile inference LLM call to top-level calls.jsonl.
        raw_content = profile_llm_result.content
        if hasattr(raw_content, "model_dump"):
            raw_content = raw_content.model_dump(mode="json")
        elif not isinstance(raw_content, str):
            raw_content = str(raw_content)
        _write_pipeline_call_log(
            [{
                "call": "capability_profile",
                "system_prompt": profile_llm_result.system_prompt,
                "user_prompt": profile_llm_result.user_prompt,
                "response": raw_content,
                "prompt_tokens": profile_llm_result.prompt_tokens,
                "completion_tokens": profile_llm_result.completion_tokens,
                "duration_ms": profile_llm_result.duration_ms,
            }],
            output_dir,
        )
    if zones is not None:
        requested = [z.strip() for z in zones.split(",")]
        invalid = [z for z in requested if z not in ZONE_NAMES]
        if invalid:
            raise ValueError(
                f"Unknown zone(s): {', '.join(invalid)}. Valid: {', '.join(ZONE_NAMES)}"
            )
        filtered = [z for z in requested if z in profile.zones_active]
        updates: dict = {"zones_active": filtered}
        if "memory" not in filtered:
            updates["has_persistent_memory"] = False
        if "inter_agent" not in filtered:
            updates["multi_agent"] = False
        # Strip zone tags from entry points whose zone is excluded.
        _zone_alts = "|".join(re.escape(z) for z in ZONE_NAMES)
        _zone_tag_re = re.compile(
            r"\s*\((" + _zone_alts + r")\)\s*$",
        )
        cleaned_entry_points = []
        entry_points_changed = False
        for ep in profile.entry_points:
            m = _zone_tag_re.search(ep.name)
            if m and m.group(1) not in filtered:
                cleaned_name = ep.name[: m.start()].rstrip()
                logger.warning(
                    "Stripped zone tag from entry point: '%s' -> '%s'",
                    ep.name,
                    cleaned_name,
                )
                cleaned_entry_points.append(
                    ep.model_copy(update={"name": cleaned_name})
                )
                entry_points_changed = True
            else:
                cleaned_entry_points.append(ep)
        if entry_points_changed:
            updates["entry_points"] = cleaned_entry_points
        profile = profile.model_copy(update=updates)
        logger.info("  Zone filter applied: %s", filtered)

    logger.info("  Zones active: %s", profile.zones_active)
    logger.info("  Entry points: %d", len(profile.entry_points))
    logger.info("  Confidence: %s", profile.confidence.value)

    profile_output_path = output_dir / "capability-profile.yaml"
    profile_data = profile.model_dump(mode="json", exclude_none=True)
    profile_output_path.write_text(
        yaml.dump(
            profile_data, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )
    logger.info("  Written to %s", profile_output_path)

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

    # --- Stage 3.5: Candidate Expansion + Filtering (hybrid) ---
    logger.info("[Stage 3.5] Expanding and filtering candidates...")
    candidates = expand_candidates(seeds, profile, max_techniques=max_techniques)
    candidates_expanded = len(candidates)

    # Phase 1: Deterministic rule-based pre-filter.
    rule_passed, rule_rejected, rule_verdicts = apply_rule_based_filter(
        candidates, profile
    )
    rule_rejected_count = len(rule_rejected)
    if rule_rejected_count:
        logger.info(
            "  Rule pre-filter: %d/%d candidates rejected, %d passed to LLM",
            rule_rejected_count,
            candidates_expanded,
            len(rule_passed),
        )

    # Phase 2: LLM filter on survivors only.
    filtered_seeds, filter_call_logs = filter_candidates(
        rule_passed, seeds, client, use_case, profile
    )
    # Log candidate filter LLM calls to top-level calls.jsonl.
    _write_pipeline_call_log(filter_call_logs, output_dir)
    candidates_accepted = len(filtered_seeds)
    candidates_rejected = candidates_expanded - candidates_accepted
    logger.info(
        "  %d candidates -> %d rule-rejected, %d LLM-filtered -> %d accepted",
        candidates_expanded,
        rule_rejected_count,
        len(rule_passed) - candidates_accepted,
        candidates_accepted,
    )

    # Apply per-pattern cap if requested.
    candidates_capped = 0
    if max_scenarios_per_pattern is not None:
        pre_cap_count = len(filtered_seeds)
        filtered_seeds = cap_scenarios_per_pattern(
            filtered_seeds, max_scenarios_per_pattern
        )
        candidates_capped = pre_cap_count - len(filtered_seeds)
        if candidates_capped > 0:
            logger.info(
                "  Per-pattern cap (%d): %d -> %d filtered seeds (%d capped)",
                max_scenarios_per_pattern,
                pre_cap_count,
                len(filtered_seeds),
                candidates_capped,
            )

    # --- Stage 4: Scenario Generation ---
    logger.info("[Stage 4] Generating %d scenarios...", len(filtered_seeds))
    scenarios_dir = output_dir / "scenarios"
    scenarios: list[ScenarioEnvelope] = []
    failed_count = 0

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
    # Track attack goal usage for goal diversity enforcement.
    goal_usage: Counter[str] = Counter()
    total_seeds = len(filtered_seeds)
    num_actor_types = len(ACTOR_TYPES)

    # Load attack goals taxonomy and filter to system-relevant sub-goals.
    try:
        attack_goals_taxonomy = load_attack_goals_taxonomy()
        all_sub_goals = get_all_sub_goals(attack_goals_taxonomy)
        available_goals = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=profile.zones_active,
            has_persistent_memory=profile.has_persistent_memory,
            hitl=profile.hitl,
            multi_agent=profile.multi_agent,
        )
        logger.info(
            "  Attack goals taxonomy: %d/%d sub-goals available for this system",
            len(available_goals),
            len(all_sub_goals),
        )
    except Exception as exc:
        logger.warning(
            "  Failed to load attack goals taxonomy: %s — proceeding without goal diversity",
            exc,
        )
        available_goals = []

    for i, fseed in enumerate(filtered_seeds, 1):
        label = f"{fseed.seed_id}: {fseed.attack_pattern_name}"
        logger.info("  [%d/%d] %s...", i, total_seeds, label)

        excluded_pats = get_overused_patterns(pattern_usage) or None
        excluded_structural = get_overused_structural_patterns(structural_usage) or None

        # Compute actor type diversity hints.
        # Pick the least-used actor type as preferred; exclude types over
        # their fair share (ceil(total_seeds / num_actor_types)).
        actor_fair_share = (
            math.ceil(total_seeds / num_actor_types) if total_seeds else 1
        )
        preferred_actor = min(ACTOR_TYPES, key=lambda t: actor_type_usage.get(t, 0))
        excluded_actors = [
            t for t in ACTOR_TYPES if actor_type_usage.get(t, 0) > actor_fair_share
        ] or None

        # Compute capability level diversity hint.
        # Pick the least-used capability level as preferred.
        _CAP_LEVELS = ("novice", "intermediate", "advanced", "expert")
        preferred_cap = min(_CAP_LEVELS, key=lambda c: capability_level_usage.get(c, 0))

        # Select an attack goal for this seed using fair-share diversity.
        # Narrow the sub-goal pool per-seed with architectural and
        # threat-specific exclusions (i7q8 constraint).
        selected_goal = None
        if available_goals:
            seed_goals = compute_compatible_goal_ids(
                threat_id=fseed.threat_id,
                sub_goals=available_goals,
                zones_active=profile.zones_active,
                kc_subcodes=profile.kc_subcodes,
            )
            try:
                selected_goal = select_attack_goal(
                    seed_goals,
                    goal_usage,
                    total_seeds,
                    threat_id=fseed.threat_id,
                )
            except ValueError:
                pass  # No goals available — proceed without goal diversity

        try:
            envelope, call_log_entries = generate_scenario(
                fseed,
                profile,
                client,
                use_case,
                excluded_patterns=excluded_pats,
                excluded_structural_patterns=excluded_structural,
                preferred_actor_type=preferred_actor,
                excluded_actor_types=excluded_actors,
                preferred_capability_level=preferred_cap,
                attack_goal=selected_goal,
                pinned_entry_point=fseed.pinned_entry_point,
                pinned_technique_ids=list(fseed.pinned_technique_ids),
                pinned_technique_names=list(fseed.pinned_technique_names),
            )
            # Attach candidate filter provenance data to the envelope.
            envelope.candidate_filter = {
                "pinned_entry_point": fseed.pinned_entry_point,
                "pinned_technique_ids": list(fseed.pinned_technique_ids),
                "pinned_technique_names": list(fseed.pinned_technique_names),
                "rejection_rationales": [
                    v.model_dump() for v in fseed.rejection_rationales
                ],
            }

            yaml_path, feature_path = write_scenario_outputs(envelope, scenarios_dir)
            write_call_log(call_log_entries, scenarios_dir)
            scenarios.append(envelope)

            # Track which entry point was actually chosen by the LLM.
            entry_point_usage[envelope.narrative.entry_point] += 1

            # Track which actor type was generated for diversity enforcement.
            if envelope.actor_profile is not None:
                actor_type_usage[envelope.actor_profile.actor_type] += 1
                capability_level_usage[envelope.actor_profile.capability_level] += 1
                # Track goal category usage for goal diversity enforcement.
                if envelope.actor_profile.goal_category is not None:
                    goal_usage[envelope.actor_profile.goal_category] += 1

            # Track attack pattern keywords for diversity enforcement.
            keywords = extract_narrative_keywords(
                envelope.narrative, attack_pattern_name=fseed.attack_pattern_name
            )
            pattern_usage.update(keywords)

            # Track structural attack pattern for deep diversity enforcement.
            structural_pattern = extract_structural_pattern(envelope.narrative)
            structural_usage[structural_pattern] += 1

            notes = envelope.generation.notes or []
            generation_notes.extend(notes)
        except GenerationError as exc:
            if exc.call_log_entries:
                write_call_log(exc.call_log_entries, scenarios_dir)
            msg = f"Generation failed for {fseed.seed_id}: {exc}"
            logger.error("    %s", msg)
            generation_notes.append(msg)
            failed_count += 1
        except Exception as exc:
            msg = f"Generation failed for {fseed.seed_id}: {exc}"
            logger.error("    %s", msg)
            generation_notes.append(msg)
            failed_count += 1

    logger.info(
        "  %d/%d scenarios generated successfully", len(scenarios), len(filtered_seeds)
    )
    if generation_notes:
        logger.info("  %d note(s) recorded", len(generation_notes))

    # --- Phantom Capability Validation Pass ---
    logger.info("[Validation] Checking for phantom capabilities...")
    validation_result = validate_phantom_capabilities(scenarios, profile)
    if validation_result.flagged_count:
        for flagged_scenario, violations in validation_result.flagged_scenarios:
            for v in violations:
                logger.warning(
                    "  Phantom capability in %s step %d (%s): [%s] %s",
                    flagged_scenario.scenario_id,
                    v.step_number,
                    v.field,
                    v.category,
                    v.matched_text,
                )
        logger.info(
            "  %d/%d scenarios passed phantom validation, %d flagged (warn+mark)",
            validation_result.valid_count,
            len(scenarios),
            validation_result.flagged_count,
        )
    else:
        logger.info("  All %d scenarios passed phantom validation", len(scenarios))
    # Note: scenarios are NOT dropped. They carry validation.phantom results.

    # --- Structural Validation Pass ---
    logger.info("[Validation] Running structural (JSON Schema) validation...")
    validate_scenario_structure(scenarios)
    structural_fail_count = sum(
        1 for s in scenarios
        if s.validation is not None and not s.validation.structural.valid
    )
    if structural_fail_count:
        logger.warning(
            "  %d/%d scenarios have structural validation issues (warn+mark)",
            structural_fail_count,
            len(scenarios),
        )
    else:
        logger.info("  All %d scenarios passed structural validation", len(scenarios))

    # --- Semantic Validation Pass ---
    logger.info("[Validation] Running semantic validation...")
    validate_scenario_semantics(scenarios, profile)
    semantic_fail_count = sum(
        1 for s in scenarios
        if s.validation is not None and not s.validation.semantic.valid
    )
    if semantic_fail_count:
        logger.warning(
            "  %d/%d scenarios have semantic validation issues (warn+mark)",
            semantic_fail_count,
            len(scenarios),
        )
    else:
        logger.info("  All %d scenarios passed semantic validation", len(scenarios))

    # --- Insider Access Floor Pass ---
    logger.info("[Validation] Checking insider access floor...")
    insider_result = validate_insider_access_floor(scenarios)
    if insider_result.flagged_count:
        for flagged_scenario, violation in insider_result.flagged_scenarios:
            logger.warning(
                "  Insider access floor: %s — %s",
                violation.scenario_id,
                violation.reason,
            )
        logger.info(
            "  %d/%d malicious-insider scenarios flagged (warn only)",
            insider_result.flagged_count,
            insider_result.flagged_count + insider_result.clean_count,
        )
    else:
        logger.info("  All scenarios passed insider access floor check")

    # --- Leaf Technique Provenance Pass ---
    logger.info("[Validation] Checking leaf technique provenance...")
    leaf_technique_result = check_leaf_technique_provenance(scenarios)
    if leaf_technique_result.flagged_count:
        for flagged_scenario, violations in leaf_technique_result.flagged_scenarios:
            for v in violations:
                logger.warning(
                    "  Missing technique_id in %s node %s (%s, zone=%s): %s",
                    flagged_scenario.scenario_id,
                    v.node_id,
                    v.label,
                    v.zone,
                    v.reason,
                )
        logger.info(
            "  %d/%d scenarios clean, %d flagged (warnings only)",
            leaf_technique_result.clean_count,
            len(scenarios),
            leaf_technique_result.flagged_count,
        )
    else:
        logger.info(
            "  All %d scenarios have complete leaf technique provenance",
            len(scenarios),
        )

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
            available_goals=available_goals,
            goal_usage=goal_usage,
        )
        scenarios.extend(remediation_scenarios)
        generation_notes.extend(remediation_notes)

    # --- Coverage Analysis ---
    logger.info("[Post-Generation] Analyzing coverage gaps...")
    coverage_gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
    attacker_diversity = analyze_attacker_diversity(scenarios)

    # --- Funnel-stage attribution for coverage gaps ---
    if coverage_gaps.has_gaps:
        coverage_gaps.gap_attributions = _compute_gap_attributions(
            coverage_gaps,
            seeds,
            candidates,
            filtered_seeds,
            scenarios,
        )
    write_coverage_report(coverage_gaps, output_dir, attacker_diversity)

    # --- Update run manifest (end) — before report so it can read stats ---
    manifest["timestamp_end"] = datetime.now(timezone.utc).isoformat()
    manifest["seeds_generated"] = len(seeds)
    manifest["candidates_expanded"] = candidates_expanded
    manifest["candidates_rule_rejected"] = rule_rejected_count
    manifest["candidates_accepted"] = candidates_accepted
    manifest["candidates_rejected"] = candidates_rejected
    if max_scenarios_per_pattern is not None:
        manifest["max_scenarios_per_pattern"] = max_scenarios_per_pattern
        manifest["candidates_capped"] = candidates_capped
    manifest["scenarios_generated"] = len(scenarios)
    manifest["scenarios_failed"] = failed_count
    manifest["phantom_validation"] = {
        "flagged_count": validation_result.flagged_count,
        "violation_categories": validation_result.violation_categories,
    }
    manifest["structural_validation"] = {
        "failed_count": structural_fail_count,
        "passed_count": len(scenarios) - structural_fail_count,
    }
    manifest["semantic_validation"] = {
        "failed_count": semantic_fail_count,
        "passed_count": len(scenarios) - semantic_fail_count,
    }
    manifest["leaf_technique_provenance"] = {
        "flagged_count": leaf_technique_result.flagged_count,
        "clean_count": leaf_technique_result.clean_count,
    }
    manifest_path.write_text(
        yaml.dump(manifest, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )

    # --- Auto-evaluate scenarios (deterministic metrics) ---
    if eval:
        try:
            from scenario_forge.eval.runner import run_evaluation

            logger.info("[Eval] Running deterministic quality metrics...")
            scorecard = run_evaluation(output_dir, threats_path=threats_path)
            scorecard_path = output_dir / "eval-scorecard.yaml"
            scorecard_path.write_text(
                yaml.dump(
                    scorecard,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                ),
                encoding="utf-8",
            )
            logger.info("  Scorecard written to %s", scorecard_path)
        except Exception as exc:
            logger.warning("Eval scorecard generation failed: %s", exc)
    else:
        logger.info(
            "[Eval] Skipped (--no-eval). Run 'scenario-forge eval --output-dir %s' to generate.",
            output_dir,
        )

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
        filtered_seeds=filtered_seeds,
        scenarios=scenarios,
        governance_only_count=governance_count,
        generation_notes=generation_notes,
    )
