"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import hashlib
import importlib.metadata
import logging
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import BaseModel

from scenario_forge.data.loaders import (
    load_attack_goals_taxonomy,
    load_risk_extraction,
)
from scenario_forge.data.validation import validate_risk_card_coherence
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.capability_profile import (
    ZONE_NAMES,
    CapabilityProfile,
)
from scenario_forge.models.scenario import ScenarioEnvelope
from scenario_forge.pipeline.candidates import (
    CandidateFunnel,
    CandidateTriple,
    FilterProtocolError,
    FilteredSeed,
    StageRecord,
    apply_rule_based_filter,
    cap_scenarios_per_pattern,
    compute_candidate_id,
    expand_candidates,
    filter_candidates,
)
from scenario_forge.pipeline.diversity import DiversityTracker
from scenario_forge.pipeline.generate import (
    GenerationError,
    ScenarioForgeIntegrityError,
    compute_artifact_hash,
    compute_entry_point_affinity,
    compute_compatible_goal_ids,
    filter_sub_goals_by_zones,
    generate_run_id,
    generate_scenario,
    get_all_sub_goals,
    replace_scenario_outputs,
    select_attack_goal,
    write_call_log,
    write_scenario_outputs,
)
from scenario_forge.pipeline.io import (
    get_scenarios_dir,
    setup_pipeline_output,
    write_capability_profile,
    write_eval_scorecard,
    write_final_manifest,
    write_pipeline_call_log,
    write_threat_surface,
)
from scenario_forge.pipeline.coverage import (
    CoverageGaps,
    GapAttributions,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from scenario_forge.pipeline.profile import infer_capability_profile
from scenario_forge.pipeline.validation import (
    check_leaf_technique_provenance,
    enforce_parsimony,
    validate_gate_logic_consistency,
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
    profile: CapabilityProfile | None = None,
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
            if env.validation is not None and not env.validation.phantom.valid:
                _phantom_seed_ids.add(env.faceting.taxonomy_chain.scenario_seed)
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
    # Entry-point lookup sets by canonical entry_point_id.
    # Note: seeds don't carry entry points; candidates are the first stage
    # that pairs seeds with entry points.
    candidate_entry_points_norm: set[str] = {c.entry_point_id for c in candidates}
    filtered_entry_points_norm: set[str] = {f.entry_point_id for f in filtered_seeds}

    # Phantom-flagged lookup: build threat/AP/EP sets from the seed IDs of
    # scenarios that were flagged by phantom validation.
    phantom_threat_ids: set[str] = set()
    phantom_ap_ids: set[str] = _phantom_seed_ids
    phantom_entry_points_norm: set[str] = set()
    for fs in filtered_seeds:
        if fs.seed_id in _phantom_seed_ids:
            phantom_threat_ids.add(fs.threat_id)
            phantom_entry_points_norm.add(fs.entry_point_id)

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
    # Attribution is keyed by entry_point_id (canonical identity), not by
    # display name.  EntryPointGap records carry both the ID and the name,
    # so we join directly by ID.
    ep_attrs: dict[str, str] = {}
    for ep_gap in coverage_gaps.uncovered_entry_points:
        ep_id = ep_gap.entry_point_id
        if ep_id not in candidate_entry_points_norm:
            ep_attrs[ep_id] = "no_candidate"
        elif ep_id not in filtered_entry_points_norm:
            ep_attrs[ep_id] = "rejected"
        elif ep_id in phantom_entry_points_norm:
            ep_attrs[ep_id] = "phantom_flagged"
        else:
            ep_attrs[ep_id] = "generation_failed"

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
    run_id: str,
    attempted_candidate_ids: set[str],
    admitted_candidate_ids: set[str],
    admitted_scenario_ids: set[str],
    write_receipts: list[dict],
    available_goals: list[dict] | None = None,
    goal_usage: Counter | None = None,
) -> tuple[list[ScenarioEnvelope], list[str], int, int]:
    """Generate additional scenarios for entry points that received none.

    Remediation scenarios go through the same generation, write, and
    admission path as main candidates — they are counted in
    attempted/admitted/failed funnel metrics.  The candidate ID is
    computed from the actual pinned technique tuple (the seed's
    ATLAS technique IDs for the selected entry point), not an empty
    technique set.

    Returns:
        Tuple of (remediation_scenarios, generation_notes,
        remediation_attempted, remediation_failed).
    """
    if not coverage_gaps.uncovered_entry_points:
        return [], [], 0, 0

    remediation_scenarios: list[ScenarioEnvelope] = []
    generation_notes: list[str] = []
    remediation_attempted = 0
    remediation_failed = 0

    uncovered = coverage_gaps.uncovered_entry_points
    logger.info(
        "[Remediation] %d uncovered entry point(s) to remediate: %s",
        len(uncovered),
        [ep.name for ep in uncovered],
    )

    remediated_ids: set[str] = set()

    for ep_gap in uncovered:
        ep_id: str | None = ep_gap.entry_point_id
        ep_name: str = ep_gap.name

        if ep_id in remediated_ids:
            continue
        if ep_id is not None:
            remediated_ids.add(ep_id)

        seed = _pick_best_seed_for_entry_point(ep_name, seeds, profile)
        if seed is None:
            note = (
                f"Remediation skipped for entry point '{ep_name}': no seeds available"
            )
            logger.warning("  %s", note)
            generation_notes.append(note)
            continue

        logger.info(
            "  Remediating entry point '%s' (id=%s) with seed %s (%s)...",
            ep_name,
            ep_id or "none",
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

        # Compute candidate_id from the actual pinned technique tuple
        # (the seed's ATLAS technique IDs), not an empty set.
        pinned_technique_ids = seed.atlas_technique_ids or []
        remediation_candidate_id = compute_candidate_id(
            seed.seed_id, ep_id or "", pinned_technique_ids
        )

        # Fatal: duplicate candidate admission aborts the run.
        if remediation_candidate_id in attempted_candidate_ids:
            raise ScenarioForgeIntegrityError(
                f"Remediation duplicate candidate_id "
                f"'{remediation_candidate_id}' already attempted. Aborting run."
            )

        attempted_candidate_ids.add(remediation_candidate_id)
        remediation_attempted += 1

        try:
            envelope, call_log_entries = generate_scenario(
                seed,
                profile,
                client,
                use_case,
                pinned_entry_point=ep_name,
                pinned_entry_point_id=ep_id,
                pinned_technique_ids=pinned_technique_ids,
                attack_goal=selected_goal,
                run_id=run_id,
                candidate_id=remediation_candidate_id,
            )
            envelope.candidate_filter = {
                "candidate_id": remediation_candidate_id,
                "entry_point_id": ep_id,
                "pinned_entry_point": ep_name,
                "pinned_technique_ids": pinned_technique_ids,
                "pinned_technique_names": [],
                "origins": [],
                "rejection_rationales": [],
                "is_remediation": True,
            }

            # Fatal: duplicate scenario ID.
            if envelope.scenario_id in admitted_scenario_ids:
                raise ScenarioForgeIntegrityError(
                    f"Remediation duplicate scenario ID: "
                    f"'{envelope.scenario_id}' already admitted. Aborting run."
                )

            yaml_path, feature_path = write_scenario_outputs(envelope, scenarios_dir)

            # Call-log failure after artifact creation is fatal.
            try:
                write_call_log(call_log_entries, scenarios_dir)
            except Exception as exc:
                raise ScenarioForgeIntegrityError(
                    f"Remediation call-log write failed after artifact "
                    f"creation for scenario '{envelope.scenario_id}': {exc}. "
                    f"Aborting run."
                ) from exc

            admitted_candidate_ids.add(remediation_candidate_id)
            admitted_scenario_ids.add(envelope.scenario_id)
            remediation_scenarios.append(envelope)
            write_receipts.append(
                {
                    "scenario_id": envelope.scenario_id,
                    "candidate_id": remediation_candidate_id,
                    "yaml_path": str(yaml_path),
                    "feature_path": str(feature_path) if feature_path else None,
                }
            )

            if goal_usage is not None and envelope.actor_profile is not None:
                if envelope.actor_profile.goal_category is not None:
                    goal_usage[envelope.actor_profile.goal_category] += 1
            logger.info(
                "    Remediation scenario generated: %s (entry point: %s)",
                envelope.scenario_id,
                envelope.narrative.entry_point,
            )
        except ScenarioForgeIntegrityError:
            raise
        except GenerationError as exc:
            if exc.call_log_entries:
                write_call_log(exc.call_log_entries, scenarios_dir)
            note = (
                f"Remediation generation failed for entry point '{ep_name}' "
                f"with seed {seed.seed_id}: {exc}"
            )
            logger.error("    %s", note)
            generation_notes.append(note)
            remediation_failed += 1
        except Exception as exc:
            note = (
                f"Remediation generation failed for entry point '{ep_name}' "
                f"with seed {seed.seed_id}: {exc}"
            )
            logger.error("    %s", note)
            generation_notes.append(note)
            remediation_failed += 1

    logger.info(
        "[Remediation] %d/%d uncovered entry points remediated",
        len(remediation_scenarios),
        len(uncovered),
    )

    return (
        remediation_scenarios,
        generation_notes,
        remediation_attempted,
        remediation_failed,
    )


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
    generation_notes: list[str] = []

    client = LLMClient(base_url=base_url, api_key=api_key, model=model)

    # --- Per-invocation run identity (minimal seam for cmps.1) ---
    run_id = generate_run_id()
    logger.info("Run ID: %s", run_id)

    # --- I/O boundary: pipeline setup (output dir, use-case, manifest sentinel) ---
    timestamp_start = setup_pipeline_output(output_dir, use_case, run_id=run_id)

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
        write_pipeline_call_log(
            [
                {
                    "call": "capability_profile",
                    "system_prompt": profile_llm_result.system_prompt,
                    "user_prompt": profile_llm_result.user_prompt,
                    "response": raw_content,
                    "prompt_tokens": profile_llm_result.prompt_tokens,
                    "completion_tokens": profile_llm_result.completion_tokens,
                    "duration_ms": profile_llm_result.duration_ms,
                }
            ],
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
        # When zones are filtered, strip KC codes that would activate
        # computed flags for the excluded zones so the boolean flags
        # (has_persistent_memory, multi_agent) naturally become False.
        kc_codes = list(profile.kc_subcodes)
        if "memory" not in filtered:
            kc_codes = [
                kc
                for kc in kc_codes
                if kc not in {"KC4.3", "KC4.4", "KC4.5", "KC4.6", "KCX-PMEM"}
            ]
        if "inter_agent" not in filtered:
            kc_codes = [kc for kc in kc_codes if kc not in {"KC2.3", "KCX-MAGENT"}]
        if kc_codes != list(profile.kc_subcodes):
            updates["kc_subcodes"] = kc_codes
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
            # Re-run canonical dedup after zone-tag stripping — removing
            # zone tags may cause two formerly-distinct entry points to
            # become semantic duplicates or collide.
            from scenario_forge.models.capability_profile import (
                deduplicate_entry_points,
            )

            updates["entry_points"] = deduplicate_entry_points(cleaned_entry_points)
        profile = profile.model_copy(update=updates)
        logger.info("  Zone filter applied: %s", filtered)

    logger.info("  Zones active: %s", profile.zones_active)
    logger.info("  Entry points: %d", len(profile.entry_points))
    logger.info("  Confidence: %s", profile.confidence.value)

    # --- I/O boundary: capability profile ---
    profile_output_path = write_capability_profile(profile, output_dir)
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

    # --- I/O boundary: threat surface ---
    ts_path = write_threat_surface(threat_surface, output_dir)
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
    stage_records: list[StageRecord] = []

    # expand_candidates deduplicates internally and records its stage.
    candidates = expand_candidates(
        seeds,
        profile,
        max_techniques=max_techniques,
        stage_records=stage_records,
    )
    expansion_record = (
        stage_records[-1]
        if stage_records
        else StageRecord(
            stage="expansion", input_count=0, output_count=0, collapsed_count=0
        )
    )
    expanded_instances = expansion_record.input_count
    unique_pre_rule_identities = expansion_record.output_count

    # Phase 1: Deterministic rule-based pre-filter.
    # apply_rule_based_filter deduplicates internally and records its stage.
    rule_passed, rule_rejected, rule_verdicts = apply_rule_based_filter(
        candidates, profile, stage_records=stage_records
    )
    rule_rejected_count = len(rule_rejected)
    # Count unique source candidate identities that had at least one
    # technique pruned by rules (pre-collapse, not post-dedup outputs).
    rule_transformed_count = len(
        {
            o.source_candidate_id
            for c in rule_passed
            for o in c.origins
            if o.transform_stage == "rule_pruning"
        }
    )
    # Get post-rule collapse count from the typed stage record.
    rule_stage = (
        stage_records[-1]
        if stage_records
        else StageRecord(
            stage="rule_pruning", input_count=0, output_count=0, collapsed_count=0
        )
    )
    post_rule_collapsed = rule_stage.collapsed_count
    filter_submitted = len(rule_passed)

    if rule_rejected_count:
        logger.info(
            "  Rule pre-filter: %d/%d candidates rejected, %d passed to LLM",
            rule_rejected_count,
            unique_pre_rule_identities,
            filter_submitted,
        )

    # Phase 2: LLM filter on survivors only.
    try:
        filtered_seeds, filter_call_logs = filter_candidates(
            rule_passed, seeds, client, use_case, profile
        )
    except FilterProtocolError as exc:
        # Persist call/protocol evidence before failing the run.
        write_pipeline_call_log(exc.call_log_entries, output_dir)
        raise
    # Log candidate filter LLM calls to top-level calls.jsonl.
    write_pipeline_call_log(filter_call_logs, output_dir)
    filter_accepted = len(filtered_seeds)
    logger.info(
        "  %d candidates -> %d rule-rejected, %d LLM-filtered -> %d accepted",
        unique_pre_rule_identities,
        rule_rejected_count,
        filter_submitted - filter_accepted,
        filter_accepted,
    )

    # Apply per-pattern cap if requested.
    candidates_capped = 0
    if max_scenarios_per_pattern is not None:
        pre_cap_count = len(filtered_seeds)
        filtered_seeds = cap_scenarios_per_pattern(
            filtered_seeds,
            max_scenarios_per_pattern,
            stage_records=stage_records,
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
    selected_count = len(filtered_seeds)

    # --- Stage 4: Scenario Generation ---
    logger.info("[Stage 4] Generating %d scenarios...", len(filtered_seeds))
    scenarios_dir = get_scenarios_dir(output_dir)

    # Reject non-empty scenarios directory at setup — at this minimal seam
    # we rely on write receipts as the sole source of truth for this run's
    # artifacts.  A non-empty directory would introduce foreign artifacts.
    if scenarios_dir.is_dir():
        existing = list(scenarios_dir.iterdir())
        if existing:
            raise ScenarioForgeIntegrityError(
                f"Scenarios directory is not empty at setup: "
                f"{len(existing)} foreign file(s) found in {scenarios_dir}"
            )

    scenarios: list[ScenarioEnvelope] = []
    failed_count = 0
    attempted_count = 0
    admitted_candidate_ids: set[str] = set()
    attempted_candidate_ids: set[str] = set()
    admitted_scenario_ids: set[str] = set()
    write_receipts: list[dict] = []

    tracker = DiversityTracker()
    total_seeds = len(filtered_seeds)

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

        hints = tracker.get_diversity_hints(
            seed_threat_id=fseed.threat_id,
            total_seeds=total_seeds,
            available_goals=available_goals,
            zones_active=profile.zones_active,
            kc_subcodes=profile.kc_subcodes,
        )

        try:
            # Fatal: duplicate candidate admission aborts the run.
            if fseed.candidate_id in attempted_candidate_ids:
                raise ScenarioForgeIntegrityError(
                    f"Duplicate candidate admission: candidate_id "
                    f"'{fseed.candidate_id}' already attempted. Aborting run."
                )

            # Reserve candidate_id before LLM invocation — one attempt
            # per candidate.
            attempted_candidate_ids.add(fseed.candidate_id)
            attempted_count += 1

            envelope, call_log_entries = generate_scenario(
                fseed,
                profile,
                client,
                use_case,
                excluded_patterns=hints.excluded_patterns,
                excluded_structural_patterns=hints.excluded_structural_patterns,
                preferred_actor_type=hints.preferred_actor_type,
                excluded_actor_types=hints.excluded_actor_types,
                preferred_capability_level=hints.preferred_capability_level,
                attack_goal=hints.selected_goal,
                pinned_entry_point=fseed.pinned_entry_point,
                pinned_technique_ids=list(fseed.pinned_technique_ids),
                pinned_technique_names=list(fseed.pinned_technique_names),
                prior_titles=tracker.prior_titles if tracker.prior_titles else None,
                pinned_entry_point_id=fseed.entry_point_id,
                run_id=run_id,
                candidate_id=fseed.candidate_id,
            )
            # Attach candidate filter provenance data to the envelope.
            envelope.candidate_filter = {
                "candidate_id": fseed.candidate_id,
                "entry_point_id": fseed.entry_point_id,
                "pinned_entry_point": fseed.pinned_entry_point,
                "pinned_technique_ids": list(fseed.pinned_technique_ids),
                "pinned_technique_names": list(fseed.pinned_technique_names),
                "origins": [o.model_dump(mode="json") for o in fseed.origins],
                "rejection_rationales": [
                    v.model_dump() for v in fseed.rejection_rationales
                ],
            }

            # Fatal: duplicate scenario ID aborts the run.
            if envelope.scenario_id in admitted_scenario_ids:
                raise ScenarioForgeIntegrityError(
                    f"Duplicate scenario ID: '{envelope.scenario_id}' "
                    f"already admitted. Aborting run."
                )

            yaml_path, feature_path = write_scenario_outputs(envelope, scenarios_dir)

            # Call-log failure after artifact creation is fatal — it
            # would leave manifest/admission state silently inconsistent.
            try:
                write_call_log(call_log_entries, scenarios_dir)
            except Exception as exc:
                raise ScenarioForgeIntegrityError(
                    f"Call-log write failed after artifact creation for "
                    f"scenario '{envelope.scenario_id}': {exc}. Aborting run."
                ) from exc

            admitted_candidate_ids.add(fseed.candidate_id)
            admitted_scenario_ids.add(envelope.scenario_id)
            scenarios.append(envelope)
            write_receipts.append(
                {
                    "scenario_id": envelope.scenario_id,
                    "candidate_id": fseed.candidate_id,
                    "yaml_path": str(yaml_path),
                    "feature_path": str(feature_path) if feature_path else None,
                }
            )

            # Update diversity counters for subsequent seeds.
            tracker.update(envelope, attack_pattern_name=fseed.attack_pattern_name)

            notes = envelope.generation.notes or []
            generation_notes.extend(notes)
        except ScenarioForgeIntegrityError:
            # Fatal integrity errors propagate — do not catch as recoverable.
            raise
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

    # --- Coverage Remediation Pass (before validation) ---
    # Remediation scenarios go through the same generation/write/admission
    # path as main candidates, then pass through all validation passes.
    pre_remediation_gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
    if pre_remediation_gaps.uncovered_entry_points:
        remediation_scenarios, remediation_notes, rem_attempted, rem_failed = (
            _remediate_coverage_gaps(
                pre_remediation_gaps,
                seeds,
                profile,
                client,
                use_case,
                scenarios_dir,
                run_id=run_id,
                attempted_candidate_ids=attempted_candidate_ids,
                admitted_candidate_ids=admitted_candidate_ids,
                admitted_scenario_ids=admitted_scenario_ids,
                write_receipts=write_receipts,
                available_goals=available_goals,
                goal_usage=tracker.goal_usage,
            )
        )
        scenarios.extend(remediation_scenarios)
        generation_notes.extend(remediation_notes)
        attempted_count += rem_attempted
        failed_count += rem_failed

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
        1
        for s in scenarios
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
        1
        for s in scenarios
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

    # --- Gate-Logic Consistency Pass ---
    logger.info("[Validation] Checking gate-logic consistency...")
    gate_logic_result = validate_gate_logic_consistency(scenarios)
    if gate_logic_result.flagged_count:
        for flagged_scenario, violation in gate_logic_result.flagged_scenarios:
            logger.warning(
                "  Gate-logic mismatch: %s — %s",
                violation.scenario_id,
                violation.reason,
            )
        logger.info(
            "  %d/%d scenarios flagged for gate-logic inconsistency (warn only)",
            gate_logic_result.flagged_count,
            gate_logic_result.flagged_count + gate_logic_result.clean_count,
        )
    else:
        logger.info("  All scenarios passed gate-logic consistency check")

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

    # --- Parsimony Pruning Pass ---
    logger.info("[Validation] Enforcing parsimony on attack trees...")
    parsimony_result = enforce_parsimony(scenarios)
    parsimony_pruned_count = len(parsimony_result.pruned_scenarios)
    parsimony_unprunable_count = len(parsimony_result.unprunable_scenarios)
    if parsimony_pruned_count or parsimony_unprunable_count:
        for pruned_scenario, pruned_nodes in parsimony_result.pruned_scenarios:
            # Replace the in-memory scenario's attack tree with the pruned version
            for i, s in enumerate(scenarios):
                if s.scenario_id == pruned_scenario.scenario_id:
                    scenarios[i].attack_tree = pruned_scenario.attack_tree
                    break
            logger.warning(
                "  Pruned %d nodes from %s",
                len(pruned_nodes),
                pruned_scenario.scenario_id,
            )
        for (
            unprunable_scenario,
            leaf_count,
            budget,
        ) in parsimony_result.unprunable_scenarios:
            # Mark as unprunable so it's visible in the YAML
            if unprunable_scenario.validation is None:
                from scenario_forge.models.scenario import ValidationBlock

                unprunable_scenario.validation = ValidationBlock()
            unprunable_scenario.validation.parsimony_unprunable = (
                f"Could not prune to budget: {leaf_count} leaves, budget {budget}"
            )
            logger.warning(
                "  Unprunable: %s (%d leaves, budget %d)",
                unprunable_scenario.scenario_id,
                leaf_count,
                budget,
            )
        logger.info(
            "  %d compliant, %d pruned, %d unprunable",
            len(parsimony_result.compliant_scenarios),
            parsimony_pruned_count,
            parsimony_unprunable_count,
        )
    else:
        logger.info(
            "  All %d scenarios are within parsimony budget",
            len(scenarios),
        )

    # --- Persist validation marks to scenario YAMLs ---
    # Guarded replacement of scenario files so validation blocks reach disk.
    # Uses replace_scenario_outputs (not write_scenario_outputs) to prove
    # same scenario/stem and never silently overwrite.
    logger.info("[Post-Validation] Re-writing scenario YAMLs with validation marks...")
    rewrite_count = 0
    for scenario in scenarios:
        replace_scenario_outputs(
            scenario, scenarios_dir, admitted_scenario_id=scenario.scenario_id
        )
        rewrite_count += 1
    logger.info(
        "  %d scenario YAML(s) re-written with validation metadata", rewrite_count
    )

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
            profile=profile,
        )
    write_coverage_report(coverage_gaps, output_dir, attacker_diversity)

    # --- Compute artifact hashes from this run's write receipts ---
    # Inventory is built exclusively from write receipts (not glob), then
    # the directory is scanned to detect extra/orphan artifacts.
    artifact_records: list[dict] = []
    scenarios_dir_final = get_scenarios_dir(output_dir)
    receipt_stems: set[str] = set()
    for receipt in write_receipts:
        yaml_path = Path(receipt["yaml_path"])
        if not yaml_path.exists():
            raise ScenarioForgeIntegrityError(
                f"Missing scenario YAML for admitted scenario "
                f"'{receipt['scenario_id']}': {yaml_path}"
            )
        yaml_bytes = yaml_path.read_bytes()
        record: dict = {
            "yaml_path": f"scenarios/{yaml_path.name}",
            "yaml_sha256": compute_artifact_hash(yaml_bytes),
        }
        receipt_stems.add(yaml_path.stem)

        feature_path_str = receipt.get("feature_path")
        if feature_path_str is not None:
            feature_path = Path(feature_path_str)
            if not feature_path.exists():
                raise ScenarioForgeIntegrityError(
                    f"Missing scenario feature for admitted scenario "
                    f"'{receipt['scenario_id']}': {feature_path}"
                )
            feature_bytes = feature_path.read_bytes()
            record["feature_path"] = f"scenarios/{feature_path.name}"
            record["feature_sha256"] = compute_artifact_hash(feature_bytes)
            if feature_path.stem != yaml_path.stem:
                raise ScenarioForgeIntegrityError(
                    f"YAML/feature stem mismatch: {yaml_path.name} vs "
                    f"{feature_path.name}"
                )
        artifact_records.append(record)

    # Detect extra/orphan .yaml/.feature files not in receipts.
    if scenarios_dir_final.is_dir():
        for f in scenarios_dir_final.iterdir():
            if f.suffix in (".yaml", ".feature"):
                if f.stem not in receipt_stems:
                    raise ScenarioForgeIntegrityError(
                        f"Extra/orphan artifact not in write receipts: {f}"
                    )

    persisted_artifacts = len(artifact_records)

    # --- Compute quarantine count ---
    quarantined_count = sum(
        1
        for s in scenarios
        if s.validation is not None
        and (
            not s.validation.phantom.valid
            or not s.validation.structural.valid
            or not s.validation.semantic.valid
        )
    )

    # --- Write final run manifest — single complete build ---
    funnel = CandidateFunnel(
        expanded_instances=expanded_instances,
        unique_pre_rule_identities=unique_pre_rule_identities,
        rule_rejected=rule_rejected_count,
        rule_transformed=rule_transformed_count,
        post_rule_collapsed=post_rule_collapsed,
        filter_submitted=filter_submitted,
        filter_accepted=filter_accepted,
        selected=selected_count,
        attempted=attempted_count,
        admitted=len(scenarios),
        quarantined=quarantined_count,
        persisted_artifacts=persisted_artifacts,
    )
    manifest = {
        "version": importlib.metadata.version("scenario-forge"),
        "run_id": run_id,
        "timestamp_start": timestamp_start,
        "timestamp_end": datetime.now(timezone.utc).isoformat(),
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
        "seeds_generated": len(seeds),
        "funnel": funnel.model_dump(),
        "stage_records": [r.model_dump() for r in stage_records],
        "rule_verdicts": [v.model_dump() for v in rule_verdicts],
        **(
            {
                "max_scenarios_per_pattern": max_scenarios_per_pattern,
                "candidates_capped": candidates_capped,
            }
            if max_scenarios_per_pattern is not None
            else {}
        ),
        "scenarios_generated": len(scenarios),
        "scenarios_failed": failed_count,
        "artifacts": artifact_records,
        "phantom_validation": {
            "flagged_count": validation_result.flagged_count,
            "violation_categories": validation_result.violation_categories,
        },
        "structural_validation": {
            "failed_count": structural_fail_count,
            "passed_count": len(scenarios) - structural_fail_count,
        },
        "semantic_validation": {
            "failed_count": semantic_fail_count,
            "passed_count": len(scenarios) - semantic_fail_count,
        },
        "leaf_technique_provenance": {
            "flagged_count": leaf_technique_result.flagged_count,
            "clean_count": leaf_technique_result.clean_count,
        },
        "parsimony": {
            "compliant_count": len(parsimony_result.compliant_scenarios),
            "pruned_count": parsimony_pruned_count,
            "unprunable_count": parsimony_unprunable_count,
        },
    }
    # --- I/O boundary: final manifest ---
    write_final_manifest(manifest, output_dir)

    # --- Auto-evaluate scenarios (deterministic metrics) ---
    if eval:
        try:
            from scenario_forge.eval.runner import run_evaluation

            logger.info("[Eval] Running deterministic quality metrics...")
            scorecard = run_evaluation(output_dir, threats_path=threats_path)
            # --- I/O boundary: eval scorecard ---
            scorecard_path = write_eval_scorecard(scorecard, output_dir)
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
        from scenario_forge.report.data import load_report_data
        from scenario_forge.report.generator import generate_report

        report_data = load_report_data(output_dir)
        report_path = generate_report(report_data, output_dir)
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
