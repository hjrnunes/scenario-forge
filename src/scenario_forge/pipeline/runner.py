"""Pipeline runner — wires stages 1-4 into a single orchestrated run."""

from __future__ import annotations

import hashlib
import importlib.metadata
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel

from scenario_forge.data.loaders import (
    load_attack_goals_taxonomy,
    load_attack_patterns,
    load_risk_extraction,
)
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.data.validation import validate_risk_card_coherence
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.manifest import (
    _ROLE_METADATA,
    ARTIFACT_SCHEMA_VERSION,
    ArtifactEntry,
    ArtifactRole,
    AttemptDisposition,
    AttemptPhase,
    AttemptRecord,
    InputHashes,
    ManifestIntegrityError,
    ManifestInventoryResolver,
    ModelConfig,
    Provenance,
    RunManifest,
    RunStatus,
    build_artifact_entry,
    build_in_memory_resolver,
    capture_provenance,
    compute_bytes_sha256,
    compute_config_digest,
    compute_file_sha256,
    derive_funnel_from_attempts,
    finalize_manifest,
    load_manifest,
    resolve_run_dir,
    validate_attempt_equations,
    validate_completed_inventory,
    write_failed_manifest,
    write_manifest_sentinel,
    write_started_manifest,
)
from scenario_forge.manifest import (
    MANIFEST_V3 as MANIFEST_VERSION,
)
from scenario_forge.models.capability_profile import (
    ZONE_NAMES,
    CapabilityProfile,
)
from scenario_forge.models.scenario import BehaviorSpec, ScenarioEnvelope
from scenario_forge.pipeline.candidates import (
    CandidateFunnel,
    CandidateTriple,
    FilteredSeed,
    FilterProtocolError,
    StageRecord,
    apply_rule_based_filter,
    expand_candidates,
    filter_candidates,
)
from scenario_forge.pipeline.coverage import (
    CoverageGaps,
    GapAttributions,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from scenario_forge.pipeline.coverage_planning import (
    STAGE_ADMISSION,
    STAGE_FILTER,
    STAGE_GENERATION,
    STAGE_PROJECTION,
    STAGE_QUARANTINE,
    STAGE_RULES,
    STAGE_SELECTION,
    CoverageGapReason,
    StageLedger,
    build_coverage_plan,
    build_coverage_universe,
    build_fallback_queues,
    build_qualified_candidates,
    emit_quality_gaps,
    select_with_coverage_priority,
)
from scenario_forge.pipeline.diversity import DiversityTracker
from scenario_forge.pipeline.generate import (
    GenerationError,
    ScenarioForgeIntegrityError,
    compute_artifact_hash,
    compute_scenario_id,
    filter_sub_goals_by_zones,
    generate_run_id,
    generate_scenario,
    get_all_sub_goals,
    replace_scenario_outputs,
    write_call_log,
    write_scenario_outputs,
)
from scenario_forge.pipeline.io import (
    get_scenarios_dir,
    write_capability_profile,
    write_eval_scorecard,
    write_pipeline_call_log,
    write_threat_surface,
    write_use_case,
)
from scenario_forge.pipeline.profile import infer_capability_profile
from scenario_forge.pipeline.projection import (
    ProjectedCandidate,
    ProjectionBudget,
    capture_capability_snapshot,
    project_authoritative_candidates,
)
from scenario_forge.pipeline.seeds import ScenarioSeed, expand_seeds
from scenario_forge.pipeline.threats import ThreatSurface, determine_threat_surface
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
    run_dir: Path | None = None
    run_id: str | None = None


def _load_admitted_scenarios(
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    finalization_inventory: object,
) -> list[ScenarioEnvelope]:
    """Load admitted YAML only from one hash-verified resolver snapshot."""
    from scenario_forge.pipeline.runner_finalization import build_v3_inventory

    manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.STARTED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        package_version=importlib.metadata.version("scenario-forge"),
        provenance=provenance,
        inventory=build_v3_inventory(
            run_dir,
            finalization_inventory,
            include_coverage=False,
            include_quarantine=False,
        ),
    )
    resolver = ManifestInventoryResolver(run_dir, manifest, check_orphans=False)
    return [
        ScenarioEnvelope.model_validate(resolver.read_yaml(entry))
        for entry in resolver.entries_by_role(ArtifactRole.SCENARIO_YAML)
    ]


def _complete_v3_run(
    *,
    run_dir: Path,
    run_id: str,
    timestamp_start: str,
    provenance: Provenance | None,
    profile: CapabilityProfile,
    threat_surface: ThreatSurface,
    finalization: object,
    coverage_universe: object,
    stage_ledger: StageLedger,
    selection_result: object,
    fallback_queues: dict,
    projection_limitation_target_ids: set[str],
    threats_path: Path | None,
    eval_enabled: bool,
    seeds: list[ScenarioSeed],
    filtered_seeds: list[FilteredSeed] | None,
    governance_count: int,
    generation_notes: list[str],
) -> PipelineResult:
    """Run the single shared v3 coverage, eval, report, and manifest tail."""
    from scenario_forge.pipeline.persistence import read_finalization_inventory
    from scenario_forge.pipeline.runner_finalization import build_v3_inventory

    final_inventory_doc = read_finalization_inventory(run_dir)
    admitted_scenarios = _load_admitted_scenarios(
        run_dir, run_id, timestamp_start, provenance, final_inventory_doc
    )
    coverage_gaps = analyze_coverage_gaps(profile, threat_surface, admitted_scenarios)
    decisions = {
        item.candidate_id: item for item in final_inventory_doc.admission_decisions
    }
    generated_target_ids: set[str] = set()
    quarantined_target_ids: set[str] = set()
    for candidate_attempt in final_inventory_doc.candidate_attempts:
        decision = decisions[candidate_attempt.candidate_id]
        if decision.admitted:
            generated_target_ids.add(candidate_attempt.target_entry_point_id)
            stage_ledger.record(
                candidate_attempt.target_entry_point_id,
                candidate_attempt.candidate_id,
                STAGE_GENERATION,
                "generated",
                "Candidate completed all generated stages.",
            )
            stage_ledger.record(
                candidate_attempt.target_entry_point_id,
                candidate_attempt.candidate_id,
                STAGE_ADMISSION,
                "admitted",
                "Candidate passed postbehavior admission.",
            )
        else:
            quarantined_target_ids.add(candidate_attempt.target_entry_point_id)
            stage_ledger.record(
                candidate_attempt.target_entry_point_id,
                candidate_attempt.candidate_id,
                STAGE_QUARANTINE,
                decision.status.value,
                "; ".join(item.detail for item in decision.violations),
            )
    quality_gaps, coverage_summary = emit_quality_gaps(
        coverage_universe,
        stage_ledger,
        selection_result,
        fallback_queues,
        generated_target_ids=generated_target_ids,
        quarantined_target_ids=quarantined_target_ids - generated_target_ids,
        projection_limitation_target_ids=projection_limitation_target_ids,
    )
    write_coverage_report(
        coverage_gaps,
        run_dir,
        analyze_attacker_diversity(admitted_scenarios),
        coverage_universe=coverage_universe,
        quality_gaps=quality_gaps,
        coverage_plan=finalization.coverage_plan,
        coverage_summary=coverage_summary,
        stage_ledger=stage_ledger,
        finalization_inventory=final_inventory_doc,
    )

    # A prior interrupted completion tail is non-authoritative. Reconcile its
    # optional products before regeneration so failed/disabled retries cannot
    # leave unmanifested stale files behind.
    for stale_name in ("eval-scorecard.yaml", "report.html"):
        (run_dir / stale_name).unlink(missing_ok=True)

    eval_success = False
    eval_manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=RunStatus.STARTED,
        run_id=run_id,
        timestamp_start=timestamp_start,
        package_version=importlib.metadata.version("scenario-forge"),
        provenance=provenance,
        inventory=build_v3_inventory(
            run_dir, final_inventory_doc, include_quarantine=False
        ),
    )
    if eval_enabled:
        try:
            from scenario_forge.eval.runner import run_evaluation

            scorecard = run_evaluation(
                resolver=build_in_memory_resolver(run_dir, eval_manifest),
                threats_path=threats_path,
            )
            write_eval_scorecard(scorecard, run_dir)
            eval_success = True
        except Exception as exc:  # noqa: BLE001 - non-authoritative output
            logger.warning("Eval scorecard generation failed: %s", exc)
    else:
        logger.info("[Eval] Skipped (--no-eval) — non-authoritative.")

    had_quarantine = bool(final_inventory_doc.quarantine_inventory)
    terminal_processing_succeeded = all(
        target.target_state.value in {"admitted", "exhausted"}
        for target in finalization.coverage_plan.targets
    )
    intended_status = (
        RunStatus.COMPLETED
        if terminal_processing_succeeded
        and not had_quarantine
        and eval_enabled
        and eval_success
        else RunStatus.COMPLETED_WITH_ERRORS
    )

    report_success = False
    try:
        from scenario_forge.report.data import load_report_data
        from scenario_forge.report.generator import generate_report

        report_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("scenario-forge"),
            provenance=provenance,
            inventory=build_v3_inventory(
                run_dir, final_inventory_doc, include_eval=eval_success
            ),
        )
        report_data = load_report_data(
            resolver=build_in_memory_resolver(run_dir, report_manifest)
        )
        generate_report(report_data, run_dir)
        report_success = True
    except Exception as exc:  # noqa: BLE001 - non-authoritative output
        logger.warning("Report generation failed: %s", exc)

    final_status = (
        intended_status if report_success else RunStatus.COMPLETED_WITH_ERRORS
    )
    sf_logger = logging.getLogger("scenario_forge")
    for handler in sf_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            handler.flush()
            handler.close()
            sf_logger.removeHandler(handler)
    inventory = build_v3_inventory(
        run_dir,
        final_inventory_doc,
        include_eval=eval_success,
        include_report=report_success,
        include_log=True,
    )
    timestamp_end = datetime.now(UTC).isoformat()
    if provenance is not None:
        provenance.timestamp_end = timestamp_end
        provenance.input_hashes.effective_profile_hash = compute_file_sha256(
            run_dir / "capability-profile.yaml"
        )
    final_manifest = RunManifest(
        manifest_version=MANIFEST_VERSION,
        status=final_status,
        run_id=run_id,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
        package_version=importlib.metadata.version("scenario-forge"),
        provenance=provenance,
        inventory=inventory,
    )
    if final_status is RunStatus.COMPLETED:
        validate_completed_inventory(
            final_manifest, eval_enabled=eval_enabled, run_dir=run_dir
        )
    else:
        ManifestInventoryResolver(run_dir, final_manifest, check_orphans=True)
    finalize_manifest(run_dir, final_manifest)
    return PipelineResult(
        capability_profile=profile,
        threat_surface=threat_surface,
        seeds=seeds,
        filtered_seeds=filtered_seeds,
        scenarios=admitted_scenarios,
        governance_only_count=governance_count,
        generation_notes=generation_notes,
        run_dir=run_dir,
        run_id=run_id,
    )


def resume_pipeline(
    run_dir: Path,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    eval: bool = True,
    log_level: str = "INFO",
    structured: bool = False,
) -> PipelineResult:
    """Resume exactly one interrupted manifest-v3 run in place."""
    from scenario_forge.log_config import setup_logging
    from scenario_forge.pipeline.coverage_planning import CoveragePlan, SelectionResult
    from scenario_forge.pipeline.persistence import (
        read_finalization_inventory,
        recover_finalization_journal,
    )
    from scenario_forge.pipeline.runner_finalization import run_target_finalization

    try:
        supplied = Path(run_dir).resolve(strict=True)
    except OSError as exc:
        raise ManifestIntegrityError(
            "resume requires an existing run directory"
        ) from exc
    if not supplied.is_dir():
        raise ManifestIntegrityError("resume requires an existing run directory")
    recover_finalization_journal(supplied)
    manifest = load_manifest(supplied, requested_version=MANIFEST_VERSION)
    if manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("only a v3 STARTED run can be resumed")
    if supplied.name != manifest.run_id:
        raise ManifestIntegrityError("manifest run_id does not match run directory")
    support = ManifestInventoryResolver(supplied, manifest, check_orphans=False)
    use_entry = support.entry_by_role(ArtifactRole.USE_CASE)
    profile_entry = support.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    threat_entry = support.entry_by_role(ArtifactRole.THREAT_SURFACE)
    if not all((use_entry, profile_entry, threat_entry)):
        raise ManifestIntegrityError("started manifest support inventory is incomplete")
    use_case = support.read_text(use_entry)  # type: ignore[arg-type]
    profile = CapabilityProfile.model_validate(support.read_yaml(profile_entry))  # type: ignore[arg-type]
    threat_surface = ThreatSurface.model_validate(support.read_yaml(threat_entry))  # type: ignore[arg-type]
    inventory = read_finalization_inventory(supplied)
    if inventory.run_id != manifest.run_id:
        raise ManifestIntegrityError("finalization inventory run_id mismatch")

    setup_logging(log_level=log_level, output_dir=supplied, structured=structured)
    persisted_model = (
        manifest.provenance.model_config_provenance
        if manifest.provenance is not None
        else None
    )
    if persisted_model is None:
        raise ManifestIntegrityError(
            "resumable v3 run requires persisted model configuration"
        )
    if model is not None and model != persisted_model.model:
        raise ManifestIntegrityError("resume model override conflicts with provenance")
    if base_url is not None and base_url != persisted_model.base_url:
        raise ManifestIntegrityError(
            "resume endpoint override conflicts with provenance"
        )
    client = LLMClient(
        base_url=base_url or (persisted_model.base_url if persisted_model else None),
        api_key=api_key,
        model=model or (persisted_model.model if persisted_model else None),
        temperature=persisted_model.temperature if persisted_model else None,
        max_completion_tokens=(
            persisted_model.max_completion_tokens if persisted_model else None
        ),
    )
    finalization = run_target_finalization(
        run_dir=supplied,
        run_id=manifest.run_id,
        plan=CoveragePlan(
            schema_version="1",
            completeness="not_applicable",
            evidence_refs=[],
            targets=[],
        ),
        profile=profile,
        client=client,
        use_case=use_case,
        taxonomy_resolver=load_taxonomy_resolver(),
        capability_snapshot=capture_capability_snapshot(profile),
        trusted_catalog=list(load_attack_patterns().values()),
    )
    durable_plan = finalization.coverage_plan
    selection_result = SelectionResult(
        uncovered_target_ids=[
            target.entry_point_id
            for target in durable_plan.targets
            if not target.ordered_choices
        ],
        primary_candidate_ids={
            target.entry_point_id: target.primary_candidate_id
            for target in durable_plan.targets
            if target.primary_candidate_id is not None
        },
        attempted_candidate_ids={
            candidate_id
            for target in durable_plan.targets
            for candidate_id in target.attempted_candidate_ids
        },
        selection_limitation_target_ids=list(
            durable_plan.selection_limitation_target_ids
        ),
    )
    return _complete_v3_run(
        run_dir=supplied,
        run_id=manifest.run_id,
        timestamp_start=manifest.timestamp_start,
        provenance=manifest.provenance,
        profile=profile,
        threat_surface=threat_surface,
        finalization=finalization,
        coverage_universe=build_coverage_universe(profile),
        stage_ledger=StageLedger(),
        selection_result=selection_result,
        fallback_queues={},
        projection_limitation_target_ids=set(),
        threats_path=None,
        eval_enabled=eval,
        seeds=[],
        filtered_seeds=None,
        governance_count=len(threat_surface.governance_only),
        generation_notes=[],
    )


def _iter_leaves(node):
    """Yield all leaf nodes in an attack tree (no private imports)."""
    if not node.children:
        yield node
        return
    for child in node.children:
        yield from _iter_leaves(child)


def _assert_entry_point_ownership(
    envelope: ScenarioEnvelope, candidate_entry_point_id: str
) -> None:
    """Assert that the envelope, actor access, candidate, and all tree
    initial_ingress IDs all equal the one candidate-owned ID (cmps.6).

    Raises :class:`ScenarioForgeIntegrityError` on any mismatch or when
    actor access provenance is missing.  This is the pre-write ownership
    gate — it runs immediately before the first artifact write so no
    divergent-ID or unevidenced scenario can be persisted.
    """
    # 1. Envelope top-level ID must equal the candidate ID.
    if envelope.initial_entry_point_id != candidate_entry_point_id:
        raise ScenarioForgeIntegrityError(
            f"Envelope initial_entry_point_id "
            f"'{envelope.initial_entry_point_id}' does not match candidate "
            f"entry_point_id '{candidate_entry_point_id}'. Aborting run."
        )

    # 2. Actor access provenance must exist and its ID must equal the
    #    candidate ID.  Missing access is a fatal integrity error — the
    #    cmps.6 policy is authoritative, not optional.
    actor = envelope.actor_profile
    if actor is None or actor.access is None:
        raise ScenarioForgeIntegrityError(
            "Actor access provenance is missing — every generated scenario "
            "must carry typed access evidence (cmps.6). Aborting run."
        )
    if actor.access.initial_entry_point_id != candidate_entry_point_id:
        raise ScenarioForgeIntegrityError(
            f"Actor access initial_entry_point_id "
            f"'{actor.access.initial_entry_point_id}' does not match "
            f"candidate entry_point_id '{candidate_entry_point_id}'. "
            f"Aborting run."
        )

    # 3. Every tree initial_ingress ID must equal the candidate ID.
    if envelope.attack_tree is not None:
        for leaf in _iter_leaves(envelope.attack_tree.root):
            if (
                leaf.action is not None
                and leaf.action.kind == "initial_ingress"
                and leaf.action.entry_point_id != candidate_entry_point_id
            ):
                raise ScenarioForgeIntegrityError(
                    f"Attack tree initial_ingress action '{leaf.id}' uses "
                    f"entry_point_id '{leaf.action.entry_point_id}' which "
                    f"diverges from candidate '{candidate_entry_point_id}'. "
                    f"Aborting run."
                )


def _run_early_access_gate(
    envelope: ScenarioEnvelope,
    profile: CapabilityProfile,
) -> list[str]:
    """Run the cmps.6 access gate immediately after generation (cmps.6).

    Returns a list of violation messages (empty if valid).  This is the
    early gate that prevents invalid-access scenarios from participating
    in coverage remediation or diversity state — not a replacement for
    full semantic validation, which runs later and catches additional
    issues (phantom, structural, etc.).
    """
    from scenario_forge.pipeline.generate.actor import (
        validate_actor_access_provenance,
    )
    from scenario_forge.pipeline.generate.narrative import (
        validate_narrative_access_realization,
    )

    violations: list[str] = []
    if envelope.actor_profile is not None:
        for v in validate_actor_access_provenance(envelope.actor_profile, profile):
            violations.append(v.message)
        for v in validate_narrative_access_realization(
            envelope.narrative, envelope.actor_profile
        ):
            violations.append(v.message)
    return violations


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


def _reconcile_artifacts(
    scenarios: list[ScenarioEnvelope],
    write_receipts: list[dict],
    scenarios_dir: Path,
) -> list[dict]:
    """Reconcile write receipts against admitted scenarios and compute
    artifact hashes.

    Builds the exact expected resolved path set from receipts, requires
    each receipt ``(scenario_id, candidate_id)`` belongs to admitted
    scenarios, requires ``seen_receipt_keys == admitted_keys``, resolves
    receipt paths and requires exact equality with canonical
    ``scenarios_dir/scenario_id.{yaml,feature}``, detects
    extra/orphan files, and returns artifact records with SHA-256 hashes.

    Raises:
        ScenarioForgeIntegrityError: On any mismatch.
    """
    artifact_records: list[dict] = []
    scenarios_dir_resolved = scenarios_dir.resolve()
    expected_yaml_paths: set[Path] = set()
    expected_feature_paths: set[Path] = set()
    seen_receipt_keys: set[tuple[str, str]] = set()
    admitted_keys: set[tuple[str, str]] = set()
    admitted_behavior_spec: dict[str, bool] = {}
    for s in scenarios:
        admitted_keys.add((s.scenario_id, s.candidate_id))
        has_bs = s.behavior_spec is not None and isinstance(
            s.behavior_spec, BehaviorSpec
        )
        admitted_behavior_spec[s.scenario_id] = has_bs

    for receipt in write_receipts:
        receipt_key = (receipt["scenario_id"], receipt["candidate_id"])
        if receipt_key in seen_receipt_keys:
            raise ScenarioForgeIntegrityError(
                f"Duplicate write receipt for (scenario_id={receipt['scenario_id']}, "
                f"candidate_id={receipt['candidate_id']})"
            )
        seen_receipt_keys.add(receipt_key)

        if receipt_key not in admitted_keys:
            raise ScenarioForgeIntegrityError(
                f"Write receipt (scenario_id={receipt['scenario_id']}, "
                f"candidate_id={receipt['candidate_id']}) does not match any "
                f"admitted scenario. Aborting run."
            )

        has_feature_receipt = receipt.get("feature_path") is not None
        expected_has_feature = admitted_behavior_spec[receipt["scenario_id"]]
        if has_feature_receipt != expected_has_feature:
            raise ScenarioForgeIntegrityError(
                f"Feature receipt presence ({has_feature_receipt}) does not "
                f"match envelope behavior_spec ({expected_has_feature}) for "
                f"scenario '{receipt['scenario_id']}'. Aborting run."
            )

        yaml_path = Path(receipt["yaml_path"]).resolve()
        canonical_yaml = scenarios_dir_resolved / f"{receipt['scenario_id']}.yaml"
        if yaml_path != canonical_yaml:
            raise ScenarioForgeIntegrityError(
                f"YAML path '{yaml_path}' does not match canonical path "
                f"'{canonical_yaml}'. Aborting run."
            )
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
        expected_yaml_paths.add(yaml_path)

        feature_path_str = receipt.get("feature_path")
        if feature_path_str is not None:
            feature_path = Path(feature_path_str).resolve()
            canonical_feature = (
                scenarios_dir_resolved / f"{receipt['scenario_id']}.feature"
            )
            if feature_path != canonical_feature:
                raise ScenarioForgeIntegrityError(
                    f"Feature path '{feature_path}' does not match canonical "
                    f"path '{canonical_feature}'. Aborting run."
                )
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
            expected_feature_paths.add(feature_path)
        artifact_records.append(record)

    if seen_receipt_keys != admitted_keys:
        missing = admitted_keys - seen_receipt_keys
        extra = seen_receipt_keys - admitted_keys
        parts: list[str] = []
        if missing:
            parts.append(f"missing receipts for {sorted(missing)}")
        if extra:
            parts.append(f"extra receipts for {sorted(extra)}")
        raise ScenarioForgeIntegrityError(
            f"Receipt/admission mismatch: {'; '.join(parts)}. Aborting run."
        )

    # Detect extra/orphan .yaml/.feature files not in expected path set.
    if scenarios_dir.is_dir():
        for f in scenarios_dir.iterdir():
            if f.suffix == ".yaml" and f.resolve() not in expected_yaml_paths:
                raise ScenarioForgeIntegrityError(
                    f"Extra/orphan YAML artifact not in write receipts: {f}"
                )
            elif f.suffix == ".feature" and f.resolve() not in expected_feature_paths:
                raise ScenarioForgeIntegrityError(
                    f"Extra/orphan feature artifact not in write receipts: {f}"
                )

    return artifact_records


def run_profile_only(
    use_case: str,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> tuple[CapabilityProfile, LLMResult]:
    """Run Stage 1 only: infer a capability profile from a use-case description."""
    client = LLMClient(base_url=base_url, api_key=api_key, model=model)
    return infer_capability_profile(use_case, client)


def _reserve_attempt(
    attempts: list[AttemptRecord],
    *,
    candidate_id: str,
    scenario_id: str,
    phase: AttemptPhase,
) -> AttemptRecord:
    """Record an attempt at candidate reservation, before LLM invocation.

    The attempt is created with ``FAILED`` disposition and interrupt
    evidence so that if a failure occurs between reservation and the
    normal finalize site, the attempt is still recorded.  The caller
    finalizes the disposition via :func:`_finalize_attempt`.

    Returns the created :class:`AttemptRecord` (also appended to
    *attempts*).
    """
    record = AttemptRecord(
        candidate_id=candidate_id,
        scenario_id=scenario_id,
        disposition=AttemptDisposition.FAILED,
        failure_evidence="Attempt interrupted before completion",
        phase=phase,
    )
    attempts.append(record)
    return record


def _finalize_attempt(
    record: AttemptRecord,
    *,
    disposition: AttemptDisposition,
    failure_evidence: str | None = None,
    exc: BaseException | None = None,
) -> None:
    """Finalize the disposition of a previously reserved attempt.

    Updates the in-place record so the attempts list stays consistent
    even if the record was already appended at reservation time.

    For FAILED and QUARANTINED dispositions, ensures nonempty evidence
    by falling back to the exception class name when the error message
    is blank.
    """
    evidence = failure_evidence
    if disposition in (AttemptDisposition.FAILED, AttemptDisposition.QUARANTINED) and (
        not evidence or not evidence.strip()
    ):
        if exc is not None:
            evidence = f"{type(exc).__name__}: no detailed error message"
        else:
            evidence = f"{disposition.value}: no detailed error message"
    record.disposition = disposition
    record.failure_evidence = evidence


def _capture_input_hashes(
    use_case: str,
    risk_extraction_path: Path,
    sssom_path: Path,
    ct_path: Path,
    threats_path: Path | None,
    profile_path: Path | None,
) -> InputHashes:
    """Capture SHA-256 hashes of all effective inputs at run start.

    Hashes every effective input before any processing can change them:
    use case, risk extraction, SSSOM, explicit/default cross taxonomy,
    explicit/default threats, optional source profile, and bundled
    taxonomies (attack patterns, attack goals, threat-goal affinity).
    """
    from scenario_forge.data.loaders import (
        _THREAT_GOAL_AFFINITY_PATH,
    )
    from scenario_forge.pipeline.seeds import _DEFAULT_THREATS_PATH

    effective_threats = threats_path or _DEFAULT_THREATS_PATH

    # Bundled data paths
    data_root = Path(__file__).resolve().parents[3] / "data" / "taxonomies"
    attack_patterns_dir = data_root / "attack-patterns"
    attack_patterns_yaml = attack_patterns_dir / "attack-patterns.yaml"
    attack_patterns_sssom = attack_patterns_dir / "attack-patterns.sssom.tsv"
    attack_goals_json = data_root / "attack-goals" / "attack-goals.json"

    # Hash every file actually loaded by the attack-patterns*.yaml and
    # attack-patterns*.sssom.tsv globs as deterministic sorted path→hash maps.
    attack_patterns_yaml_map: dict[str, str] = {}
    attack_patterns_sssom_map: dict[str, str] = {}
    if attack_patterns_dir.exists():
        for yaml_file in sorted(attack_patterns_dir.glob("attack-patterns*.yaml")):
            rel = str(yaml_file.relative_to(data_root))
            attack_patterns_yaml_map[rel] = compute_file_sha256(yaml_file)
        for sssom_file in sorted(
            attack_patterns_dir.glob("attack-patterns*.sssom.tsv")
        ):
            rel = str(sssom_file.relative_to(data_root))
            attack_patterns_sssom_map[rel] = compute_file_sha256(sssom_file)

    hashes = InputHashes(
        use_case_hash=compute_bytes_sha256(use_case.encode("utf-8")),
        risk_extraction_hash=compute_file_sha256(risk_extraction_path),
        sssom_hash=compute_file_sha256(sssom_path),
        cross_taxonomy_hash=compute_file_sha256(ct_path),
        threats_hash=compute_file_sha256(effective_threats),
        attack_patterns_yaml_map=attack_patterns_yaml_map,
        attack_patterns_sssom_map=attack_patterns_sssom_map,
    )
    if profile_path is not None:
        hashes.source_profile_hash = compute_file_sha256(profile_path)
    if attack_patterns_yaml.exists():
        hashes.attack_patterns_hash = compute_file_sha256(attack_patterns_yaml)
    if attack_patterns_sssom.exists():
        hashes.attack_patterns_sssom_hash = compute_file_sha256(attack_patterns_sssom)
    if attack_goals_json.exists():
        hashes.attack_goals_taxonomy_hash = compute_file_sha256(attack_goals_json)
    if _THREAT_GOAL_AFFINITY_PATH.exists():
        hashes.threat_goal_affinity_hash = compute_file_sha256(
            _THREAT_GOAL_AFFINITY_PATH
        )
    return hashes


def _build_failed_evidence_inventory(
    run_dir: Path,
    write_receipts: list[dict],
) -> list[ArtifactEntry]:
    """Tolerantly inventory each existing recognized artifact independently.

    Unlike :func:`_build_run_inventory`, this builder does **not** require
    any late-stage artifact (coverage, scorecard, report, pipeline.log).
    Each known path is checked independently and added only if it exists.
    This ensures failed runs retain evidence for every artifact that was
    actually written before the failure.
    """
    inventory: list[ArtifactEntry] = []

    def _add_if_exists(
        role: ArtifactRole,
        rel_path: str,
        scenario_id: str | None = None,
        candidate_id: str | None = None,
    ) -> None:
        full = run_dir / rel_path
        if full.exists() and full.is_file():
            try:
                inventory.append(
                    build_artifact_entry(
                        role=role,
                        run_dir=run_dir,
                        rel_path=rel_path,
                        scenario_id=scenario_id,
                        candidate_id=candidate_id,
                        schema_version=(
                            "2" if role is ArtifactRole.COVERAGE_PLAN else "1"
                        ),
                    )
                )
            except ManifestIntegrityError:
                # If we cannot build a valid entry (e.g. hash computation
                # failure), still record the file with a best-effort hash
                # so orphan checks don't flag it.  This is evidence, not
                # authoritative inventory.
                try:
                    inventory.append(
                        ArtifactEntry(
                            role=role,
                            path=rel_path,
                            sha256=compute_file_sha256(full),
                            scenario_id=scenario_id,
                            candidate_id=candidate_id,
                            media_type=_ROLE_METADATA.get(role, {}).get(
                                "media_type", "application/octet-stream"
                            ),
                            schema_version=ARTIFACT_SCHEMA_VERSION,
                        )
                    )
                except Exception:  # noqa: BLE001, S110 - orphan check will flag unreadable files
                    pass  # truly unreadable — orphan check will flag it

    # Top-level singleton artifacts
    _add_if_exists(ArtifactRole.USE_CASE, "use-case.txt")
    _add_if_exists(ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml")
    _add_if_exists(ArtifactRole.THREAT_SURFACE, "threat-surface.yaml")
    _add_if_exists(ArtifactRole.COVERAGE_REPORT, "coverage-gaps.json")
    _add_if_exists(ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl")
    _add_if_exists(ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml")
    _add_if_exists(ArtifactRole.REPORT, "report.html")
    _add_if_exists(ArtifactRole.PIPELINE_LOG, "pipeline.log")
    _add_if_exists(ArtifactRole.COVERAGE_PLAN, "coverage-plan.json")
    _add_if_exists(ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json")

    # V3 terminal files are discovered only through the durable inventory,
    # never by globbing scenario/quarantine directories.
    finalization_path = run_dir / "finalization-inventory.json"
    if finalization_path.is_file():
        try:
            from scenario_forge.pipeline.persistence import (
                FinalizationInventoryV1,
            )

            finalization_inventory = FinalizationInventoryV1.model_validate_json(
                finalization_path.read_text(encoding="utf-8")
            )
            for receipt in [
                *finalization_inventory.admitted_inventory,
                *finalization_inventory.quarantine_inventory,
            ]:
                _add_if_exists(
                    receipt.role,
                    receipt.path,
                    scenario_id=receipt.scenario_id,
                    candidate_id=receipt.candidate_id,
                )
        except Exception:  # noqa: BLE001 - failed-manifest evidence is best effort
            pass

    # Scenario artifacts from write receipts
    for receipt in write_receipts:
        sid = receipt.get("scenario_id")
        cid = receipt.get("candidate_id")
        yaml_name = Path(receipt["yaml_path"]).name
        _add_if_exists(
            ArtifactRole.SCENARIO_YAML,
            f"scenarios/{yaml_name}",
            scenario_id=sid,
            candidate_id=cid,
        )
        feat_path = receipt.get("feature_path")
        if feat_path:
            feat_name = Path(feat_path).name
            _add_if_exists(
                ArtifactRole.SCENARIO_FEATURE,
                f"scenarios/{feat_name}",
                scenario_id=sid,
                candidate_id=cid,
            )

    # Optional scenario call log
    _add_if_exists(ArtifactRole.SCENARIO_CALL_LOG, "scenarios/calls.jsonl")

    return inventory


def _build_run_inventory(
    run_dir: Path,
    write_receipts: list[dict],
    scenarios: list[ScenarioEnvelope],
    include_eval: bool = False,
    include_final: bool = False,
) -> list[ArtifactEntry]:
    """Build the typed artifact inventory for a run directory.

    Maps every persisted file to a typed :class:`ArtifactEntry` with role,
    canonical relative path, SHA-256, media_type, schema_version, and
    scenario/candidate IDs where applicable.

    Expected-but-missing outputs **raise** :class:`ManifestIntegrityError`
    rather than being silently omitted.  Optional artifacts (call logs
    that may be empty) are only added when they exist.

    The manifest container file (``run-manifest.yaml``) is **not** an
    inventory entry — it is the sole orphan exception.
    """
    inventory: list[ArtifactEntry] = []

    def _add_required(
        role: ArtifactRole,
        rel_path: str,
        scenario_id: str | None = None,
        candidate_id: str | None = None,
    ) -> None:
        """Add an entry that must exist — raises if missing."""
        inventory.append(
            build_artifact_entry(
                role=role,
                run_dir=run_dir,
                rel_path=rel_path,
                scenario_id=scenario_id,
                candidate_id=candidate_id,
            )
        )

    def _add_optional(
        role: ArtifactRole,
        rel_path: str,
        scenario_id: str | None = None,
        candidate_id: str | None = None,
    ) -> None:
        """Add an entry only if the file exists (optional artifacts)."""
        full = run_dir / rel_path
        if full.exists():
            _add_required(role, rel_path, scenario_id, candidate_id)

    # Required top-level artifacts
    _add_required(ArtifactRole.USE_CASE, "use-case.txt")
    _add_required(ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml")
    _add_required(ArtifactRole.THREAT_SURFACE, "threat-surface.yaml")
    _add_required(ArtifactRole.COVERAGE_REPORT, "coverage-gaps.json")

    # Optional call logs (may not exist if no calls were made)
    _add_optional(ArtifactRole.PIPELINE_CALL_LOG, "calls.jsonl")

    # Scenario artifacts from write receipts (all required)
    for receipt in write_receipts:
        sid = receipt["scenario_id"]
        cid = receipt["candidate_id"]
        yaml_name = Path(receipt["yaml_path"]).name
        _add_required(
            ArtifactRole.SCENARIO_YAML,
            f"scenarios/{yaml_name}",
            scenario_id=sid,
            candidate_id=cid,
        )
        feat_path = receipt.get("feature_path")
        if feat_path:
            feat_name = Path(feat_path).name
            _add_required(
                ArtifactRole.SCENARIO_FEATURE,
                f"scenarios/{feat_name}",
                scenario_id=sid,
                candidate_id=cid,
            )

    # Optional scenario call log
    _add_optional(ArtifactRole.SCENARIO_CALL_LOG, "scenarios/calls.jsonl")

    # Eval scorecard (added if present; required only for completed validation)
    if include_eval or include_final:
        _add_optional(ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml")

    # Final artifacts (report, pipeline log)
    if include_final:
        _add_optional(ArtifactRole.REPORT, "report.html")
        _add_required(ArtifactRole.PIPELINE_LOG, "pipeline.log")

    return inventory


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
    log_level: str = "INFO",
    structured: bool = False,
) -> PipelineResult:
    """Run the full scenario-forge pipeline (stages 1-4).

    Args:
        use_case: Free-text description of the AI system under assessment.
        risk_extraction_path: Path to policy-mapper risk-extraction.json.
        sssom_path: Path to SSSOM TSV mapping file.
        output_dir: **Collection** directory for pipeline outputs.  Each
            invocation creates a new immutable ``<run_id>`` child directory.
        cross_taxonomy_path: Path to cross-taxonomy-mappings.yaml (defaults to bundled).
        threats_path: Path to OWASP agentic threats YAML (defaults to bundled).
        profile_path: Path to a pre-built capability-profile.yaml (skips Stage 1 inference).
        base_url: LLM endpoint URL override.
        api_key: LLM API key override.
        model: LLM model name override.
        max_scenarios_per_pattern: Cap on scenarios per attack pattern (None = no cap).
        eval: Whether to run deterministic eval metrics after generation (default True).
        log_level: Logging level for the console handler.
        structured: Whether the run-local file log uses JSON-lines format.

    Returns:
        PipelineResult with all artifacts from the pipeline run.
    """
    ct_path = cross_taxonomy_path or _DEFAULT_CROSS_TAXONOMY_PATH
    generation_notes: list[str] = []

    # --- Per-invocation run identity (cmps.1 sortable format) ---
    run_id = generate_run_id()

    # --- Collection → run directory resolution (single ownership boundary) ---
    # This happens BEFORE any fallible setup (LLMClient, logging, etc.)
    # so the immutable run directory and sentinel exist for every exit path.
    run_dir, run_id = resolve_run_dir(output_dir, run_id)

    # --- Manifest sentinel before any pipeline work ---
    timestamp_start = datetime.now(UTC).isoformat()
    write_manifest_sentinel(
        run_dir, run_id, timestamp_start, manifest_version=MANIFEST_VERSION
    )

    # --- Initialize lifecycle tracking state for failed-manifest evidence ---
    client: LLMClient | None = None
    profile: CapabilityProfile | None = None
    threat_surface: ThreatSurface | None = None
    seeds: list[ScenarioSeed] = []
    filtered_seeds: list[FilteredSeed] = []
    scenarios: list[ScenarioEnvelope] = []
    write_receipts: list[dict] = []
    attempts: list[AttemptRecord] = []
    stage_records: list[StageRecord] = []
    rule_verdicts: list = []
    funnel: CandidateFunnel | None = None
    governance_count = 0
    has_quarantine = False
    eval_success = False
    report_success = False
    input_hashes: InputHashes = InputHashes()
    provenance: Provenance | None = None
    partial_manifest: RunManifest | None = None
    early_quarantined_sids: set[str] = set()

    try:
        # --- Capture input hashes at run start (before inputs can change) ---
        input_hashes = _capture_input_hashes(
            use_case,
            risk_extraction_path,
            sssom_path,
            ct_path,
            threats_path,
            profile_path,
        )

        # --- Client construction (after sentinel) ---
        client = LLMClient(base_url=base_url, api_key=api_key, model=model)

        # --- Capture provenance at run start, before inputs can change ---
        # This captures Git state, resolved model config, prompt hashes,
        # input hashes, and canonical config digest of all normalized
        # effective options. Stored in partial_manifest so failed runs
        # retain it; finalization only adds effective written-profile hash
        # and end timestamp.
        #
        # The config digest is bound to the RESOLVED effective options
        # (client-resolved model/base_url/temperature/token config plus
        # resolved default/explicit input paths and normalized generation
        # settings), never raw None CLI args or API key material.  The
        # same object is persisted so digest verification is possible.
        # All default/explicit paths are resolved consistently; zones are
        # parsed and trimmed into a canonical list so whitespace-equivalent
        # inputs produce identical digests.
        from scenario_forge.pipeline.seeds import _DEFAULT_THREATS_PATH

        effective_threats_path = (threats_path or _DEFAULT_THREATS_PATH).resolve()
        effective_zones: list[str] | None = None
        if zones is not None:
            effective_zones = [z.strip() for z in zones.split(",") if z.strip()]

        effective_options = {
            "use_case_hash": input_hashes.use_case_hash,
            "risk_extraction_path": str(risk_extraction_path.resolve()),
            "sssom_path": str(sssom_path.resolve()),
            "cross_taxonomy_path": str(ct_path.resolve()),
            "threats_path": str(effective_threats_path),
            "profile_path": str(profile_path.resolve()) if profile_path else None,
            "model": client.model,
            "base_url": client.base_url,
            "temperature": client.temperature,
            "max_completion_tokens": client.max_completion_tokens,
            "max_techniques": max_techniques,
            "max_scenarios_per_pattern": max_scenarios_per_pattern,
            "zones": effective_zones,
            "eval": eval,
        }
        config_digest = compute_config_digest(effective_options)
        provenance = capture_provenance(
            run_id=run_id,
            timestamp_start=timestamp_start,
            command="generate",
            options=effective_options,
            model_config=ModelConfig(
                model=client.model,
                base_url=client.base_url,
                temperature=client.temperature,
                max_completion_tokens=client.max_completion_tokens,
            ),
            prompt_template_hashes=hash_prompt_templates(),
            input_hashes=input_hashes,
            config_digest=config_digest,
        )
        provenance.manifest_version = MANIFEST_VERSION

        # --- Build partial manifest inside guarded lifecycle ---
        partial_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("scenario-forge"),
            provenance=provenance,
        )

        # --- Run-local logging (fresh, never appends across runs) ---
        from scenario_forge.log_config import setup_logging

        setup_logging(log_level=log_level, output_dir=run_dir, structured=structured)
        logger.info("Run ID: %s", run_id)
        logger.info("Run directory: %s", run_dir)

        # --- Persist use-case description ---
        write_use_case(run_dir, use_case)
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
                run_dir,
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
        profile_output_path = write_capability_profile(profile, run_dir)
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
        ts_path = write_threat_surface(threat_surface, run_dir)
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
            filtered_seeds, filter_call_logs, filter_rejected_verdicts = (
                filter_candidates(rule_passed, seeds, client, use_case, profile)
            )
        except FilterProtocolError as exc:
            # Persist call/protocol evidence before failing the run.
            write_pipeline_call_log(exc.call_log_entries, run_dir)
            raise
        # Log candidate filter LLM calls to top-level calls.jsonl.
        write_pipeline_call_log(filter_call_logs, run_dir)
        filter_accepted = len(filtered_seeds)
        logger.info(
            "  %d candidates -> %d rule-rejected, %d LLM-filtered -> %d accepted",
            unique_pre_rule_identities,
            rule_rejected_count,
            filter_submitted - filter_accepted,
            filter_accepted,
        )

        # --- Stage 3.6: Authoritative Projection (422o.4) ---
        # Project qualified candidate-v2 records from the authoritative
        # catalog.  Each generated scenario must receive a real
        # ProjectedCandidate + CapabilityFactSnapshot — never a fabricated
        # identity from legacy seed fields.
        #
        # cmps.4 blocker 5: Build the coverage universe BEFORE projection
        # so that coverage-aware budget allocation can reserve one feasible
        # candidate per coverage target before binding variants.
        logger.info("[Stage 3.6] Projecting authoritative candidates...")
        attack_pattern_records = list(load_attack_patterns().values())
        taxonomy_resolver = load_taxonomy_resolver()
        capability_snapshot = capture_capability_snapshot(profile)

        # Build coverage universe before projection (cmps.4 blocker 5).
        coverage_universe = build_coverage_universe(profile)

        # Coverage-aware projection: pass feasible target IDs so projection
        # reserves one candidate per target before variant expansion.
        projection_batch = project_authoritative_candidates(
            attack_pattern_records,
            taxonomy_resolver,
            capability_snapshot,
            coverage_target_ids=coverage_universe.feasible_target_ids,
        )
        # Build lookup: pattern_id → list[ProjectedCandidate]
        projected_by_pattern: dict[str, list[ProjectedCandidate]] = {}
        for pc in projection_batch.candidates:
            projected_by_pattern.setdefault(pc.pattern_id, []).append(pc)
        logger.info(
            "  Projected %d candidates (%d infeasible, %d limited)",
            len(projection_batch.candidates),
            len(projection_batch.infeasibilities),
            len(projection_batch.limitations),
        )

        # --- cmps.4: Stage ledger for actual stage-event recording ---
        # Records events as they occur through the pipeline.  The furthest
        # actual event per target determines gap attribution — never
        # backward set-membership inference.
        stage_ledger = StageLedger()

        # Record rule-rejection events from the rule filter stage.
        for c in rule_rejected:
            # cmps.4 blocker 4: Record actual rule-rejection details and
            # identities/rationales.  RejectionRecord verdicts from the
            # rule filter are matched by candidate_id for per-candidate
            # removal-decision provenance.
            matching_verdicts = [
                v for v in rule_verdicts if v.candidate_id == c.candidate_id
            ]
            if matching_verdicts:
                removals = [
                    f"{d.rule_name}: {d.rationale}"
                    for v in matching_verdicts
                    for d in v.removal_decisions
                ]
                rule_reasons = "; ".join(removals) or matching_verdicts[0].rationale
            else:
                rule_reasons = "Rejected by deterministic rule filter"
            stage_ledger.record(
                entry_point_id=c.entry_point_id,
                candidate_id=c.candidate_id,
                stage=STAGE_RULES,
                reason="deterministic_rule_rejection",
                detail=f"pattern={c.seed_id}: {rule_reasons}",
            )

        # Record filter-rejection events (rule-passed but LLM-rejected).
        # cmps.4 blocker 4: Use the actual typed FilterVerdict rationale,
        # not generic text.  The rejected verdicts survive from the filter
        # protocol result, indexed by candidate_id.
        accepted_filter_ids = {f.candidate_id for f in filtered_seeds}
        filter_rejection_by_id = {v.candidate_id: v for v in filter_rejected_verdicts}
        for c in rule_passed:
            if c.candidate_id not in accepted_filter_ids:
                verdict = filter_rejection_by_id.get(c.candidate_id)
                rationale = (
                    verdict.rationale
                    if verdict is not None
                    else "Candidate rejected by LLM filter."
                )
                stage_ledger.record(
                    entry_point_id=c.entry_point_id,
                    candidate_id=c.candidate_id,
                    stage=STAGE_FILTER,
                    reason="filter_rejection",
                    detail=f"pattern={c.seed_id}: {rationale}",
                    payload=(
                        verdict.model_dump(mode="json") if verdict is not None else None
                    ),
                )

        # --- cmps.4 blocker 1: Qualified candidates over ProjectedCandidate ---
        # Fan out all valid projected matches (distinct bindings for same
        # pattern+ingress are alternatives, not fatal ambiguity).  Dedupe
        # by projected candidate_id.  Preserve accepted filter verdict and
        # provenance as first-class typed evidence.
        projection_rejected_count = 0
        projection_rejected_by_target: dict[str, list[str]] = {}
        for fseed in filtered_seeds:
            pc_list = projected_by_pattern.get(fseed.seed_id)
            if not pc_list:
                projection_rejected_count += 1
                projection_rejected_by_target.setdefault(
                    fseed.entry_point_id, []
                ).append(fseed.candidate_id)
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=fseed.candidate_id,
                    stage=STAGE_PROJECTION,
                    reason="no_projection",
                    detail=f"No projected candidate for pattern '{fseed.seed_id}'.",
                )
                continue
            matching_pcs = [
                pc
                for pc in pc_list
                if pc.canonical_ingress.entry_point_id == fseed.entry_point_id
            ]
            if not matching_pcs:
                projection_rejected_count += 1
                projection_rejected_by_target.setdefault(
                    fseed.entry_point_id, []
                ).append(fseed.candidate_id)
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=fseed.candidate_id,
                    stage=STAGE_PROJECTION,
                    reason="no_exact_ingress_match",
                    detail=(
                        f"No projected candidate for pattern '{fseed.seed_id}' "
                        f"with ingress entry_point_id '{fseed.entry_point_id}'."
                    ),
                )
                continue
            # Multiple matches with distinct bindings are valid alternatives.
            # Record projection acceptance for each matching candidate.
            for pc in matching_pcs:
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=pc.candidate_id,
                    stage=STAGE_PROJECTION,
                    reason="projected",
                    detail=f"Projected candidate for pattern '{fseed.seed_id}'.",
                )

        if projection_rejected_count:
            logger.info(
                "  %d filtered seed(s) rejected at projection stage "
                "(no exact ingress match).",
                projection_rejected_count,
            )

        # Build qualified candidates: fan out all valid projected matches,
        # dedupe by projected candidate_id, preserve filter provenance.
        qualified_candidates = build_qualified_candidates(
            filtered_seeds, projected_by_pattern
        )

        # --- Stage 3.7: Coverage-Aware Planning (cmps.4) ---
        # Build deterministic ranked fallback queues per feasible target
        # from qualified projected candidates, bounded to at most three
        # choices per target.  Ranking is deterministic and
        # encounter-independent: (pattern_id, candidate_id) — NOT
        # pinned-technique count and NOT filter-result arrival order.
        fallback_queues = build_fallback_queues(qualified_candidates, coverage_universe)

        # cmps.4 blocker 4: Do NOT append synthetic selection/no_qualified
        # events for empty queues.  Selection limitation requires qualified
        # candidates deliberately not chosen.  The gap for an empty queue is
        # already attributed by the furthest actual event (rules/filter/
        # projection) in the stage ledger — never a synthetic selection event.

        # Check for projection budget limitations affecting coverage targets.
        # Use the authoritative unreserved_coverage_targets from the projection
        # batch (cmps.4 blocker 3), not backward set-membership inference.
        projection_limitation_target_ids: set[str] = set(
            projection_batch.unreserved_coverage_targets
        )

        # Record projection-limitation events for targets omitted by budget
        # allocation (cmps.4 blocker 3).  Includes the budget and exact target
        # IDs — not backward set-membership inference.
        budget_max = ProjectionBudget().max_candidates
        for ep_id in projection_batch.unreserved_coverage_targets:
            stage_ledger.record(
                entry_point_id=ep_id,
                candidate_id="",
                stage=STAGE_PROJECTION,
                reason="budget_exhausted",
                detail=(
                    f"Coverage target omitted by projection budget allocation "
                    f"(budget={budget_max}, target_id={ep_id})."
                ),
            )

        # Record infeasible coverage targets (no compatible projection at all)
        # as structural projection gaps (cmps.4 blocker 3).
        for ep_id in projection_batch.infeasible_coverage_targets:
            stage_ledger.record(
                entry_point_id=ep_id,
                candidate_id="",
                stage=STAGE_PROJECTION,
                reason="no_compatible_projection",
                detail=(
                    f"Coverage target has no compatible projection (target_id={ep_id})."
                ),
            )

        # Preserve projection issues as stage events with complete typed
        # payload (cmps.4 blocker 3: persist complete ProjectionIssue/
        # ProjectionLimitation payloads — step_id, slot_id, evidence/results
        # — not reduced strings/counts).
        for issue in projection_batch.infeasibilities:
            stage_ledger.record(
                entry_point_id="",
                candidate_id="",
                stage=STAGE_PROJECTION,
                reason=issue.code,
                detail=f"pattern={issue.pattern_id}: {issue.detail}",
                payload=issue.model_dump(mode="json"),
            )
        for limitation in projection_batch.limitations:
            stage_ledger.record(
                entry_point_id="",
                candidate_id="",
                stage=STAGE_PROJECTION,
                reason="variant_truncation",
                detail=(
                    f"pattern={limitation.pattern_id}: "
                    f"{limitation.emitted_bindings}/"
                    f"{limitation.total_compatible_bindings} bindings emitted"
                ),
                payload=limitation.model_dump(mode="json"),
            )

        # Coverage-aware selection: first hard objective is one candidate
        # for every feasible coverage target.  Only then optimize secondary
        # diversity / per-pattern caps.  Capping must not discard a target's
        # sole accepted candidate.  Phase 1 is cap-immune.  Only primaries
        # are selected — remaining choices are fallback_available for cmps.5.
        selection_result = select_with_coverage_priority(
            qualified_candidates,
            fallback_queues,
            coverage_universe,
            max_per_pattern=max_scenarios_per_pattern,
        )
        selected_count = len(selection_result.selected)
        candidates_capped = selection_result.capped_count

        # Record selection events for selected candidates.
        for qc in selection_result.selected:
            stage_ledger.record(
                entry_point_id=qc.entry_point_id,
                candidate_id=qc.candidate_id,
                stage=STAGE_SELECTION,
                reason="selected",
                detail=f"Selected for generation (rank {qc.rank}).",
            )

        # Record selection-limitation events for targets where a per-pattern
        # cap could not be respected (cmps.4 blocker 2/4: these are real
        # selection limitations where qualified candidates were deliberately
        # not chosen for cap reasons — not synthetic events for empty queues).
        for ep_id in selection_result.selection_limitation_target_ids:
            stage_ledger.record(
                entry_point_id=ep_id,
                candidate_id=selection_result.primary_candidate_ids.get(ep_id, ""),
                stage=STAGE_SELECTION,
                reason="selection_limitation",
                detail=(
                    "Per-pattern cap could not be respected for this target; "
                    "coverage preserved but cap violated."
                ),
            )

        if candidates_capped > 0:
            logger.info(
                "  Coverage-aware selection: %d candidates capped by "
                "per-pattern limit (sole-target candidates preserved).",
                candidates_capped,
            )
        if selection_result.uncovered_target_ids:
            logger.info(
                "  %d feasible target(s) with no candidate: %s",
                len(selection_result.uncovered_target_ids),
                selection_result.uncovered_target_ids,
            )
        logger.info(
            "  Selected %d candidate(s) from %d qualified (%d projection-rejected).",
            selected_count,
            len(qualified_candidates),
            projection_rejected_count,
        )

        # --- Manifest v3: target-scoped finalization is the sole lifecycle ---
        # Persist the immutable plan and empty inventory before entering any
        # candidate callback.  Everything below this return is intentionally
        # retained as the v2 implementation for Phase 6 removal only.
        from scenario_forge.pipeline.persistence import (
            make_finalization_persistence_adapter,
        )
        from scenario_forge.pipeline.runner_finalization import (
            run_target_finalization,
            strict_v3_coverage_plan,
        )

        initial_plan = build_coverage_plan(
            coverage_universe, fallback_queues, selection_result
        )
        # Atomically replace the sentinel with a hash-bound inventory of
        # immutable resume support before publishing mutable lifecycle state.
        # This keeps a crash immediately after plan persistence resumable.
        partial_manifest.inventory = [
            build_artifact_entry(role, run_dir, path)
            for role, path in (
                (ArtifactRole.USE_CASE, "use-case.txt"),
                (ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"),
                (ArtifactRole.THREAT_SURFACE, "threat-surface.yaml"),
            )
        ]
        write_started_manifest(run_dir, partial_manifest)
        make_finalization_persistence_adapter(
            run_dir,
            run_id=run_id,
            coverage_plan=strict_v3_coverage_plan(initial_plan),
        )
        finalization = run_target_finalization(
            run_dir=run_dir,
            run_id=run_id,
            plan=initial_plan,
            profile=profile,
            client=client,
            use_case=use_case,
            taxonomy_resolver=taxonomy_resolver,
            capability_snapshot=capability_snapshot,
            trusted_catalog=attack_pattern_records,
        )
        return _complete_v3_run(
            run_dir=run_dir,
            run_id=run_id,
            timestamp_start=timestamp_start,
            provenance=provenance,
            profile=profile,
            threat_surface=threat_surface,
            finalization=finalization,
            coverage_universe=coverage_universe,
            stage_ledger=stage_ledger,
            selection_result=selection_result,
            fallback_queues=fallback_queues,
            projection_limitation_target_ids=projection_limitation_target_ids,
            threats_path=threats_path,
            eval_enabled=eval,
            seeds=seeds,
            filtered_seeds=filtered_seeds,
            governance_count=governance_count,
            generation_notes=generation_notes,
        )

        # cmps.4 blocker 5: Capture actual qualified and projection_rejected
        # counts immediately after qualification/selection, BEFORE generation
        # may fail.  Store in partial_manifest.funnel so exception
        # reconstruction uses actual counts, not defaulted values.
        partial_manifest.funnel = {
            **partial_manifest.funnel,
            "qualified": len(qualified_candidates),
            "projection_rejected": projection_rejected_count,
            # Planned count is diagnostic only; failed lifecycle selected is
            # reconstructed from actual main reservations in the exception
            # path so selected == main_attempted always holds.
            "planned_selected": selected_count,
            "filter_accepted": filter_accepted,
            "filter_submitted": filter_submitted,
            "unique_pre_rule_identities": unique_pre_rule_identities,
            "rule_rejected": rule_rejected_count,
            "rule_transformed": rule_transformed_count,
            "post_rule_collapsed": post_rule_collapsed,
            "expanded_instances": expanded_instances,
        }

        # --- Stage 4: Scenario Generation ---
        logger.info("[Stage 4] Generating %d scenarios...", selected_count)
        scenarios_dir = get_scenarios_dir(run_dir)

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
        main_admitted_count = 0
        admitted_candidate_ids: set[str] = set()
        attempted_candidate_ids: set[str] = set()
        admitted_scenario_ids: set[str] = set()
        write_receipts: list[dict] = []

        tracker = DiversityTracker()
        total_seeds = selected_count

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
        except Exception as exc:  # noqa: BLE001 - non-critical taxonomy load, logs and proceeds
            logger.warning(
                "  Failed to load attack goals taxonomy: %s — proceeding without goal diversity",
                exc,
            )
            available_goals = []

        for i, qc in enumerate(selection_result.selected, 1):
            fseed = qc.filtered_seed
            projected_candidate = qc.projected
            label = f"{fseed.seed_id}: {fseed.attack_pattern_name}"
            logger.info("  [%d/%d] %s...", i, selected_count, label)

            hints = tracker.get_diversity_hints(
                seed_threat_id=fseed.threat_id,
                total_seeds=total_seeds,
                available_goals=available_goals,
                zones_active=profile.zones_active,
                kc_subcodes=profile.kc_subcodes,
            )

            try:
                # 422o.4: projected_candidate is prejoined before
                # selected_count.  Its cand:v2 identity is authoritative —
                # used for attempt, envelope, receipt, admitted, inventory.
                # The filter candidate_id (fseed.candidate_id) is persisted
                # separately in candidate_filter for provenance only.
                authoritative_candidate_id = projected_candidate.candidate_id

                # Fatal: duplicate candidate admission aborts the run.
                if authoritative_candidate_id in attempted_candidate_ids:
                    raise ScenarioForgeIntegrityError(
                        f"Duplicate candidate admission: candidate_id "
                        f"'{authoritative_candidate_id}' already attempted. "
                        f"Aborting run."
                    )

                # Reserve candidate_id before LLM invocation — one attempt
                # per candidate.  Record the attempt at reservation so it
                # exists even if a failure occurs before the normal
                # finalize site.
                attempted_candidate_ids.add(authoritative_candidate_id)
                attempted_count += 1
                expected_scenario_id = compute_scenario_id(
                    run_id, authoritative_candidate_id, 1
                )
                attempt_rec = _reserve_attempt(
                    attempts,
                    candidate_id=authoritative_candidate_id,
                    scenario_id=expected_scenario_id,
                    phase=AttemptPhase.MAIN,
                )

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
                    candidate_id=authoritative_candidate_id,
                    projected_candidate=projected_candidate,
                    capability_snapshot=capability_snapshot,
                )
                # Attach candidate filter provenance data to the envelope.
                # candidate_id is the authoritative projected candidate ID;
                # filter_candidate_id preserves the filter-stage identity.
                # cmps.4 blocker 1: Use merged provenance from all accepted
                # filter records, not just the single generation seed.
                envelope.candidate_filter = {
                    "candidate_id": authoritative_candidate_id,
                    "filter_candidate_id": fseed.candidate_id,
                    "entry_point_id": fseed.entry_point_id,
                    "pinned_entry_point": fseed.pinned_entry_point,
                    "pinned_technique_ids": list(fseed.pinned_technique_ids),
                    "pinned_technique_names": list(fseed.pinned_technique_names),
                    "origins": [o.model_dump(mode="json") for o in qc.merged_origins],
                    "rejection_rationales": [
                        v.model_dump(mode="json")
                        for v in qc.merged_rejection_rationales
                    ],
                }

                # Fatal: duplicate scenario ID aborts the run.
                if envelope.scenario_id in admitted_scenario_ids:
                    raise ScenarioForgeIntegrityError(
                        f"Duplicate scenario ID: '{envelope.scenario_id}' "
                        f"already admitted. Aborting run."
                    )

                # Pre-write identity verification: the returned envelope must
                # carry the candidate_id we attempted and a scenario_id that
                # matches compute_scenario_id(run_id, candidate_id, attempt).
                if envelope.candidate_id != authoritative_candidate_id:
                    raise ScenarioForgeIntegrityError(
                        f"Returned envelope candidate_id '{envelope.candidate_id}' "
                        f"does not match attempted candidate_id "
                        f"'{authoritative_candidate_id}'. Aborting run."
                    )
                expected_sid = compute_scenario_id(
                    run_id, authoritative_candidate_id, 1
                )
                if envelope.scenario_id != expected_sid:
                    raise ScenarioForgeIntegrityError(
                        f"Returned envelope scenario_id '{envelope.scenario_id}' "
                        f"does not match expected '{expected_sid}' from "
                        f"compute_scenario_id(run_id, candidate_id, 1). Aborting run."
                    )

                # Pre-write candidate-ownership assertion (cmps.6): the
                # envelope, actor access, candidate (fseed.entry_point_id),
                # and every tree initial_ingress ID must all equal the one
                # candidate-owned ID.  No divergent IDs accepted.
                _assert_entry_point_ownership(envelope, fseed.entry_point_id)

                yaml_path, feature_path = write_scenario_outputs(
                    envelope, scenarios_dir
                )

                # Record a provisional receipt immediately after successful
                # paired artifact creation, before the call-log write.  If
                # the call-log write fails, the failed-evidence builder can
                # still discover these artifacts and they will not become
                # strict-forensic orphans.
                _provisional_receipt = {
                    "scenario_id": envelope.scenario_id,
                    "candidate_id": authoritative_candidate_id,
                    "yaml_path": str(yaml_path),
                    "feature_path": str(feature_path) if feature_path else None,
                }
                write_receipts.append(_provisional_receipt)

                # Call-log failure after artifact creation is fatal — it
                # would leave manifest/admission state silently inconsistent.
                try:
                    write_call_log(call_log_entries, scenarios_dir)
                except Exception as exc:
                    raise ScenarioForgeIntegrityError(
                        f"Call-log write failed after artifact creation for "
                        f"scenario '{envelope.scenario_id}': {exc}. Aborting run."
                    ) from exc

                admitted_candidate_ids.add(authoritative_candidate_id)
                admitted_scenario_ids.add(envelope.scenario_id)
                scenarios.append(envelope)
                main_admitted_count += 1
                _finalize_attempt(
                    attempt_rec,
                    disposition=AttemptDisposition.ADMITTED,
                )

                # cmps.4: Record generation+admission stage events.
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=authoritative_candidate_id,
                    stage=STAGE_GENERATION,
                    reason="generated",
                    detail=f"Scenario {envelope.scenario_id} generated.",
                )
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=authoritative_candidate_id,
                    stage=STAGE_ADMISSION,
                    reason="admitted",
                    detail=f"Scenario {envelope.scenario_id} admitted.",
                )

                # cmps.6 early access gate: run immediately after write to
                # prevent invalid-access scenarios from participating in
                # coverage remediation or diversity state.  The scenario
                # is still in ``scenarios`` (for artifact reconciliation)
                # and ADMITTED (late quarantine will catch it via full
                # semantic validation), but it does NOT update diversity
                # and is excluded from coverage gap analysis.
                _early_access_violations = _run_early_access_gate(envelope, profile)
                if _early_access_violations:
                    early_quarantined_sids.add(envelope.scenario_id)
                    logger.warning(
                        "Early access gate QUARANTINED %s: %s",
                        envelope.scenario_id,
                        "; ".join(_early_access_violations),
                    )
                else:
                    # Update diversity counters for subsequent seeds only
                    # for access-valid scenarios (cmps.6).
                    tracker.update(
                        envelope, attack_pattern_name=fseed.attack_pattern_name
                    )

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
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=authoritative_candidate_id,
                    stage=STAGE_GENERATION,
                    reason="generation_failed",
                    detail=str(exc),
                )
                _finalize_attempt(
                    attempt_rec,
                    disposition=AttemptDisposition.FAILED,
                    failure_evidence=str(exc),
                    exc=exc,
                )
            except Exception as exc:  # noqa: BLE001 - generation must catch all to record failure
                msg = f"Generation failed for {fseed.seed_id}: {exc}"
                logger.error("    %s", msg)
                generation_notes.append(msg)
                failed_count += 1
                stage_ledger.record(
                    entry_point_id=fseed.entry_point_id,
                    candidate_id=authoritative_candidate_id,
                    stage=STAGE_GENERATION,
                    reason="generation_failed",
                    detail=str(exc),
                )
                _finalize_attempt(
                    attempt_rec,
                    disposition=AttemptDisposition.FAILED,
                    failure_evidence=str(exc),
                    exc=exc,
                )

        logger.info(
            "  %d/%d scenarios generated successfully",
            len(scenarios),
            selected_count,
        )
        if generation_notes:
            logger.info("  %d note(s) recorded", len(generation_notes))

        # --- cmps.4: No post-validation raw-seed remediation ---
        # The legacy remediation pass has been removed.  Coverage-aware
        # planning (Stage 3.7) ensures one candidate per feasible target
        # before generation.  Uncovered targets receive typed quality
        # gaps in the coverage report (below).  No scenario is generated
        # from a raw/unfiltered seed after normal generation/validation.
        rem_attempted = 0
        rem_failed = 0
        rem_admitted = 0

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
            logger.info(
                "  All %d scenarios passed structural validation", len(scenarios)
            )

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
        logger.info(
            "[Post-Validation] Re-writing scenario YAMLs with validation marks..."
        )
        rewrite_count = 0
        for scenario in scenarios:
            replace_scenario_outputs(
                scenario, scenarios_dir, admitted_scenario_id=scenario.scenario_id
            )
            rewrite_count += 1
        logger.info(
            "  %d scenario YAML(s) re-written with validation metadata", rewrite_count
        )

        # --- cmps.6: compute quarantine partition before coverage/eval ---
        # Validation is complete; partition admitted vs quarantined now so
        # coverage, diversity, eval, and report only see admitted scenarios.
        # Quarantine artifacts/receipts are retained as forensic evidence.
        # Include early-quarantined scenarios (from the cmps.6 access gate)
        # in addition to validation-failed scenarios.
        quarantined_sids = {
            s.scenario_id
            for s in scenarios
            if s.scenario_id in early_quarantined_sids
            or (
                s.validation is not None
                and (
                    not s.validation.phantom.valid
                    or not s.validation.structural.valid
                    or not s.validation.semantic.valid
                )
            )
        }
        quarantined_count = len(quarantined_sids)
        admitted_scenarios = [
            s for s in scenarios if s.scenario_id not in quarantined_sids
        ]

        # cmps.4: Record quarantine stage events with exact candidate IDs.
        for env in scenarios:
            if env.scenario_id in quarantined_sids:
                cf = env.candidate_filter or {}
                ep_id = cf.get("entry_point_id", "")
                cid = cf.get("candidate_id", "")
                if ep_id and cid:
                    stage_ledger.record(
                        entry_point_id=ep_id,
                        candidate_id=cid,
                        stage=STAGE_QUARANTINE,
                        reason="quarantined",
                        detail=f"Scenario {env.scenario_id} quarantined during validation.",
                    )

        # --- Coverage Analysis ---
        logger.info("[Post-Generation] Analyzing coverage gaps...")
        coverage_gaps = analyze_coverage_gaps(
            profile, threat_surface, admitted_scenarios
        )
        attacker_diversity = analyze_attacker_diversity(admitted_scenarios)

        # --- Funnel-stage attribution for coverage gaps ---
        # cmps.4 blocker 4: Legacy _compute_gap_attributions uses backward
        # set-membership inference that can invent generation_failed/no_seed.
        # Entry-point attribution is now authoritative from the stage ledger
        # (via quality_gaps below).  We call _compute_gap_attributions for
        # backward-compatible gap detection, but clear zone/threat/pattern
        # attribution maps — the template no longer renders them as
        # funnel-stage claims, and the ledger summary is the sole
        # funnel-stage attribution.
        if coverage_gaps.has_gaps:
            coverage_gaps.gap_attributions = _compute_gap_attributions(
                coverage_gaps,
                seeds,
                candidates,
                filtered_seeds,
                scenarios,
                profile=profile,
            )
            # Clear legacy inferred attributions for non-entry-point
            # dimensions — not authoritative ledger evidence.
            coverage_gaps.gap_attributions.zones = {}
            coverage_gaps.gap_attributions.threats = {}
            coverage_gaps.gap_attributions.attack_patterns = {}

        # --- cmps.4: Typed quality gaps from actual stage ledger evidence ---
        # Emit typed, stage-attributed quality gaps for feasible targets
        # without coverage.  Gap attribution comes from the furthest actual
        # stage event in the ledger — never backward set-membership inference.
        # Coverage is never fabricated.
        generated_target_ids: set[str] = set()
        quarantined_target_ids: set[str] = set()
        for env in scenarios:
            cf = env.candidate_filter or {}
            ep_id = cf.get("entry_point_id")
            if ep_id:
                if env.scenario_id in quarantined_sids:
                    quarantined_target_ids.add(ep_id)
                else:
                    generated_target_ids.add(ep_id)

        # Build generation outcomes for the coverage plan.
        generation_outcomes: dict[str, str] = {}
        for env in scenarios:
            cf = env.candidate_filter or {}
            cid = cf.get("candidate_id")
            if cid:
                if env.scenario_id in quarantined_sids:
                    generation_outcomes[cid] = "quarantined"
                else:
                    generation_outcomes[cid] = "generated"
        # Include failed candidates.
        for event in stage_ledger.events:
            if event.stage == STAGE_GENERATION and event.reason == "generation_failed":
                generation_outcomes[event.candidate_id] = "failed"

        quality_gaps, coverage_summary = emit_quality_gaps(
            coverage_universe,
            stage_ledger,
            selection_result,
            fallback_queues,
            generated_target_ids=generated_target_ids,
            quarantined_target_ids=quarantined_target_ids,
            projection_limitation_target_ids=projection_limitation_target_ids,
        )
        if quality_gaps:
            logger.info(
                "  %d quality gap(s) emitted for uncovered targets.",
                len(quality_gaps),
            )

        # cmps.4 blocker 4: Always replace legacy entry-point attributions
        # with ledger-derived values so the HTML cannot render contradictory
        # old (inferred) and new (ledger-derived) claims.  When quality_gaps
        # is empty, the entry-point map is cleared (no invented attributions).
        if coverage_gaps.has_gaps:
            _QUALITY_GAP_TO_ATTR: dict[str, str] = {
                CoverageGapReason.NO_SEED.value: "no_seed",
                CoverageGapReason.DETERMINISTIC_RULE_REJECTION.value: "rejected",
                CoverageGapReason.FILTER_REJECTION.value: "rejected",
                CoverageGapReason.PROJECTION_REJECTION.value: "no_candidate",
                CoverageGapReason.SELECTION_LIMITATION.value: "selection_limitation",
                CoverageGapReason.GENERATION_EXHAUSTION.value: "generation_failed",
                CoverageGapReason.ADMISSION_FAILURE.value: "admission_failure",
                CoverageGapReason.PROJECTION_LIMITATION.value: "projection_limitation",
            }
            ledger_ep_attrs: dict[str, str] = {}
            for gap in quality_gaps:
                ledger_ep_attrs[gap.entry_point_id] = _QUALITY_GAP_TO_ATTR.get(
                    gap.reason.value, gap.reason.value
                )
            # Authoritative replacement — ledger-derived values are the
            # only entry-point attributions, no merge with legacy inference.
            coverage_gaps.gap_attributions.entry_points = ledger_ep_attrs

        # --- cmps.4 blocker 2: Build and persist versioned coverage plan ---
        coverage_plan = build_coverage_plan(
            coverage_universe,
            fallback_queues,
            selection_result,
            generation_outcomes=generation_outcomes,
        )

        write_coverage_report(
            coverage_gaps,
            run_dir,
            attacker_diversity,
            coverage_universe=coverage_universe,
            quality_gaps=quality_gaps,
            coverage_plan=coverage_plan,
            coverage_summary=coverage_summary,
            stage_ledger=stage_ledger,
        )

        # --- Compute artifact hashes from this run's write receipts ---
        scenarios_dir_final = get_scenarios_dir(run_dir)
        artifact_records = _reconcile_artifacts(
            scenarios=scenarios,
            write_receipts=write_receipts,
            scenarios_dir=scenarios_dir_final,
        )

        persisted_artifacts = len(artifact_records)

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
            qualified=len(qualified_candidates),
            projection_rejected=projection_rejected_count,
            main_attempted=selected_count,
            main_admitted=main_admitted_count,
            generation_failed=failed_count - rem_failed,
            remediation_attempted=rem_attempted,
            remediation_admitted=rem_admitted,
            remediation_failed=rem_failed,
            attempted=attempted_count,
            # Funnel admission counts include generated artifacts later
            # partitioned into admitted and quarantined dispositions.
            admitted=len(scenarios),
            quarantined=quarantined_count,
            persisted_artifacts=persisted_artifacts,
        )
        manifest = {
            "version": importlib.metadata.version("scenario-forge"),
            "run_id": run_id,
            "timestamp_start": timestamp_start,
            "timestamp_end": datetime.now(UTC).isoformat(),
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
        # --- Determine quarantine status and update attempt records ---
        has_quarantine = quarantined_count > 0
        if has_quarantine:
            for a in attempts:
                if (
                    a.disposition == AttemptDisposition.ADMITTED
                    and a.scenario_id in quarantined_sids
                ):
                    _finalize_attempt(
                        a,
                        disposition=AttemptDisposition.QUARANTINED,
                        failure_evidence="Validation failure (phantom/structural/semantic)",
                    )

        # --- Build pre-eval in-memory inventory (no persisted started manifest) ---
        # cmps.6: exclude quarantined scenario artifacts from eval/report
        # inventories; retain all receipts for the final forensic inventory.
        admitted_receipts = [
            r for r in write_receipts if r["scenario_id"] not in quarantined_sids
        ]
        pre_eval_inventory = _build_run_inventory(
            run_dir, admitted_receipts, admitted_scenarios
        )
        eval_snapshot_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=RunStatus.STARTED,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("scenario-forge"),
            inventory=pre_eval_inventory,
            attempts=attempts,
            inputs=manifest.get("inputs", {}),
            config=manifest.get("config", {}),
            seeds_generated=manifest.get("seeds_generated", 0),
            funnel=manifest.get("funnel", {}),
            stage_records=manifest.get("stage_records", []),
            rule_verdicts=manifest.get("rule_verdicts", []),
            scenarios_generated=manifest.get("scenarios_generated", 0),
            scenarios_failed=manifest.get("scenarios_failed", 0),
            artifacts=manifest.get("artifacts", []),
            phantom_validation=manifest.get("phantom_validation", {}),
            structural_validation=manifest.get("structural_validation", {}),
            semantic_validation=manifest.get("semantic_validation", {}),
            leaf_technique_provenance=manifest.get("leaf_technique_provenance", {}),
            parsimony=manifest.get("parsimony", {}),
        )
        eval_resolver = build_in_memory_resolver(run_dir, eval_snapshot_manifest)

        # --- Auto-evaluate scenarios (deterministic metrics) ---
        if eval:
            try:
                from scenario_forge.eval.runner import run_evaluation

                logger.info("[Eval] Running deterministic quality metrics...")
                scorecard = run_evaluation(
                    resolver=eval_resolver, threats_path=threats_path
                )
                # --- I/O boundary: eval scorecard ---
                scorecard_path = write_eval_scorecard(scorecard, run_dir)
                logger.info("  Scorecard written to %s", scorecard_path)
                eval_success = True
            except Exception as exc:  # noqa: BLE001 - eval failure is non-fatal, logs warning
                logger.warning("Eval scorecard generation failed: %s", exc)
                eval_success = False
        else:
            logger.info("[Eval] Skipped (--no-eval) — non-authoritative.")
            # --no-eval is non-authoritative (completed_with_errors), not completed.
            eval_success = False

        # --- Build in-memory inventory with scorecard for report ---
        pre_report_inventory = _build_run_inventory(
            run_dir,
            admitted_receipts,
            admitted_scenarios,
            include_eval=eval_success,
        )
        # Compute intended final status for the report view.
        # This is the status the run will have if report generation succeeds.
        if eval and not has_quarantine and eval_success:
            intended_final_status = RunStatus.COMPLETED
        else:
            intended_final_status = RunStatus.COMPLETED_WITH_ERRORS
        report_snapshot_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=intended_final_status,
            run_id=run_id,
            timestamp_start=timestamp_start,
            package_version=importlib.metadata.version("scenario-forge"),
            provenance=provenance,
            inventory=pre_report_inventory,
            attempts=attempts,
            inputs=manifest.get("inputs", {}),
            config=manifest.get("config", {}),
            seeds_generated=manifest.get("seeds_generated", 0),
            funnel=manifest.get("funnel", {}),
            stage_records=manifest.get("stage_records", []),
            rule_verdicts=manifest.get("rule_verdicts", []),
            scenarios_generated=manifest.get("scenarios_generated", 0),
            scenarios_failed=manifest.get("scenarios_failed", 0),
            artifacts=manifest.get("artifacts", []),
            phantom_validation=manifest.get("phantom_validation", {}),
            structural_validation=manifest.get("structural_validation", {}),
            semantic_validation=manifest.get("semantic_validation", {}),
            leaf_technique_provenance=manifest.get("leaf_technique_provenance", {}),
            parsimony=manifest.get("parsimony", {}),
        )
        report_resolver = build_in_memory_resolver(run_dir, report_snapshot_manifest)

        # --- Auto-generate HTML report ---
        try:
            from scenario_forge.report.data import load_report_data
            from scenario_forge.report.generator import generate_report

            report_data = load_report_data(resolver=report_resolver)
            report_path = generate_report(report_data, run_dir)
            logger.info("Report written to %s", report_path)
            report_success = True
        except Exception as exc:  # noqa: BLE001 - report failure is non-fatal, logs warning
            logger.warning("Report generation failed: %s", exc)
            report_success = False

        # --- Flush and close file handler so pipeline.log hash is stable ---
        sf_logger = logging.getLogger("scenario_forge")
        for handler in sf_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                handler.flush()
                handler.close()
                sf_logger.removeHandler(handler)

        # --- Build final typed inventory (all artifacts) ---
        final_inventory = _build_run_inventory(
            run_dir,
            write_receipts,
            scenarios,
            include_eval=eval_success,
            include_final=True,
        )

        # --- Update provenance with end timestamp and effective profile hash ---
        # Provenance was captured at run start; finalization only adds
        # the effective written-profile hash and end timestamp.
        effective_profile_hash: str | None = None
        profile_path_on_disk = run_dir / "capability-profile.yaml"
        if profile_path_on_disk.exists():
            effective_profile_hash = compute_file_sha256(profile_path_on_disk)
        provenance.input_hashes.effective_profile_hash = effective_profile_hash
        provenance.timestamp_end = datetime.now(UTC).isoformat()

        # --- Determine final status ---
        # completed: only if eval enabled, no quarantine, eval+report succeed.
        # --no-eval is always completed_with_errors (non-authoritative).
        if eval and not has_quarantine and eval_success and report_success:
            final_status = RunStatus.COMPLETED
        else:
            final_status = RunStatus.COMPLETED_WITH_ERRORS

        # --- Build PipelineResult BEFORE finalization ---
        pipeline_result = PipelineResult(
            capability_profile=profile,
            threat_surface=threat_surface,
            seeds=seeds,
            filtered_seeds=filtered_seeds,
            scenarios=admitted_scenarios,
            governance_only_count=governance_count,
            generation_notes=generation_notes,
            run_dir=run_dir,
            run_id=run_id,
        )

        # --- Build final manifest ---
        final_manifest = RunManifest(
            manifest_version=MANIFEST_VERSION,
            status=final_status,
            run_id=run_id,
            timestamp_start=timestamp_start,
            timestamp_end=datetime.now(UTC).isoformat(),
            package_version=importlib.metadata.version("scenario-forge"),
            provenance=provenance,
            inventory=final_inventory,
            attempts=attempts,
            inputs=manifest.get("inputs", {}),
            config=manifest.get("config", {}),
            seeds_generated=manifest.get("seeds_generated", 0),
            funnel=manifest.get("funnel", {}),
            stage_records=manifest.get("stage_records", []),
            rule_verdicts=manifest.get("rule_verdicts", []),
            scenarios_generated=manifest.get("scenarios_generated", 0),
            scenarios_failed=manifest.get("scenarios_failed", 0),
            artifacts=manifest.get("artifacts", []),
            phantom_validation=manifest.get("phantom_validation", {}),
            structural_validation=manifest.get("structural_validation", {}),
            semantic_validation=manifest.get("semantic_validation", {}),
            leaf_technique_provenance=manifest.get("leaf_technique_provenance", {}),
            parsimony=manifest.get("parsimony", {}),
        )

        # --- Validate completed inventory before atomically committing ---
        if final_status == RunStatus.COMPLETED:
            validate_completed_inventory(
                final_manifest, eval_enabled=eval, run_dir=run_dir
            )

        # --- Attempt/funnel equations for every final status ---
        validate_attempt_equations(final_manifest)

        # --- Atomic final-manifest commit (LAST fallible operation) ---
        # Log intent before commit; nothing fallible may follow the commit.
        logger.info("Manifest finalized: %s", final_status.value)
        finalize_manifest(run_dir, final_manifest)

        return pipeline_result
    except Exception as exc:
        # Best-effort failed manifest with accumulated evidence, then re-raise.
        # Flush/close/remove run-local file handlers BEFORE hashing failed
        # evidence so pipeline.log is stable and we don't log through a
        # closed handler afterward.
        sf_logger = logging.getLogger("scenario_forge")
        for handler in sf_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                try:
                    handler.flush()
                    handler.close()
                except Exception:  # noqa: BLE001, S110 - handler cleanup must not fail
                    pass
                sf_logger.removeHandler(handler)
        # Log to stderr only (run-local handler removed).
        logging.getLogger("scenario_forge").error("Pipeline failed: %s", exc)
        try:
            # If partial_manifest was never constructed (very early failure),
            # load the sentinel from disk as a base.
            if partial_manifest is not None:
                failed_manifest = partial_manifest
            else:
                try:
                    failed_manifest = load_manifest(run_dir)
                except Exception:  # noqa: BLE001 - create fallback manifest if load fails
                    failed_manifest = RunManifest(
                        manifest_version=MANIFEST_VERSION,
                        status=RunStatus.STARTED,
                        run_id=run_id,
                        timestamp_start=timestamp_start,
                        package_version=importlib.metadata.version("scenario-forge"),
                        provenance=Provenance(
                            run_id=run_id,
                            timestamp_start=timestamp_start,
                        )
                        if provenance is not None
                        else None,
                    )
            failed_manifest.status = RunStatus.FAILED
            failed_manifest.timestamp_end = datetime.now(UTC).isoformat()
            failed_manifest.error = str(exc)
            if failed_manifest.provenance:
                failed_manifest.provenance.timestamp_end = failed_manifest.timestamp_end
            if failed_manifest.manifest_version == MANIFEST_VERSION:
                # Finish any interrupted two-document publication before the
                # failed manifest inventories forensic state.  V3 has one
                # lifecycle authority, so legacy mirrors remain empty.
                from scenario_forge.pipeline.persistence import (
                    recover_finalization_journal,
                )

                recover_finalization_journal(run_dir)
                failed_manifest.attempts = []
                failed_manifest.funnel = {}
                failed_manifest.stage_records = []
                failed_manifest.rule_verdicts = []
                failed_manifest.artifacts = []
                failed_manifest.phantom_validation = {}
                failed_manifest.structural_validation = {}
                failed_manifest.semantic_validation = {}
                failed_manifest.leaf_technique_provenance = {}
                failed_manifest.parsimony = {}
                failed_manifest.scenarios_generated = 0
                failed_manifest.scenarios_failed = 0
                failed_manifest.inventory = _build_failed_evidence_inventory(
                    run_dir, []
                )
                write_failed_manifest(run_dir, failed_manifest)
                raise
            # Include any accumulated attempts
            failed_manifest.attempts = attempts
            # Derive a status-aware funnel from accumulated attempts so
            # terminal equation validation can run even when the normal
            # funnel construction was never reached.  Preserve existing
            # funnel data if present.
            existing_funnel = failed_manifest.funnel or {}
            failed_manifest.funnel = derive_funnel_from_attempts(
                attempts,
                expanded_instances=existing_funnel.get("expanded_instances", 0),
                unique_pre_rule_identities=existing_funnel.get(
                    "unique_pre_rule_identities", 0
                ),
                rule_rejected=existing_funnel.get("rule_rejected", 0),
                rule_transformed=existing_funnel.get("rule_transformed", 0),
                post_rule_collapsed=existing_funnel.get("post_rule_collapsed", 0),
                filter_submitted=existing_funnel.get("filter_submitted", 0),
                filter_accepted=existing_funnel.get("filter_accepted", 0),
                qualified=existing_funnel.get("qualified", 0),
                projection_rejected=existing_funnel.get("projection_rejected", 0),
                persisted_artifacts=existing_funnel.get("persisted_artifacts", 0),
                seeds_generated=existing_funnel.get("seeds_generated", 0),
            )
            # Tolerantly inventory each existing recognized artifact
            # independently, without requiring late-stage outputs.
            failed_manifest.inventory = _build_failed_evidence_inventory(
                run_dir, write_receipts
            )
            # Validate terminal equations before writing failed manifest.
            validate_attempt_equations(failed_manifest)
            write_failed_manifest(run_dir, failed_manifest)
        except Exception:  # noqa: BLE001, S110 - best-effort write during error path
            pass
        raise
