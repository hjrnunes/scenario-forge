"""Envelope assembly, I/O, and the generate_scenario entry point."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.attack_tree import AttackTree
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import (
    ActorProfile,
    ArchitectureMatch,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    NarrativeLayer,
    ScenarioEnvelope,
    TaxonomyChain,
)
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.pipeline.validation import (
    check_goal_narrative_alignment,
    check_seed_mechanism_fidelity,
)

from scenario_forge.pipeline.generate.constants import (
    _ADVERSARIAL_ONLY_THREATS,
    _CONSISTENCY_MAX_RETRIES,
    _GENERATOR_VERSION,
    _ZONE_TO_DEFAULT_MAESTRO,
)
from scenario_forge.pipeline.generate.priority import (
    _compute_priority,
    _extract_maestro_layers_from_tree,
)
from scenario_forge.pipeline.generate.tree import (
    _check_consistency,
    _validate_technique_zone_compatibility,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Error class
# ---------------------------------------------------------------------------


class GenerationError(Exception):
    """Raised when scenario generation fails.

    Carries partial ``call_log_entries`` for any LLM calls that completed
    before the failure, plus a synthetic error entry for the failing call,
    so callers can persist them to ``calls.jsonl``.
    """

    def __init__(
        self,
        message: str,
        call_log_entries: list[dict] | None = None,
        seed_id: str = "",
    ) -> None:
        super().__init__(message)
        self.call_log_entries: list[dict] = call_log_entries or []
        self.seed_id = seed_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scenario_hash(
    seed_id: str,
    use_case: str,
    pinned_technique_ids: tuple[str, ...] | list[str] | None = None,
    pinned_entry_point: str | None = None,
) -> str:
    key = f"{seed_id}:{use_case}"
    if pinned_technique_ids:
        key += ":" + ",".join(pinned_technique_ids)
    if pinned_entry_point:
        key += ":" + pinned_entry_point
    return hashlib.sha256(key.encode()).hexdigest()[:6]


def _call_metadata(call_name: CallName, result: LLMResult) -> CallMetadata:
    return CallMetadata(
        call=call_name,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        duration_ms=result.duration_ms,
    )


def _call_log_entry(
    call_name: CallName,
    result: LLMResult,
    scenario_id: str,
) -> dict:
    """Build a JSON-serialisable log entry for a single LLM call."""
    raw_content = result.content
    if hasattr(raw_content, "model_dump"):
        raw_content = raw_content.model_dump(mode="json")
    elif not isinstance(raw_content, str):
        raw_content = str(raw_content)
    return {
        "scenario_id": scenario_id,
        "call": call_name.value,
        "system_prompt": result.system_prompt,
        "user_prompt": result.user_prompt,
        "response": raw_content,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "duration_ms": result.duration_ms,
    }


def _call_log_entry_error(
    call_name: CallName,
    result: LLMResult | None,
    scenario_id: str,
    error: str,
) -> dict:
    """Build a JSON-serialisable log entry for a *failed* LLM call.

    When ``result`` is available (e.g. the LLM returned text that failed
    parsing/validation), its prompts and raw response are preserved.  When
    ``result`` is ``None`` (e.g. the LLM call itself raised), only the
    error message is recorded.
    """
    if result is not None:
        raw_content = result.content
        if hasattr(raw_content, "model_dump"):
            raw_content = raw_content.model_dump(mode="json")
        elif not isinstance(raw_content, str):
            raw_content = str(raw_content)
        return {
            "scenario_id": scenario_id,
            "call": call_name.value,
            "system_prompt": result.system_prompt,
            "user_prompt": result.user_prompt,
            "response": raw_content,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "duration_ms": result.duration_ms,
            "error": error,
        }
    return {
        "scenario_id": scenario_id,
        "call": call_name.value,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Envelope assembly
# ---------------------------------------------------------------------------


def _assemble_envelope(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    narrative: NarrativeLayer,
    attack_tree: AttackTree | None,
    behavior_spec: str | None,
    call_metadata_list: list[CallMetadata],
    model_name: str,
    use_case: str,
    notes: list[str],
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_entry_point: str | None = None,
) -> ScenarioEnvelope:
    scenario_hash = _scenario_hash(
        seed.seed_id, use_case, pinned_technique_ids, pinned_entry_point
    )
    scenario_id = f"{seed.seed_id}-{scenario_hash}"

    maestro_layers: set[int] = set()
    if attack_tree is not None:
        maestro_layers = _extract_maestro_layers_from_tree(attack_tree.root)
    if not maestro_layers:
        for z in narrative.zone_sequence:
            default = _ZONE_TO_DEFAULT_MAESTRO.get(z)
            if default is not None:
                maestro_layers.add(default)
    if not maestro_layers:
        maestro_layers = {3}

    # Derive atlas_technique_ids from the actual attack tree content,
    # not from seed metadata.  The seed's atlas_technique_ids reflects
    # upstream provenance; the tree may legitimately drop techniques
    # (e.g. the candidate filter pins fewer).  Using tree-derived IDs
    # prevents orphan claims in the taxonomy chain.
    if attack_tree is not None:
        tree_technique_ids = attack_tree.collect_technique_ids()
        reconciled_technique_ids = tree_technique_ids if tree_technique_ids else None
    else:
        # No tree — fall back to seed metadata (best available).
        reconciled_technique_ids = seed.atlas_technique_ids or None

    faceting = FacetingMetadata(
        risk_card=seed.risk_card_ref,
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=seed.owasp_llm_ids,
            agentic_threat_ids=seed.agentic_threat_ids,
            owasp_asi_ids=seed.owasp_asi_ids,
            atlas_technique_ids=reconciled_technique_ids,
            scenario_seed=seed.seed_id,
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=narrative.zone_sequence,
            architecture_match=ArchitectureMatch.explicit,
            entry_point=narrative.entry_point,
        ),
        maestro_layers=sorted(maestro_layers),
    )

    priority = _compute_priority(narrative, attack_tree, seed)

    generation = GenerationMetadata(
        model=model_name,
        call_metadata=call_metadata_list,
        notes=notes if notes else None,
    )

    scenario_seed_metadata = {
        "seed_id": seed.seed_id,
        "threat_id": seed.threat_id,
        "threat_name": seed.threat_name,
        "attack_pattern_name": seed.attack_pattern_name,
        "attack_pattern_description": seed.attack_pattern_description,
        "owasp_origin": seed.owasp_origin,
        "laaf_technique_ids": seed.laaf_technique_ids,
        "atlas_provenance_ids": seed.atlas_provenance_ids,
    }

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        version=1,
        generated_at=datetime.now(UTC),
        generator_version=_GENERATOR_VERSION,
        scenario_seed_metadata=scenario_seed_metadata,
        legitimate_task=use_case,
        actor_profile=actor_profile,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec,
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_scenario(
    seed: ScenarioSeed,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    preferred_entry_point: str | None = None,
    excluded_entry_points: list[str] | None = None,
    excluded_patterns: list[str] | None = None,
    excluded_structural_patterns: list[str] | None = None,
    preferred_actor_type: str | None = None,
    excluded_actor_types: list[str] | None = None,
    preferred_capability_level: str | None = None,
    attack_goal: dict[str, Any] | None = None,
    pinned_entry_point: str | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
    prior_titles: list[str] | None = None,
) -> tuple[ScenarioEnvelope, list[dict]]:
    """Generate a complete ScenarioEnvelope from a single seed.

    Four sequential LLM calls:
      0. Actor profile (structured output)
      1. Narrative (structured output, grounded in actor profile)
      2. Attack tree (YAML text, parsed)
      3. Behavior spec (Gherkin plain text)

    All four calls must succeed; failures propagate to the caller.
    The runner's per-scenario try/except handles logging and continuation.

    Returns:
        A tuple of (envelope, call_log_entries).  The call log entries are
        JSON-serialisable dicts suitable for writing to ``calls.jsonl``.

    Args:
        seed: The scenario seed to generate from.
        profile: The system's capability profile.
        client: LLM client for generation calls.
        use_case: Free-text description of the system under assessment.
        preferred_entry_point: Suggested entry point for diversity (hint, not enforced).
        excluded_entry_points: Entry points to avoid (already overused in this batch).
        excluded_patterns: Attack pattern keywords to avoid (already overused in this batch).
        excluded_structural_patterns: Structural attack phase sequences to avoid
            (e.g., "inject->hallucinate->persist->bypass").
        preferred_actor_type: Suggested actor type for diversity (hint, not enforced).
        excluded_actor_types: Actor types to avoid (already overused in this batch).
        preferred_capability_level: Suggested capability level for diversity
            (hint, not enforced).
        attack_goal: Selected attack goal sub-goal dict from the taxonomy.
            When provided, orients the actor's desires toward this goal category.
        pinned_entry_point: Hard-constrained entry point from the candidate filter.
            When set, overrides preferred_entry_point and excluded_entry_points.
        pinned_technique_ids: Hard-constrained ATLAS technique IDs from the candidate
            filter. When set, only these techniques are passed to prompt context.
        pinned_technique_names: Human-readable names of the pinned techniques, for
            context in prompts.
        prior_titles: List of titles already generated in this batch. Passed to
            the Call 1 diversity section so the LLM avoids duplicate titles.
    """
    # Late imports: these names are looked up from the package namespace
    # so that unittest.mock.patch("scenario_forge.pipeline.generate.X")
    # correctly intercepts them.
    import scenario_forge.pipeline.generate as _gen
    _call_actor_profile = _gen._call_actor_profile
    _validate_actor_type = _gen._validate_actor_type
    _call_narrative = _gen._call_narrative
    _call_attack_tree = _gen._call_attack_tree
    _call_behavior_spec = _gen._call_behavior_spec
    _strip_non_skeleton_techniques = _gen._strip_non_skeleton_techniques
    _warn_dominant_threat_id_crossref_fn = _gen._warn_dominant_threat_id_crossref
    _assemble_envelope_fn = _gen._assemble_envelope

    call_metas: list[CallMetadata] = []
    scenario_hash = _scenario_hash(
        seed.seed_id, use_case, pinned_technique_ids, pinned_entry_point
    )

    # Partial scenario_id for error logging (before envelope is assembled).
    partial_scenario_id = f"{seed.seed_id}-{scenario_hash}"

    # Collect call log entries incrementally so that failures still produce
    # a trace in calls.jsonl.
    call_log_entries: list[dict] = []
    results: dict[CallName, LLMResult] = {}

    # --- Pre-filter: exclude negligent-insider for adversarial-only threats ---
    if seed.threat_id in _ADVERSARIAL_ONLY_THREATS:
        excluded_actor_types = list(excluded_actor_types) if excluded_actor_types else []
        if "negligent-insider" not in excluded_actor_types:
            excluded_actor_types.append("negligent-insider")
            logger.debug(
                "Excluding negligent-insider for adversarial-only threat %s "
                "(seed %s)",
                seed.threat_id,
                seed.seed_id,
            )

    # --- Call 0: Actor Profile ---
    try:
        actor_profile, result0 = _call_actor_profile(
            seed,
            profile,
            client,
            use_case,
            preferred_actor_type=preferred_actor_type,
            excluded_actor_types=excluded_actor_types,
            preferred_capability_level=preferred_capability_level,
            attack_goal=attack_goal,
            pinned_technique_ids=pinned_technique_ids,
            pinned_entry_point=pinned_entry_point,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.actor_profile, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    original_actor_type = actor_profile.actor_type
    actor_profile = _validate_actor_type(actor_profile)

    # If BDI validation reassigned the actor type, regenerate the full profile
    # so that beliefs/desires/intentions/resources match the corrected type.
    if actor_profile.actor_type != original_actor_type:
        logger.warning(
            "BDI reassignment: regenerating actor profile with forced "
            "actor_type '%s' (was '%s') for seed %s",
            actor_profile.actor_type,
            original_actor_type,
            seed.seed_id,
        )
        corrected_type = actor_profile.actor_type
        try:
            actor_profile, result0 = _call_actor_profile(
                seed,
                profile,
                client,
                use_case,
                excluded_actor_types=excluded_actor_types,
                preferred_capability_level=preferred_capability_level,
                attack_goal=attack_goal,
                pinned_technique_ids=pinned_technique_ids,
                forced_actor_type=corrected_type,
                pinned_entry_point=pinned_entry_point,
            )
        except Exception as exc:
            call_log_entries.append(
                _call_log_entry_error(
                    CallName.actor_profile,
                    None,
                    partial_scenario_id,
                    f"BDI regeneration failed: {exc}",
                )
            )
            raise GenerationError(
                f"BDI regeneration failed: {exc}",
                call_log_entries,
                seed.seed_id,
            ) from exc

        # Defence in depth: re-validate the regenerated profile.
        actor_profile = _validate_actor_type(actor_profile)
        if actor_profile.actor_type != corrected_type:
            logger.warning(
                "BDI regeneration: regenerated profile still has wrong "
                "actor_type '%s' (expected '%s') — accepting as-is",
                actor_profile.actor_type,
                corrected_type,
            )

    # Store the selected goal category on the actor profile (Step 5).
    if attack_goal is not None:
        actor_profile.goal_category = attack_goal["id"]
        actor_profile.goal_category_name = attack_goal["name"]
        actor_profile.goal_category_parent = attack_goal["category_name"]

    call_metas.append(_call_metadata(CallName.actor_profile, result0))
    results[CallName.actor_profile] = result0
    call_log_entries.append(
        _call_log_entry(CallName.actor_profile, result0, partial_scenario_id)
    )

    # --- Call 1: Narrative ---
    try:
        narrative, result1 = _call_narrative(
            seed,
            profile,
            client,
            use_case,
            actor_profile=actor_profile,
            preferred_entry_point=preferred_entry_point,
            excluded_entry_points=excluded_entry_points,
            excluded_patterns=excluded_patterns,
            excluded_structural_patterns=excluded_structural_patterns,
            pinned_entry_point=pinned_entry_point,
            pinned_technique_ids=pinned_technique_ids,
            prior_titles=prior_titles,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.narrative, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    call_metas.append(_call_metadata(CallName.narrative, result1))
    results[CallName.narrative] = result1
    call_log_entries.append(
        _call_log_entry(CallName.narrative, result1, partial_scenario_id)
    )

    # --- Post-Call-1 heuristic checks (warn-only, gmtc) ---
    try:
        _narrative_text = " ".join(
            [narrative.title, narrative.summary]
            + [f"{s.action} {s.effect}" for s in narrative.steps]
        )

        # Part C: Goal-narrative alignment
        _goal_id = actor_profile.goal_category if actor_profile else None
        if isinstance(_goal_id, str):
            _goal_warn = check_goal_narrative_alignment(
                _goal_id, _narrative_text
            )
            if _goal_warn:
                logger.warning(
                    "Scenario %s: %s", partial_scenario_id, _goal_warn
                )

        # Part D: Seed mechanism fidelity
        _mechanism_warn = check_seed_mechanism_fidelity(
            seed.attack_pattern_name, _narrative_text
        )
        if _mechanism_warn:
            logger.warning(
                "Scenario %s: %s", partial_scenario_id, _mechanism_warn
            )
    except (TypeError, AttributeError):
        # Defensive: skip heuristic checks if narrative fields are not strings
        # (e.g. in tests using MagicMock objects).
        pass

    # --- Call 2: Attack Tree (with consistency enforcement retries) ---
    # Compute parsimony budget using the same formula as _call_attack_tree.
    _tech_ids_for_budget = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    _technique_count = len(_tech_ids_for_budget) if _tech_ids_for_budget else 0
    parsimony_budget = (
        2 * _technique_count + 2 if _technique_count > 0 else 5
    )

    try:
        attack_tree, result2 = _call_attack_tree(
            seed,
            narrative,
            client,
            use_case,
            profile=profile,
            actor_profile=actor_profile,
            pinned_technique_ids=pinned_technique_ids,
            pinned_technique_names=pinned_technique_names,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.attack_tree, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    # --- Post-generation consistency enforcement ---
    consistency_violations = _check_consistency(
        attack_tree, narrative, parsimony_budget
    )
    consistency_retry = 0
    while consistency_violations and consistency_retry < _CONSISTENCY_MAX_RETRIES:
        consistency_retry += 1
        logger.warning(
            "Consistency violations in %s (retry %d/%d): %s",
            partial_scenario_id,
            consistency_retry,
            _CONSISTENCY_MAX_RETRIES,
            "; ".join(consistency_violations),
        )
        try:
            attack_tree, result2 = _call_attack_tree(
                seed,
                narrative,
                client,
                use_case,
                profile=profile,
                actor_profile=actor_profile,
                pinned_technique_ids=pinned_technique_ids,
                pinned_technique_names=pinned_technique_names,
            )
        except Exception as exc:
            logger.warning(
                "Consistency retry %d/%d failed for %s: %s",
                consistency_retry,
                _CONSISTENCY_MAX_RETRIES,
                partial_scenario_id,
                exc,
            )
            break
        consistency_violations = _check_consistency(
            attack_tree, narrative, parsimony_budget
        )

    if consistency_violations:
        logger.warning(
            "Consistency violations persist after %d retries for %s: %s",
            consistency_retry,
            partial_scenario_id,
            "; ".join(consistency_violations),
        )

    call_metas.append(_call_metadata(CallName.attack_tree, result2))
    results[CallName.attack_tree] = result2
    call_log_entries.append(
        _call_log_entry(CallName.attack_tree, result2, partial_scenario_id)
    )

    # --- Post-generation threat_id cross-ref validation ---
    _warn_dominant_threat_id_crossref_fn(attack_tree, seed.threat_id, partial_scenario_id)

    # --- Post-generation: strip non-skeleton technique IDs ---
    skeleton_ids = set(pinned_technique_ids) if pinned_technique_ids else set()
    stripped_count = _strip_non_skeleton_techniques(attack_tree, skeleton_ids)
    if stripped_count > 0:
        logger.info(
            "Stripped %d non-skeleton technique_id(s) from tree leaves "
            "(seed %s)",
            stripped_count,
            seed.seed_id,
        )

    # --- Post-generation: technique-zone compatibility validation ---
    tz_stripped = _validate_technique_zone_compatibility(attack_tree)
    if tz_stripped > 0:
        logger.info(
            "Stripped %d technique_id(s) for zone incompatibility "
            "(seed %s)",
            tz_stripped,
            seed.seed_id,
        )

    # --- Call 3: Behavior Spec ---
    try:
        behavior_spec, result3 = _call_behavior_spec(
            seed,
            narrative,
            attack_tree,
            profile,
            client,
            use_case,
            scenario_hash,
            pinned_technique_ids=pinned_technique_ids,
        )
    except Exception as exc:
        call_log_entries.append(
            _call_log_entry_error(
                CallName.behavior_spec, None, partial_scenario_id, str(exc)
            )
        )
        raise GenerationError(str(exc), call_log_entries, seed.seed_id) from exc

    call_metas.append(_call_metadata(CallName.behavior_spec, result3))
    results[CallName.behavior_spec] = result3
    call_log_entries.append(
        _call_log_entry(CallName.behavior_spec, result3, partial_scenario_id)
    )

    envelope = _assemble_envelope_fn(
        seed=seed,
        profile=profile,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec,
        call_metadata_list=call_metas,
        model_name=client.model,
        use_case=use_case,
        notes=[],
        actor_profile=actor_profile,
        pinned_technique_ids=pinned_technique_ids,
        pinned_entry_point=pinned_entry_point,
    )

    # Update call log entries with the final scenario_id (replacing partial).
    for entry in call_log_entries:
        entry["scenario_id"] = envelope.scenario_id

    return envelope, call_log_entries


def write_scenario_outputs(
    envelope: ScenarioEnvelope,
    output_dir: Path,
) -> tuple[Path, Path | None]:
    """Write scenario envelope to disk as YAML and optional Gherkin file.

    Returns:
        Tuple of (envelope_path, feature_path_or_none).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    envelope_path = output_dir / f"{envelope.scenario_id}.yaml"
    data = envelope.model_dump(mode="json", exclude_none=True)
    envelope_path.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    feature_path: Path | None = None
    if envelope.behavior_spec is not None and isinstance(envelope.behavior_spec, str):
        feature_path = output_dir / f"{envelope.scenario_id}.feature"
        feature_path.write_text(envelope.behavior_spec, encoding="utf-8")

    return envelope_path, feature_path


def write_call_log(
    call_log_entries: list[dict],
    output_dir: Path,
) -> None:
    """Append call-log entries to ``calls.jsonl`` in *output_dir*.

    Each entry is written as a single JSON line.  The file is opened in
    append mode so multiple scenarios can safely be written incrementally.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    calls_path = output_dir / "calls.jsonl"
    with calls_path.open("a", encoding="utf-8") as fh:
        for entry in call_log_entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
