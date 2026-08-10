"""SP3 run orchestration — Stage 5 → Stage 6 → Stage 7.

Orchestrates the full SP3 pipeline:
  Stage 5: BDI generation (1 LLM call per scenario)
  Stage 6: Narrative + attack tree + Gherkin (3 LLM calls per scenario, parallelizable)
  Stage 7: Validators + eval metrics + coverage gap analysis (0 LLM calls)

All LLM calls are logged to ``calls.jsonl``. A run manifest is written
at run end with stage summary, validation results, eval scorecard,
coverage gaps, input hashes, and prompt hashes.
"""

from __future__ import annotations

import hashlib
import json
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.templates import TemplateLoader, hash_prompt_templates
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR
from .assembly import assemble_envelope
from .bdi_generation import (
    assemble_scenario_spec,
    generate_bdi,
    populate_defender_bdi,
)
from .coverage import compute_coverage_gaps, write_coverage_gaps
from .eval_metrics import compute_eval_scorecard, write_eval_scorecard
from .validators import (
    validate_bdi_grounding,
    validate_gherkin_structure,
    validate_traceability,
    validate_tree_branch_coverage,
    validate_tree_id_references,
    validate_vulnerability_completeness,
)

DEFAULT_TEMPERATURE = 0.4

__all__ = ["SP3RunResult", "run_sp3"]


@dataclass
class SP3RunResult:
    """Result of a full SP3 run."""

    scenario_specs: list[ScenarioSpec] = field(default_factory=list)
    scenario_envelopes: list[ScenarioEnvelope] = field(default_factory=list)
    eval_scorecard: dict = field(default_factory=dict)
    coverage_gaps: dict = field(default_factory=dict)
    stage_errors: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)


def run_sp3(
    *,
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    max_workers: int = 1,
    temperature: float = DEFAULT_TEMPERATURE,
) -> SP3RunResult:
    """Run the full SP3 pipeline: Stage 5 → Stage 6 → Stage 7.

    Args:
        llm_client: LLM client for making completion calls.
        enriched_threat_set: SP2 enriched threat set.
        control_structure: SP1 control structure.
        loss_analysis: SP1 loss analysis.
        run_dir: Directory for output artifacts.
        max_workers: Maximum parallel workers for LLM calls.
        temperature: LLM temperature.

    Returns:
        An :class:`SP3RunResult` with artifacts and diagnostics.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    scenarios_dir = run_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    loader = TemplateLoader(PROMPTS_DIR)

    stage_errors: list[str] = []
    validation_errors: list[str] = []
    scenario_specs: list[ScenarioSpec] = []
    scenario_envelopes: list[ScenarioEnvelope] = []

    threats = enriched_threat_set.structural_threats

    # --- Stage 5: BDI generation (1 LLM call per scenario) ---
    for idx, threat in enumerate(threats):
        spec = _run_stage5_for_threat(
            llm_client, threat, control_structure, run_dir, idx, loader, temperature, stage_errors
        )
        if spec is not None:
            scenario_specs.append(spec)

    # --- Stage 6: Concretization (3 LLM calls per scenario, parallelizable) ---
    for spec in scenario_specs:
        envelope = _run_stage6_for_spec(
            llm_client, spec, control_structure, loss_analysis,
            run_dir, loader, temperature, max_workers, stage_errors
        )
        if envelope is not None:
            scenario_envelopes.append(envelope)
            _write_scenario_artifacts(envelope, scenarios_dir)

    # --- Stage 7: Validation + eval metrics + coverage gaps ---
    _run_stage7_validations(
        scenario_envelopes, scenario_specs, control_structure,
        enriched_threat_set, loss_analysis, validation_errors
    )

    coverage_gaps = compute_coverage_gaps(
        enriched_threat_set, control_structure, scenario_envelopes, loss_analysis
    )

    trace_errors = validate_traceability(
        scenario_envelopes, enriched_threat_set, control_structure, loss_analysis
    )
    trace_error_msgs = [
        f"{e.scenario_id}: broken {e.broken_link}" for e in trace_errors
    ]

    eval_scorecard = compute_eval_scorecard(
        scenario_envelopes, enriched_threat_set, control_structure, loss_analysis,
        stage_local_errors=validation_errors,
        traceability_errors=trace_error_msgs,
        coverage_gaps=coverage_gaps,
    )

    # --- Write output artifacts ---
    write_eval_scorecard(eval_scorecard, run_dir)
    write_coverage_gaps(coverage_gaps, run_dir)

    # --- Write run manifest ---
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        enriched_threat_set=enriched_threat_set,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        scenario_envelopes=scenario_envelopes,
        validation_errors=validation_errors + trace_error_msgs,
        max_workers=max_workers,
        stage_errors=stage_errors,
    )

    return SP3RunResult(
        scenario_specs=scenario_specs,
        scenario_envelopes=scenario_envelopes,
        eval_scorecard=eval_scorecard,
        coverage_gaps=coverage_gaps,
        stage_errors=stage_errors,
        validation_errors=validation_errors + trace_error_msgs,
    )


def _run_stage5_for_threat(
    llm_client: LLMClient,
    threat,
    control_structure: ControlStructure,
    run_dir: Path,
    scenario_index: int,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
) -> ScenarioSpec | None:
    """Run Stage 5 BDI generation for a single threat."""
    from scenario_forge.stpa.scenario_prod.bdi_generation import parse_ica_slot_id

    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    target_resp_id = slot_parts["controller"]

    try:
        defender_bdi = populate_defender_bdi(control_structure, target_resp_id)
    except ValueError as e:
        stage_errors.append(f"Stage 5: {e}")
        return None

    llm_result, error = generate_bdi(
        llm_client, defender_bdi, threat, control_structure, run_dir,
        loader=loader, temperature=temperature,
    )

    if error is not None or llm_result is None:
        stage_errors.append(f"Stage 5 BDI generation failed: {error}")
        return None

    spec = assemble_scenario_spec(
        defender_bdi, llm_result, threat, control_structure, scenario_index
    )

    # Validate
    grounding = validate_bdi_grounding(spec, control_structure)
    if not grounding.passed:
        stage_errors.extend(grounding.errors)

    completeness = validate_vulnerability_completeness(spec)
    if not completeness.passed:
        stage_errors.extend(completeness.errors)

    return spec


def _run_stage6_for_spec(
    llm_client: LLMClient,
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    max_workers: int,
    stage_errors: list[str],
) -> ScenarioEnvelope | None:
    """Run Stage 6 concretization for a single scenario spec."""
    from scenario_forge.stpa.scenario_prod.narrative import build_narrative_prompts
    from scenario_forge.stpa.scenario_prod.attack_tree import build_attack_tree_prompts
    from scenario_forge.stpa.scenario_prod.gherkin import build_gherkin_prompts, _find_security_constraint
    from scenario_forge.stpa.scenario_prod.attack_tree import parse_attack_tree

    # Build prompts for all 3 calls
    nar_sys, nar_user = build_narrative_prompts(spec, loader)
    tree_sys, tree_user = build_attack_tree_prompts(spec, control_structure, loader)
    sc = _find_security_constraint(spec, loss_analysis)
    ghk_sys, ghk_user = build_gherkin_prompts(spec, sc, loader)

    # Execute 3 calls in parallel
    # For narrative and gherkin, we use None response_format (raw text)
    # For attack tree, we also use raw text and parse manually
    # Since parallel_safe_llm_calls expects a response_format (Pydantic model),
    # we'll call them individually for simplicity, or use a wrapper
    narrative_text = None
    attack_tree = None
    gherkin_text = None

    # Use parallel execution for the 3 calls
    results = _parallel_stage6_calls(
        llm_client=llm_client,
        run_dir=run_dir,
        nar_sys=nar_sys, nar_user=nar_user,
        tree_sys=tree_sys, tree_user=tree_user,
        ghk_sys=ghk_sys, ghk_user=ghk_user,
        temperature=temperature,
        max_workers=max_workers,
    )

    narrative_text, narrative_err = results["narrative"]
    attack_tree_raw, tree_err = results["attack_tree"]
    gherkin_text, ghk_err = results["gherkin"]

    if narrative_err:
        stage_errors.append(f"Stage 6 narrative failed for {spec.scenario_id}: {narrative_err}")
    if tree_err:
        stage_errors.append(f"Stage 6 attack tree failed for {spec.scenario_id}: {tree_err}")
    if ghk_err:
        stage_errors.append(f"Stage 6 gherkin failed for {spec.scenario_id}: {ghk_err}")

    if narrative_text is None or attack_tree_raw is None or gherkin_text is None:
        # Use fallbacks for missing artifacts
        narrative_text = narrative_text or ""
        attack_tree = parse_attack_tree(attack_tree_raw) or {"root": "", "branches": [], "leaves": []}
        gherkin_text = gherkin_text or ""
    else:
        attack_tree = parse_attack_tree(attack_tree_raw) or {"root": "", "branches": [], "leaves": []}

    # Validate tree branch coverage
    branch_result = validate_tree_branch_coverage(attack_tree)
    if not branch_result.passed:
        stage_errors.extend(branch_result.errors)

    # Validate Gherkin structure
    gherkin_result = validate_gherkin_structure(gherkin_text)
    if not gherkin_result.passed:
        stage_errors.extend(gherkin_result.errors)

    # Validate tree ID references
    tree_id_result = validate_tree_id_references(attack_tree, control_structure)
    if not tree_id_result.passed:
        stage_errors.extend(tree_id_result.errors)

    return assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative_text,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_text,
    )


def _parallel_stage6_calls(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    nar_sys: str, nar_user: str,
    tree_sys: str, tree_user: str,
    ghk_sys: str, ghk_user: str,
    temperature: float,
    max_workers: int,
) -> dict[str, tuple[Any | None, str | None]]:
    """Execute the 3 Stage 6 calls, optionally in parallel.

    Uses :func:`safe_llm_call_raw` for each call to ensure proper call
    logging and error handling. The calls are independent and can be
    parallelized via ``ThreadPoolExecutor``.
    """
    from concurrent.futures import ThreadPoolExecutor
    from scenario_forge.stpa.infra.llm_helpers import safe_llm_call_raw

    def _do_safe_llm_call_raw_narrative():
        text, _result, error = safe_llm_call_raw(
            llm_client=llm_client,
            system_prompt=nar_sys,
            user_prompt=nar_user,
            run_dir=run_dir,
            stage="stage_6",
            step="narrative",
            temperature=temperature,
        )
        if error is not None:
            return None, error
        return text, None

    def _do_safe_llm_call_raw_tree():
        text, _result, error = safe_llm_call_raw(
            llm_client=llm_client,
            system_prompt=tree_sys,
            user_prompt=tree_user,
            run_dir=run_dir,
            stage="stage_6",
            step="attack_tree",
            temperature=temperature,
        )
        if error is not None:
            return None, error
        return text, None

    def _do_safe_llm_call_raw_gherkin():
        text, _result, error = safe_llm_call_raw(
            llm_client=llm_client,
            system_prompt=ghk_sys,
            user_prompt=ghk_user,
            run_dir=run_dir,
            stage="stage_6",
            step="gherkin",
            temperature=temperature,
        )
        if error is not None:
            return None, error
        return text, None

    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                "narrative": executor.submit(_do_safe_llm_call_raw_narrative),
                "attack_tree": executor.submit(_do_safe_llm_call_raw_tree),
                "gherkin": executor.submit(_do_safe_llm_call_raw_gherkin),
            }
            return {k: f.result() for k, f in futures.items()}
    else:
        return {
            "narrative": _do_safe_llm_call_raw_narrative(),
            "attack_tree": _do_safe_llm_call_raw_tree(),
            "gherkin": _do_safe_llm_call_raw_gherkin(),
        }


def _run_stage7_validations(
    envelopes: list[ScenarioEnvelope],
    specs: list[ScenarioSpec],
    control_structure: ControlStructure,
    enriched_threat_set: EnrichedThreatSet,
    loss_analysis: LossAnalysis,
    validation_errors: list[str],
) -> None:
    """Run Stage 7 validations."""
    for spec in specs:
        grounding = validate_bdi_grounding(spec, control_structure)
        if not grounding.passed:
            validation_errors.extend(grounding.errors)
        completeness = validate_vulnerability_completeness(spec)
        if not completeness.passed:
            validation_errors.extend(completeness.errors)

    for env in envelopes:
        branch_result = validate_tree_branch_coverage(env.attack_tree)
        if not branch_result.passed:
            validation_errors.extend(branch_result.errors)
        gherkin_result = validate_gherkin_structure(env.gherkin_spec)
        if not gherkin_result.passed:
            validation_errors.extend(gherkin_result.errors)


def _write_scenario_artifacts(
    envelope: ScenarioEnvelope,
    scenarios_dir: Path,
) -> None:
    """Write scenario YAML and .feature files."""
    write_yaml(envelope, scenarios_dir / f"{envelope.scenario_id}.yaml")
    (scenarios_dir / f"{envelope.scenario_id}.feature").write_text(
        envelope.gherkin_spec, encoding="utf-8"
    )


def _write_manifest(
    run_dir: Path,
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenario_envelopes: list[ScenarioEnvelope],
    validation_errors: list[str],
    max_workers: int,
    stage_errors: list[str],
) -> None:
    """Write the run manifest YAML."""
    input_hashes = {
        "enriched_threat_set": _hash_model(enriched_threat_set),
        "control_structure": _hash_model(control_structure),
        "loss_analysis": _hash_model(loss_analysis),
    }
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)
    stage_summary = _count_calls_by_stage(run_dir)

    manifest = {
        "run_id": f"sp3-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "run_dir": str(run_dir),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_config": {
            "model": llm_client.model,
            "base_url": llm_client.base_url,
            "temperature": llm_client.temperature,
        },
        "input_hashes": input_hashes,
        "prompt_hashes": prompt_hashes,
        "stage_summary": stage_summary,
        "scenario_count": len(scenario_envelopes),
        "validation_error_count": len(validation_errors),
        "validation_errors": validation_errors,
        "max_workers": max_workers,
        "stage_errors": stage_errors,
        "eval_scorecard_path": "eval-scorecard.yaml",
    }

    manifest_path = run_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(manifest, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _hash_model(model: Any) -> str:
    """Compute SHA-256 hash of a Pydantic model's YAML representation."""
    content = yaml.dump(
        model.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _count_calls_by_stage(run_dir: Path) -> dict[str, dict[str, int]]:
    """Count calls by stage from calls.jsonl."""
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return {}

    counts: dict[str, dict[str, int]] = {}
    for line in calls_file.read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        stage = entry.get("stage", "unknown")
        if stage not in counts:
            counts[stage] = {"call_count": 0, "total_tokens": 0}
        counts[stage]["call_count"] += 1
        counts[stage]["total_tokens"] += (
            entry.get("prompt_tokens", 0) + entry.get("completion_tokens", 0)
        )

    return counts
