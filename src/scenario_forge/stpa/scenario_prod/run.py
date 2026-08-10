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

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call_raw
from scenario_forge.stpa.infra.manifest_helpers import count_calls_by_stage, hash_model
from scenario_forge.stpa.infra.templates import TemplateLoader, hash_prompt_templates
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.enriched_threat_set import EnrichedThreatSet
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR
from .assembly import assemble_envelope
from .attack_tree import build_attack_tree_prompts, parse_attack_tree
from .bdi_generation import (
    assemble_scenario_spec,
    generate_bdi,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from .coverage import compute_coverage_gaps, write_coverage_gaps
from .eval_metrics import compute_eval_scorecard, write_eval_scorecard
from .gherkin import build_gherkin_prompts, find_security_constraint
from .narrative import build_narrative_prompts
from .validators import (
    TraceabilityError,
    validate_bdi_grounding,
    validate_gherkin_structure,
    validate_traceability,
    validate_tree_branch_coverage,
    validate_tree_id_references,
    validate_vulnerability_completeness,
)

DEFAULT_TEMPERATURE = 0.4

__all__ = ["SP3RunResult", "run_sp3"]

_EMPTY_ATTACK_TREE: dict = {"root": "", "branches": [], "leaves": []}


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

    # --- Stage 5: BDI generation (1 LLM call per scenario) ---
    for idx, threat in enumerate(enriched_threat_set.structural_threats):
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
        scenario_envelopes, scenario_specs, control_structure, validation_errors
    )

    trace_errors = validate_traceability(
        scenario_envelopes, enriched_threat_set, control_structure, loss_analysis
    )
    trace_error_msgs = _format_traceability_errors(trace_errors)
    all_validation_errors = validation_errors + trace_error_msgs

    coverage_gaps = compute_coverage_gaps(
        enriched_threat_set, control_structure, scenario_envelopes, loss_analysis,
        precomputed_trace_errors=trace_errors,
    )

    eval_scorecard = compute_eval_scorecard(
        scenario_envelopes, enriched_threat_set, control_structure, loss_analysis,
        stage_local_errors=validation_errors,
        traceability_errors=trace_error_msgs,
        coverage_gaps=coverage_gaps,
        precomputed_trace_errors=trace_errors,
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
        validation_errors=all_validation_errors,
        max_workers=max_workers,
        stage_errors=stage_errors,
    )

    return SP3RunResult(
        scenario_specs=scenario_specs,
        scenario_envelopes=scenario_envelopes,
        eval_scorecard=eval_scorecard,
        coverage_gaps=coverage_gaps,
        stage_errors=stage_errors,
        validation_errors=all_validation_errors,
    )


def _format_traceability_errors(errors: list[TraceabilityError]) -> list[str]:
    """Format traceability errors as human-readable messages."""
    return [f"{e.scenario_id}: broken {e.broken_link}" for e in errors]


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
    _validate_stage5_spec(spec, control_structure, stage_errors)
    return spec


def _validate_stage5_spec(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    stage_errors: list[str],
) -> None:
    """Run stage-local validators for a Stage 5 scenario spec."""
    grounding = validate_bdi_grounding(spec, control_structure)
    if not grounding.passed:
        stage_errors.extend(grounding.errors)

    completeness = validate_vulnerability_completeness(spec)
    if not completeness.passed:
        stage_errors.extend(completeness.errors)


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
    prompts = _build_stage6_prompts(spec, control_structure, loss_analysis, loader)

    results = _parallel_stage6_calls(
        llm_client=llm_client,
        run_dir=run_dir,
        prompts=prompts,
        temperature=temperature,
        max_workers=max_workers,
    )

    _collect_stage6_errors(spec.scenario_id, results, stage_errors)

    narrative_text, attack_tree, gherkin_text = _parse_stage6_results(results)

    _validate_stage6_artifacts(attack_tree, gherkin_text, control_structure, stage_errors)

    return assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative_text,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_text,
    )


@dataclass
class _Stage6Prompts:
    """Container for the three Stage 6 prompt pairs."""

    narrative: tuple[str, str]
    attack_tree: tuple[str, str]
    gherkin: tuple[str, str]


def _build_stage6_prompts(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
) -> _Stage6Prompts:
    """Build system/user prompt pairs for all three Stage 6 calls."""
    nar_prompts = build_narrative_prompts(spec, loader)
    tree_prompts = build_attack_tree_prompts(spec, control_structure, loader)
    sc = find_security_constraint(spec, loss_analysis)
    ghk_prompts = build_gherkin_prompts(spec, sc, loader)

    return _Stage6Prompts(
        narrative=nar_prompts,
        attack_tree=tree_prompts,
        gherkin=ghk_prompts,
    )


def _collect_stage6_errors(
    scenario_id: str,
    results: dict[str, tuple[Any | None, str | None]],
    stage_errors: list[str],
) -> None:
    """Append error messages from Stage 6 call results."""
    for step in ("narrative", "attack_tree", "gherkin"):
        _text, err = results[step]
        if err:
            stage_errors.append(f"Stage 6 {step} failed for {scenario_id}: {err}")


def _parse_stage6_results(
    results: dict[str, tuple[Any | None, str | None]],
) -> tuple[str, dict, str]:
    """Parse Stage 6 call results with fallbacks for missing artifacts."""
    narrative_raw, _ = results["narrative"]
    attack_tree_raw, _ = results["attack_tree"]
    gherkin_raw, _ = results["gherkin"]

    narrative_text = narrative_raw or ""
    gherkin_text = gherkin_raw or ""
    attack_tree = parse_attack_tree(attack_tree_raw) or dict(_EMPTY_ATTACK_TREE)

    return narrative_text, attack_tree, gherkin_text


def _validate_stage6_artifacts(
    attack_tree: dict,
    gherkin_text: str,
    control_structure: ControlStructure,
    stage_errors: list[str],
) -> None:
    """Run stage-local validators for Stage 6 artifacts."""
    for result in (
        validate_tree_branch_coverage(attack_tree),
        validate_gherkin_structure(gherkin_text),
        validate_tree_id_references(attack_tree, control_structure),
    ):
        if not result.passed:
            stage_errors.extend(result.errors)


def _parallel_stage6_calls(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    prompts: _Stage6Prompts,
    temperature: float,
    max_workers: int,
) -> dict[str, tuple[str | None, str | None]]:
    """Execute the 3 Stage 6 calls, optionally in parallel.

    Uses :func:`safe_llm_call_raw` for each call to ensure proper call
    logging and error handling. The calls are independent and can be
    parallelized via ``ThreadPoolExecutor``.
    """
    call_specs = [
        ("narrative", prompts.narrative),
        ("attack_tree", prompts.attack_tree),
        ("gherkin", prompts.gherkin),
    ]

    def _run_call(step: str, prompt_pair: tuple[str, str]) -> tuple[str | None, str | None]:
        sys_prompt, user_prompt = prompt_pair
        text, _result, error = safe_llm_call_raw(
            llm_client=llm_client,
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            run_dir=run_dir,
            stage="stage_6",
            step=step,
            temperature=temperature,
        )
        if error is not None:
            return None, error
        return text, None

    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                step: executor.submit(_run_call, step, pair)
                for step, pair in call_specs
            }
            return {step: f.result() for step, f in futures.items()}
    else:
        return {step: _run_call(step, pair) for step, pair in call_specs}


def _run_stage7_validations(
    envelopes: list[ScenarioEnvelope],
    specs: list[ScenarioSpec],
    control_structure: ControlStructure,
    validation_errors: list[str],
) -> None:
    """Run Stage 7 validations on all specs and envelopes."""
    for spec in specs:
        _validate_spec_stage7(spec, control_structure, validation_errors)

    for env in envelopes:
        _validate_envelope_stage7(env, validation_errors)


def _validate_spec_stage7(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    validation_errors: list[str],
) -> None:
    """Run stage-local validators for a single spec in Stage 7."""
    for result in (
        validate_bdi_grounding(spec, control_structure),
        validate_vulnerability_completeness(spec),
    ):
        if not result.passed:
            validation_errors.extend(result.errors)


def _validate_envelope_stage7(
    envelope: ScenarioEnvelope,
    validation_errors: list[str],
) -> None:
    """Run stage-local validators for a single envelope in Stage 7."""
    for result in (
        validate_tree_branch_coverage(envelope.attack_tree),
        validate_gherkin_structure(envelope.gherkin_spec),
    ):
        if not result.passed:
            validation_errors.extend(result.errors)


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
        "enriched_threat_set": hash_model(enriched_threat_set),
        "control_structure": hash_model(control_structure),
        "loss_analysis": hash_model(loss_analysis),
    }
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)
    stage_summary = count_calls_by_stage(run_dir)

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
