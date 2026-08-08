"""SP1 run orchestration — Stages 1a → 1b → 2.

Orchestrates the full SP1 pipeline:
  Stage 1a: Loss analysis derivation
  Stage 1b: Capability profile inference (or load with --profile)
  Stage 2: Control structure derivation (3 calls + heuristics + critic + revision)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import StageError
from scenario_forge.stpa.infra.manifest import STPARunManifest
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR
from scenario_forge.stpa.system_model.control_structure import (
    derive_control_structure,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    has_unjustified_gaps,
    run_completeness_critic,
    run_revision,
)
from scenario_forge.stpa.system_model.heuristics import (
    check_solution_neutrality,
    run_heuristics,
)
from scenario_forge.stpa.system_model.loss_analysis import derive_loss_analysis
from scenario_forge.stpa.system_model.profile import (
    derive_capability_profile,
    load_capability_profile,
)

DEFAULT_TEMPERATURE = 0.4


@dataclass
class SP1RunResult:
    """Result of a full SP1 run.

    On partial failure, ``loss_analysis``, ``capability_profile``, and
    ``control_structure`` may be ``None`` and ``stage_errors`` lists
    the failures that occurred.
    """

    loss_analysis: LossAnalysis | None = None
    capability_profile: CapabilityProfile | None = None
    control_structure: ControlStructure | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False
    stage_errors: list[str] = field(default_factory=list)


def run_sp1(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    profile_path: Path | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> SP1RunResult:
    """Run the full SP1 pipeline: Stages 1a → 1b → 2.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        profile_path: Optional path to a pre-built capability-profile.yaml.
            When provided, Stage 1b LLM call is skipped.
        temperature: LLM temperature (default 0.4).

    Returns:
        SP1RunResult with all artifacts and diagnostic info. On partial
        failure, returns a partial result with ``stage_errors`` populated
        and remaining artifacts as None.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    loader = TemplateLoader(PROMPTS_DIR)

    stage_errors: list[str] = []

    # --- Stage 1a: Loss Analysis ---
    loss_analysis = _try_derive_loss_analysis(
        llm_client, use_case_text, risk_cards, run_dir, loader, temperature,
        stage_errors,
    )

    # --- Stage 1b: Capability Profile ---
    capability_profile = _try_derive_capability_profile(
        llm_client, use_case_text, loss_analysis, run_dir, loader, temperature,
        profile_path, stage_errors,
    )

    # --- Stage 2: Control Structure + heuristics + critic + revision ---
    stage2_result = _run_stage_2_block(
        llm_client, use_case_text, loss_analysis, capability_profile,
        run_dir, loader, temperature, stage_errors,
    )

    # Write run manifest (always, even on partial failure)
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        use_case_text=use_case_text,
        risk_cards=risk_cards,
        loader=loader,
        critic_findings=stage2_result.critic_findings,
        temperature=temperature,
        profile_skipped=profile_path is not None,
        stage_errors=stage_errors,
    )

    return SP1RunResult(
        loss_analysis=loss_analysis,
        capability_profile=capability_profile,
        control_structure=stage2_result.control_structure,
        critic_findings=stage2_result.critic_findings,
        heuristic_errors=stage2_result.heuristic_errors,
        heuristic_warnings=stage2_result.heuristic_warnings,
        solution_neutrality_warnings=stage2_result.solution_neutrality_warnings,
        post_revision_warnings=stage2_result.post_revision_warnings,
        revised=stage2_result.revised,
        stage_errors=stage_errors,
    )


@dataclass
class _Stage2Result:
    """Internal result container for the Stage 2 block."""

    control_structure: ControlStructure | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False


def _try_derive_loss_analysis(
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
) -> LossAnalysis | None:
    """Run Stage 1a, recording errors on failure."""
    try:
        return derive_loss_analysis(
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return None


def _try_derive_capability_profile(
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis | None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    profile_path: Path | None,
    stage_errors: list[str],
) -> CapabilityProfile | None:
    """Run Stage 1b (or load a pre-built profile), recording errors on failure."""
    if loss_analysis is None:
        return None
    if profile_path is not None:
        return load_capability_profile(profile_path)
    try:
        return derive_capability_profile(
            llm_client=llm_client,
            use_case_text=use_case_text,
            loss_analysis=loss_analysis,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return None


def _run_stage_2_block(
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis | None,
    capability_profile: CapabilityProfile | None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
) -> _Stage2Result:
    """Run Stage 2: control structure derivation, heuristics, critic, and revision.

    Returns an empty result when prerequisites are missing or derivation fails.
    """
    if loss_analysis is None or capability_profile is None:
        return _Stage2Result()

    try:
        control_structure = derive_control_structure(
            llm_client=llm_client,
            use_case_text=use_case_text,
            loss_analysis=loss_analysis,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return _Stage2Result()

    # Structural heuristics (always run after Call 3)
    heuristic_result = run_heuristics(control_structure, loss_analysis)
    solution_neutrality_warnings = check_solution_neutrality(control_structure)

    # Completeness critic (graceful — returns empty findings on failure)
    critic_findings = run_completeness_critic(
        llm_client=llm_client,
        control_structure=control_structure,
        capability_profile=capability_profile,
        use_case_text=use_case_text,
        run_dir=run_dir,
        template_loader=loader,
        temperature=temperature,
    )

    # Revision (single attempt if unjustified gaps; graceful on failure)
    post_revision_warnings: list[str] = []
    revised = False
    if has_unjustified_gaps(critic_findings):
        revised = True
        control_structure, post_revision_warnings = run_revision(
            llm_client=llm_client,
            control_structure=control_structure,
            critic_findings=critic_findings,
            use_case_text=use_case_text,
            run_dir=run_dir,
            loss_analysis=loss_analysis,
            template_loader=loader,
            temperature=temperature,
        )
        write_yaml(control_structure, run_dir / "control-structure.yaml")

    return _Stage2Result(
        control_structure=control_structure,
        critic_findings=critic_findings,
        heuristic_errors=list(heuristic_result.errors),
        heuristic_warnings=list(heuristic_result.warnings),
        solution_neutrality_warnings=solution_neutrality_warnings,
        post_revision_warnings=post_revision_warnings,
        revised=revised,
    )


def _compute_input_hashes(use_case_text: str, risk_cards: list[RiskCard]) -> dict[str, str]:
    """Compute SHA-256 hashes of input artifacts for the manifest."""
    hashes = {"use_case_text": hashlib.sha256(use_case_text.encode("utf-8")).hexdigest()}
    if risk_cards:
        risk_ids = ",".join(rc.risk_id for rc in risk_cards)
        hashes["risk_extraction"] = hashlib.sha256(risk_ids.encode("utf-8")).hexdigest()
    else:
        hashes["risk_extraction"] = hashlib.sha256(b"").hexdigest()
    return hashes


def _summarize_critic_findings(critic_findings: CriticFindings | None) -> list[str]:
    """Build a human-readable summary list from critic findings."""
    if critic_findings is None:
        return []
    return [f"{gap.gap_type}: {gap.description}" for gap in critic_findings.gaps]


def _write_manifest(
    *,
    run_dir: Path,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    loader: TemplateLoader,
    critic_findings: CriticFindings | None,
    temperature: float,
    profile_skipped: bool,
    stage_errors: list[str] | None = None,
) -> None:
    """Write the run manifest with stage summary, input hashes, and prompt hashes."""
    input_hashes = _compute_input_hashes(use_case_text, risk_cards)
    prompt_hashes = loader.hash_prompt_templates()
    critic_summary = _summarize_critic_findings(critic_findings)
    stage_1b_calls = 0 if profile_skipped else 1

    manifest = STPARunManifest(
        run_id=run_dir.name,
        run_dir=str(run_dir),
        created_at=datetime.now(timezone.utc).isoformat(),
        **{  # type: ignore[arg-type]
            "model_config": {
                "model": llm_client.model,
                "base_url": llm_client.base_url,
                "temperature": temperature,
            }
        },
        input_hashes=input_hashes,
        prompt_hashes=prompt_hashes,
        stage_summary={
            "stage_1a": {"call_count": 1},
            "stage_1b": {"call_count": stage_1b_calls},
            "stage_2": {"call_count": 3},
        },
        critic_findings=critic_summary,
    )
    if stage_errors:
        manifest.stage_errors = stage_errors
    write_yaml(manifest, run_dir / "run-manifest.yaml")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:45:29Z","module_hash":"175e788adf6257a3af9565fec8e49b4cbc540bfaa08231a00ad38539090ac0f3","functions":[{"id":"func/run_sp1","name":"run_sp1","line":65,"end_line":183,"hash":"391fc785c55d3433b251a263316a3acde1ea692f049fc611a7733f387df15626"},{"id":"func/_write_manifest","name":"_write_manifest","line":186,"end_line":237,"hash":"ce0763d77bdca98f957ebc4f472f943e2cc3681d0eea1815edbcba3f2b50467b"}]}
# mutate4py-manifest-end
