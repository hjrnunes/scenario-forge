"""Stage 1b — Capability Profile inference.

New STPA-conditioned prompt for capability profile inference. Receives
LossAnalysis from Stage 1a as context. Produces Stage1Profile which is
promoted to CapabilityProfile via to_capability_profile(). The --profile
flag skips this stage (loads a pre-built profile).
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from scenario_forge.stpa.infra.call_log import append_call_log, make_call_log_entry
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml
from scenario_forge.stpa.models.loss_analysis import LossAnalysis

PROMPTS_DIR = Path(__file__).parent / "prompts"
STAGE = "stage_1b"
STEP = "capability_profile"
DEFAULT_TEMPERATURE = 0.4


def derive_capability_profile(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> CapabilityProfile:
    """Run Stage 1b: derive capability profile from use-case text and loss analysis.

    Makes a single LLM call producing a Stage1Profile, promotes it to a
    CapabilityProfile, logs the call, writes the output to
    capability-profile.yaml, and returns the validated model.

    Args:
        llm_client: LLM client for making the completion call.
        use_case_text: Free-text use-case description.
        loss_analysis: LossAnalysis from Stage 1a.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        Validated CapabilityProfile model.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("stage1b_system.j2")
    all_losses = loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    user_prompt = loader.render_prompt(
        "stage1b_user.j2",
        use_case_text=use_case_text,
        loss_analysis=loss_analysis,
        all_losses=all_losses,
    )

    result = llm_client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=Stage1Profile,
        temperature=temperature,
    )

    stage1_profile = _parse_stage1_profile(result)
    capability_profile = stage1_profile.to_capability_profile()
    _log_call(result, llm_client.model, run_dir)
    write_yaml(capability_profile, run_dir / "capability-profile.yaml")
    return capability_profile


def load_capability_profile(profile_path: Path) -> CapabilityProfile:
    """Load a pre-built capability profile from a YAML file.

    Used when the --profile flag is provided to skip Stage 1b.

    Args:
        profile_path: Path to capability-profile.yaml.

    Returns:
        Validated CapabilityProfile model.
    """
    return read_yaml(profile_path, CapabilityProfile)


def _parse_stage1_profile(result: LLMResult) -> Stage1Profile:
    """Parse and validate the LLM result into a Stage1Profile."""
    content = result.content
    if isinstance(content, Stage1Profile):
        return content
    if isinstance(content, dict):
        return Stage1Profile.model_validate(content)
    if isinstance(content, str):
        return Stage1Profile.model_validate(json.loads(content))
    raise ValidationError(
        f"Unexpected LLM result content type: {type(content)}",
        Stage1Profile,
    )


def _log_call(result: LLMResult, model: str, run_dir: Path) -> None:
    """Append a call-log entry for the Stage 1b capability profile call."""
    entry = make_call_log_entry(
        stage=STAGE,
        step=STEP,
        model=model,
        system_prompt=result.system_prompt,
        user_prompt=result.user_prompt,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        duration_ms=result.duration_ms,
        success=True,
    )
    append_call_log([entry], run_dir)
