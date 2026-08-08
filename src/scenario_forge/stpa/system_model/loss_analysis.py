"""Stage 1a — Loss Analysis derivation.

Single LLM call derives losses, hazards, and security constraints from
use-case text and risk cards. Dual-source output: risk-card-derived losses
(provenance=risk_card, non-empty source_risk_cards) and use-case-derived
losses (provenance=use_case, empty source_risk_cards).
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.call_log import append_call_log, make_call_log_entry
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.loss_analysis import LossAnalysis

PROMPTS_DIR = Path(__file__).parent / "prompts"
STAGE = "stage_1a"
STEP = "loss_analysis"
DEFAULT_TEMPERATURE = 0.4


def derive_loss_analysis(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> LossAnalysis:
    """Run Stage 1a: derive loss analysis from use-case text and risk cards.

    Makes a single LLM call, validates the response into a LossAnalysis,
    logs the call, writes the output to loss-analysis.yaml, and returns
    the validated model.

    Args:
        llm_client: LLM client for making the completion call.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        Validated LossAnalysis model.

    Raises:
        ValidationError: If the LLM response does not produce a valid LossAnalysis.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("stage1a_system.j2")
    user_prompt = loader.render_prompt(
        "stage1a_user.j2",
        use_case_text=use_case_text,
        risk_cards=risk_cards,
    )

    result = llm_client.complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=LossAnalysis,
        temperature=temperature,
    )

    loss_analysis = _parse_loss_analysis(result)
    _log_call(result, llm_client.model, run_dir)
    write_yaml(loss_analysis, run_dir / "loss-analysis.yaml")
    return loss_analysis


def _parse_loss_analysis(result: LLMResult) -> LossAnalysis:
    """Parse and validate the LLM result into a LossAnalysis."""
    content = result.content
    if isinstance(content, LossAnalysis):
        return content
    if isinstance(content, dict):
        return LossAnalysis.model_validate(content)
    if isinstance(content, str):
        return LossAnalysis.model_validate(json.loads(content))
    raise ValidationError(
        f"Unexpected LLM result content type: {type(content)}",
        LossAnalysis,
    )


def _log_call(result: LLMResult, model: str, run_dir: Path) -> None:
    """Append a call-log entry for the Stage 1a loss analysis call."""
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
