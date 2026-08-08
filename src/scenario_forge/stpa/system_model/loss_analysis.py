"""Stage 1a — Loss Analysis derivation.

Single LLM call derives losses, hazards, and security constraints from
use-case text and risk cards. Dual-source output: risk-card-derived losses
(provenance=risk_card, non-empty source_risk_cards) and use-case-derived
losses (provenance=use_case, empty source_risk_cards).
"""

from __future__ import annotations

from pathlib import Path

from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import StageError, safe_llm_call
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

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
        StageError: If the LLM call fails or the response fails validation.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    system_prompt = loader.render_prompt("stage1a_system.j2")
    user_prompt = loader.render_prompt(
        "stage1a_user.j2",
        use_case_text=use_case_text,
        risk_cards=risk_cards,
    )

    loss_analysis, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=LossAnalysis,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP,
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=STEP, message=error_msg)

    write_yaml(loss_analysis, run_dir / "loss-analysis.yaml")
    return loss_analysis


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"6fbc1bb66686e3d234e6793037cfe366e7474d06e8e8bb49eaa4787708df5ca6","functions":[{"id":"func/derive_loss_analysis","name":"derive_loss_analysis","line":26,"end_line":78,"hash":"d4cb1ff4ffaa970b84b08020c7af05605109aadb8080ed9e8c06cd0036acae9d"}]}
# mutate4py-manifest-end
