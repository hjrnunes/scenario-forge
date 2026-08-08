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
from scenario_forge.stpa.infra.llm_helpers import log_llm_call, parse_llm_result
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

    loss_analysis = parse_llm_result(result, LossAnalysis)
    log_llm_call(result, llm_client.model, run_dir, STAGE, STEP)
    write_yaml(loss_analysis, run_dir / "loss-analysis.yaml")
    return loss_analysis


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T14:39:00Z","module_hash":"dbb5316a49239d95bc3658b532a9a04fa08722c06b7ff008c94d9a2927d94d50","functions":[{"id":"func/derive_loss_analysis","name":"derive_loss_analysis","line":26,"end_line":74,"hash":"417e25404ba6bfb698e25d39d6422f7358decaa67f39ea786d066e3b40e9186e"}]}
# mutate4py-manifest-end
