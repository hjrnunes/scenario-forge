"""Stage 6 Call A — Attack narrative.

One LLM call per scenario produces a 7-step attack narrative as a
dialectic between attacker and defender BDIs.
"""

from __future__ import annotations

import yaml
from pathlib import Path

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call_raw
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR

__all__ = ["generate_narrative", "build_narrative_prompts"]


def generate_narrative(
    llm_client: LLMClient,
    scenario_spec: ScenarioSpec,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_6",
    step: str = "narrative",
    temperature: float = 0.4,
) -> tuple[str | None, str | None]:
    """Execute the narrative LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        scenario_spec: The scenario specification.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.

    Returns:
        A tuple of (narrative_text or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    system_prompt, user_prompt = build_narrative_prompts(scenario_spec, loader)

    text, _result, error = safe_llm_call_raw(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        run_dir=run_dir,
        stage=stage,
        step=step,
        temperature=temperature,
    )

    if error is not None:
        return None, error
    return text, None


def build_narrative_prompts(
    scenario_spec: ScenarioSpec,
    loader: TemplateLoader,
) -> tuple[str, str]:
    """Build the system and user prompts for the narrative call.

    Args:
        scenario_spec: The scenario specification.
        loader: Template loader.

    Returns:
        A tuple of (system_prompt, user_prompt).
    """
    scenario_spec_yaml = yaml.dump(
        scenario_spec.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    loss_scenario = scenario_spec.loss_scenario
    ica_text = f"ICA type: {scenario_spec.ica_type.value} on {scenario_spec.target_control_action}"

    system_prompt = loader.render_prompt("stage6a_narrative_system.j2")
    user_prompt = loader.render_prompt(
        "stage6a_narrative_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        ica_text=ica_text,
        loss_scenario=loss_scenario,
    )

    return system_prompt, user_prompt
