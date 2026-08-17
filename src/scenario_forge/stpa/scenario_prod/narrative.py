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
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec
from scenario_forge.stpa.threat_enum.technology_context import context_for

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
    capability_profile: CapabilityProfile | None = None,
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
        capability_profile: Optional capability profile used to ground
            technology-specific feedback mechanisms in the prompt.

    Returns:
        A tuple of (narrative_text or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    system_prompt, user_prompt = build_narrative_prompts(
        scenario_spec,
        loader,
        capability_profile=capability_profile,
    )

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
    capability_profile: CapabilityProfile | None = None,
) -> tuple[str, str]:
    """Build the system and user prompts for the narrative call.

    Args:
        scenario_spec: The scenario specification.
        loader: Template loader.
        capability_profile: Optional capability profile used to ground
            technology-specific feedback mechanisms in the prompt.

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
    technology_context = context_for(capability_profile)

    system_prompt = loader.render_prompt("stage6a_narrative_system.j2")
    user_prompt = loader.render_prompt(
        "stage6a_narrative_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        ica_text=ica_text,
        loss_scenario=loss_scenario,
        technology_context=technology_context,
    )

    return system_prompt, user_prompt


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-14T09:07:18Z","module_hash":"c21de3b96d76b9f988e29ec0fc9da6cf06e74066f05aa1e092778025a4849002","functions":[{"id":"func/generate_narrative","name":"generate_narrative","line":24,"end_line":71,"hash":"45b1b3df64e80ba8fb67270e38c724c45d26465aab5ef860721774f9e98b9a65"},{"id":"func/build_narrative_prompts","name":"build_narrative_prompts","line":74,"end_line":110,"hash":"d0b3cea13fae2a4c9ab64cfdf9a4f79c13a5bba14c59fc6669b8eada7c990fef"}]}
# mutate4py-manifest-end
