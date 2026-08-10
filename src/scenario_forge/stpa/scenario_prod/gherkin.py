"""Stage 6 Call C — Gherkin behavior specification.

One LLM call per scenario produces Gherkin .feature text with the
should/but structure mapping to control structure state transitions.
"""

from __future__ import annotations

import yaml
from pathlib import Path

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call_raw
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.models.loss_analysis import LossAnalysis, SecurityConstraint
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR

__all__ = ["generate_gherkin", "build_gherkin_prompts", "find_security_constraint"]


def generate_gherkin(
    llm_client: LLMClient,
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_6",
    step: str = "gherkin",
    temperature: float = 0.4,
) -> tuple[str | None, str | None]:
    """Execute the Gherkin LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        scenario_spec: The scenario specification.
        loss_analysis: The loss analysis for security constraint lookup.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.

    Returns:
        A tuple of (gherkin_text or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    security_constraint = find_security_constraint(scenario_spec, loss_analysis)
    system_prompt, user_prompt = build_gherkin_prompts(
        scenario_spec, security_constraint, loader
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


def find_security_constraint(
    scenario_spec: ScenarioSpec,
    loss_analysis: LossAnalysis,
) -> SecurityConstraint | None:
    """Find the security constraint related to the scenario's ICA.

    For MVP, returns the first security constraint from the loss analysis.
    The run.py orchestrator can override this by passing a more specific
    constraint lookup.
    """
    if loss_analysis.security_constraints:
        return loss_analysis.security_constraints[0]
    return None


def build_gherkin_prompts(
    scenario_spec: ScenarioSpec,
    security_constraint: SecurityConstraint | None,
    loader: TemplateLoader,
) -> tuple[str, str]:
    """Build the system and user prompts for the Gherkin call.

    Args:
        scenario_spec: The scenario specification.
        security_constraint: The security constraint for the should clause.
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

    constraint_text = (
        f"{security_constraint.constraint_id}: {security_constraint.description}"
        if security_constraint
        else "No security constraint found."
    )

    ica_text = f"ICA type: {scenario_spec.ica_type.value} on {scenario_spec.target_control_action}"

    system_prompt = loader.render_prompt("stage6c_gherkin_system.j2")
    user_prompt = loader.render_prompt(
        "stage6c_gherkin_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        security_constraint=constraint_text,
        ica_type=scenario_spec.ica_type.value,
        control_action=scenario_spec.target_control_action,
        ica_text=ica_text,
    )

    return system_prompt, user_prompt
