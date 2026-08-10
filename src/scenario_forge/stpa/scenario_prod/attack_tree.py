"""Stage 6 Call B — Attack tree.

One LLM call per scenario produces a YAML-serializable attack tree
using the STPA two-level causal taxonomy with 3 branch categories:
controller_side, path_side, coordination_gap.
"""

from __future__ import annotations

import json
import yaml
from pathlib import Path

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import safe_llm_call_raw
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR

__all__ = ["generate_attack_tree", "build_attack_tree_prompts", "parse_attack_tree"]


def generate_attack_tree(
    llm_client: LLMClient,
    scenario_spec: ScenarioSpec,
    control_structure: ControlStructure,
    run_dir: Path,
    loader: TemplateLoader | None = None,
    stage: str = "stage_6",
    step: str = "attack_tree",
    temperature: float = 0.4,
) -> tuple[dict | None, str | None]:
    """Execute the attack tree LLM call.

    Args:
        llm_client: LLM client for making the completion call.
        scenario_spec: The scenario specification.
        control_structure: The full control structure.
        run_dir: Directory for call logging.
        loader: Template loader (default: SP3 prompts directory).
        stage: Pipeline stage label.
        step: Sub-step label.
        temperature: LLM temperature.

    Returns:
        A tuple of (attack_tree_dict or None, error_message or None).
    """
    if loader is None:
        loader = TemplateLoader(PROMPTS_DIR)

    system_prompt, user_prompt = build_attack_tree_prompts(
        scenario_spec, control_structure, loader
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
    if text is None:
        return None, "No response text"
    tree = parse_attack_tree(text)
    if tree is None:
        return None, "Failed to parse attack tree from LLM response"
    return tree, None


def parse_attack_tree(content) -> dict | None:
    """Parse LLM response content into an attack tree dict.

    Handles dicts, JSON strings, and YAML strings.

    Args:
        content: The LLM response content (string or dict).

    Returns:
        A dict with ``root``, ``branches``, and ``leaves`` keys, or None.
    """
    if content is None:
        return None
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        try:
            return json.loads(content)
        except (json.JSONDecodeError, ValueError):
            try:
                parsed = yaml.safe_load(content)
                if isinstance(parsed, dict):
                    return parsed
            except yaml.YAMLError:
                pass
    return None


def build_attack_tree_prompts(
    scenario_spec: ScenarioSpec,
    control_structure: ControlStructure,
    loader: TemplateLoader,
) -> tuple[str, str]:
    """Build the system and user prompts for the attack tree call.

    Args:
        scenario_spec: The scenario specification.
        control_structure: The full control structure.
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
    control_structure_yaml = yaml.dump(
        control_structure.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )

    system_prompt = loader.render_prompt("stage6b_tree_system.j2")
    user_prompt = loader.render_prompt(
        "stage6b_tree_user.j2",
        scenario_spec_yaml=scenario_spec_yaml,
        control_structure_yaml=control_structure_yaml,
    )

    return system_prompt, user_prompt
