"""Stage 2 — Control Structure derivation.

Three sequential LLM calls applying Poh's Behavioral Design Process:
  Call 1 — Requirements (Step 2a)
  Call 2 — Responsibilities + Elements (Steps 2b-2c)
  Call 3 — Connections (Steps 2d-2e)
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import StageError, safe_llm_call
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
    ControlledProcess,
)
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

STAGE = "stage_2"
DEFAULT_TEMPERATURE = 0.4


# ---------------------------------------------------------------------------
# Internal models
# ---------------------------------------------------------------------------


class Requirement(BaseModel):
    """A solution-neutral requirement derived from a security constraint."""

    req_id: str  # REQ-1, REQ-2, ...
    description: str
    classification: Literal["control", "constraint"]
    source_constraint: str  # SC-* ref


class RequirementSet(BaseModel):
    """A set of requirements derived from security constraints."""

    requirements: list[Requirement]


class ResponsibilitySet(BaseModel):
    """A set of responsibilities with controlled processes (Call 2 output).

    Wraps the Foundation Responsibility list plus ControlledProcess list.
    """

    responsibilities: list[Responsibility]
    controlled_processes: list[ControlledProcess] = []


# ---------------------------------------------------------------------------
# Stage 2 — three sequential LLM calls
# ---------------------------------------------------------------------------


def derive_control_structure(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
) -> ControlStructure:
    """Run all three Stage 2 calls in sequence and assemble the ControlStructure.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        loss_analysis: LossAnalysis from Stage 1a (provides security constraints).
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        Validated ControlStructure model.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    # Call 1 — Requirements
    requirement_set = _call_1_requirements(
        llm_client=llm_client,
        use_case_text=use_case_text,
        loss_analysis=loss_analysis,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Call 2 — Responsibilities + Elements
    responsibility_set = _call_2_responsibilities(
        llm_client=llm_client,
        use_case_text=use_case_text,
        requirement_set=requirement_set,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Call 3 — Connections
    control_structure = _call_3_connections(
        llm_client=llm_client,
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    write_yaml(control_structure, run_dir / "control-structure.yaml")
    return control_structure


# ---------------------------------------------------------------------------
# Call 1 — Requirements
# ---------------------------------------------------------------------------


def _call_1_requirements(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> RequirementSet:
    """Run Call 1: derive requirements from security constraints.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    system_prompt = loader.render_prompt("stage2_call1_system.j2")
    user_prompt = loader.render_prompt(
        "stage2_call1_user.j2",
        use_case_text=use_case_text,
        security_constraints=loss_analysis.security_constraints,
    )

    requirement_set, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=RequirementSet,
        run_dir=run_dir,
        stage=STAGE,
        step="call_1_requirements",
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step="call_1_requirements", message=error_msg)
    return requirement_set


# ---------------------------------------------------------------------------
# Call 2 — Responsibilities + Elements
# ---------------------------------------------------------------------------


def _call_2_responsibilities(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    requirement_set: RequirementSet,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ResponsibilitySet:
    """Run Call 2: derive responsibilities, PM/CA/FB elements, and controlled processes.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    system_prompt = loader.render_prompt("stage2_call2_system.j2")
    user_prompt = loader.render_prompt(
        "stage2_call2_user.j2",
        use_case_text=use_case_text,
        requirements=requirement_set.requirements,
    )

    responsibility_set, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=ResponsibilitySet,
        run_dir=run_dir,
        stage=STAGE,
        step="call_2_responsibilities",
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step="call_2_responsibilities", message=error_msg)
    return responsibility_set


# ---------------------------------------------------------------------------
# Call 3 — Connections
# ---------------------------------------------------------------------------


def _call_3_connections(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    responsibility_set: ResponsibilitySet,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ControlStructure:
    """Run Call 3: identify connections, coordination links, and assemble ControlStructure.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    system_prompt = loader.render_prompt("stage2_call3_system.j2")
    user_prompt = loader.render_prompt(
        "stage2_call3_user.j2",
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
    )

    control_structure, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=ControlStructure,
        run_dir=run_dir,
        stage=STAGE,
        step="call_3_connections",
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step="call_3_connections", message=error_msg)
    return control_structure


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T18:00:31Z","module_hash":"52b5150d948737f515d511ff935911c248559a8c3324804463f36ffda0042a5c","functions":[{"id":"func/derive_control_structure","name":"derive_control_structure","line":67,"end_line":122,"hash":"2ba98232f6d2c58b7beaf290942635d5b3aae809212973a234f22a5fdc358252"},{"id":"func/_call_1_requirements","name":"_call_1_requirements","line":130,"end_line":163,"hash":"fd9bc8ae6b88e5852532eecfc104323c9eedd2cea5c485991da751403cc39071"},{"id":"func/_call_2_responsibilities","name":"_call_2_responsibilities","line":171,"end_line":204,"hash":"8af8c975b002066a88b41680d635114de89efa0669e9244f564329144365fb60"},{"id":"func/_call_3_connections","name":"_call_3_connections","line":212,"end_line":245,"hash":"d8a64302f0032a55af6245ae24ce4af28d05f35696f6dd971065f5273e2b6b5f"}]}
# mutate4py-manifest-end
