"""Stage 2 — Control Structure derivation.

Three sequential LLM calls applying Poh's Behavioral Design Process:
  Call 1 — Requirements (Step 2a)
  Call 2 — Responsibilities + Elements (Steps 2b-2c)
  Call 3 — Connections (Steps 2d-2e)
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from scenario_forge.stpa.infra.llm import LLMClient
from scenario_forge.stpa.infra.llm_helpers import (
    StageError,
    log_llm_call_failure,
    safe_llm_call,
)
from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
    ControlledProcess,
    ElementRef,
    Responsibility,
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


class ConnectionAssignment(BaseModel):
    """A connection assignment for a feedback channel or control action."""

    element_id: str  # FB-* or CA-*
    target: ElementRef | None = None  # for control actions: which element receives the action
    source: ElementRef | None = None  # for feedback channels: which element provides the info


class ConnectionSet(BaseModel):
    """Slim schema for Call 3 — only new outputs."""

    coordination_links: list[CoordinationLink] = []
    controlled_processes: list[ControlledProcess] = []
    connection_assignments: list[ConnectionAssignment] = []


# ---------------------------------------------------------------------------
# Merge — combine ResponsibilitySet (Call 2) with ConnectionSet (Call 3)
# ---------------------------------------------------------------------------


def merge_connection_set(
    responsibility_set: ResponsibilitySet,
    connection_set: ConnectionSet,
) -> ControlStructure:
    """Merge ResponsibilitySet from Call 2 with ConnectionSet from Call 3.

    - Applies connection assignments to responsibilities (sets feedback
      sources, control action targets by element ID)
    - Adds coordination links and controlled processes
    - Produces and validates the final ControlStructure
    """
    responsibilities = copy.deepcopy(responsibility_set.responsibilities)

    for assignment in connection_set.connection_assignments:
        _apply_connection_assignment(responsibilities, assignment)

    controlled_processes = _merge_controlled_processes(
        responsibility_set.controlled_processes,
        connection_set.controlled_processes,
    )

    return ControlStructure(
        responsibilities=responsibilities,
        controlled_processes=controlled_processes,
        coordination_links=connection_set.coordination_links,
    )


def _apply_connection_assignment(
    responsibilities: list[Responsibility],
    assignment: ConnectionAssignment,
) -> None:
    """Apply a single connection assignment to the matching feedback channel or control action."""
    for resp in responsibilities:
        if _try_set_feedback_source(resp, assignment):
            return
        if _try_set_control_action_target(resp, assignment):
            return


def _try_set_feedback_source(
    resp: Responsibility, assignment: ConnectionAssignment
) -> bool:
    """Set the feedback source if the assignment matches a feedback channel in this responsibility."""
    if assignment.source is None:
        return False
    for fb in resp.feedback_channels:
        if fb.fb_id == assignment.element_id:
            fb.source = assignment.source
            return True
    return False


def _try_set_control_action_target(
    resp: Responsibility, assignment: ConnectionAssignment
) -> bool:
    """Set the control action target if the assignment matches a control action in this responsibility."""
    if assignment.target is None:
        return False
    for ca in resp.control_actions:
        if ca.ca_id == assignment.element_id:
            ca.target = assignment.target
            return True
    return False


def _merge_controlled_processes(
    from_call2: list[ControlledProcess],
    from_call3: list[ControlledProcess],
) -> list[ControlledProcess]:
    """Merge controlled processes from Call 2 and Call 3, deduplicating by cp_id."""
    seen: set[str] = set()
    merged: list[ControlledProcess] = []
    for cp in from_call2 + from_call3:
        if cp.cp_id not in seen:
            seen.add(cp.cp_id)
            merged.append(cp)
    return merged


# ---------------------------------------------------------------------------
# Merge with fallback — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _merge_with_fallback(
    responsibility_set: ResponsibilitySet,
    connection_set: ConnectionSet,
    run_dir: Path,
    model: str,
) -> tuple[ControlStructure, list[str]]:
    """Merge ConnectionSet into ResponsibilitySet, falling back on failure.

    On merge failure (invalid cross-references in the ConnectionSet), the
    failure is logged to ``calls.jsonl`` and a fallback ControlStructure is
    built from the ResponsibilitySet alone (without coordination links).

    This function is deterministic and has no LLM dependency, so it can be
    tested independently of the Stage 2 LLM call sequence.

    Args:
        responsibility_set: Responsibilities and controlled processes from Call 2.
        connection_set: Coordination links, CPs, and assignments from Call 3.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).

    Returns:
        A tuple of (ControlStructure, merge_warnings). The warning list
        is empty when the merge succeeds.
    """
    try:
        return merge_connection_set(responsibility_set, connection_set), []
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log_llm_call_failure(
            model,
            run_dir,
            STAGE,
            "merge_connection_set",
            error_msg,
        )
        warnings = [f"{STAGE}/merge_connection_set: {error_msg}"]
        # Deep-copy to match merge_connection_set's non-mutation contract
        fallback = ControlStructure(
            responsibilities=copy.deepcopy(responsibility_set.responsibilities),
            controlled_processes=copy.deepcopy(responsibility_set.controlled_processes),
        )
        return fallback, warnings


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
) -> tuple[ControlStructure, list[str]]:
    """Run all three Stage 2 calls in sequence and assemble the ControlStructure.

    If the merge of ResponsibilitySet (Call 2) and ConnectionSet (Call 3)
    fails due to invalid cross-references in the ConnectionSet, the merge
    failure is logged and a fallback ControlStructure is built from the
    ResponsibilitySet alone (without coordination links). The returned
    warning list is non-empty in that case.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        loss_analysis: LossAnalysis from Stage 1a (provides security constraints).
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        A tuple of (validated ControlStructure, merge_warnings). The
        warning list is empty when the merge succeeds.
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
    connection_set = _call_3_connections(
        llm_client=llm_client,
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    control_structure, merge_warnings = _merge_with_fallback(
        responsibility_set, connection_set, run_dir, llm_client.model,
    )

    write_yaml(control_structure, run_dir / "control-structure.yaml")
    return control_structure, merge_warnings


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
) -> ConnectionSet:
    """Run Call 3: identify connections, coordination links, and connection assignments.

    Returns a ConnectionSet (slim schema) that is later merged with the
    ResponsibilitySet from Call 2 to produce the final ControlStructure.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    system_prompt = loader.render_prompt("stage2_call3_system.j2")
    user_prompt = loader.render_prompt(
        "stage2_call3_user.j2",
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
    )

    connection_set, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=ConnectionSet,
        run_dir=run_dir,
        stage=STAGE,
        step="call_3_connections",
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step="call_3_connections", message=error_msg)
    return connection_set


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T13:27:20Z","module_hash":"a927b39cc912bcd17f4476519121fce422bbe2240942086838e5c06508d876d4","functions":[{"id":"func/merge_connection_set","name":"merge_connection_set","line":90,"end_line":115,"hash":"91401c9996d67d5255695a66ae446cf4a08e2ade63f41901d56d5ff07f0061e3"},{"id":"func/_apply_connection_assignment","name":"_apply_connection_assignment","line":118,"end_line":127,"hash":"4826885a653c30e772ae1c2a33be78235229c39814c0237dae054cdfd4723b92"},{"id":"func/_try_set_feedback_source","name":"_try_set_feedback_source","line":130,"end_line":140,"hash":"b570aa8dbc9545c3cb8e4e4bbc6c29415d0a1fc4411931cf0b89ec7cbe1730c0"},{"id":"func/_try_set_control_action_target","name":"_try_set_control_action_target","line":143,"end_line":153,"hash":"0f0ecda079875b1d7e7a0b35a2596c263a0df3a38060058645e132e5b42f6333"},{"id":"func/_merge_controlled_processes","name":"_merge_controlled_processes","line":156,"end_line":167,"hash":"b6e9a76bea5acbc4e6d1f164d2bab1edc9ed699e8512a42f90752025a74148e8"},{"id":"func/_merge_with_fallback","name":"_merge_with_fallback","line":175,"end_line":217,"hash":"69e88d52b93e18ce59aeb24efa7b31b80ed7cd4a94b9f9fac3d430010446813a"},{"id":"func/derive_control_structure","name":"derive_control_structure","line":225,"end_line":291,"hash":"e7d15b2690c4c0191d38c1cf43747051d794840a90b1187f0cd18bfe7db857e2"},{"id":"func/_call_1_requirements","name":"_call_1_requirements","line":299,"end_line":332,"hash":"fd9bc8ae6b88e5852532eecfc104323c9eedd2cea5c485991da751403cc39071"},{"id":"func/_call_2_responsibilities","name":"_call_2_responsibilities","line":340,"end_line":373,"hash":"8af8c975b002066a88b41680d635114de89efa0669e9244f564329144365fb60"},{"id":"func/_call_3_connections","name":"_call_3_connections","line":381,"end_line":417,"hash":"88f9e669aebbe55f102f1a491e96a23a31e806ef8785ee6ce67eefd866f03462"}]}
# mutate4py-manifest-end
