"""Stage 2 — Control Structure derivation.

Three sequential LLM calls applying Poh's Behavioral Design Process:
  Call 1 — Requirements (Step 2a)
  Call 2 — Responsibilities + Elements (Steps 2b-2c)
  Call 3 — Connections (Steps 2d-2e)
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from scenario_forge.models.capability_profile import CapabilityProfile
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
    FeedbackChannel,
    Responsibility,
    _is_valid_element_ref,
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


def _iter_resp_ref_fields(
    resp: Responsibility,
) -> list[tuple[str, str, Any]]:
    """Yield (element_label, field_name, item) for each ElementRef-bearing field.

    Each tuple identifies a single ElementRef slot inside the
    responsibility: the PM feedback_source, CA target, and FB source.
    The caller can ``getattr``/``setattr`` *field_name* on *item* to
    read or nullify the ref.
    """
    return [
        (f"PM {pm.pm_id}", "feedback_source", pm)
        for pm in resp.process_model_parts
    ] + [
        (f"CA {ca.ca_id}", "target", ca)
        for ca in resp.control_actions
    ] + [
        (f"FB {fb.fb_id}", "source", fb)
        for fb in resp.feedback_channels
    ]


def _nullify_invalid_refs_in_resp(
    resp: Responsibility,
    resp_ids: set[str],
    cp_ids: set[str],
) -> list[str]:
    """Nullify unresolvable ElementRefs in a single responsibility.

    Returns a warning string for each stripped ref.
    """
    warnings: list[str] = []
    for element_label, field_name, item in _iter_resp_ref_fields(resp):
        ref = getattr(item, field_name)
        if ref is not None and not _is_valid_element_ref(ref, resp_ids, cp_ids):
            warnings.append(
                f"Stripped invalid {field_name} from {element_label}: "
                f"{ref.type.value} '{ref.id}' "
                f"not found in responsibilities or controlled processes."
            )
            setattr(item, field_name, None)
    return warnings


def _sanitize_for_fallback(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> tuple[list[Responsibility], list[ControlledProcess], list[str]]:
    """Nullify ElementRefs that cannot be resolved against available IDs.

    Iterates deep-copied responsibilities and nullifies any
    ``feedback_source``, ``control_action.target``, or
    ``feedback_channel.source`` whose ElementRef id cannot be resolved
    against the available resp_ids and cp_ids.

    Args:
        responsibilities: Responsibilities from the ResponsibilitySet.
        controlled_processes: Controlled processes from the ResponsibilitySet.

    Returns:
        A tuple of (sanitized responsibilities, controlled processes,
        warnings). The warnings list contains one entry per stripped
        ElementRef.
    """
    resp_ids = {r.resp_id for r in responsibilities}
    cp_ids = {cp.cp_id for cp in controlled_processes}
    sanitized_resps = copy.deepcopy(responsibilities)
    sanitized_cps = copy.deepcopy(controlled_processes)
    warnings: list[str] = []

    for resp in sanitized_resps:
        warnings.extend(_nullify_invalid_refs_in_resp(resp, resp_ids, cp_ids))

    return sanitized_resps, sanitized_cps, warnings


def _strip_all_refs_in_resp(resp: Responsibility) -> list[str]:
    """Strip ALL ElementRefs from a single responsibility, returning warnings."""
    warnings: list[str] = []
    for element_label, field_name, item in _iter_resp_ref_fields(resp):
        ref = getattr(item, field_name)
        if ref is not None:
            warnings.append(
                f"Further-degraded: stripped {field_name} from {element_label}."
            )
            setattr(item, field_name, None)
    return warnings


def _strip_all_element_refs(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> tuple[list[Responsibility], list[ControlledProcess], list[str]]:
    """Strip ALL ElementRefs from responsibilities (further-degraded fallback).

    Sets all feedback_source to None, removes all control_action targets,
    and sets all feedback_channel.source to None. Also deduplicates
    responsibilities by resp_id (keeping the first occurrence) so that
    the resulting ControlStructure can pass validation even when the
    original ResponsibilitySet had duplicate IDs.

    Args:
        responsibilities: Responsibilities to strip.
        controlled_processes: Controlled processes (deduplicated by cp_id).

    Returns:
        A tuple of (stripped responsibilities, controlled processes,
        warnings). The warnings list contains one entry per stripped
        ElementRef and per duplicate responsibility.
    """
    stripped_resps: list[Responsibility] = []
    seen_resp_ids: set[str] = set()
    warnings: list[str] = []

    for resp in copy.deepcopy(responsibilities):
        if resp.resp_id in seen_resp_ids:
            warnings.append(
                f"Further-degraded: removed duplicate responsibility "
                f"{resp.resp_id}."
            )
            continue
        seen_resp_ids.add(resp.resp_id)
        warnings.extend(_strip_all_refs_in_resp(resp))
        stripped_resps.append(resp)

    # Deduplicate controlled processes by cp_id
    stripped_cps: list[ControlledProcess] = []
    seen_cp_ids: set[str] = set()
    for cp in copy.deepcopy(controlled_processes):
        if cp.cp_id not in seen_cp_ids:
            seen_cp_ids.add(cp.cp_id)
            stripped_cps.append(cp)

    return stripped_resps, stripped_cps, warnings


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

    The fallback path first sanitizes invalid ElementRefs via
    ``_sanitize_for_fallback``. If sanitization still fails (e.g. duplicate
    IDs), a further-degraded path strips ALL ElementRefs.

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

        # First fallback: sanitize invalid ElementRefs
        try:
            sanitized_resps, sanitized_cps, sanitize_warnings = (
                _sanitize_for_fallback(
                    responsibility_set.responsibilities,
                    responsibility_set.controlled_processes,
                )
            )
            warnings.extend(sanitize_warnings)
            fallback = ControlStructure(
                responsibilities=sanitized_resps,
                controlled_processes=sanitized_cps,
            )
            return fallback, warnings
        except Exception:
            # Further-degraded fallback: strip ALL ElementRefs
            stripped_resps, stripped_cps, strip_warnings = (
                _strip_all_element_refs(
                    responsibility_set.responsibilities,
                    responsibility_set.controlled_processes,
                )
            )
            warnings.extend(strip_warnings)
            fallback = ControlStructure(
                responsibilities=stripped_resps,
                controlled_processes=stripped_cps,
            )
            return fallback, warnings


# ---------------------------------------------------------------------------
# Orphan PM repair — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _extract_resp_num(resp_id: str) -> int:
    """Extract the numeric suffix from a resp_id like 'RESP-3'."""
    match = re.search(r"\d+", resp_id)
    return int(match.group()) if match else 0


def _next_fb_num(resp: Responsibility) -> int:
    """Return the next available FB number for a responsibility.

    Scans existing feedback_channels and returns ``max(fb_nums) + 1``,
    or 1 when the responsibility has no feedback channels.
    """
    nums = []
    for fb in resp.feedback_channels:
        match = re.match(r"FB-\d+-(\d+)", fb.fb_id)
        if match:
            nums.append(int(match.group(1)))
    return max(nums, default=0) + 1


def _find_orphan_pms(resp: Responsibility) -> list[str]:
    """Return PM IDs in *resp* that no feedback channel updates."""
    updated_pms = {fb.updates for fb in resp.feedback_channels}
    return [
        pm.pm_id for pm in resp.process_model_parts
        if pm.pm_id not in updated_pms
    ]


def _create_stub_fb(
    resp: Responsibility,
    pm_id: str,
    fb_num: int,
) -> FeedbackChannel:
    """Create a stub FeedbackChannel for an orphan PM.

    Args:
        resp: The responsibility containing the orphan PM.
        pm_id: The orphan PM's ID (e.g. 'PM-1-3').
        fb_num: The FB number to assign (e.g. 2 → 'FB-1-2').

    Returns:
        A FeedbackChannel with auto-generated description and updates
        referencing the orphan PM.
    """
    resp_num = _extract_resp_num(resp.resp_id)
    fb_id = f"FB-{resp_num}-{fb_num}"
    # Reuse an existing feedback_source if any FB has one
    source = None
    for fb in resp.feedback_channels:
        if fb.source is not None:
            source = fb.source
            break
    return FeedbackChannel(
        fb_id=fb_id,
        description=f"Auto-generated feedback for orphan {pm_id}",
        updates=pm_id,
        source=source,
    )


def repair_orphan_pms(
    responsibility_set: ResponsibilitySet,
) -> tuple[ResponsibilitySet, list[str]]:
    """Repair orphan PM parts by auto-generating stub feedback channels.

    For each responsibility, finds PM parts where no feedback channel has
    that PM in its ``updates`` list. For each orphan PM, creates a stub
    feedback channel:
      - ``fb_id``: ``FB-{resp_num}-{next_fb_num}``
      - ``description``: ``"Auto-generated feedback for orphan PM {pm_id}"``
      - ``updates``: ``[pm_id]``
      - ``source``: reuses an existing FB source if available, else None

    Args:
        responsibility_set: The ResponsibilitySet from Call 2.

    Returns:
        A tuple of (repaired ResponsibilitySet, warnings). Each warning
        mentions the orphan PM ID. If no orphans exist, the set is
        returned unchanged with an empty warnings list.
    """
    warnings: list[str] = []
    any_repaired = False
    repaired_resps: list[Responsibility] = []

    for resp in responsibility_set.responsibilities:
        orphan_pm_ids = _find_orphan_pms(resp)
        if not orphan_pm_ids:
            repaired_resps.append(resp)
            continue

        any_repaired = True
        resp_copy = copy.deepcopy(resp)
        next_num = _next_fb_num(resp_copy)
        for pm_id in orphan_pm_ids:
            stub = _create_stub_fb(resp_copy, pm_id, next_num)
            resp_copy.feedback_channels.append(stub)
            warnings.append(
                f"Auto-generated feedback channel {stub.fb_id} "
                f"for orphan PM {pm_id} in responsibility {resp.resp_id}."
            )
            next_num += 1
        repaired_resps.append(resp_copy)

    if not any_repaired:
        return responsibility_set, warnings

    repaired_set = responsibility_set.model_copy(
        update={"responsibilities": repaired_resps},
    )
    return repaired_set, warnings


# ---------------------------------------------------------------------------
# Stage 2 — three sequential LLM calls
# ---------------------------------------------------------------------------


def derive_control_structure(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    capability_profile: CapabilityProfile | None = None,
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
        capability_profile=capability_profile,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Repair orphan PMs — auto-generate stub FB channels before Call 3
    responsibility_set, repair_warnings = repair_orphan_pms(responsibility_set)

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
    return control_structure, merge_warnings + repair_warnings


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
    capability_profile: CapabilityProfile | None = None,
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
        capability_profile=capability_profile,
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
# {"version":1,"tested_at":"2026-08-09T21:58:37Z","module_hash":"a0f80807bfc4fd0049deb40007f6490421e620554cb03770f26e5eabc570f810","functions":[{"id":"func/merge_connection_set","name":"merge_connection_set","line":94,"end_line":119,"hash":"91401c9996d67d5255695a66ae446cf4a08e2ade63f41901d56d5ff07f0061e3"},{"id":"func/_apply_connection_assignment","name":"_apply_connection_assignment","line":122,"end_line":131,"hash":"4826885a653c30e772ae1c2a33be78235229c39814c0237dae054cdfd4723b92"},{"id":"func/_try_set_feedback_source","name":"_try_set_feedback_source","line":134,"end_line":144,"hash":"b570aa8dbc9545c3cb8e4e4bbc6c29415d0a1fc4411931cf0b89ec7cbe1730c0"},{"id":"func/_try_set_control_action_target","name":"_try_set_control_action_target","line":147,"end_line":157,"hash":"0f0ecda079875b1d7e7a0b35a2596c263a0df3a38060058645e132e5b42f6333"},{"id":"func/_merge_controlled_processes","name":"_merge_controlled_processes","line":160,"end_line":171,"hash":"b6e9a76bea5acbc4e6d1f164d2bab1edc9ed699e8512a42f90752025a74148e8"},{"id":"func/_iter_resp_ref_fields","name":"_iter_resp_ref_fields","line":179,"end_line":198,"hash":"21d182b1d761a480a796f41095d59725a6220a8e29ffecd32c99498ac49ec687"},{"id":"func/_nullify_invalid_refs_in_resp","name":"_nullify_invalid_refs_in_resp","line":201,"end_line":220,"hash":"e65b30e4d03db7268047d722a7779cb10c44e502d4751a97d71b86116fac0563"},{"id":"func/_sanitize_for_fallback","name":"_sanitize_for_fallback","line":223,"end_line":252,"hash":"6915f5c5c82fecb20e9fcff469fe980cb4bb7111158209e176ff983db23f1727"},{"id":"func/_strip_all_refs_in_resp","name":"_strip_all_refs_in_resp","line":255,"end_line":265,"hash":"14f54711c6202a0ef276c6c0c7f6b5f27a33e3f4125758cb98fa94f78ea2bccf"},{"id":"func/_strip_all_element_refs","name":"_strip_all_element_refs","line":268,"end_line":312,"hash":"14f48de3852ad03fb33765514e83f3d9e7c13e260dd799212082098fff75709f"},{"id":"func/_merge_with_fallback","name":"_merge_with_fallback","line":315,"end_line":384,"hash":"eeea88fa3c976c61f11e7d86432017510e0c28c913f260fbc33709e82ce25e82"},{"id":"func/_extract_resp_num","name":"_extract_resp_num","line":392,"end_line":395,"hash":"c60c17bbd15fed1d2c23c18c009e959d98aad10f2483586f45376e2e2040a07b"},{"id":"func/_next_fb_num","name":"_next_fb_num","line":398,"end_line":409,"hash":"9cb65fc906923ba464247da1827ef99279c6681dc8bd9a336a2a7b50817c86c8"},{"id":"func/_find_orphan_pms","name":"_find_orphan_pms","line":412,"end_line":418,"hash":"0e41d0d10fcfc7d0b5b6d7ac81657b077239b0a2a6b6b5b13924221a1f5e3b18"},{"id":"func/_create_stub_fb","name":"_create_stub_fb","line":421,"end_line":450,"hash":"78fc6869e1c08b137ede0c35ca809bae8b70ab9ef4fcca809688233f60c57d4b"},{"id":"func/repair_orphan_pms","name":"repair_orphan_pms","line":453,"end_line":503,"hash":"5e492cbf68051d9d09c65c6cc299d12f33c68a0299070cec7e88de60f1bf0e06"},{"id":"func/derive_control_structure","name":"derive_control_structure","line":511,"end_line":582,"hash":"d3bf1a6aa69e55ad6883d3dacbdb54daaf1f2e8680fed6b94bcd5ed2a9838200"},{"id":"func/_call_1_requirements","name":"_call_1_requirements","line":590,"end_line":623,"hash":"fd9bc8ae6b88e5852532eecfc104323c9eedd2cea5c485991da751403cc39071"},{"id":"func/_call_2_responsibilities","name":"_call_2_responsibilities","line":631,"end_line":666,"hash":"0b200435fbb5d1f73446ae42cafbf55a652db2c3635f432d8e18d59c2d020d53"},{"id":"func/_call_3_connections","name":"_call_3_connections","line":674,"end_line":710,"hash":"88f9e669aebbe55f102f1a491e96a23a31e806ef8785ee6ce67eefd866f03462"}]}
# mutate4py-manifest-end
