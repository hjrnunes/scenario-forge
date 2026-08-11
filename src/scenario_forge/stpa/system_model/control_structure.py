"""Stage 2 — Control Structure derivation.

Four sequential LLM calls:
  Call 1  — Requirements
  Call 2a — Responsibilities + Responsibility Constraints + Process Model parts
  Call 2b — Control Actions + Feedback Channels + Controlled Processes
  Call 3  — Coordination links + integrity findings
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Literal, TypeVar

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
    ControlAction,
    ControlStructure,
    CoordinationLink,
    ControlledProcess,
    FeedbackChannel,
    Responsibility,
    _is_valid_element_ref,
)
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model._constants import PROMPTS_DIR

STAGE = "stage_2"
STAGE_2_CALL_COUNT = 4
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
    """Call 2a output: responsibilities with RCs and PM parts only.

    No control actions, feedback channels, or controlled processes —
    those are derived in Call 2b.
    """

    responsibilities: list[Responsibility]


class ControlElementSet(BaseModel):
    """Call 2b output: control actions, feedback channels, and controlled processes."""

    control_actions: list[ControlAction] = []
    feedback_channels: list[FeedbackChannel] = []
    controlled_processes: list[ControlledProcess] = []


class CoordinationAnalysis(BaseModel):
    """Call 3 output: coordination links and integrity findings."""

    coordination_links: list[CoordinationLink] = []
    integrity_findings: list[str] = []


# ---------------------------------------------------------------------------
# Assembly — merge Call 2a (ResponsibilitySet) with Call 2b (ControlElementSet)
# ---------------------------------------------------------------------------


def _extract_resp_num(element_id: str) -> int:
    """Extract the numeric suffix from a resp_id or element ID like 'RESP-3' or 'CA-3-1'."""
    match = re.search(r"\d+", element_id)
    return int(match.group()) if match else 0


def _assign_elements_to_responsibilities(
    elements: list,
    id_attr: str,
    resp_by_num: dict[int, Responsibility],
    target_attr: str,
) -> None:
    """Assign elements (CAs or FBs) to their parent responsibility by ID prefix.

    For each element, extracts the numeric prefix from its ``id_attr``
    (e.g. ``CA-3-1`` → 3) and appends it to the matching responsibility's
    ``target_attr`` list. Elements with no matching responsibility are
    silently dropped, matching the original assembly behavior.
    """
    for element in elements:
        resp = resp_by_num.get(_extract_resp_num(getattr(element, id_attr)))
        if resp is not None:
            getattr(resp, target_attr).append(element)


def _enrich_responsibilities(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
) -> list[Responsibility]:
    """Deep-copy responsibilities and assign Call 2b CAs/FBs onto them by ID prefix.

    Returns a deep-copied list of the Call 2a responsibilities with the
    Call 2b ``control_actions`` and ``feedback_channels`` appended to the
    matching responsibility by ID prefix (CA-X-Y → RESP-X, FB-X-Y → RESP-X).

    ``resp_by_num`` keeps the FIRST occurrence of each responsibility number.
    This is only observable on the fallback strip tier (which deduplicates
    by resp_id keeping the first occurrence); the normal assembly path
    rejects duplicate resp_ids during ControlStructure validation, so the
    assignment destination is discarded before any result is returned.
    """
    enriched = copy.deepcopy(responsibility_set.responsibilities)
    resp_by_num: dict[int, Responsibility] = {}
    for resp in enriched:
        resp_by_num.setdefault(_extract_resp_num(resp.resp_id), resp)
    _assign_elements_to_responsibilities(
        control_element_set.control_actions,
        "ca_id",
        resp_by_num,
        "control_actions",
    )
    _assign_elements_to_responsibilities(
        control_element_set.feedback_channels,
        "fb_id",
        resp_by_num,
        "feedback_channels",
    )
    return enriched


def _assemble_control_structure(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
) -> ControlStructure:
    """Merge Call 2a (responsibilities + RCs + PMs) and Call 2b (CAs + FBs + CPs).

    Matches CAs and FBs to responsibilities by ID prefix (CA-X-Y → RESP-X,
    FB-X-Y → RESP-X). Produces and validates the final ControlStructure.
    """
    responsibilities = _enrich_responsibilities(
        responsibility_set, control_element_set
    )
    controlled_processes = copy.deepcopy(control_element_set.controlled_processes)

    return ControlStructure(
        responsibilities=responsibilities,
        controlled_processes=controlled_processes,
    )


# ---------------------------------------------------------------------------
# Fallback helpers — deterministic, no LLM dependency
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
        controlled_processes: Controlled processes from the ControlElementSet.

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


def _assemble_with_fallback(
    responsibility_set: ResponsibilitySet,
    control_element_set: ControlElementSet,
    run_dir: Path,
    model: str,
) -> tuple[ControlStructure, list[str]]:
    """Assemble ControlStructure from Call 2a + Call 2b, falling back on failure.

    On assembly failure (invalid cross-references in the ControlElementSet),
    the failure is logged to ``calls.jsonl`` and a fallback ControlStructure
    is built from the ResponsibilitySet alone (without coordination links).

    Before falling back, the Call 2b control actions and feedback channels
    are assigned onto the Call 2a responsibilities via
    ``_enrich_responsibilities`` so they are preserved on the degraded
    path. The fallback path then sanitizes invalid ElementRefs via
    ``_sanitize_for_fallback``. If sanitization still fails (e.g. duplicate
    IDs), a further-degraded path strips ALL ElementRefs.

    This function is deterministic and has no LLM dependency, so it can
    be tested independently of the Stage 2 LLM call sequence.

    Args:
        responsibility_set: Responsibilities with RCs and PMs from Call 2a.
        control_element_set: CAs, FBs, and CPs from Call 2b.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).

    Returns:
        A tuple of (ControlStructure, assembly_warnings). The warning list
        is empty when the assembly succeeds.
    """
    try:
        return _assemble_control_structure(responsibility_set, control_element_set), []
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log_llm_call_failure(
            model,
            run_dir,
            STAGE,
            "assemble_control_structure",
            error_msg,
        )
        warnings = [f"{STAGE}/assemble_control_structure: {error_msg}"]

        # Enrich Call 2a responsibilities with Call 2b control actions and
        # feedback channels before sanitization/stripping. Without this, the
        # fallback tiers silently discard all CAs and FBs (the
        # ``responsibility_set.responsibilities`` passed in only carry RCs
        # and PM parts). The enriched list is built once and reused for both
        # tiers; each tier deep-copies it internally, so there is no risk of
        # cross-tier mutation.
        enriched_resps = _enrich_responsibilities(
            responsibility_set, control_element_set
        )

        # First fallback: sanitize invalid ElementRefs
        try:
            sanitized_resps, sanitized_cps, sanitize_warnings = (
                _sanitize_for_fallback(
                    enriched_resps,
                    control_element_set.controlled_processes,
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
                    enriched_resps,
                    control_element_set.controlled_processes,
                )
            )
            warnings.extend(strip_warnings)
            fallback = ControlStructure(
                responsibilities=stripped_resps,
                controlled_processes=stripped_cps,
            )
            return fallback, warnings


# ---------------------------------------------------------------------------
# Coordination link addition — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


def _add_coordination_links_with_fallback(
    control_structure: ControlStructure,
    coordination_analysis: CoordinationAnalysis,
    run_dir: Path,
    model: str,
) -> tuple[ControlStructure, list[str]]:
    """Add coordination links from Call 3 to the ControlStructure.

    On failure (invalid coordination link references), the failure is
    logged and the ControlStructure is returned without coordination links.

    Args:
        control_structure: The assembled ControlStructure (without links).
        coordination_analysis: Coordination links and integrity findings from Call 3.
        run_dir: Directory for failure logging.
        model: LLM model name (used in the call-log entry).

    Returns:
        A tuple of (ControlStructure, warnings). The warning list is empty
        when the coordination links are added successfully.
    """
    if not coordination_analysis.coordination_links:
        return control_structure, []

    try:
        return ControlStructure(
            responsibilities=control_structure.responsibilities,
            controlled_processes=control_structure.controlled_processes,
            coordination_links=coordination_analysis.coordination_links,
        ), []
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log_llm_call_failure(
            model,
            run_dir,
            STAGE,
            "add_coordination_links",
            error_msg,
        )
        warnings = [f"{STAGE}/add_coordination_links: {error_msg}"]
        return control_structure, warnings


# ---------------------------------------------------------------------------
# Orphan PM repair — deterministic, no LLM dependency
# ---------------------------------------------------------------------------


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
    control_structure: ControlStructure,
) -> tuple[ControlStructure, list[str]]:
    """Repair orphan PM parts by auto-generating stub feedback channels.

    For each responsibility, finds PM parts where no feedback channel has
    that PM in its ``updates`` list. For each orphan PM, creates a stub
    feedback channel:
      - ``fb_id``: ``FB-{resp_num}-{next_fb_num}``
      - ``description``: ``"Auto-generated feedback for orphan PM {pm_id}"``
      - ``updates``: ``[pm_id]``
      - ``source``: reuses an existing FB source if available, else None

    Args:
        control_structure: The assembled ControlStructure.

    Returns:
        A tuple of (repaired ControlStructure, warnings). Each warning
        mentions the orphan PM ID. If no orphans exist, the structure is
        returned unchanged with an empty warnings list.
    """
    warnings: list[str] = []
    any_repaired = False
    repaired_resps: list[Responsibility] = []

    for resp in control_structure.responsibilities:
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
        return control_structure, warnings

    repaired_cs = control_structure.model_copy(
        update={"responsibilities": repaired_resps},
    )
    return repaired_cs, warnings


# ---------------------------------------------------------------------------
# Stage 2 — four sequential LLM calls
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
    """Run all four Stage 2 calls in sequence and assemble the ControlStructure.

    Call 1  — Requirements (from security constraints)
    Call 2a — Responsibilities + RCs + PM parts (from requirements + capability profile)
    Call 2b — Control actions + feedback channels + controlled processes (from responsibilities)
    Call 3  — Coordination links + integrity findings (from full control structure)

    If the assembly of Call 2a + Call 2b fails due to invalid cross-references,
    the assembly failure is logged and a fallback ControlStructure is built
    from the ResponsibilitySet alone (without coordination links). The returned
    warning list is non-empty in that case.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        loss_analysis: LossAnalysis from Stage 1a (provides security constraints).
        capability_profile: Optional capability profile for zone-driven responsibilities.
        run_dir: Directory for output artifacts.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        A tuple of (validated ControlStructure, warnings). The
        warning list is empty when the assembly succeeds.
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

    # Call 2a — Responsibilities + RCs + PM parts
    responsibility_set = _call_2a_responsibilities(
        llm_client=llm_client,
        use_case_text=use_case_text,
        requirement_set=requirement_set,
        capability_profile=capability_profile,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Call 2b — CAs + FBs + CPs
    control_element_set = _call_2b_control_elements(
        llm_client=llm_client,
        use_case_text=use_case_text,
        responsibility_set=responsibility_set,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Assembly: merge Call 2a + Call 2b → ControlStructure (with fallback)
    control_structure, assembly_warnings = _assemble_with_fallback(
        responsibility_set, control_element_set, run_dir, llm_client.model,
    )

    # Repair orphan PMs — auto-generate stub FB channels before Call 3
    control_structure, repair_warnings = repair_orphan_pms(control_structure)

    # Call 3 — Coordination + integrity (receives full assembled control structure)
    coordination_analysis = _call_3_coordination(
        llm_client=llm_client,
        use_case_text=use_case_text,
        control_structure=control_structure,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )

    # Add coordination links to the ControlStructure (with fallback)
    control_structure, coord_warnings = _add_coordination_links_with_fallback(
        control_structure, coordination_analysis, run_dir, llm_client.model,
    )

    write_yaml(control_structure, run_dir / "control-structure.yaml")
    return control_structure, assembly_warnings + repair_warnings + coord_warnings


# ---------------------------------------------------------------------------
# Shared LLM call backbone for the four Stage 2 calls
# ---------------------------------------------------------------------------


_Stage2ModelT = TypeVar("_Stage2ModelT", bound=BaseModel)


def _run_stage2_llm_call(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    system_template: str,
    user_template: str,
    user_prompt_kwargs: dict[str, Any],
    response_format: type[_Stage2ModelT],
    step: str,
) -> _Stage2ModelT:
    """Render prompts, call the LLM, validate, and raise StageError on failure.

    Shared backbone for the four Stage 2 LLM calls (Call 1, 2a, 2b, 3).
    Each call renders a system + user prompt, invokes the LLM via
    ``safe_llm_call``, and raises ``StageError`` if the call or validation
    fails.
    """
    system_prompt = loader.render_prompt(system_template)
    user_prompt = loader.render_prompt(user_template, **user_prompt_kwargs)

    result, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=response_format,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        temperature=temperature,
    )
    if error_msg is not None:
        raise StageError(stage=STAGE, step=step, message=error_msg)
    return result  # type: ignore[return-value]


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
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call1_system.j2",
        user_template="stage2_call1_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "security_constraints": loss_analysis.security_constraints,
        },
        response_format=RequirementSet,
        step="call_1_requirements",
    )


# ---------------------------------------------------------------------------
# Call 2a — Responsibilities + RCs + PM parts
# ---------------------------------------------------------------------------


def _call_2a_responsibilities(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    requirement_set: RequirementSet,
    capability_profile: CapabilityProfile | None = None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ResponsibilitySet:
    """Run Call 2a: derive responsibilities, responsibility constraints, and PM parts.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call2a_system.j2",
        user_template="stage2_call2a_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "requirements": requirement_set.requirements,
            "capability_profile": capability_profile,
        },
        response_format=ResponsibilitySet,
        step="call_2a_responsibilities",
    )


# ---------------------------------------------------------------------------
# Call 2b — Control Actions + Feedback Channels + Controlled Processes
# ---------------------------------------------------------------------------


def _call_2b_control_elements(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    responsibility_set: ResponsibilitySet,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> ControlElementSet:
    """Run Call 2b: derive control actions, feedback channels, and controlled processes.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call2b_system.j2",
        user_template="stage2_call2b_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "responsibilities": responsibility_set.responsibilities,
        },
        response_format=ControlElementSet,
        step="call_2b_control_elements",
    )


# ---------------------------------------------------------------------------
# Call 3 — Coordination + integrity
# ---------------------------------------------------------------------------


def _call_3_coordination(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    control_structure: ControlStructure,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> CoordinationAnalysis:
    """Run Call 3: identify coordination links and verify connection integrity.

    Returns a CoordinationAnalysis containing coordination links and
    integrity findings. Does NOT fix integrity issues — flags them for
    the revision step.

    Raises:
        StageError: If the LLM call fails or the response fails validation.
    """
    return _run_stage2_llm_call(
        llm_client=llm_client,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        system_template="stage2_call3_system.j2",
        user_template="stage2_call3_user.j2",
        user_prompt_kwargs={
            "use_case_text": use_case_text,
            "control_structure": control_structure,
        },
        response_format=CoordinationAnalysis,
        step="call_3_coordination",
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-11T23:18:11Z","module_hash":"36881ead7f5abdd206ea9c4e912f57cfaefaa2a2dffb152763038096b298812b","functions":[{"id":"func/_extract_resp_num","name":"_extract_resp_num","line":95,"end_line":98,"hash":"8a82453efa2fa3f0884536e7e2e61333144799a6d4c1692fb68fb11454f9d656"},{"id":"func/_assign_elements_to_responsibilities","name":"_assign_elements_to_responsibilities","line":101,"end_line":117,"hash":"d0608f13ddfd48a6b5075bc63d1727a38cd77cd0c4e1211d81120831df034e8f"},{"id":"func/_enrich_responsibilities","name":"_enrich_responsibilities","line":120,"end_line":152,"hash":"f2db9b63696497cbdb5d2d84b3f5e1964c5097b0863a59f94691e675fda86d51"},{"id":"func/_assemble_control_structure","name":"_assemble_control_structure","line":155,"end_line":172,"hash":"f9123ddec802ad9a0f322109ed6d2724f38e47352dded320ccc2495965c59cbc"},{"id":"func/_iter_resp_ref_fields","name":"_iter_resp_ref_fields","line":180,"end_line":199,"hash":"21d182b1d761a480a796f41095d59725a6220a8e29ffecd32c99498ac49ec687"},{"id":"func/_nullify_invalid_refs_in_resp","name":"_nullify_invalid_refs_in_resp","line":202,"end_line":221,"hash":"e65b30e4d03db7268047d722a7779cb10c44e502d4751a97d71b86116fac0563"},{"id":"func/_sanitize_for_fallback","name":"_sanitize_for_fallback","line":224,"end_line":253,"hash":"ee3e40aa1934e75d876d3420f39f423a25bb8797569c1d0b30167b4f3ca9ae62"},{"id":"func/_strip_all_refs_in_resp","name":"_strip_all_refs_in_resp","line":256,"end_line":266,"hash":"14f54711c6202a0ef276c6c0c7f6b5f27a33e3f4125758cb98fa94f78ea2bccf"},{"id":"func/_strip_all_element_refs","name":"_strip_all_element_refs","line":269,"end_line":313,"hash":"14f48de3852ad03fb33765514e83f3d9e7c13e260dd799212082098fff75709f"},{"id":"func/_assemble_with_fallback","name":"_assemble_with_fallback","line":316,"end_line":399,"hash":"cd394ee806532be9994b143c13f3dab5c6a7aa85a1fce3731dd0af6e15235910"},{"id":"func/_add_coordination_links_with_fallback","name":"_add_coordination_links_with_fallback","line":407,"end_line":447,"hash":"ad5e25850d4f3c8d40efaf91958590ee891b7b111b7569e62ee1af32a7a391f7"},{"id":"func/_next_fb_num","name":"_next_fb_num","line":455,"end_line":466,"hash":"9cb65fc906923ba464247da1827ef99279c6681dc8bd9a336a2a7b50817c86c8"},{"id":"func/_find_orphan_pms","name":"_find_orphan_pms","line":469,"end_line":475,"hash":"0e41d0d10fcfc7d0b5b6d7ac81657b077239b0a2a6b6b5b13924221a1f5e3b18"},{"id":"func/_create_stub_fb","name":"_create_stub_fb","line":478,"end_line":507,"hash":"78fc6869e1c08b137ede0c35ca809bae8b70ab9ef4fcca809688233f60c57d4b"},{"id":"func/repair_orphan_pms","name":"repair_orphan_pms","line":510,"end_line":560,"hash":"90812445d8e9fa58728948f8c453f8db9a05a1e6ce944b223fef1b5e096d9a1c"},{"id":"func/derive_control_structure","name":"derive_control_structure","line":568,"end_line":660,"hash":"feba85533cc201cc3defcf115ad795f755895c9481316a93feaaf04475e63b97"},{"id":"func/_run_stage2_llm_call","name":"_run_stage2_llm_call","line":671,"end_line":705,"hash":"dd937af7790507a48c4b39a9513d78c069c1994b40795cc2b29e17854c0326ed"},{"id":"func/_call_1_requirements","name":"_call_1_requirements","line":713,"end_line":740,"hash":"007c8d20fe7df856c98b2a2bf227737196834122b9d747074868cb46401b083e"},{"id":"func/_call_2a_responsibilities","name":"_call_2a_responsibilities","line":748,"end_line":777,"hash":"6a319304b5e3c14f3042a1fdb6f09ef882e8a8f8c90a75bb4931acc5d4f31c33"},{"id":"func/_call_2b_control_elements","name":"_call_2b_control_elements","line":785,"end_line":812,"hash":"a2cb61eadb73753fcac4ae3f227155d88a00c112a69241c56a05bddb45cedf1e"},{"id":"func/_call_3_coordination","name":"_call_3_coordination","line":820,"end_line":851,"hash":"8dc150351cc054d6aa6383a7c3ef70e12c75ae6e1d82c97a4a4255d27dc86719"}]}
# mutate4py-manifest-end
