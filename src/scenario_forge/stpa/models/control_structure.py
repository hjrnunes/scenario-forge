"""ControlStructure boundary schema (Section 4.2 of the STPA-Sec foundation spec).

SP1 output, consumed by SP2 and SP3.

Cross-reference validation is done in Pydantic validators. Structural
heuristics are **separate** deterministic post-checks (``check_structural_heuristics``)
because the Gherkin distinguishes "the control structure is validated"
vs "the control structure structural heuristics are checked".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, model_validator

from scenario_forge.stpa.models._validation import check_duplicate_ids

if TYPE_CHECKING:
    from scenario_forge.stpa.models.loss_analysis import LossAnalysis


class ReferenceType(str, Enum):
    """Type of element referenced by an ElementRef."""

    responsibility = "responsibility"
    controlled_process = "controlled_process"


class ElementRef(BaseModel):
    """A reference to a responsibility or controlled process."""

    type: ReferenceType
    id: str  # RESP-* or CP-*


class ResponsibilityConstraint(BaseModel):
    """A constraint on a responsibility."""

    rc_id: str  # RC-X-Y
    description: str


class ProcessModelPart(BaseModel):
    """A part of a controller's process model."""

    pm_id: str  # PM-X-Y
    description: str
    feedback_source: ElementRef | None = None


class ControlAction(BaseModel):
    """A control action a controller can execute."""

    ca_id: str  # CA-X-Y
    description: str
    target: ElementRef | None = None


class FeedbackChannel(BaseModel):
    """A feedback channel providing information to a controller."""

    fb_id: str  # FB-X-Y
    description: str
    updates: str  # pm_id ref
    source: ElementRef


class Responsibility(BaseModel):
    """A controller's responsibility in the control structure."""

    resp_id: str  # RESP-1, RESP-2, ...
    description: str
    responsibility_constraints: list[ResponsibilityConstraint] = Field(
        default_factory=list
    )
    process_model_parts: list[ProcessModelPart] = Field(default_factory=list)
    control_actions: list[ControlAction] = Field(default_factory=list)
    feedback_channels: list[FeedbackChannel] = Field(default_factory=list)


class ControlledProcess(BaseModel):
    """A controlled process in the control structure."""

    cp_id: str  # CP-1, CP-2, ...
    description: str


class CoordinationMechanism(BaseModel):
    """A mechanism for coordinating between controllers."""

    cm_id: str  # CM-X
    description: str
    payload: str


class CoordinationLink(BaseModel):
    """A coordination link between two controllers."""

    link_id: str  # CL-1, CL-2, ...
    source: str  # resp_id
    target: str  # resp_id
    shared_pm: str  # pm_id ref
    coordination_mechanism: CoordinationMechanism
    description: str


class ControlStructure(BaseModel):
    """The hierarchical control structure of the system."""

    responsibilities: list[Responsibility]
    controlled_processes: list[ControlledProcess] = Field(default_factory=list)
    coordination_links: list[CoordinationLink] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references_and_duplicates(self) -> ControlStructure:
        resp_ids = {r.resp_id for r in self.responsibilities}
        cp_ids = {cp.cp_id for cp in self.controlled_processes}

        check_duplicate_ids([r.resp_id for r in self.responsibilities], "resp_id")
        check_duplicate_ids([cp.cp_id for cp in self.controlled_processes], "cp_id")

        all_pm_ids, all_ca_ids, all_fb_ids, pm_by_resp = _collect_child_ids(
            self.responsibilities
        )

        check_duplicate_ids(all_pm_ids, "pm_id")
        check_duplicate_ids(all_ca_ids, "ca_id")
        check_duplicate_ids(all_fb_ids, "fb_id")
        check_duplicate_ids(
            [cl.link_id for cl in self.coordination_links], "link_id"
        )

        _validate_element_refs(self.responsibilities, resp_ids, cp_ids)
        _validate_feedback_updates(self.responsibilities, pm_by_resp)
        _validate_coordination_links(
            self.coordination_links, resp_ids, all_pm_ids
        )

        return self


def _is_valid_element_ref(
    ref: ElementRef,
    resp_ids: set[str],
    cp_ids: set[str],
) -> bool:
    """Check if an ElementRef points to a valid responsibility or controlled process."""
    if ref.type == ReferenceType.responsibility:
        return ref.id in resp_ids
    if ref.type == ReferenceType.controlled_process:
        return ref.id in cp_ids
    return False


def _collect_child_ids(
    responsibilities: list[Responsibility],
) -> tuple[list[str], list[str], list[str], dict[str, set[str]]]:
    """Collect all PM/CA/FB IDs and check for per-responsibility duplicates.

    Returns:
        A tuple of (all_pm_ids, all_ca_ids, all_fb_ids, pm_ids_by_resp).
    """
    all_pm_ids: list[str] = []
    all_ca_ids: list[str] = []
    all_fb_ids: list[str] = []
    pm_by_resp: dict[str, set[str]] = {}

    for resp in responsibilities:
        pm_list = [pm.pm_id for pm in resp.process_model_parts]
        ca_list = [ca.ca_id for ca in resp.control_actions]
        fb_list = [fb.fb_id for fb in resp.feedback_channels]

        pm_by_resp[resp.resp_id] = set(pm_list)
        all_pm_ids.extend(pm_list)
        all_ca_ids.extend(ca_list)
        all_fb_ids.extend(fb_list)

        check_duplicate_ids(pm_list, "pm_id")
        check_duplicate_ids(ca_list, "ca_id")
        check_duplicate_ids(fb_list, "fb_id")

    return all_pm_ids, all_ca_ids, all_fb_ids, pm_by_resp


def _validate_element_refs(
    responsibilities: list[Responsibility],
    resp_ids: set[str],
    cp_ids: set[str],
) -> None:
    """Validate ElementRef targets in PMs, CAs, and FBs."""
    for resp in responsibilities:
        _validate_pm_refs(resp, resp_ids, cp_ids)
        _validate_ca_refs(resp, resp_ids, cp_ids)
        _validate_fb_source_refs(resp, resp_ids, cp_ids)


def _validate_pm_refs(
    resp: Responsibility, resp_ids: set[str], cp_ids: set[str]
) -> None:
    """Validate feedback_source references in process model parts."""
    for pm in resp.process_model_parts:
        if pm.feedback_source is not None:
            if not _is_valid_element_ref(pm.feedback_source, resp_ids, cp_ids):
                raise ValueError(
                    f"ProcessModelPart {pm.pm_id} feedback_source "
                    f"references non-existent element "
                    f"{pm.feedback_source.type.value} '{pm.feedback_source.id}'."
                )


def _validate_ca_refs(
    resp: Responsibility, resp_ids: set[str], cp_ids: set[str]
) -> None:
    """Validate target references in control actions."""
    for ca in resp.control_actions:
        if ca.target is not None:
            if not _is_valid_element_ref(ca.target, resp_ids, cp_ids):
                raise ValueError(
                    f"ControlAction {ca.ca_id} target references "
                    f"non-existent element "
                    f"{ca.target.type.value} '{ca.target.id}'."
                )


def _validate_fb_source_refs(
    resp: Responsibility, resp_ids: set[str], cp_ids: set[str]
) -> None:
    """Validate source references in feedback channels."""
    for fb in resp.feedback_channels:
        if not _is_valid_element_ref(fb.source, resp_ids, cp_ids):
            raise ValueError(
                f"FeedbackChannel {fb.fb_id} source references "
                f"non-existent element "
                f"{fb.source.type.value} '{fb.source.id}'."
            )


def _validate_feedback_updates(
    responsibilities: list[Responsibility],
    pm_by_resp: dict[str, set[str]],
) -> None:
    """Validate that feedback channel updates reference a PM in the same responsibility."""
    all_pm_ids = {pm for s in pm_by_resp.values() for pm in s}
    for resp in responsibilities:
        local_pm_ids = pm_by_resp[resp.resp_id]
        for fb in resp.feedback_channels:
            _validate_fb_update_target(fb, resp.resp_id, local_pm_ids, all_pm_ids)


def _validate_fb_update_target(
    fb: FeedbackChannel,
    resp_id: str,
    local_pm_ids: set[str],
    all_pm_ids: set[str],
) -> None:
    """Validate a single feedback channel's updates reference."""
    if fb.updates in local_pm_ids:
        return
    if fb.updates in all_pm_ids:
        raise ValueError(
            f"FeedbackChannel {fb.fb_id} updates references "
            f"PM '{fb.updates}' which belongs to a different "
            f"responsibility (not {resp_id})."
        )
    raise ValueError(
        f"FeedbackChannel {fb.fb_id} updates references "
        f"non-existent PM '{fb.updates}'."
    )


def _validate_coordination_links(
    links: list[CoordinationLink],
    resp_ids: set[str],
    all_pm_ids: list[str],
) -> None:
    """Validate coordination link source/target/shared_pm references."""
    pm_id_set = set(all_pm_ids)
    for cl in links:
        if cl.source not in resp_ids:
            raise ValueError(
                f"CoordinationLink {cl.link_id} source references "
                f"non-existent responsibility '{cl.source}'."
            )
        if cl.target not in resp_ids:
            raise ValueError(
                f"CoordinationLink {cl.link_id} target references "
                f"non-existent responsibility '{cl.target}'."
            )
        if cl.shared_pm not in pm_id_set:
            raise ValueError(
                f"CoordinationLink {cl.link_id} shared_pm references "
                f"non-existent PM '{cl.shared_pm}'."
            )


# ---------------------------------------------------------------------------
# Structural heuristics (deterministic post-checks, separate from validation)
# ---------------------------------------------------------------------------


@dataclass
class HeuristicResult:
    """Result of structural heuristic checks."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0


def check_structural_heuristics(
    cs: ControlStructure,
    loss_analysis: LossAnalysis | None = None,
) -> HeuristicResult:
    """Run deterministic structural heuristic post-checks on a control structure.

    These are separate from Pydantic field validation. They check:

    - Every responsibility has >=1 process model part, >=1 control action,
      >=1 feedback channel.
    - Every controlled process is referenced by >=1 feedback channel source
      OR >=1 control action target.
    - Every hazard (from LossAnalysis) traces to >=1 responsibility
      (via security constraints -> responsibilities).
    - Orphan PM parts (not updated by any feedback channel) are flagged as
      warnings.

    Args:
        cs: The control structure to check.
        loss_analysis: Optional loss analysis for hazard tracing.

    Returns:
        A HeuristicResult with errors and warnings.
    """
    result = HeuristicResult()

    _check_responsibility_completeness(cs, result)
    _check_controlled_process_references(cs, result)
    _check_orphan_pms(cs, result)
    if loss_analysis is not None:
        _check_hazard_tracing(cs, loss_analysis, result)

    return result


def _check_responsibility_completeness(
    cs: ControlStructure, result: HeuristicResult
) -> None:
    """Every responsibility has >=1 PM, >=1 CA, >=1 FB."""
    for resp in cs.responsibilities:
        if not resp.process_model_parts:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no process model part."
            )
        if not resp.control_actions:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no control action."
            )
        if not resp.feedback_channels:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no feedback channel."
            )


def _check_controlled_process_references(
    cs: ControlStructure, result: HeuristicResult
) -> None:
    """Every controlled process is referenced by >=1 feedback source or CA target."""
    referenced_cps = _collect_referenced_cps(cs.responsibilities)
    for cp in cs.controlled_processes:
        if cp.cp_id not in referenced_cps:
            result.errors.append(
                f"Controlled process {cp.cp_id} is not referenced by any "
                f"feedback channel source or control action target."
            )


def _collect_referenced_cps(responsibilities: list[Responsibility]) -> set[str]:
    """Collect CP IDs referenced by feedback sources or CA targets."""
    referenced: set[str] = set()
    for resp in responsibilities:
        _add_cps_from_feedback(referenced, resp.feedback_channels)
        _add_cps_from_control_actions(referenced, resp.control_actions)
    return referenced


def _add_cps_from_feedback(referenced: set[str], channels: list[FeedbackChannel]) -> None:
    """Add CP IDs referenced by feedback channel sources."""
    for fb in channels:
        if fb.source.type == ReferenceType.controlled_process:
            referenced.add(fb.source.id)


def _add_cps_from_control_actions(referenced: set[str], actions: list[ControlAction]) -> None:
    """Add CP IDs referenced by control action targets."""
    for ca in actions:
        if ca.target is not None and ca.target.type == ReferenceType.controlled_process:
            referenced.add(ca.target.id)


def _check_orphan_pms(cs: ControlStructure, result: HeuristicResult) -> None:
    """Orphan PM parts (not updated by any feedback channel) produce warnings."""
    for resp in cs.responsibilities:
        updated_pms = {fb.updates for fb in resp.feedback_channels}
        for pm in resp.process_model_parts:
            if pm.pm_id not in updated_pms:
                result.warnings.append(
                    f"Orphan PM {pm.pm_id} in responsibility {resp.resp_id} "
                    f"is not updated by any feedback channel."
                )


def _check_hazard_tracing(
    cs: ControlStructure,
    loss_analysis: LossAnalysis,
    result: HeuristicResult,
) -> None:
    """Every hazard traces to >=1 responsibility via security constraints."""
    constraints_by_resp = _build_constraints_by_resp(cs.responsibilities)
    hazard_to_constraints = _build_hazard_to_constraints(
        loss_analysis.security_constraints
    )

    for hazard in loss_analysis.hazards:
        covering = hazard_to_constraints.get(hazard.hazard_id, set())
        traced_resps = _trace_responsibilities(covering, constraints_by_resp)
        if not traced_resps:
            result.errors.append(
                f"Hazard {hazard.hazard_id} is not traced to any "
                f"responsibility (no responsibility references a constraint "
                f"that covers this hazard)."
            )


def _build_constraints_by_resp(
    responsibilities: list[Responsibility],
) -> dict[str, set[str]]:
    """Map rc_id -> set of resp_ids that reference it."""
    mapping: dict[str, set[str]] = {}
    for resp in responsibilities:
        for rc in resp.responsibility_constraints:
            mapping.setdefault(rc.rc_id, set()).add(resp.resp_id)
    return mapping


def _build_hazard_to_constraints(
    security_constraints: list,
) -> dict[str, set[str]]:
    """Map hazard_id -> set of constraint_ids that cover it."""
    mapping: dict[str, set[str]] = {}
    for sc in security_constraints:
        for h_id in sc.related_hazards:
            mapping.setdefault(h_id, set()).add(sc.constraint_id)
    return mapping


def _trace_responsibilities(
    covering_constraints: set[str],
    constraints_by_resp: dict[str, set[str]],
) -> set[str]:
    """Find all responsibilities referenced by the covering constraints."""
    traced: set[str] = set()
    for c_id in covering_constraints:
        traced.update(constraints_by_resp.get(c_id, set()))
    return traced
