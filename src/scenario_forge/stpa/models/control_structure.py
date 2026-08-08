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
        # Build lookup sets
        resp_ids = {r.resp_id for r in self.responsibilities}
        cp_ids = {cp.cp_id for cp in self.controlled_processes}

        # No duplicate resp_id
        _check_duplicates([r.resp_id for r in self.responsibilities], "resp_id")
        # No duplicate cp_id
        _check_duplicates([cp.cp_id for cp in self.controlled_processes], "cp_id")

        # Collect all PM/CA/FB IDs across responsibilities
        all_pm_ids: list[str] = []
        all_ca_ids: list[str] = []
        all_fb_ids: list[str] = []
        pm_by_resp: dict[str, set[str]] = {}

        for resp in self.responsibilities:
            pm_ids = {pm.pm_id for pm in resp.process_model_parts}
            pm_by_resp[resp.resp_id] = pm_ids
            all_pm_ids.extend(pm.pm_id for pm in resp.process_model_parts)
            all_ca_ids.extend(ca.ca_id for ca in resp.control_actions)
            all_fb_ids.extend(fb.fb_id for fb in resp.feedback_channels)

            # No duplicate PM within a responsibility
            _check_duplicates(
                [pm.pm_id for pm in resp.process_model_parts], "pm_id"
            )
            # No duplicate CA within a responsibility
            _check_duplicates(
                [ca.ca_id for ca in resp.control_actions], "ca_id"
            )
            # No duplicate FB within a responsibility
            _check_duplicates(
                [fb.fb_id for fb in resp.feedback_channels], "fb_id"
            )

        # No duplicate link_id
        _check_duplicates(
            [cl.link_id for cl in self.coordination_links], "link_id"
        )

        # All PM IDs are unique across responsibilities
        _check_duplicates(all_pm_ids, "pm_id")
        # All CA IDs are unique across responsibilities
        _check_duplicates(all_ca_ids, "ca_id")
        # All FB IDs are unique across responsibilities
        _check_duplicates(all_fb_ids, "fb_id")

        # Validate feedback_source references in ProcessModelParts
        for resp in self.responsibilities:
            for pm in resp.process_model_parts:
                if pm.feedback_source is not None:
                    if not _is_valid_element_ref(pm.feedback_source, resp_ids, cp_ids):
                        raise ValueError(
                            f"ProcessModelPart {pm.pm_id} feedback_source "
                            f"references non-existent element "
                            f"{pm.feedback_source.type.value} '{pm.feedback_source.id}'."
                        )

        # Validate target references in ControlActions
        for resp in self.responsibilities:
            for ca in resp.control_actions:
                if ca.target is not None:
                    if not _is_valid_element_ref(ca.target, resp_ids, cp_ids):
                        raise ValueError(
                            f"ControlAction {ca.ca_id} target references "
                            f"non-existent element "
                            f"{ca.target.type.value} '{ca.target.id}'."
                        )

        # Validate FeedbackChannel.updates — must reference a valid PM
        # within the SAME responsibility
        for resp in self.responsibilities:
            local_pm_ids = pm_by_resp[resp.resp_id]
            for fb in resp.feedback_channels:
                if fb.updates not in local_pm_ids:
                    # Check if it exists in another responsibility
                    if fb.updates in {pm for s in pm_by_resp.values() for pm in s}:
                        raise ValueError(
                            f"FeedbackChannel {fb.fb_id} updates references "
                            f"PM '{fb.updates}' which belongs to a different "
                            f"responsibility (not {resp.resp_id})."
                        )
                    else:
                        raise ValueError(
                            f"FeedbackChannel {fb.fb_id} updates references "
                            f"non-existent PM '{fb.updates}'."
                        )

        # Validate FeedbackChannel.source references
        for resp in self.responsibilities:
            for fb in resp.feedback_channels:
                if not _is_valid_element_ref(fb.source, resp_ids, cp_ids):
                    raise ValueError(
                        f"FeedbackChannel {fb.fb_id} source references "
                        f"non-existent element "
                        f"{fb.source.type.value} '{fb.source.id}'."
                    )

        # Validate CoordinationLink source/target/shared_pm
        for cl in self.coordination_links:
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
            if cl.shared_pm not in set(all_pm_ids):
                raise ValueError(
                    f"CoordinationLink {cl.link_id} shared_pm references "
                    f"non-existent PM '{cl.shared_pm}'."
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
    elif ref.type == ReferenceType.controlled_process:
        return ref.id in cp_ids
    return False


def _check_duplicates(ids: list[str], field_name: str) -> None:
    """Raise ValueError if *ids* contains duplicates."""
    seen: set[str] = set()
    for id_val in ids:
        if id_val in seen:
            raise ValueError(f"Duplicate {field_name}: '{id_val}'.")
        seen.add(id_val)


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
      (via security constraints → responsibilities).
    - Orphan PM parts (not updated by any feedback channel) are flagged as
      warnings.

    Args:
        cs: The control structure to check.
        loss_analysis: Optional loss analysis for hazard tracing.

    Returns:
        A HeuristicResult with errors and warnings.
    """
    result = HeuristicResult()

    # 1. Every responsibility has >=1 PM, >=1 CA, >=1 FB
    for resp in cs.responsibilities:
        if len(resp.process_model_parts) < 1:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no process model part."
            )
        if len(resp.control_actions) < 1:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no control action."
            )
        if len(resp.feedback_channels) < 1:
            result.errors.append(
                f"Responsibility {resp.resp_id} has no feedback channel."
            )

    # 2. Every controlled process is referenced by >=1 feedback source
    #    OR >=1 control action target
    referenced_cps: set[str] = set()
    for resp in cs.responsibilities:
        for fb in resp.feedback_channels:
            if fb.source.type == ReferenceType.controlled_process:
                referenced_cps.add(fb.source.id)
        for ca in resp.control_actions:
            if ca.target is not None and ca.target.type == ReferenceType.controlled_process:
                referenced_cps.add(ca.target.id)

    for cp in cs.controlled_processes:
        if cp.cp_id not in referenced_cps:
            result.errors.append(
                f"Controlled process {cp.cp_id} is not referenced by any "
                f"feedback channel source or control action target."
            )

    # 3. Orphan PM parts (not updated by any feedback channel) -> warnings
    for resp in cs.responsibilities:
        updated_pms = {fb.updates for fb in resp.feedback_channels}
        for pm in resp.process_model_parts:
            if pm.pm_id not in updated_pms:
                result.warnings.append(
                    f"Orphan PM {pm.pm_id} in responsibility {resp.resp_id} "
                    f"is not updated by any feedback channel."
                )

    # 4. Hazard tracing (requires loss_analysis)
    if loss_analysis is not None:
        # Build a mapping: constraint_id -> which responsibility references it
        # in its responsibility_constraints
        constraints_by_resp: dict[str, set[str]] = {}
        for resp in cs.responsibilities:
            for rc in resp.responsibility_constraints:
                constraints_by_resp.setdefault(rc.rc_id, set()).add(resp.resp_id)

        # Map hazard_id -> set of constraint IDs that reference it
        # Security constraints from LossAnalysis have related_hazards
        hazard_to_constraints: dict[str, set[str]] = {}
        for sc in loss_analysis.security_constraints:
            for h_id in sc.related_hazards:
                hazard_to_constraints.setdefault(h_id, set()).add(sc.constraint_id)

        # For each hazard, check that at least one responsibility references
        # a constraint that covers that hazard
        for hazard in loss_analysis.hazards:
            covering_constraints = hazard_to_constraints.get(hazard.hazard_id, set())
            traced_resps: set[str] = set()
            for c_id in covering_constraints:
                traced_resps.update(constraints_by_resp.get(c_id, set()))
            if not traced_resps:
                result.errors.append(
                    f"Hazard {hazard.hazard_id} is not traced to any "
                    f"responsibility (no responsibility references a constraint "
                    f"that covers this hazard)."
                )

    return result
