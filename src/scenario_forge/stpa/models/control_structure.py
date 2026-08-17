"""ControlStructure boundary schema (Section 4.2 of the STPA-Sec foundation spec).

SP1 output, consumed by SP2 and SP3.

Cross-reference validation is done in Pydantic validators. Structural
heuristics are **separate** deterministic post-checks (``check_structural_heuristics``)
because the Gherkin distinguishes "the control structure is validated"
vs "the control structure structural heuristics are checked".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator, model_validator

from scenario_forge.stpa.models._validation import check_duplicate_ids

if TYPE_CHECKING:
    from scenario_forge.stpa.models.loss_analysis import LossAnalysis


def _validate_id_format(
    value: str,
    field_name: str,
    format_spec: str,
    example: str,
    pattern: str,
) -> str:
    """Validate that *value* matches the expected ID format.

    All control-structure ID fields share the same validation logic:
    regex-check the value and raise a descriptive ValueError on mismatch.
    This helper eliminates the per-field boilerplate while keeping each
    field's error message specific.

    Args:
        value: The ID string to validate.
        field_name: Human-readable field name for the error message.
        format_spec: Format placeholder (e.g. ``"RC-X-Y"``).
        example: Concrete example for the error message (e.g. ``"RC-1-1"``).
        pattern: Anchored regex pattern the value must match.

    Returns:
        The validated value (unchanged).

    Raises:
        ValueError: If *value* does not match *pattern*.
    """
    if not re.match(pattern, value):
        raise ValueError(
            f"{field_name} must match format '{format_spec}' "
            f"(e.g. '{example}'), got '{value}'"
        )
    return value


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
    description: str = Field(min_length=1)

    @field_validator("rc_id")
    @classmethod
    def validate_rc_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "rc_id", "RC-X-Y", "RC-1-1", r"^RC-\d+-\d+$")


class ProcessModelPart(BaseModel):
    """A part of a controller's process model."""

    pm_id: str  # PM-X-Y
    description: str = Field(min_length=1)
    feedback_source: ElementRef | None = None

    @field_validator("pm_id")
    @classmethod
    def validate_pm_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "pm_id", "PM-X-Y", "PM-1-1", r"^PM-\d+-\d+$")


class ControlAction(BaseModel):
    """A control action a controller can execute."""

    ca_id: str  # CA-X-Y
    description: str = Field(min_length=1)
    target: ElementRef | None = None

    @field_validator("ca_id")
    @classmethod
    def validate_ca_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "ca_id", "CA-X-Y", "CA-1-1", r"^CA-\d+-\d+$")


class FeedbackChannel(BaseModel):
    """A feedback channel providing information to a controller."""

    fb_id: str  # FB-X-Y
    description: str = Field(min_length=1)
    updates: str  # pm_id ref
    source: ElementRef | None = None

    @field_validator("fb_id")
    @classmethod
    def validate_fb_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "fb_id", "FB-X-Y", "FB-1-1", r"^FB-\d+-\d+$")


class Responsibility(BaseModel):
    """A controller's responsibility in the control structure."""

    resp_id: str  # RESP-1, RESP-2, ...
    description: str = Field(min_length=1)
    responsibility_constraints: list[ResponsibilityConstraint] = Field(
        default_factory=list
    )
    security_constraint_refs: list[str] = Field(
        default_factory=list,
        description="SC-N IDs from LossAnalysis that this responsibility implements.",
    )
    process_model_parts: list[ProcessModelPart] = Field(default_factory=list)
    control_actions: list[ControlAction] = Field(default_factory=list)
    feedback_channels: list[FeedbackChannel] = Field(default_factory=list)

    @field_validator("resp_id")
    @classmethod
    def validate_resp_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "resp_id", "RESP-N", "RESP-1", r"^RESP-\d+$")


class ControlledProcess(BaseModel):
    """A controlled process in the control structure."""

    cp_id: str  # CP-1, CP-2, ...
    description: str = Field(min_length=1)

    @field_validator("cp_id")
    @classmethod
    def validate_cp_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "cp_id", "CP-N", "CP-1", r"^CP-\d+$")


class CoordinationMechanism(BaseModel):
    """A mechanism for coordinating between controllers."""

    cm_id: str  # CM-X
    description: str = Field(min_length=1)
    payload: str

    @field_validator("cm_id")
    @classmethod
    def validate_cm_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "cm_id", "CM-N", "CM-1", r"^CM-\d+$")


class CoordinationLink(BaseModel):
    """A coordination link between two controllers."""

    link_id: str  # CL-1, CL-2, ...
    source: str  # resp_id
    target: str  # resp_id
    shared_pm: str  # pm_id ref
    coordination_mechanism: CoordinationMechanism
    description: str = Field(min_length=1)

    @field_validator("link_id")
    @classmethod
    def validate_link_id_format(cls, v: str) -> str:
        return _validate_id_format(v, "link_id", "CL-N", "CL-1", r"^CL-\d+$")


class ControlStructure(BaseModel):
    """The hierarchical control structure of the system."""

    responsibilities: list[Responsibility] = Field(min_length=1)
    controlled_processes: list[ControlledProcess] = Field(default_factory=list)
    coordination_links: list[CoordinationLink] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_references_and_duplicates(self) -> ControlStructure:
        resp_ids = {r.resp_id for r in self.responsibilities}
        cp_ids = {cp.cp_id for cp in self.controlled_processes}

        all_rc_ids, all_pm_ids, all_ca_ids, all_fb_ids, pm_by_resp = _collect_child_ids(
            self.responsibilities
        )

        _check_all_duplicate_ids(
            self.responsibilities,
            self.controlled_processes,
            self.coordination_links,
            all_rc_ids,
            all_pm_ids,
            all_ca_ids,
            all_fb_ids,
        )

        _check_cross_namespace_collision(
            self.responsibilities, self.controlled_processes
        )

        _validate_element_refs(self.responsibilities, resp_ids, cp_ids)
        _validate_feedback_updates(self.responsibilities, pm_by_resp)
        _validate_coordination_links(self.coordination_links, resp_ids, all_pm_ids)

        return self


def _check_all_duplicate_ids(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
    coordination_links: list[CoordinationLink],
    all_rc_ids: list[str],
    all_pm_ids: list[str],
    all_ca_ids: list[str],
    all_fb_ids: list[str],
) -> None:
    """Check every ID type for duplicates at the control-structure level."""
    check_duplicate_ids([r.resp_id for r in responsibilities], "resp_id")
    check_duplicate_ids([cp.cp_id for cp in controlled_processes], "cp_id")
    check_duplicate_ids(all_rc_ids, "rc_id")
    check_duplicate_ids(all_pm_ids, "pm_id")
    check_duplicate_ids(all_ca_ids, "ca_id")
    check_duplicate_ids(all_fb_ids, "fb_id")
    check_duplicate_ids([cl.link_id for cl in coordination_links], "link_id")
    check_duplicate_ids(
        [cl.coordination_mechanism.cm_id for cl in coordination_links], "cm_id"
    )


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
) -> tuple[list[str], list[str], list[str], list[str], dict[str, set[str]]]:
    """Collect all RC/PM/CA/FB IDs and check for per-responsibility duplicates.

    Returns:
        A tuple of (all_rc_ids, all_pm_ids, all_ca_ids, all_fb_ids, pm_ids_by_resp).
    """
    all_rc_ids: list[str] = []
    all_pm_ids: list[str] = []
    all_ca_ids: list[str] = []
    all_fb_ids: list[str] = []
    pm_by_resp: dict[str, set[str]] = {}

    for resp in responsibilities:
        rc_list = [rc.rc_id for rc in resp.responsibility_constraints]
        pm_list = [pm.pm_id for pm in resp.process_model_parts]
        ca_list = [ca.ca_id for ca in resp.control_actions]
        fb_list = [fb.fb_id for fb in resp.feedback_channels]

        pm_by_resp[resp.resp_id] = set(pm_list)
        all_rc_ids.extend(rc_list)
        all_pm_ids.extend(pm_list)
        all_ca_ids.extend(ca_list)
        all_fb_ids.extend(fb_list)

        check_duplicate_ids(rc_list, "rc_id")
        check_duplicate_ids(pm_list, "pm_id")
        check_duplicate_ids(ca_list, "ca_id")
        check_duplicate_ids(fb_list, "fb_id")

    return all_rc_ids, all_pm_ids, all_ca_ids, all_fb_ids, pm_by_resp


def _collect_all_id_sets(
    responsibilities: list[Responsibility],
) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    """Collect all RC/PM/CA/FB/RESP ID sets across responsibilities.

    Returns:
        A tuple of (rc_ids, pm_ids, ca_ids, fb_ids, resp_ids).
    """
    rc_ids: set[str] = set()
    pm_ids: set[str] = set()
    ca_ids: set[str] = set()
    fb_ids: set[str] = set()
    resp_ids: set[str] = set()
    for resp in responsibilities:
        resp_ids.add(resp.resp_id)
        rc_ids.update(rc.rc_id for rc in resp.responsibility_constraints)
        pm_ids.update(pm.pm_id for pm in resp.process_model_parts)
        ca_ids.update(ca.ca_id for ca in resp.control_actions)
        fb_ids.update(fb.fb_id for fb in resp.feedback_channels)
    return rc_ids, pm_ids, ca_ids, fb_ids, resp_ids


def _collect_namespace_buckets(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> list[tuple[str, set[str]]]:
    """Collect ID sets grouped by namespace name.

    Returns a list of (namespace_name, id_set) pairs for every ID type
    in the control structure.
    """
    rc_ids, pm_ids, ca_ids, fb_ids, resp_ids = _collect_all_id_sets(responsibilities)
    cp_ids = {cp.cp_id for cp in controlled_processes}
    return [
        ("rc_id", rc_ids),
        ("pm_id", pm_ids),
        ("ca_id", ca_ids),
        ("fb_id", fb_ids),
        ("resp_id", resp_ids),
        ("cp_id", cp_ids),
    ]


def _check_cross_namespace_collision(
    responsibilities: list[Responsibility],
    controlled_processes: list[ControlledProcess],
) -> None:
    """Detect IDs that appear in more than one ID namespace.

    Collects every ID from each element type into a separate namespace
    bucket, then checks whether any ID value appears in more than one
    bucket.  This catches cross-namespace collisions that field
    validators alone cannot detect when validators are bypassed (e.g.
    an RC-1-1 value used as both rc_id and pm_id).
    """
    namespace_buckets = _collect_namespace_buckets(
        responsibilities, controlled_processes
    )
    for i, (name_a, bucket_a) in enumerate(namespace_buckets):
        for name_b, bucket_b in namespace_buckets[i + 1 :]:
            shared = bucket_a & bucket_b
            if shared:
                raise ValueError(
                    f"Cross-namespace collision: ID(s) {sorted(shared)} "
                    f"appear in both {name_a} and {name_b} namespaces. "
                    f"Each ID value must belong to exactly one namespace."
                )


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
        if fb.source is None:
            continue
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
        f"FeedbackChannel {fb.fb_id} updates references non-existent PM '{fb.updates}'."
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


def _add_cps_from_feedback(
    referenced: set[str], channels: list[FeedbackChannel]
) -> None:
    """Add CP IDs referenced by feedback channel sources."""
    for fb in channels:
        if fb.source is not None and fb.source.type == ReferenceType.controlled_process:
            referenced.add(fb.source.id)


def _add_cps_from_control_actions(
    referenced: set[str], actions: list[ControlAction]
) -> None:
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
    """Map security_constraint_id -> set of resp_ids that reference it."""
    mapping: dict[str, set[str]] = {}
    for resp in responsibilities:
        for sc_id in resp.security_constraint_refs:
            mapping.setdefault(sc_id, set()).add(resp.resp_id)
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T00:23:11Z","module_hash":"6ee15fe07bafe91e841979b50f570d984e1e294151f1d3cc7d233a9d937a4d43","functions":[{"id":"func/_validate_id_format","name":"_validate_id_format","line":26,"end_line":58,"hash":"26d495ff08e46b0c213ae96829378a180cfd6e48c495e778b8f7b76db11529e2"},{"id":"func/ResponsibilityConstraint.validate_rc_id_format","name":"validate_rc_id_format","line":83,"end_line":84,"hash":"54934cf044471649b30037f15d5d6450e73dd342d7826283dc16e1191b0b3e8b"},{"id":"func/ProcessModelPart.validate_pm_id_format","name":"validate_pm_id_format","line":96,"end_line":97,"hash":"41664a8c35f693bb031497b8093da0328d8250071d92feb8ab5c2fe9aaed337d"},{"id":"func/ControlAction.validate_ca_id_format","name":"validate_ca_id_format","line":109,"end_line":110,"hash":"f1408b7395402c8bb293befed6aacad7a10ba40c05930e2cbdb29d84c642af30"},{"id":"func/FeedbackChannel.validate_fb_id_format","name":"validate_fb_id_format","line":123,"end_line":124,"hash":"acbdc8d5529b12d9c829e799581b09b727405cc8d78d2378be56d258b0e94205"},{"id":"func/Responsibility.validate_resp_id_format","name":"validate_resp_id_format","line":141,"end_line":142,"hash":"1ca47303034039184cdf16b8f57b0417337992c998c4a4e3c085826217ab6cef"},{"id":"func/ControlledProcess.validate_cp_id_format","name":"validate_cp_id_format","line":153,"end_line":154,"hash":"6685b9ef205e2b953f635e369651ec8b43e31aed8bc370c766a02e93d9344cec"},{"id":"func/CoordinationMechanism.validate_cm_id_format","name":"validate_cm_id_format","line":166,"end_line":167,"hash":"cbb8c84359382b0d74477b8b7ab765bc6886911e47f016282612eee10705e1ea"},{"id":"func/CoordinationLink.validate_link_id_format","name":"validate_link_id_format","line":182,"end_line":183,"hash":"287b79b0efaeae72ae65b88f1dc5cbb2810726d3ae8b54a6f5fe2f261b130d76"},{"id":"func/ControlStructure.validate_references_and_duplicates","name":"validate_references_and_duplicates","line":194,"end_line":220,"hash":"686ca9c8289bd4de370e01e5a2d71125ff4a1c25a1362961826f1746b5ec2955"},{"id":"func/_check_all_duplicate_ids","name":"_check_all_duplicate_ids","line":223,"end_line":242,"hash":"16bf688d86169963c8d652bae975f9110a12c6571c51564ee6b461cdacd3fe82"},{"id":"func/_is_valid_element_ref","name":"_is_valid_element_ref","line":245,"end_line":255,"hash":"227e60e3dcd0c7c5d2acfc7257a6309dabbd61e47ef3ef1a088d976cee8f1690"},{"id":"func/_collect_child_ids","name":"_collect_child_ids","line":258,"end_line":289,"hash":"98d6808433b292c6892fe8708073c231add122c1715a53d7cc90193206623925"},{"id":"func/_collect_all_id_sets","name":"_collect_all_id_sets","line":292,"end_line":311,"hash":"22dfac9a221bfd6ae639d5103b1f245446bb04da887f6e61db2926437b2a0ee7"},{"id":"func/_collect_namespace_buckets","name":"_collect_namespace_buckets","line":314,"end_line":334,"hash":"183476922d47aaf4f810fd09a0a766e20a0625ae5ea887bf54e11bd08711a0e9"},{"id":"func/_check_cross_namespace_collision","name":"_check_cross_namespace_collision","line":337,"end_line":360,"hash":"3ff945814004983296df6f0a3ac99f17e7035504545437673ad4882b2e53309a"},{"id":"func/_validate_element_refs","name":"_validate_element_refs","line":363,"end_line":372,"hash":"e0c8c05818efc09db79d465489e19d3d83e24ee3b36cc621e52a6caa823c5aaf"},{"id":"func/_validate_pm_refs","name":"_validate_pm_refs","line":375,"end_line":386,"hash":"dc5a93174935f8408b4f4040329a8913595b8518a611049d6f06b2f0f73dba3a"},{"id":"func/_validate_ca_refs","name":"_validate_ca_refs","line":389,"end_line":400,"hash":"89eaa7e89532b0507ba400c9e98a155fd7c5e071430673676e8c3eb9850de914"},{"id":"func/_validate_fb_source_refs","name":"_validate_fb_source_refs","line":403,"end_line":415,"hash":"208666dfa83b3616b832b56519682ff557b30bdf61d4970a48de48280bf197be"},{"id":"func/_validate_feedback_updates","name":"_validate_feedback_updates","line":418,"end_line":427,"hash":"ead7695af3cad8a3eeec9337851e7f0293648db9cfc705ffb7efcc2cb95134e7"},{"id":"func/_validate_fb_update_target","name":"_validate_fb_update_target","line":430,"end_line":448,"hash":"af14dcfbcd84a47350829354726c5e09db1507bc5ed28dc876d03c4ede86f1b3"},{"id":"func/_validate_coordination_links","name":"_validate_coordination_links","line":451,"end_line":473,"hash":"0243d2effd556e73b1e3258403b9b0bbab3977ad42dfdf3927e1103b403823b1"},{"id":"func/HeuristicResult.passed","name":"passed","line":489,"end_line":490,"hash":"0ef739a09d12644ab453fbf96631fafa8638030d29ebdf028b8f07cc66a72bf6"},{"id":"func/check_structural_heuristics","name":"check_structural_heuristics","line":493,"end_line":525,"hash":"0425800cf0961914dc2d73162a76855d0573d5f65e063e32e8086d1c4656cb8e"},{"id":"func/_check_responsibility_completeness","name":"_check_responsibility_completeness","line":528,"end_line":544,"hash":"56c2647038d9d38a898e9872c92966b4d10a28e4335b44cfa95f4e76dd6db907"},{"id":"func/_check_controlled_process_references","name":"_check_controlled_process_references","line":547,"end_line":557,"hash":"57aa22dbdc230d5cfea736813aaa233125a1298d646af2a48ef44c0c9de21152"},{"id":"func/_collect_referenced_cps","name":"_collect_referenced_cps","line":560,"end_line":566,"hash":"189e1f58a1ac90ef4f9d076aa85c7e6b42364d8e6c266f3f297059dd316c0e79"},{"id":"func/_add_cps_from_feedback","name":"_add_cps_from_feedback","line":569,"end_line":573,"hash":"872f65d602be3cdc07047f6770a0f2336f15d5b3de8405de75a18047e4cb4944"},{"id":"func/_add_cps_from_control_actions","name":"_add_cps_from_control_actions","line":576,"end_line":580,"hash":"ff5fba066edcbab037b9b5970162f225343e7159dd5579bd1451d4085b226cb2"},{"id":"func/_check_orphan_pms","name":"_check_orphan_pms","line":583,"end_line":592,"hash":"d247830f0ac1c81cbf42fecd7d4f6a48e37a6fb78237be832d7f99d7e5130aa3"},{"id":"func/_check_hazard_tracing","name":"_check_hazard_tracing","line":595,"end_line":614,"hash":"fa52fe48ef647ba233c3d88282fd1e776b12043388b10b5e51383a5e29abd2b0"},{"id":"func/_build_constraints_by_resp","name":"_build_constraints_by_resp","line":617,"end_line":625,"hash":"4d61e7f43dd8e76e17315c0ce0523c39899f89a773d8b5fbda879b0a46c323e5"},{"id":"func/_build_hazard_to_constraints","name":"_build_hazard_to_constraints","line":628,"end_line":636,"hash":"d6fec50df7df4548b0cd3e34b80c17c98534da2612a50acb2e788bb007c88745"},{"id":"func/_trace_responsibilities","name":"_trace_responsibilities","line":639,"end_line":647,"hash":"842c4546b7230d027a566e53ad355aed0aaeb5c9fc223b04a158962129f84871"}]}
# mutate4py-manifest-end
