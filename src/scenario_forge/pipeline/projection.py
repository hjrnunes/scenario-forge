"""Deterministic authoritative-chain projection and candidate-v2 expansion.

This module is an explicit migration seam.  It does not consume
``ScenarioSeed`` or the legacy attack-pattern catalogue shape, and it is not
wired into the current generation runner.  Future generation stages consume
only :class:`ProjectedCandidate` instances from this boundary.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable, Sequence
from itertools import product
from math import prod
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scenario_forge.models.attack_pattern import (
    AgentInternalResourceReference,
    AllCondition,
    AnyCondition,
    AttackPattern,
    AuthoritativeFactReference,
    CanonicalAttackChain,
    CanonicalResourceReference,
    Condition,
    ConditionEvaluationResult,
    DirectInputControlRequirement,
    EntryPointResourceReference,
    EvaluatedFactEvidence,
    ExecutionRequirement,
    IntegrationResourceReference,
    MappingDecision,
    NotCondition,
    ObservationRequirement,
    OutputSurfaceResourceReference,
    ProjectionSnapshot,
    ResourceBinding,
    SecurityOutcomeAssertionRequirement,
    StateChangingToolFixtureRequirement,
    StepOmission,
    TaxonomyResolver,
    ToolResourceReference,
    TrustBoundaryResourceReference,
    UpstreamSourceInfluenceRequirement,
    compute_projection_digest,
    evaluate_condition,
    validate_attack_pattern,
    validate_projection_snapshot,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ProjectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _canonical_json(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    value = _normalize_unicode(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _normalize_unicode(value: Any) -> Any:
    """Apply the canonical contract's NFC rule to values and mapping keys."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", key): _normalize_unicode(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_unicode(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_normalize_unicode(item) for item in value)
    return value


def _digest(domain: str, value: Any) -> str:
    payload = domain.encode() + b"\0" + _canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


#: Domain separator for execution-requirements digest computation.
EXECUTION_REQUIREMENTS_DIGEST_DOMAIN = "scenario-forge:execution-requirements:v1"

#: Domain separator for derivation context digest computation.
DERIVATION_CONTEXT_DIGEST_DOMAIN = "scenario-forge:derivation-context:v1"


def compute_execution_requirements_digest(
    requirements: Any,
) -> str:
    """Compute the canonical digest for a sequence of execution requirements.

    Accepts model instances (with ``model_dump``) or pre-serialized dicts.
    """
    payloads: list[Any] = []
    for item in requirements:
        if hasattr(item, "model_dump"):
            payloads.append(item.model_dump(mode="json"))
        else:
            payloads.append(item)
    return _digest(EXECUTION_REQUIREMENTS_DIGEST_DOMAIN, payloads)


def compute_derivation_context_digest(
    projection_digest: str,
    pattern_id: str,
    ingress_controllability: str,
) -> str:
    """Compute the derivation context digest binding controllability.

    Binds projection_digest + pattern_id + ingress_controllability into a
    verified immutable digest so a caller cannot flip controllability and
    re-sign arbitrary requirements.
    """
    return _digest(
        DERIVATION_CONTEXT_DIGEST_DOMAIN,
        {
            "projection_digest": projection_digest,
            "pattern_id": pattern_id,
            "ingress_controllability": ingress_controllability,
        },
    )


def _fact_key(reference: AuthoritativeFactReference) -> str:
    return _canonical_json(reference.model_dump(mode="json"))


def _resource_key(reference: CanonicalResourceReference) -> str:
    return _canonical_json(reference.model_dump(mode="json"))


def _requirement_id(prefix: str, *components: str) -> str:
    """Generate an injective, stable requirement ID from components.

    Composite requirement IDs must be collision-free even when individual
    components contain dots (e.g. step ``a`` + slot ``b.c`` vs step ``a.b``
    + slot ``c``).  Dot concatenation is ambiguous; hashing is not
    guaranteed injective.  Instead, each component is encoded as its full
    UTF-8 hexadecimal representation, and the encoded components are joined
    with ``:`` — a character that never appears in hexadecimal output.
    This makes the mapping ``(prefix, *components) → ID`` injective: the
    component list can be recovered by splitting on ``:`` and hex-decoding
    each segment, so distinct inputs always produce distinct IDs.

    IDs are **unbounded in length**: hex encoding doubles each component's
    byte length, so long step IDs or slot IDs produce long requirement IDs.
    Downstream persistence must use unbounded text columns or establish a
    future explicit bound.  No bounded consumer exists in candidate-v2.
    """
    encoded = ":".join(c.encode("utf-8").hex() for c in components)
    return f"{prefix}.{encoded}"


_SEMANTICALLY_UNORDERED_FIELDS = {
    "bindings",
    "condition_results",
    "consumed",
    "evidence",
    "ids",
    "mappings",
    "min_zones",
    "observable_postconditions",
    "observable_outcome_links",
    "omissions",
    "operands",
    "preconditions",
    "produced",
    "references",
    "resource_links",
    "resource_slots",
    "values",
}


def _normalize_semantic_order(value: Any, field_name: str | None = None) -> Any:
    value = _normalize_unicode(value)
    if isinstance(value, dict):
        return {
            key: _normalize_semantic_order(item, key) for key, item in value.items()
        }
    if isinstance(value, list):
        items = [_normalize_semantic_order(item) for item in value]
        if field_name in _SEMANTICALLY_UNORDERED_FIELDS:
            items.sort(key=_canonical_json)
        return items
    return value


class CapabilityFactSnapshot(ProjectionModel):
    """One immutable, content-addressed pre-LLM profile/fact reading."""

    profile: CapabilityProfile
    facts: tuple[EvaluatedFactEvidence, ...]
    snapshot_digest: Digest

    @property
    def capability_fact_snapshot_digest(self) -> str:
        """Implement the merged :class:`CapabilitySnapshotResolver` pin."""
        self.assert_integrity()
        return self.snapshot_digest

    def assert_integrity(self) -> None:
        """Fail closed if a nested mutable profile was changed after capture."""
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("capability/fact snapshot changed after capture")

    def fact(
        self, reference: AuthoritativeFactReference
    ) -> EvaluatedFactEvidence | None:
        self.assert_integrity()
        return {_fact_key(item.fact): item for item in self.facts}.get(
            _fact_key(reference)
        )

    def contains_resource(self, reference: CanonicalResourceReference) -> bool:
        self.assert_integrity()
        if isinstance(reference, EntryPointResourceReference):
            return (
                self.profile.resolve_entry_point(reference.entry_point_id) is not None
            )
        if isinstance(reference, ToolResourceReference):
            return self.profile.resolve_tool(reference.tool_id) is not None
        if isinstance(reference, IntegrationResourceReference):
            return (
                self.profile.resolve_integration(reference.integration_id) is not None
            )
        if isinstance(reference, TrustBoundaryResourceReference):
            return (
                self.profile.resolve_trust_boundary(reference.trust_boundary_id)
                is not None
            )
        if isinstance(reference, OutputSurfaceResourceReference):
            return (
                self.profile.resolve_output_surface(reference.entry_point_id)
                is not None
            )
        if isinstance(reference, AgentInternalResourceReference):
            # Agent-internal state has no authoritative profile inventory;
            # it is always unresolvable, making patterns that require it
            # typed-infeasible for candidate-v2.
            return False
        return False

    @model_validator(mode="after")
    def coherent_digest(self) -> CapabilityFactSnapshot:
        keys = [_fact_key(item.fact) for item in self.facts]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("snapshot facts must be uniquely sorted by reference")
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("snapshot_digest does not match capability/fact content")
        return self


def _snapshot_resource_payload(profile: CapabilityProfile) -> dict[str, Any]:
    return {
        "zones_active": sorted(set(profile.zones_active)),
        "kc_subcodes": sorted(set(profile.kc_subcodes)),
        "entry_points": sorted(
            (item.model_dump(mode="json") for item in profile.entry_points),
            key=lambda item: item["entry_point_id"],
        ),
        "tools": sorted(
            (item.model_dump(mode="json") for item in profile.tool_inventory or ()),
            key=lambda item: item["tool_id"],
        ),
        "tool_types": sorted(
            (item.model_dump(mode="json") for item in profile.tool_types or ()),
            key=lambda item: _canonical_json(item),
        ),
        "integrations": sorted(
            (
                item.model_dump(mode="json")
                for item in profile.external_integrations or ()
            ),
            key=lambda item: item["integration_id"],
        ),
        "trust_boundaries": sorted(
            (item.model_dump(mode="json") for item in profile.trust_boundaries or ()),
            key=lambda item: item["trust_boundary_id"],
        ),
    }


def _compute_snapshot_digest(
    profile: CapabilityProfile, facts: tuple[EvaluatedFactEvidence, ...]
) -> str:
    return _digest(
        "scenario-forge:capability-fact-snapshot:v1",
        {
            "profile": _snapshot_resource_payload(profile),
            "facts": [item.model_dump(mode="json") for item in facts],
        },
    )


def capture_capability_snapshot(
    profile: CapabilityProfile,
    facts: Iterable[EvaluatedFactEvidence] = (),
) -> CapabilityFactSnapshot:
    """Capture a deterministic resolver snapshot before any LLM stage."""
    by_reference: dict[str, EvaluatedFactEvidence] = {}
    for item in facts:
        key = _fact_key(item.fact)
        previous = by_reference.get(key)
        if previous is not None and previous != item:
            raise ValueError("conflicting authoritative readings for one fact")
        by_reference[key] = item
    ordered = tuple(by_reference[key] for key in sorted(by_reference))
    captured_profile = profile.model_copy(deep=True)
    return CapabilityFactSnapshot(
        profile=captured_profile,
        facts=ordered,
        snapshot_digest=_compute_snapshot_digest(captured_profile, ordered),
    )


class ProjectionBudget(ProjectionModel):
    """Explicit global expansion bound."""

    max_candidates: int = Field(default=256, gt=0)


class PreconditionEvaluationResult(ProjectionModel):
    step_id: str
    condition_id: str
    result: Literal["true", "false", "unknown"]
    evidence: tuple[EvaluatedFactEvidence, ...] = Field(min_length=1)


class ProjectionIssue(ProjectionModel):
    code: Literal[
        "unresolved_condition",
        "precondition_not_satisfied",
        "missing_compatible_resource",
        "incompatible_profile",
        "unsupported_requirement_derivation",
        "inapplicable_projection",
    ]
    pattern_id: str
    detail: str
    step_id: str | None = None
    slot_id: str | None = None
    condition_results: tuple[ConditionEvaluationResult, ...] = ()
    precondition_results: tuple[PreconditionEvaluationResult, ...] = ()


class ProjectionLimitation(ProjectionModel):
    code: Literal["candidate_budget_exhausted"]
    pattern_id: str
    total_compatible_bindings: int = Field(ge=0)
    emitted_bindings: int = Field(ge=0)


class ProjectedMapping(ProjectionModel):
    scope: Literal["chain", "step"]
    step_id: str | None = None
    mapping: MappingDecision

    @model_validator(mode="after")
    def scope_matches_step(self) -> ProjectedMapping:
        if (self.scope == "step") != (self.step_id is not None):
            raise ValueError("step mappings require step_id; chain mappings forbid it")
        return self


class CandidateComplexityInputs(ProjectionModel):
    """Policy-free inputs reserved for the future cmps.7 complexity policy."""

    selected_step_count: int = Field(ge=1)
    attacker_controlled_step_count: int = Field(ge=1)
    boundary_crossing_step_count: int = Field(ge=0)
    selected_conditional_step_count: int = Field(ge=0)
    concrete_binding_count: int = Field(ge=1)
    execution_requirement_count: int = Field(ge=1)


class ProjectedCandidate(ProjectionModel):
    """Sole candidate-v2 contract intended for future generation stages."""

    candidate_id: str = Field(pattern=r"^cand:v2:[0-9a-f]{32}$")
    pattern_id: str
    chain_id: str
    chain_semantic_revision: int = Field(gt=0)
    chain_semantic_digest: Digest
    projection: ProjectionSnapshot
    canonical_ingress: EntryPointResourceReference
    ingress_controllability: Literal["direct", "indirect"]
    projected_mappings: tuple[ProjectedMapping, ...]
    precondition_results: tuple[PreconditionEvaluationResult, ...]
    execution_requirements: tuple[ExecutionRequirement, ...]
    requirement_derivation_version: Literal["1"]
    execution_requirements_digest: Digest
    complexity_inputs: CandidateComplexityInputs

    @model_validator(mode="after")
    def verifiable_identity_and_derivation(self) -> ProjectedCandidate:
        chain = self.projection.source_chain
        req_ids = [item.requirement_id for item in self.execution_requirements]
        if len(req_ids) != len(set(req_ids)):
            raise ValueError("execution requirement IDs must be unique")
        if (
            self.pattern_id != chain.pattern_id
            or self.chain_id != chain.chain_id
            or self.chain_semantic_revision != chain.semantic_revision
            or self.chain_semantic_digest != chain.semantic_digest
        ):
            raise ValueError("candidate chain identity does not match its projection")
        ingress = next(
            binding.resource_ref
            for binding in self.projection.bindings
            if binding.slot_id == chain.initial_ingress_slot_id
        )
        if ingress != self.canonical_ingress:
            raise ValueError("canonical_ingress does not match the projection binding")
        expected_requirements_digest = compute_execution_requirements_digest(
            self.execution_requirements
        )
        if self.execution_requirements_digest != expected_requirements_digest:
            raise ValueError(
                "execution_requirements_digest does not match requirements"
            )
        if self.candidate_id != _candidate_v2_id(self.pattern_id, self.projection):
            raise ValueError("candidate_id does not match candidate-v2 identity inputs")
        expected_preconditions = {
            (step.step_id, precondition.condition_id): precondition.condition
            for step in chain.steps
            if step.step_id in set(self.projection.selected_step_ids)
            for precondition in step.preconditions
        }
        supplied_preconditions = {
            (item.step_id, item.condition_id): item
            for item in self.precondition_results
        }
        if len(supplied_preconditions) != len(self.precondition_results):
            raise ValueError("precondition result keys must be unique")
        if set(expected_preconditions) != set(supplied_preconditions):
            raise ValueError("precondition results must exactly cover selected steps")
        for key, condition in expected_preconditions.items():
            supplied = supplied_preconditions[key]
            if (
                supplied.result != "true"
                or evaluate_condition(condition, supplied.evidence) != "true"
            ):
                raise ValueError("projected candidate preconditions must evaluate true")
        if self.projected_mappings != _projected_mappings(
            chain, self.projection.selected_step_ids
        ):
            raise ValueError("projected mappings are incomplete or non-authoritative")
        selected_steps = [
            step
            for step in chain.steps
            if step.step_id in set(self.projection.selected_step_ids)
        ]
        expected_complexity = CandidateComplexityInputs(
            selected_step_count=len(selected_steps),
            attacker_controlled_step_count=sum(
                step.attacker_controlled for step in selected_steps
            ),
            boundary_crossing_step_count=sum(
                step.boundary_position == "crossing" for step in selected_steps
            ),
            selected_conditional_step_count=sum(
                step.requirement == "conditional" for step in selected_steps
            ),
            concrete_binding_count=len(self.projection.bindings),
            execution_requirement_count=len(self.execution_requirements),
        )
        if self.complexity_inputs != expected_complexity:
            raise ValueError("complexity inputs do not match projected candidate")
        return self


class ProjectionBatch(ProjectionModel):
    """Complete deterministic result, including typed non-candidate outcomes."""

    capability_fact_snapshot_digest: Digest
    candidates: tuple[ProjectedCandidate, ...]
    infeasibilities: tuple[ProjectionIssue, ...]
    limitations: tuple[ProjectionLimitation, ...]
    # Coverage targets that could not be reserved due to budget exhaustion
    # (cmps.4 blocker 5).  Empty when coverage_target_ids is not provided.
    unreserved_coverage_targets: tuple[str, ...] = ()


def _condition_facts(condition: Condition) -> tuple[AuthoritativeFactReference, ...]:
    if isinstance(condition, (AllCondition, AnyCondition)):
        items = [
            fact for operand in condition.operands for fact in _condition_facts(operand)
        ]
    elif isinstance(condition, NotCondition):
        items = list(_condition_facts(condition.operand))
    else:
        items = [condition.fact]
    return tuple(
        {_fact_key(item): item for item in items}[key]
        for key in sorted({_fact_key(item): item for item in items})
    )


def _evaluate_projection_conditions(
    pattern: AttackPattern, snapshot: CapabilityFactSnapshot
) -> tuple[ConditionEvaluationResult, ...]:
    results: list[ConditionEvaluationResult] = []
    for step in pattern.canonical_chain.steps:
        if step.condition is None:
            continue
        evidence = tuple(
            snapshot.fact(reference)
            or EvaluatedFactEvidence(fact=reference, status="unknown", value=None)
            for reference in _condition_facts(step.condition)
        )
        results.append(
            ConditionEvaluationResult(
                condition_step_id=step.step_id,
                result=evaluate_condition(step.condition, evidence),
                evidence=evidence,
            )
        )
    return tuple(results)


def _evaluate_preconditions(
    pattern: AttackPattern,
    selected_step_ids: tuple[str, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[PreconditionEvaluationResult, ...]:
    selected = set(selected_step_ids)
    results: list[PreconditionEvaluationResult] = []
    for step in pattern.canonical_chain.steps:
        if step.step_id not in selected:
            continue
        for precondition in step.preconditions:
            evidence = tuple(
                snapshot.fact(reference)
                or EvaluatedFactEvidence(fact=reference, status="unknown", value=None)
                for reference in _condition_facts(precondition.condition)
            )
            results.append(
                PreconditionEvaluationResult(
                    step_id=step.step_id,
                    condition_id=precondition.condition_id,
                    result=evaluate_condition(precondition.condition, evidence),
                    evidence=evidence,
                )
            )
    return tuple(results)


def _references_for_kind(
    kind: str,
    snapshot: CapabilityFactSnapshot,
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> tuple[CanonicalResourceReference, ...]:
    profile = snapshot.profile
    active_zones = set(profile.zones_active)
    if kind == "entry_point":
        entries = (
            item
            for item in profile.entry_points
            if not (initial_ingress or attacker_influence_required)
            or is_attacker_accessible_ingress(item, active_zones)
        )
        refs: list[CanonicalResourceReference] = [
            EntryPointResourceReference(
                kind="entry_point", entry_point_id=item.entry_point_id
            )
            for item in entries
        ]
    elif kind == "tool":
        refs = [
            ToolResourceReference(kind="tool", tool_id=item.tool_id)
            for item in profile.tool_inventory or ()
        ]
    elif kind == "integration":
        refs = [
            IntegrationResourceReference(
                kind="integration", integration_id=item.integration_id
            )
            for item in profile.external_integrations or ()
        ]
    elif kind == "output_surface":
        refs = [
            OutputSurfaceResourceReference(
                kind="output_surface", entry_point_id=item.entry_point_id
            )
            for item in profile.entry_points
            if item.direction in ("output", "bidirectional")
        ]
    elif kind == "agent_internal":
        # No authoritative profile inventory for agent-internal state;
        # patterns requiring this slot kind are typed-infeasible.
        refs = []
    else:
        refs = [
            TrustBoundaryResourceReference(
                kind="trust_boundary", trust_boundary_id=item.trust_boundary_id
            )
            for item in profile.trust_boundaries or ()
        ]
    return tuple(sorted(refs, key=_resource_key))


def _coverage_first_combinations(
    options: tuple[tuple[CanonicalResourceReference, ...], ...], limit: int
) -> tuple[tuple[CanonicalResourceReference, ...], ...]:
    """Cover each slot's alternatives before bounded Cartesian fill."""
    seen: set[tuple[str, ...]] = set()
    ordered: list[tuple[CanonicalResourceReference, ...]] = []

    def add(items: tuple[CanonicalResourceReference, ...]) -> None:
        key = tuple(_resource_key(item) for item in items)
        if key not in seen and len(ordered) < limit:
            seen.add(key)
            ordered.append(items)

    baseline = tuple(slot[0] for slot in options)
    add(baseline)
    for offset in range(1, max(len(slot) for slot in options)):
        for slot_index, slot in enumerate(options):
            if offset < len(slot):
                variant = list(baseline)
                variant[slot_index] = slot[offset]
                add(tuple(variant))
    if len(ordered) < limit:
        for combination in product(*options):
            add(combination)
            if len(ordered) == limit:
                break
    return tuple(ordered)


def _derive_execution_requirements_core(
    pattern_id: str,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    ingress_controllability: Literal["direct", "indirect"],
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Derive execution requirements from explicit canonical linkage only.

    Pure function over the embedded source chain, projection bindings, and
    the resolved ingress controllability.  No external snapshot is needed.
    No inference from action kind, name, prose, cardinality, taxonomy mapping,
    or catalog partition.  Every requirement is traced to an explicit
    ``resource_links`` or ``observable_outcome_links`` entry on a selected
    step.  Security-outcome assertions are derived only from postconditions
    that have an explicit observable outcome link, not from the
    ``security_relevant`` flag alone.
    """
    slots_by_id = {slot.slot_id: slot for slot in chain.resource_slots}
    selected_steps = [
        step
        for step in chain.steps
        if step.step_id in set(projection.selected_step_ids)
    ]
    requirements: list[ExecutionRequirement] = []

    for step in selected_steps:
        for link in step.resource_links:
            slot = slots_by_id[link.slot_id]
            if link.role == "ingress":
                if ingress_controllability != "direct":
                    return None, ProjectionIssue(
                        code="unsupported_requirement_derivation",
                        pattern_id=pattern_id,
                        detail=(
                            "indirect ingress requires explicit upstream-source "
                            "and trust-boundary linkage"
                        ),
                    )
                requirements.append(
                    DirectInputControlRequirement(
                        schema_version="1",
                        requirement_id=_requirement_id(
                            "req.direct-input", link.slot_id
                        ),
                        kind="direct_input_control",
                        entry_point_slot_id=link.slot_id,
                    )
                )
            elif link.role == "tool_fixture":
                requirements.append(
                    StateChangingToolFixtureRequirement(
                        schema_version="1",
                        requirement_id=_requirement_id(
                            "req.tool-fixture", step.step_id, link.slot_id
                        ),
                        kind="state_changing_tool_fixture",
                        tool_slot_id=link.slot_id,
                    )
                )
            elif link.role == "source_influence":
                source_identity_kind = (
                    "entry_point" if slot.kind == "entry_point" else "integration"
                )
                requirements.append(
                    UpstreamSourceInfluenceRequirement(
                        schema_version="1",
                        requirement_id=_requirement_id(
                            "req.source-influence",
                            step.step_id,
                            link.slot_id,
                            str(link.trust_boundary_slot_id),
                            str(link.target_ingress_slot_id),
                        ),
                        kind="upstream_source_influence",
                        source_slot_id=link.slot_id,
                        source_identity_kind=source_identity_kind,
                        trust_boundary_slot_id=link.trust_boundary_slot_id,
                        target_ingress_slot_id=link.target_ingress_slot_id,
                    )
                )

        # Build a set of postcondition IDs that have explicit outcome links.
        linked_pc_ids = {ol.postcondition_id for ol in step.observable_outcome_links}
        for outcome_link in step.observable_outcome_links:
            requirements.append(
                ObservationRequirement(
                    schema_version="1",
                    requirement_id=_requirement_id(
                        "req.observation",
                        step.step_id,
                        outcome_link.postcondition_id,
                    ),
                    kind="observation",
                    observation=outcome_link.observation,
                    binding_slot_id=outcome_link.binding_slot_id,
                )
            )

        # Security-outcome assertions are derived ONLY from security-relevant
        # postconditions that have an explicit observable outcome link.
        # A security-relevant postcondition without an outcome link does not
        # produce a requirement: the security outcome cannot be asserted
        # without an explicit observation binding.
        for postcondition in step.observable_postconditions:
            if (
                postcondition.security_relevant
                and postcondition.postcondition_id in linked_pc_ids
            ):
                requirements.append(
                    SecurityOutcomeAssertionRequirement(
                        schema_version="1",
                        requirement_id=_requirement_id(
                            "req.security-outcome",
                            step.step_id,
                            postcondition.postcondition_id,
                        ),
                        kind="security_outcome_assertion",
                        source_step_id=step.step_id,
                        postcondition_id=postcondition.postcondition_id,
                    )
                )

    sorted_reqs = tuple(sorted(requirements, key=lambda item: item.requirement_id))
    req_ids = [item.requirement_id for item in sorted_reqs]
    if len(req_ids) != len(set(req_ids)):
        duplicates = sorted({rid for rid in req_ids if req_ids.count(rid) > 1})
        return None, ProjectionIssue(
            code="unsupported_requirement_derivation",
            pattern_id=pattern_id,
            detail=(
                f"derived requirement IDs collide: {duplicates}; "
                "requirement IDs must be unique"
            ),
        )
    return sorted_reqs, None


def _fail_closed_if_no_requirements(
    pattern_id: str,
    requirements: tuple[ExecutionRequirement, ...] | None,
    issue: ProjectionIssue | None,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Absent explicit linkage must fail closed, not produce an empty candidate."""
    if issue is not None:
        return requirements, issue
    if requirements is None or len(requirements) == 0:
        return None, ProjectionIssue(
            code="unsupported_requirement_derivation",
            pattern_id=pattern_id,
            detail=(
                "no explicit resource links or observable outcome links on any "
                "selected step; absent linkage fails closed"
            ),
        )
    return requirements, issue


def _derive_execution_requirements(
    pattern_id: str,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Derive execution requirements, resolving ingress controllability from snapshot.

    Backward-compatible wrapper around :func:`_derive_execution_requirements_core`
    that resolves the ingress controllability from the capability fact snapshot.
    """
    bindings = {item.slot_id: item.resource_ref for item in projection.bindings}
    for step in chain.steps:
        if step.step_id not in set(projection.selected_step_ids):
            continue
        for link in step.resource_links:
            if link.role == "ingress":
                ingress_ref = bindings[link.slot_id]
                if not isinstance(ingress_ref, EntryPointResourceReference):
                    raise TypeError(  # pragma: no cover - contract guard
                        "ingress binding is not an entry point"
                    )
                ingress = snapshot.profile.resolve_entry_point(
                    ingress_ref.entry_point_id
                )
                if ingress is None:
                    raise ValueError("canonical ingress is absent from snapshot")
                return _derive_execution_requirements_core(
                    pattern_id, chain, projection, ingress.effective_controllability
                )
    # No ingress link found — proceed with indirect (will fail closed).
    return _derive_execution_requirements_core(
        pattern_id, chain, projection, "indirect"
    )


def _projected_mappings(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> tuple[ProjectedMapping, ...]:
    mappings = [
        ProjectedMapping(scope="chain", mapping=mapping)
        for mapping in chain.mappings
        if mapping.taxonomy == "ATLAS"
    ]
    selected = set(selected_step_ids)
    for step in chain.steps:
        if step.step_id in selected:
            mappings.extend(
                ProjectedMapping(scope="step", step_id=step.step_id, mapping=mapping)
                for mapping in step.mappings
                if mapping.taxonomy == "ATLAS"
            )
    return tuple(mappings)


def _candidate_v2_id(pattern_id: str, projection: ProjectionSnapshot) -> str:
    chain = projection.source_chain
    bindings = sorted(
        (item.model_dump(mode="json") for item in projection.bindings),
        key=lambda item: (item["slot_id"], _canonical_json(item["resource_ref"])),
    )
    ingress = next(
        item["resource_ref"]
        for item in bindings
        if item["slot_id"] == chain.initial_ingress_slot_id
    )
    identity = {
        "pattern_id": pattern_id,
        "chain_id": chain.chain_id,
        "chain_semantic_revision": chain.semantic_revision,
        "chain_semantic_digest": chain.semantic_digest,
        "projection_digest": projection.projection_digest,
        "taxonomy_context": chain.taxonomy_context.model_dump(mode="json"),
        "canonical_ingress": ingress,
        "bindings": bindings,
    }
    return f"cand:v2:{_digest('scenario-forge:candidate:v2', identity)[:32]}"


def _content_pin(domain: str, value: Any) -> str:
    return _digest(domain, value)


def validate_projected_candidate(
    candidate_dict: dict[str, Any],
    snapshot: CapabilityFactSnapshot,
    authoritative_record: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    *,
    expected_catalog_pin: Digest,
) -> ProjectedCandidate:
    """Qualify serialized candidate integrity against trusted authoritative inputs."""
    snapshot.assert_integrity()
    candidate = ProjectedCandidate.model_validate(candidate_dict)
    authoritative = validate_attack_pattern(authoritative_record, taxonomy_resolver)
    authoritative = AttackPattern.model_validate(
        _normalize_semantic_order(authoritative.model_dump(mode="json"))
    )
    if candidate.projection.source_chain != authoritative.canonical_chain:
        raise ValueError("candidate source chain does not match authoritative pattern")
    if candidate.pattern_id != authoritative.id:
        raise ValueError("candidate pattern id does not match authoritative pattern")
    if candidate.projection.pattern_pin != _pattern_pin(authoritative):
        raise ValueError("candidate pattern pin does not match authoritative pattern")
    if candidate.projection.catalog_pin != expected_catalog_pin:
        raise ValueError("candidate catalog pin does not match trusted catalog")
    prerequisites = authoritative.prerequisite_capabilities
    if not set(prerequisites.min_zones).issubset(snapshot.profile.zones_active):
        raise ValueError("authoritative pattern zones are incompatible with snapshot")
    kc_requires = prerequisites.kc_requires
    profile_kc = set(snapshot.profile.kc_subcodes)
    if kc_requires and (
        not set(kc_requires.all).issubset(profile_kc)
        or (kc_requires.any and not set(kc_requires.any).intersection(profile_kc))
    ):
        raise ValueError("authoritative pattern KC requirements are incompatible")
    if candidate.projection.capability_fact_snapshot_digest != snapshot.snapshot_digest:
        raise ValueError("candidate capability snapshot digest pin does not match")
    validate_projection_snapshot(candidate.projection.model_dump(mode="json"), snapshot)
    for result in candidate.precondition_results:
        for evidence in result.evidence:
            if snapshot.fact(evidence.fact) != evidence:
                raise ValueError(
                    "precondition fact evidence does not match resolver reading"
                )
    ingress = snapshot.profile.resolve_entry_point(
        candidate.canonical_ingress.entry_point_id
    )
    if ingress is None or ingress.effective_controllability != (
        candidate.ingress_controllability
    ):
        raise ValueError("candidate ingress controllability does not match snapshot")
    binding_by_slot = {
        binding.slot_id: binding.resource_ref
        for binding in candidate.projection.bindings
    }
    chain = candidate.projection.source_chain
    for slot in chain.resource_slots:
        allowed = _references_for_kind(
            slot.kind,
            snapshot,
            initial_ingress=slot.slot_id == chain.initial_ingress_slot_id,
            attacker_influence_required=(
                slot.kind == "entry_point" and slot.purpose == "supporting"
            ),
        )
        if binding_by_slot[slot.slot_id] not in allowed:
            raise ValueError("candidate binding is incompatible with snapshot resource")
    requirements, issue = _derive_execution_requirements(
        candidate.pattern_id,
        candidate.projection.source_chain,
        candidate.projection,
        snapshot,
    )
    requirements, issue = _fail_closed_if_no_requirements(
        candidate.pattern_id, requirements, issue
    )
    if issue is not None or requirements != candidate.execution_requirements:
        raise ValueError("candidate execution requirements do not match derivation")
    return candidate


def _pattern_pin(pattern: AttackPattern) -> str:
    prerequisites = pattern.prerequisite_capabilities
    return _content_pin(
        "scenario-forge:authoritative-pattern:v1",
        {
            "id": pattern.id,
            "threat_id": pattern.threat_id,
            "name": pattern.name,
            "description": pattern.description,
            "nist_classification": (
                pattern.nist_classification.model_dump(mode="json")
                if pattern.nist_classification
                else None
            ),
            "min_zones": sorted(set(prerequisites.min_zones)),
            "kc_requires": {
                "all": sorted(set(prerequisites.kc_requires.all)),
                "any": sorted(set(prerequisites.kc_requires.any)),
            }
            if prerequisites.kc_requires
            else None,
            "chain_semantic_digest": pattern.canonical_chain.semantic_digest,
        },
    )


def project_authoritative_candidates(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
    snapshot: CapabilityFactSnapshot,
    *,
    budget: ProjectionBudget | None = None,
    coverage_target_ids: set[str] | None = None,
) -> ProjectionBatch:
    """Qualify, project, bind, and identify authoritative candidate-v2 records.

    Structurally parsed ``AttackPattern`` objects and legacy catalogue records are
    deliberately not accepted: every raw record crosses the merged qualification
    boundary in this call.

    When ``coverage_target_ids`` is provided, the global budget allocation is
    coverage-aware: one feasible candidate per coverage target is reserved
    before binding variants and secondary expansion.  This ensures every
    ingress target receives at least one projected candidate before the
    budget is exhausted.  If ``budget.max_candidates`` is below the number of
    feasible coverage targets, reservation is best-effort and the caller
    should emit a ``selection_limitation`` for uncovered targets.
    """
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, dict)):
        raise TypeError("authoritative projection requires a sequence of raw records")
    budget = budget or ProjectionBudget()
    snapshot.assert_integrity()
    qualified: list[tuple[AttackPattern, str]] = []
    for raw in records:
        if not isinstance(raw, dict) or "canonical_chain" not in raw:
            raise ValueError(
                "authoritative projection requires qualified canonical-chain records; "
                "legacy catalogue records are isolated"
            )
        try:
            pattern = validate_attack_pattern(raw, taxonomy_resolver)
            pattern = AttackPattern.model_validate(
                _normalize_semantic_order(pattern.model_dump(mode="json"))
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"authoritative attack pattern qualification failed: {exc}"
            ) from exc
        qualified.append((pattern, _pattern_pin(pattern)))
    by_pattern: dict[str, tuple[AttackPattern, str]] = {}
    for item in qualified:
        pattern, pattern_pin = item
        previous = by_pattern.get(pattern.id)
        if previous is not None and previous[1] != pattern_pin:
            raise ValueError("conflicting authoritative records share one pattern id")
        by_pattern[pattern.id] = item
    qualified = [by_pattern[key] for key in sorted(by_pattern)]
    catalog_pin = _content_pin(
        "scenario-forge:authoritative-catalog:v1",
        [pattern_pin for _, pattern_pin in qualified],
    )

    candidate_groups: list[tuple[str, int, list[ProjectedCandidate]]] = []
    issues: list[ProjectionIssue] = []
    limitations: list[ProjectionLimitation] = []

    for pattern, pattern_pin in qualified:
        chain = pattern.canonical_chain
        prerequisites = pattern.prerequisite_capabilities
        missing_zones = sorted(
            set(prerequisites.min_zones) - set(snapshot.profile.zones_active)
        )
        kc_requires = prerequisites.kc_requires
        profile_kc = set(snapshot.profile.kc_subcodes)
        missing_all = sorted(set(kc_requires.all) - profile_kc) if kc_requires else []
        any_satisfied = (
            not kc_requires
            or not kc_requires.any
            or bool(set(kc_requires.any) & profile_kc)
        )
        if missing_zones or missing_all or not any_satisfied:
            details = []
            if missing_zones:
                details.append(f"missing zones: {', '.join(missing_zones)}")
            if missing_all:
                details.append(f"missing required KC codes: {', '.join(missing_all)}")
            if not any_satisfied and kc_requires:
                details.append(
                    "requires any KC code from: " + ", ".join(sorted(kc_requires.any))
                )
            issues.append(
                ProjectionIssue(
                    code="incompatible_profile",
                    pattern_id=pattern.id,
                    detail="; ".join(details),
                )
            )
            continue

        condition_results = _evaluate_projection_conditions(pattern, snapshot)
        unknown = [item for item in condition_results if item.result == "unknown"]
        if unknown:
            issues.append(
                ProjectionIssue(
                    code="unresolved_condition",
                    pattern_id=pattern.id,
                    step_id=unknown[0].condition_step_id,
                    detail="one or more authoritative condition facts are unresolved",
                    condition_results=condition_results,
                )
            )
            continue
        result_by_step = {
            item.condition_step_id: item.result for item in condition_results
        }
        selected = tuple(
            step.step_id
            for step in chain.steps
            if step.requirement == "required" or result_by_step[step.step_id] == "true"
        )
        if chain.steps[-1].step_id not in selected or not any(
            step.attacker_controlled and step.step_id in set(selected)
            for step in chain.steps
        ):
            issues.append(
                ProjectionIssue(
                    code="inapplicable_projection",
                    pattern_id=pattern.id,
                    detail=(
                        "condition results omit the terminal outcome or every "
                        "attacker-controlled step"
                    ),
                    condition_results=condition_results,
                )
            )
            continue
        omissions = tuple(
            StepOmission(step_id=step.step_id, reason="condition_false")
            for step in chain.steps
            if step.requirement == "conditional"
            and result_by_step[step.step_id] == "false"
        )
        precondition_results = _evaluate_preconditions(pattern, selected, snapshot)
        unresolved_preconditions = [
            item for item in precondition_results if item.result == "unknown"
        ]
        if unresolved_preconditions:
            issues.append(
                ProjectionIssue(
                    code="unresolved_condition",
                    pattern_id=pattern.id,
                    step_id=unresolved_preconditions[0].step_id,
                    detail="one or more selected-step preconditions are unresolved",
                    condition_results=condition_results,
                    precondition_results=precondition_results,
                )
            )
            continue
        false_preconditions = [
            item for item in precondition_results if item.result == "false"
        ]
        if false_preconditions:
            issues.append(
                ProjectionIssue(
                    code="precondition_not_satisfied",
                    pattern_id=pattern.id,
                    step_id=false_preconditions[0].step_id,
                    detail="one or more selected-step preconditions are false",
                    condition_results=condition_results,
                    precondition_results=precondition_results,
                )
            )
            continue

        option_sets: list[tuple[CanonicalResourceReference, ...]] = []
        missing_slots = []
        for slot in chain.resource_slots:
            options = _references_for_kind(
                slot.kind,
                snapshot,
                initial_ingress=slot.slot_id == chain.initial_ingress_slot_id,
                attacker_influence_required=(
                    slot.kind == "entry_point" and slot.purpose == "supporting"
                ),
            )
            option_sets.append(options)
            if not options:
                missing_slots.append(slot)
        if missing_slots:
            issues.extend(
                ProjectionIssue(
                    code="missing_compatible_resource",
                    pattern_id=pattern.id,
                    slot_id=slot.slot_id,
                    detail=f"no compatible canonical {slot.kind} resource for slot",
                )
                for slot in missing_slots
            )
            continue

        ingress_index = next(
            index
            for index, slot in enumerate(chain.resource_slots)
            if slot.slot_id == chain.initial_ingress_slot_id
        )
        direct_ingress_options = tuple(
            option
            for option in option_sets[ingress_index]
            if isinstance(option, EntryPointResourceReference)
            and snapshot.profile.resolve_entry_point(
                option.entry_point_id
            ).effective_controllability
            == "direct"
        )
        # A source-influence chain activates through an explicit
        # source-boundary → canonical-ingress edge, not direct ingress
        # control, so indirect ingress entry points are admissible.  A
        # direct-ingress chain still requires a directly controllable
        # ingress; indirect ingress there fails closed.
        # Activation is checked only over SELECTED steps: a conditional
        # activation step may be omitted, and the chain must still have
        # an activatable mechanism among the remaining selected steps.
        selected_set = set(selected)
        has_source_influence_activation = any(
            link.role == "source_influence"
            and link.target_ingress_slot_id == chain.initial_ingress_slot_id
            for step in chain.steps
            if step.step_id in selected_set
            for link in step.resource_links
        )
        has_direct_ingress_activation = any(
            link.role == "ingress" and link.slot_id == chain.initial_ingress_slot_id
            for step in chain.steps
            if step.step_id in selected_set
            for link in step.resource_links
        )
        if not has_source_influence_activation and not has_direct_ingress_activation:
            issues.append(
                ProjectionIssue(
                    code="unsupported_requirement_derivation",
                    pattern_id=pattern.id,
                    detail=(
                        "no activation mechanism (ingress or source_influence) "
                        "among selected steps"
                    ),
                )
            )
            continue
        if has_source_influence_activation and has_direct_ingress_activation:
            issues.append(
                ProjectionIssue(
                    code="unsupported_requirement_derivation",
                    pattern_id=pattern.id,
                    detail=(
                        "contradictory activation: selected steps contain both "
                        "direct ingress and source_influence links to the "
                        "initial ingress"
                    ),
                )
            )
            continue
        if has_source_influence_activation:
            if not option_sets[ingress_index]:
                continue
        else:
            if len(direct_ingress_options) != len(option_sets[ingress_index]):
                issues.append(
                    ProjectionIssue(
                        code="unsupported_requirement_derivation",
                        pattern_id=pattern.id,
                        detail=(
                            "indirect ingress requires explicit upstream-source and "
                            "trust-boundary linkage"
                        ),
                    )
                )
            if not direct_ingress_options:
                continue
            option_sets[ingress_index] = direct_ingress_options

        total_bindings = prod(len(options) for options in option_sets)
        generated_for_pattern: list[ProjectedCandidate] = []
        combinations = _coverage_first_combinations(
            tuple(option_sets), min(total_bindings, budget.max_candidates)
        )
        for resources in combinations:
            bindings = tuple(
                ResourceBinding(slot_id=slot.slot_id, resource_ref=resource)
                for slot, resource in zip(chain.resource_slots, resources, strict=True)
            )
            projection_data = {
                "schema_version": "1",
                "source_chain": chain.model_dump(mode="json"),
                "selected_step_ids": selected,
                "condition_results": [
                    item.model_dump(mode="json") for item in condition_results
                ],
                "omissions": [item.model_dump(mode="json") for item in omissions],
                "bindings": [item.model_dump(mode="json") for item in bindings],
                "catalog_pin": catalog_pin,
                "pattern_pin": pattern_pin,
                "capability_fact_snapshot_digest": snapshot.snapshot_digest,
                "projection_digest": "0" * 64,
            }
            projection_data["projection_digest"] = compute_projection_digest(
                projection_data
            )
            projection = validate_projection_snapshot(projection_data, snapshot)
            requirements, issue = _derive_execution_requirements(
                pattern.id, chain, projection, snapshot
            )
            requirements, issue = _fail_closed_if_no_requirements(
                pattern.id, requirements, issue
            )
            if issue is not None:
                issues.append(issue)
                continue
            assert requirements is not None
            requirements_digest = compute_execution_requirements_digest(requirements)
            ingress_ref = next(
                item.resource_ref
                for item in bindings
                if item.slot_id == chain.initial_ingress_slot_id
            )
            assert isinstance(ingress_ref, EntryPointResourceReference)
            ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
            assert ingress is not None
            selected_steps = [
                step for step in chain.steps if step.step_id in set(selected)
            ]
            generated_for_pattern.append(
                ProjectedCandidate(
                    candidate_id=_candidate_v2_id(pattern.id, projection),
                    pattern_id=pattern.id,
                    chain_id=chain.chain_id,
                    chain_semantic_revision=chain.semantic_revision,
                    chain_semantic_digest=chain.semantic_digest,
                    projection=projection,
                    canonical_ingress=ingress_ref,
                    ingress_controllability=ingress.effective_controllability,
                    projected_mappings=_projected_mappings(chain, selected),
                    precondition_results=precondition_results,
                    execution_requirements=requirements,
                    requirement_derivation_version="1",
                    execution_requirements_digest=requirements_digest,
                    complexity_inputs=CandidateComplexityInputs(
                        selected_step_count=len(selected_steps),
                        attacker_controlled_step_count=sum(
                            step.attacker_controlled for step in selected_steps
                        ),
                        boundary_crossing_step_count=sum(
                            step.boundary_position == "crossing"
                            for step in selected_steps
                        ),
                        selected_conditional_step_count=sum(
                            step.requirement == "conditional" for step in selected_steps
                        ),
                        concrete_binding_count=len(bindings),
                        execution_requirement_count=len(requirements),
                    ),
                )
            )
        candidate_groups.append((pattern.id, total_bindings, generated_for_pattern))

    # Allocate the global budget only across feasible candidates.
    #
    # Coverage-aware reservation (cmps.4 blocker 5): when coverage_target_ids
    # is provided, reserve one feasible candidate per coverage target before
    # round-robin variant expansion.  This ensures every ingress target
    # receives at least one projected candidate before the budget is
    # exhausted on binding variants.
    by_identity: dict[str, ProjectedCandidate] = {}
    emitted_by_group = [0] * len(candidate_groups)

    if coverage_target_ids:
        remaining_targets = set(coverage_target_ids)
        for group_index, (_, _, group) in enumerate(candidate_groups):
            if not remaining_targets or len(by_identity) >= budget.max_candidates:
                break
            for candidate in group:
                ep_id = candidate.canonical_ingress.entry_point_id
                if ep_id not in remaining_targets:
                    continue
                previous = by_identity.get(candidate.candidate_id)
                if previous is not None and previous != candidate:
                    raise ValueError("candidate-v2 identity collision")
                if previous is None:
                    if len(by_identity) >= budget.max_candidates:
                        break
                    by_identity[candidate.candidate_id] = candidate
                    emitted_by_group[group_index] += 1
                remaining_targets.discard(ep_id)
                break  # one per target per group
            if not remaining_targets or len(by_identity) >= budget.max_candidates:
                break
        unreserved_targets = tuple(sorted(remaining_targets))
    else:
        unreserved_targets = ()

    # Round-robin admission gives every feasible pattern a stable baseline
    # before taking a second variation, and identity collisions never consume
    # capacity.
    offset = 0
    while len(by_identity) < budget.max_candidates:
        made_progress = False
        for group_index, (_, _, group) in enumerate(candidate_groups):
            if offset >= len(group):
                continue
            made_progress = True
            candidate = group[offset]
            previous = by_identity.get(candidate.candidate_id)
            if previous is not None and previous != candidate:
                raise ValueError("candidate-v2 identity collision")
            if previous is None:
                by_identity[candidate.candidate_id] = candidate
                emitted_by_group[group_index] += 1
                if len(by_identity) == budget.max_candidates:
                    break
        if not made_progress:
            break
        offset += 1
    for group_index, (pattern_id, total_bindings, group) in enumerate(candidate_groups):
        emitted = emitted_by_group[group_index]
        if group and (emitted < len(group) or len(group) < total_bindings):
            limitations.append(
                ProjectionLimitation(
                    code="candidate_budget_exhausted",
                    pattern_id=pattern_id,
                    total_compatible_bindings=total_bindings,
                    emitted_bindings=emitted,
                )
            )
    unique_issues = {
        _canonical_json(issue.model_dump(mode="json")): issue for issue in issues
    }
    return ProjectionBatch(
        capability_fact_snapshot_digest=snapshot.snapshot_digest,
        candidates=tuple(by_identity[key] for key in sorted(by_identity)),
        infeasibilities=tuple(
            sorted(
                unique_issues.values(),
                key=lambda item: (
                    item.pattern_id,
                    item.code,
                    item.step_id or "",
                    item.slot_id or "",
                ),
            )
        ),
        limitations=tuple(
            sorted(limitations, key=lambda item: (item.pattern_id, item.code))
        ),
        unreserved_coverage_targets=unreserved_targets,
    )
