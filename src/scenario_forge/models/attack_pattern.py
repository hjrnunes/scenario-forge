"""Authoritative and legacy attack-pattern contracts.

The authoritative contract is intentionally independent from the YAML catalogue.
Catalogue records must be parsed explicitly with :class:`LegacyAttackPatternRecord`.
Generated JSON Schema describes the transport structure; Pydantic validators remain
authoritative for cross-field semantics, digests, and injected taxonomy resolution.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Annotated, Any, Literal, Protocol, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

MAX_CONDITION_DEPTH = 4
MAX_CONDITION_NODES = 32
MAX_CONDITION_OPERANDS = 16
MAX_MEMBERSHIP_VALUES = 32
MAX_PROPERTY_PATH_SEGMENTS = 4

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
]
Scalar: TypeAlias = StrictStr | StrictInt | StrictBool


class ContractModel(BaseModel):
    """Common closed, immutable configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceLink(ContractModel):
    source: str = Field(min_length=1)
    type: Literal["direct_demonstration", "variant", "enrichment"]


class CapabilityRequirements(ContractModel):
    all: tuple[str, ...] = ()
    any: tuple[str, ...] = ()


class PrerequisiteCapabilities(ContractModel):
    min_zones: tuple[str, ...]
    kc_requires: CapabilityRequirements | None = None


class NistClassification(ContractModel):
    attacker_goal: str
    attacker_knowledge: str
    learning_stage: str
    attack_class: str | None = None


class LegacyKillChainStep(ContractModel):
    step: str
    tactic: str = Field(pattern=r"^AML\.TA\d{4}$")
    techniques: tuple[Annotated[str, Field(pattern=r"^AML\.T")], ...] = Field(
        min_length=1
    )
    abstract_action: str


class LegacyPrerequisiteCapabilities(ContractModel):
    min_zones: tuple[str, ...]
    kc_requires: dict[str, tuple[str, ...]] | None = None


class LegacyAttackPatternRecord(ContractModel):
    id: str
    threat_id: str
    name: str
    description: str
    nist_classification: NistClassification | None = None
    prerequisite_capabilities: LegacyPrerequisiteCapabilities
    kill_chain: tuple[LegacyKillChainStep, ...] | None = None
    evidence: tuple[EvidenceLink, ...] | None = None


class TaxonomyPin(ContractModel):
    release: str = Field(min_length=1)
    digest: Digest


class TaxonomyContext(ContractModel):
    atlas: TaxonomyPin
    laaf: TaxonomyPin
    mapping_set_digest: Digest


class TaxonomyResolver(Protocol):
    """Optional no-I/O resolver supplied by the caller."""

    @property
    def taxonomy_context(self) -> TaxonomyContext: ...

    def contains(self, taxonomy: Literal["ATLAS", "LAAF"], identifier: str) -> bool: ...


class TypedReference(ContractModel):
    ref_id: Identifier
    value_type: Literal["string", "integer", "boolean", "object", "bytes"]


class ArtifactReference(TypedReference):
    kind: Literal["artifact"]


class StateReference(TypedReference):
    kind: Literal["state"]


class EffectReference(TypedReference):
    kind: Literal["effect"]


OutputReference = Annotated[
    ArtifactReference | StateReference | EffectReference, Field(discriminator="kind")
]
InputReference = Annotated[
    ArtifactReference | StateReference, Field(discriminator="kind")
]


class AuthoritativeFactReference(ContractModel):
    """Reference to a pre-existing authoritative fact (never a generated artifact)."""

    namespace: Literal["system", "profile", "catalog", "runtime_state"]
    fact_id: Identifier
    value_type: Literal["string", "integer", "boolean"]
    property_path: tuple[Identifier, ...] = Field(max_length=MAX_PROPERTY_PATH_SEGMENTS)


def _validate_fact_scalar(fact: AuthoritativeFactReference, value: Scalar) -> None:
    expected = {"string": str, "integer": int, "boolean": bool}[fact.value_type]
    if type(value) is not expected:
        raise ValueError(f"value must exactly match fact value_type {fact.value_type}")


class EqualityCondition(ContractModel):
    op: Literal["equality"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    value: Scalar

    @model_validator(mode="after")
    def matching_type(self) -> EqualityCondition:
        _validate_fact_scalar(self.fact, self.value)
        return self


class MembershipCondition(ContractModel):
    op: Literal["membership"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    values: tuple[Scalar, ...] = Field(min_length=1, max_length=MAX_MEMBERSHIP_VALUES)

    @model_validator(mode="after")
    def unique_values(self) -> MembershipCondition:
        for value in self.values:
            _validate_fact_scalar(self.fact, value)
        if len({_canonical_json(v) for v in self.values}) != len(self.values):
            raise ValueError("membership values must be unique")
        return self


class ExistenceCondition(ContractModel):
    op: Literal["existence"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    exists: StrictBool


class PropertyMatchCondition(ContractModel):
    op: Literal["property_match"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    value: Scalar

    @model_validator(mode="after")
    def matching_type_and_path(self) -> PropertyMatchCondition:
        if not self.fact.property_path:
            raise ValueError("property_match requires a nonempty property path")
        _validate_fact_scalar(self.fact, self.value)
        return self


class AllCondition(ContractModel):
    op: Literal["all"]
    schema_version: Literal["1"]
    operands: tuple[Condition, ...] = Field(
        min_length=2, max_length=MAX_CONDITION_OPERANDS
    )

    @model_validator(mode="after")
    def bounded(self) -> AllCondition:
        _check_condition(self)
        return self


class AnyCondition(ContractModel):
    op: Literal["any"]
    schema_version: Literal["1"]
    operands: tuple[Condition, ...] = Field(
        min_length=2, max_length=MAX_CONDITION_OPERANDS
    )

    @model_validator(mode="after")
    def bounded(self) -> AnyCondition:
        _check_condition(self)
        return self


class NotCondition(ContractModel):
    op: Literal["not"]
    schema_version: Literal["1"]
    operand: Condition

    @model_validator(mode="after")
    def bounded(self) -> NotCondition:
        _check_condition(self)
        return self


Condition: TypeAlias = Annotated[
    EqualityCondition
    | MembershipCondition
    | ExistenceCondition
    | PropertyMatchCondition
    | AllCondition
    | AnyCondition
    | NotCondition,
    Field(discriminator="op"),
]


def _check_condition(condition: Condition) -> None:
    count = 0

    def walk(node: Condition, depth: int) -> None:
        nonlocal count
        count += 1
        if depth > MAX_CONDITION_DEPTH or count > MAX_CONDITION_NODES:
            raise ValueError("condition exceeds structural limits")
        children = (
            node.operands if isinstance(node, (AllCondition, AnyCondition)) else ()
        )
        if isinstance(node, NotCondition):
            children = (node.operand,)
        if children and len(
            {_canonical_json(c.model_dump(mode="json")) for c in children}
        ) != len(children):
            raise ValueError("duplicate condition operands")
        for child in children:
            walk(child, depth + 1)

    walk(condition, 1)


class ConditionEvaluationResult(ContractModel):
    condition_step_id: Identifier
    result: Literal["true", "false", "unknown"]
    evidence_refs: tuple[OutputReference, ...] = Field(min_length=1)


class ProvenanceReference(ContractModel):
    reference_type: Literal["catalog", "publication", "observation", "design_record"]
    reference_id: str = Field(min_length=1)


class StepProvenance(ContractModel):
    tier: Literal["observed", "variant", "inferred", "designed"]
    references: tuple[ProvenanceReference, ...] = Field(min_length=1)
    confidence: StrictInt = Field(ge=0, le=100)
    adaptation_rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def unique_references(self) -> StepProvenance:
        keys = [
            (reference.reference_type, reference.reference_id)
            for reference in self.references
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("provenance references must be unique")
        return self


class ExactMapping(ContractModel):
    decision: Literal["exact"]
    taxonomy: Literal["ATLAS", "LAAF"]
    ids: tuple[Annotated[str, Field(min_length=1)], ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_ids(self) -> ExactMapping:
        if len(set(self.ids)) != len(self.ids):
            raise ValueError("exact mapping ids must be unique")
        return self


class NotApplicableMapping(ContractModel):
    decision: Literal["not_applicable"]
    taxonomy: Literal["ATLAS", "LAAF"]


class UnmappedMapping(ContractModel):
    decision: Literal["unmapped"]
    taxonomy: Literal["ATLAS", "LAAF"]
    rationale: str = Field(min_length=1)


MappingDecision: TypeAlias = Annotated[
    ExactMapping | NotApplicableMapping | UnmappedMapping,
    Field(discriminator="decision"),
]
ChainMappingDecision: TypeAlias = Annotated[
    ExactMapping | UnmappedMapping,
    Field(discriminator="decision"),
]


class StepPrecondition(ContractModel):
    condition_id: Identifier
    condition: Condition

    @model_validator(mode="after")
    def bounded(self) -> StepPrecondition:
        _check_condition(self.condition)
        return self


class ObservablePostcondition(ContractModel):
    postcondition_id: Identifier
    description: str = Field(min_length=1)
    security_relevant: StrictBool
    terminal: StrictBool


class ExecutionRequirement(ContractModel):
    schema_version: Literal["1"]
    requirement_id: Identifier
    kind: Literal[
        "network_access",
        "credential",
        "human_action",
        "compute",
        "storage",
        "capability",
    ]


class CanonicalChainStep(ContractModel):
    step_id: Identifier
    requirement: Literal["required", "conditional"]
    condition: Condition | None
    executor_role: Literal["attacker", "system", "operator", "external_service"]
    boundary_position: Literal["outside", "crossing", "inside"]
    action_kind: Literal[
        "prepare", "deliver", "invoke", "transform", "persist", "observe", "impact"
    ]
    consumed: tuple[InputReference, ...]
    produced: tuple[OutputReference, ...] = Field(min_length=1)
    preconditions: tuple[StepPrecondition, ...]
    observable_postconditions: tuple[ObservablePostcondition, ...] = Field(min_length=1)
    execution_requirements: tuple[ExecutionRequirement, ...]
    order: StrictInt = Field(gt=0)
    attacker_controlled: StrictBool
    provenance: StepProvenance
    mappings: tuple[MappingDecision, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def semantics(self) -> CanonicalChainStep:
        if (self.requirement == "conditional") != (self.condition is not None):
            raise ValueError(
                "conditional steps require a condition; required steps forbid it"
            )
        if self.condition is not None:
            _check_condition(self.condition)
        for collection, label, attribute in (
            (self.consumed, "consumed references", "ref_id"),
            (self.produced, "produced references", "ref_id"),
            (self.preconditions, "preconditions", "condition_id"),
            (
                self.observable_postconditions,
                "observable postconditions",
                "postcondition_id",
            ),
            (self.execution_requirements, "execution requirements", "requirement_id"),
        ):
            ids = [getattr(item, attribute) for item in collection]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate ids in {label}")
        taxonomies = [mapping.taxonomy for mapping in self.mappings]
        if len(set(taxonomies)) != len(taxonomies):
            raise ValueError("duplicate taxonomy decisions in step scope")
        if (
            any(isinstance(m, NotApplicableMapping) for m in self.mappings)
            and self.attacker_controlled
        ):
            raise ValueError(
                "not_applicable is only valid for non-attacker transitions"
            )
        return self


class ResourceSlot(ContractModel):
    slot_id: Identifier
    kind: Literal["artifact", "state", "endpoint", "identity", "service"]
    purpose: Literal["initial_ingress", "intermediate", "target", "supporting"]


class CanonicalAttackChain(ContractModel):
    schema_version: Literal["v1"]
    pattern_id: Identifier
    chain_id: Identifier
    semantic_revision: StrictInt = Field(gt=0)
    semantic_digest: Digest
    taxonomy_context: TaxonomyContext
    mappings: tuple[ChainMappingDecision, ...] = Field(min_length=1)
    steps: tuple[CanonicalChainStep, ...] = Field(min_length=1)
    earliest_attacker_controlled_step_id: Identifier
    resource_slots: tuple[ResourceSlot, ...] = Field(min_length=1)
    initial_ingress_slot_id: Identifier

    @model_validator(mode="after")
    def semantics(self) -> CanonicalAttackChain:
        taxonomies = [mapping.taxonomy for mapping in self.mappings]
        if len(taxonomies) != len(set(taxonomies)):
            raise ValueError("duplicate taxonomy decisions in chain scope")
        if not any(isinstance(mapping, ExactMapping) for mapping in self.mappings):
            raise ValueError("chain requires an exact ATLAS or LAAF mapping")
        if len({s.step_id for s in self.steps}) != len(self.steps):
            raise ValueError("step ids must be unique")
        if [s.order for s in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError("steps must be in total order 1..N")
        attacker = [s for s in self.steps if s.attacker_controlled]
        if (
            not attacker
            or self.earliest_attacker_controlled_step_id != attacker[0].step_id
        ):
            raise ValueError("earliest attacker-controlled step is incorrect")
        for step in self.steps[:-1]:
            if any(
                out.security_relevant and out.terminal
                for out in step.observable_postconditions
            ):
                raise ValueError(
                    "terminal security outcomes are only valid on the final step"
                )
        if not any(
            out.security_relevant and out.terminal
            for out in self.steps[-1].observable_postconditions
        ):
            raise ValueError(
                "final step requires an observable security-relevant terminal outcome"
            )
        if not any(
            any(isinstance(m, ExactMapping) for m in s.mappings) for s in attacker
        ):
            raise ValueError(
                "an attacker-controlled step requires an exact taxonomy mapping"
            )
        if len({slot.slot_id for slot in self.resource_slots}) != len(
            self.resource_slots
        ):
            raise ValueError("resource slot ids must be unique")
        ingress = [
            slot for slot in self.resource_slots if slot.purpose == "initial_ingress"
        ]
        if len(ingress) != 1 or ingress[0].slot_id != self.initial_ingress_slot_id:
            raise ValueError("exactly one referenced initial ingress slot is required")
        if self.semantic_digest != compute_chain_semantic_digest(self):
            raise ValueError("semantic_digest does not match chain semantics")
        return self


class AttackPattern(ContractModel):
    id: str
    threat_id: str
    name: str
    description: str
    nist_classification: NistClassification | None = None
    prerequisite_capabilities: PrerequisiteCapabilities
    canonical_chain: CanonicalAttackChain

    @model_validator(mode="after")
    def bind_chain(self) -> AttackPattern:
        if self.canonical_chain.pattern_id != self.id:
            raise ValueError("canonical chain pattern_id must match pattern id")
        return self


class CanonicalResourceReference(ContractModel):
    canonical_id: Identifier
    kind: Literal["artifact", "state", "endpoint", "identity", "service"]


class ResourceBinding(ContractModel):
    slot_id: Identifier
    resource_ref: CanonicalResourceReference


class StepOmission(ContractModel):
    step_id: Identifier
    reason: Literal["condition_false", "condition_unknown", "not_selected"]
    condition_step_id: Identifier | None


class ProjectionSnapshot(ContractModel):
    schema_version: Literal["1"]
    catalog_pin: Digest
    pattern_id: str
    pattern_pin: Digest
    chain_id: Identifier
    chain_semantic_digest: Digest
    semantic_revision: StrictInt = Field(gt=0)
    all_step_ids: tuple[Identifier, ...] = Field(min_length=1)
    taxonomy_context: TaxonomyContext
    selected_steps: tuple[CanonicalChainStep, ...]
    condition_results: tuple[ConditionEvaluationResult, ...]
    omissions: tuple[StepOmission, ...]
    bindings: tuple[ResourceBinding, ...]
    resource_slots: tuple[ResourceSlot, ...] = Field(min_length=1)
    initial_ingress_slot_id: Identifier
    initial_ingress_reference: CanonicalResourceReference
    projection_digest: Digest

    @model_validator(mode="after")
    def semantics(self) -> ProjectionSnapshot:
        selected = [s.step_id for s in self.selected_steps]
        omitted = [o.step_id for o in self.omissions]
        if len(set(selected)) != len(selected) or len(set(omitted)) != len(omitted):
            raise ValueError("selected and omitted step ids must be unique")
        if set(selected) & set(omitted) or set(selected) | set(omitted) != set(
            self.all_step_ids
        ):
            raise ValueError(
                "selected and omitted steps must exactly partition all_step_ids"
            )
        orders = [s.order for s in self.selected_steps]
        if len(orders) != len(set(orders)) or orders != sorted(orders):
            raise ValueError("selected step order must increase")
        if any(order > len(self.all_step_ids) for order in orders):
            raise ValueError("selected step order exceeds the source chain")
        if len(self.all_step_ids) != len(set(self.all_step_ids)):
            raise ValueError("all_step_ids must be unique")
        if any(
            self.all_step_ids[step.order - 1] != step.step_id
            for step in self.selected_steps
        ):
            raise ValueError("selected steps must retain source chain order")
        if len({r.condition_step_id for r in self.condition_results}) != len(
            self.condition_results
        ):
            raise ValueError("condition result step ids must be unique")
        if len({b.slot_id for b in self.bindings}) != len(self.bindings):
            raise ValueError("slot bindings must be unique")
        slots = {slot.slot_id: slot for slot in self.resource_slots}
        if len(slots) != len(self.resource_slots):
            raise ValueError("projection resource slot ids must be unique")
        for binding in self.bindings:
            slot = slots.get(binding.slot_id)
            if slot is None:
                raise ValueError("binding references an absent resource slot")
            if binding.resource_ref.kind != slot.kind:
                raise ValueError("binding resource kind must match its slot")
        ingress = [
            b for b in self.bindings if b.slot_id == self.initial_ingress_slot_id
        ]
        if (
            len(ingress) != 1
            or ingress[0].resource_ref != self.initial_ingress_reference
        ):
            raise ValueError("ingress requires exactly one coherent binding")
        ingress_slots = [
            s for s in self.resource_slots if s.purpose == "initial_ingress"
        ]
        if (
            len(ingress_slots) != 1
            or ingress_slots[0].slot_id != self.initial_ingress_slot_id
        ):
            raise ValueError("projection requires exactly one referenced ingress slot")
        results = {r.condition_step_id: r.result for r in self.condition_results}
        if not set(results).issubset(self.all_step_ids):
            raise ValueError("condition result references an absent chain step")
        selected_by_id = {step.step_id: step for step in self.selected_steps}
        for step_id, result in results.items():
            selected_step = selected_by_id.get(step_id)
            if selected_step is not None and (
                selected_step.requirement != "conditional" or result != "true"
            ):
                raise ValueError(
                    "selected condition results require a true conditional step"
                )
        selected_conditionals = {
            step.step_id
            for step in self.selected_steps
            if step.requirement == "conditional"
        }
        if not selected_conditionals.issubset(results):
            raise ValueError("selected conditional steps require condition results")
        for omission in self.omissions:
            if omission.reason == "not_selected":
                if (
                    omission.condition_step_id is not None
                    or omission.step_id in results
                ):
                    raise ValueError("not_selected forbids a condition result")
            else:
                expected = (
                    "false" if omission.reason == "condition_false" else "unknown"
                )
                if (
                    results.get(omission.step_id) != expected
                    or omission.condition_step_id != omission.step_id
                ):
                    raise ValueError(
                        "conditional omission requires a coherent condition result"
                    )
        if self.projection_digest != compute_projection_digest(self):
            raise ValueError("projection_digest does not match projection semantics")
        return self


class ExecutionRequirementSummary(ContractModel):
    schema_version: Literal["1"]
    chain_id: Identifier
    chain_semantic_digest: Digest
    contributing_step_ids: tuple[Identifier, ...] = Field(min_length=1)
    requirements: tuple[ExecutionRequirement, ...]

    @model_validator(mode="after")
    def unique(self) -> ExecutionRequirementSummary:
        if len(set(self.contributing_step_ids)) != len(self.contributing_step_ids):
            raise ValueError("contributing step ids must be unique")
        if len({r.requirement_id for r in self.requirements}) != len(self.requirements):
            raise ValueError("execution requirement ids must be unique")
        return self


_UNORDERED_FIELDS = {
    "consumed",
    "produced",
    "preconditions",
    "observable_postconditions",
    "references",
    "mappings",
    "ids",
    "resource_slots",
    "values",
    "evidence_refs",
    "condition_results",
    "omissions",
    "bindings",
    "requirements",
    "execution_requirements",
    "contributing_step_ids",
    "operands",
    "min_zones",
}


def _normalize(value: Any, field_name: str | None = None) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normalize(v, str(k))
            for k, v in value.items()
        }
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (tuple, list)):
        items = [_normalize(item) for item in value]
        if field_name in _UNORDERED_FIELDS:
            items.sort(key=lambda item: _canonical_json(item).encode())
        return items
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _semantic_digest(value: Any, digest_field: str, domain: str) -> str:
    payload = (
        value.model_dump(mode="python") if isinstance(value, BaseModel) else dict(value)
    )
    payload.pop(digest_field, None)
    encoded = domain.encode() + b"\0" + _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_chain_semantic_digest(chain: CanonicalAttackChain | dict[str, Any]) -> str:
    return _semantic_digest(
        chain, "semantic_digest", "scenario-forge:canonical-chain:v1"
    )


def compute_projection_digest(snapshot: ProjectionSnapshot | dict[str, Any]) -> str:
    return _semantic_digest(
        snapshot, "projection_digest", "scenario-forge:projection:v1"
    )


def validate_legacy_attack_pattern(
    pattern_dict: dict[str, Any],
) -> LegacyAttackPatternRecord:
    return LegacyAttackPatternRecord.model_validate(pattern_dict)


def validate_attack_pattern(
    pattern_dict: dict[str, Any], resolver: TaxonomyResolver | None = None
) -> AttackPattern:
    pattern = AttackPattern.model_validate(pattern_dict)
    if resolver is not None:
        if resolver.taxonomy_context != pattern.canonical_chain.taxonomy_context:
            raise ValueError("taxonomy resolver pins do not match canonical chain pins")
        mapping_scopes = [
            pattern.canonical_chain.mappings,
            *(s.mappings for s in pattern.canonical_chain.steps),
        ]
        for mappings in mapping_scopes:
            for mapping in mappings:
                if isinstance(mapping, ExactMapping):
                    for identifier in mapping.ids:
                        if not resolver.contains(mapping.taxonomy, identifier):
                            raise ValueError(
                                f"unknown {mapping.taxonomy} id: {identifier}"
                            )
    return pattern


AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NotCondition.model_rebuild()
