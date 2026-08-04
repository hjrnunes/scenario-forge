"""Focused tests for the authoritative attack-pattern v1 contract."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.models.attack_pattern import (
    MAX_CONDITION_DEPTH,
    MAX_CONDITION_NODES,
    MAX_CONDITION_OPERANDS,
    MAX_MEMBERSHIP_VALUES,
    AttackPattern,
    CanonicalAttackChain,
    Condition,
    ExecutionRequirement,
    ExecutionRequirementSummary,
    LegacyAttackPatternRecord,
    ProjectionSnapshot,
    compute_chain_semantic_digest,
    compute_projection_digest,
    validate_attack_pattern,
    validate_legacy_attack_pattern,
)

ZERO = "0" * 64
ONE = "1" * 64
CHAIN_GOLDEN = "b84615705e27348b7efd64945dfcdb944053c0c9634d2a65f80ea2af52d4ee7f"
PROJECTION_GOLDEN = "2d2f47e4168f46663f6a965eaddd62fc8739f961c6b670d0b5294485a97c8f94"
CONDITION_ADAPTER = TypeAdapter(Condition)


def fact(
    value_type: str = "string", *, path: list[str] | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "namespace": "profile",
        "fact_id": "mode",
        "value_type": value_type,
        "property_path": [],
    }
    if path is not None:
        result["property_path"] = path
    return result


def equality(value: Any = "active") -> dict[str, Any]:
    return {"op": "equality", "schema_version": "1", "fact": fact(), "value": value}


def step(step_id: str, order: int, *, attacker: bool) -> dict[str, Any]:
    final = order == 2
    return {
        "step_id": step_id,
        "requirement": "required",
        "condition": None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "deliver" if attacker else "impact",
        "consumed": []
        if attacker
        else [{"kind": "artifact", "ref_id": "artifact.1", "value_type": "object"}],
        "produced": (
            [{"kind": "artifact", "ref_id": "artifact.1", "value_type": "object"}]
            if attacker
            else [{"kind": "effect", "ref_id": "effect.1", "value_type": "boolean"}]
        ),
        "preconditions": [
            {"condition_id": f"pre.{order}", "condition": equality("active")}
        ],
        "observable_postconditions": [
            {
                "postcondition_id": f"post.{order}",
                "description": "security impact observed"
                if final
                else "input accepted",
                "security_relevant": final,
                "terminal": final,
            }
        ],
        "execution_requirements": [
            {
                "schema_version": "1",
                "requirement_id": f"req.{order}",
                "kind": "network_access" if attacker else "compute",
            }
        ],
        "order": order,
        "attacker_controlled": attacker,
        "provenance": {
            "tier": "observed" if attacker else "inferred",
            "references": [
                {"reference_type": "catalog", "reference_id": f"case-{order}"},
                {
                    "reference_type": "design_record",
                    "reference_id": f"design-{order}",
                },
            ],
            "confidence": 90 if attacker else 70,
            "adaptation_rationale": "Directly represented.",
        },
        "mappings": (
            [
                {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]},
                {
                    "decision": "unmapped",
                    "taxonomy": "LAAF",
                    "rationale": "No exact counterpart.",
                },
            ]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "LAAF"}]
        ),
    }


def chain_data() -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            "laaf": {"release": "v1", "digest": ONE},
            "mapping_set_digest": ZERO,
        },
        "mappings": [
            {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]},
            {
                "decision": "unmapped",
                "taxonomy": "LAAF",
                "rationale": "No exact counterpart.",
            },
        ],
        "steps": [step("step.1", 1, attacker=True), step("step.2", 2, attacker=False)],
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "endpoint", "purpose": "initial_ingress"},
            {"slot_id": "target", "kind": "service", "purpose": "target"},
        ],
        "initial_ingress_slot_id": "ingress",
    }
    return resign_chain(chain)


def pattern_data() -> dict[str, Any]:
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Authoritative pattern",
        "description": "A canonical pattern.",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain_data(),
    }


def resign_chain(chain: dict[str, Any]) -> dict[str, Any]:
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    return chain


def invalid_chain(mutator: Any, match: str | None = None) -> None:
    raw = chain_data()
    mutator(raw)
    resign_chain(raw)
    with pytest.raises(ValidationError, match=match):
        CanonicalAttackChain.model_validate(raw)


def projection_data() -> dict[str, Any]:
    chain = CanonicalAttackChain.model_validate(chain_data())
    raw = {
        "schema_version": "1",
        "catalog_pin": ONE,
        "pattern_id": chain.pattern_id,
        "pattern_pin": ZERO,
        "chain_id": chain.chain_id,
        "chain_semantic_digest": chain.semantic_digest,
        "semantic_revision": chain.semantic_revision,
        "all_step_ids": [s.step_id for s in chain.steps],
        "taxonomy_context": chain.taxonomy_context.model_dump(mode="json"),
        "selected_steps": [s.model_dump(mode="json") for s in chain.steps],
        "condition_results": [],
        "omissions": [],
        "bindings": [
            {
                "slot_id": "ingress",
                "resource_ref": {"canonical_id": "endpoint.main", "kind": "endpoint"},
            },
            {
                "slot_id": "target",
                "resource_ref": {"canonical_id": "service.target", "kind": "service"},
            },
        ],
        "resource_slots": [s.model_dump(mode="json") for s in chain.resource_slots],
        "initial_ingress_slot_id": chain.initial_ingress_slot_id,
        "initial_ingress_reference": {
            "canonical_id": "endpoint.main",
            "kind": "endpoint",
        },
        "projection_digest": ZERO,
    }
    return resign_projection(raw)


def resign_projection(raw: dict[str, Any]) -> dict[str, Any]:
    raw["projection_digest"] = compute_projection_digest(raw)
    return raw


def test_authoritative_construction_roundtrip_tuples_and_nested_frozen() -> None:
    pattern = AttackPattern.model_validate(pattern_data())
    assert AttackPattern.model_validate(pattern.model_dump(mode="json")) == pattern
    assert isinstance(pattern.prerequisite_capabilities.min_zones, tuple)
    assert isinstance(pattern.canonical_chain.steps, tuple)
    assert isinstance(pattern.canonical_chain.steps[0].preconditions, tuple)
    assert isinstance(
        pattern.canonical_chain.steps[0].preconditions[0].condition.fact.property_path,
        tuple,
    )
    assert isinstance(pattern.canonical_chain.steps[0].provenance.references, tuple)
    with pytest.raises(ValidationError):
        pattern.canonical_chain.steps[0].provenance.confidence = 1


def test_real_catalog_is_explicitly_legacy() -> None:
    patterns = load_attack_patterns()
    assert len(patterns) == 71
    assert patterns and all(isinstance(record, dict) for record in patterns.values())
    assert all(
        isinstance(validate_legacy_attack_pattern(record), LegacyAttackPatternRecord)
        for record in patterns.values()
    )
    assert all(not _authoritative_valid(record) for record in patterns.values())


def _authoritative_valid(raw: dict[str, Any]) -> bool:
    try:
        AttackPattern.model_validate(raw)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda c: c["steps"].__setitem__(1, {**c["steps"][1], "step_id": "step.1"}),
            "unique",
        ),
        (lambda c: c["steps"][1].__setitem__("order", 1), "total order"),
        (lambda c: c["steps"].reverse(), "total order"),
        (
            lambda c: [s.__setitem__("attacker_controlled", False) for s in c["steps"]],
            "earliest",
        ),
        (
            lambda c: c.__setitem__("earliest_attacker_controlled_step_id", "step.2"),
            "earliest",
        ),
        (
            lambda c: c["steps"][-1]["observable_postconditions"][0].__setitem__(
                "terminal", False
            ),
            "final step",
        ),
        (
            lambda c: c["steps"][0]["observable_postconditions"][0].update(
                security_relevant=True, terminal=True
            ),
            "only valid",
        ),
        (
            lambda c: c["resource_slots"].append(deepcopy(c["resource_slots"][0])),
            "unique",
        ),
        (lambda c: c.__setitem__("initial_ingress_slot_id", "target"), "ingress"),
        (
            lambda c: c.__setitem__(
                "mappings",
                [{"decision": "unmapped", "taxonomy": "ATLAS", "rationale": "pending"}],
            ),
            "requires an exact",
        ),
        (
            lambda c: c["steps"][0].__setitem__(
                "mappings",
                [{"decision": "unmapped", "taxonomy": "ATLAS", "rationale": "pending"}],
            ),
            "attacker-controlled",
        ),
    ],
)
def test_chain_invariant_negatives(mutation: Any, match: str) -> None:
    invalid_chain(mutation, match)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c["steps"][0].__setitem__(
            "mappings", [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
        lambda c: c["steps"][0].__setitem__(
            "mappings", [{"decision": "unmapped", "taxonomy": "ATLAS"}]
        ),
        lambda c: c["steps"][0].__setitem__(
            "mappings", [{"decision": "unmapped", "taxonomy": "ATLAS", "rationale": ""}]
        ),
        lambda c: c["steps"][0]["mappings"].append(
            deepcopy(c["steps"][0]["mappings"][0])
        ),
        lambda c: c["steps"][0]["mappings"][0].__setitem__(
            "ids", ["AML.T0001", "AML.T0001"]
        ),
        lambda c: c["steps"][0]["provenance"].__setitem__("confidence", 101),
        lambda c: c["steps"][0]["provenance"].__setitem__("references", []),
        lambda c: c["steps"][0]["provenance"].__setitem__("adaptation_rationale", ""),
        lambda c: c["steps"][0]["provenance"]["references"].append(
            deepcopy(c["steps"][0]["provenance"]["references"][0])
        ),
        lambda c: c.__setitem__(
            "mappings", [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    ],
)
def test_mapping_and_provenance_negatives(mutation: Any) -> None:
    invalid_chain(mutation)


@pytest.mark.parametrize(
    "raw",
    [
        equality(),
        {
            "op": "membership",
            "schema_version": "1",
            "fact": fact("integer"),
            "values": [1, 2],
        },
        {
            "op": "existence",
            "schema_version": "1",
            "fact": fact("boolean"),
            "exists": True,
        },
        {
            "op": "property_match",
            "schema_version": "1",
            "fact": fact(path=["region"]),
            "value": "eu",
        },
        {
            "op": "all",
            "schema_version": "1",
            "operands": [equality("a"), equality("b")],
        },
        {
            "op": "any",
            "schema_version": "1",
            "operands": [equality("a"), equality("b")],
        },
        {"op": "not", "schema_version": "1", "operand": equality()},
    ],
)
def test_every_condition_operator(raw: dict[str, Any]) -> None:
    assert CONDITION_ADAPTER.validate_python(raw).op == raw["op"]


@pytest.mark.parametrize(
    "raw",
    [
        {**equality(True), "fact": fact("integer")},
        {"op": "property_match", "schema_version": "1", "fact": fact(), "value": "x"},
        {"op": "all", "schema_version": "1", "operands": [equality()]},
        {
            "op": "any",
            "schema_version": "1",
            "operands": [equality(str(i)) for i in range(MAX_CONDITION_OPERANDS + 1)],
        },
        {
            "op": "membership",
            "schema_version": "1",
            "fact": fact(),
            "values": [str(i) for i in range(MAX_MEMBERSHIP_VALUES + 1)],
        },
        {"op": "all", "schema_version": "1", "operands": [equality(), equality()]},
        {**equality(), "op": "unknown"},
        {**equality(), "fact": {**fact(), "namespace": "unknown"}},
        {k: v for k, v in equality().items() if k != "op"},
        {k: v for k, v in equality().items() if k != "schema_version"},
        {**equality(), "fact": {**fact(), "namespace": "generated_artifact"}},
    ],
)
def test_condition_structural_negatives(raw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CONDITION_ADAPTER.validate_python(raw)


def test_condition_depth_and_node_limits() -> None:
    node = equality()
    for _ in range(MAX_CONDITION_DEPTH):
        node = {"op": "not", "schema_version": "1", "operand": node}
    with pytest.raises(ValidationError, match="structural limits"):
        CONDITION_ADAPTER.validate_python(node)
    leaves = [equality(str(i)) for i in range(MAX_CONDITION_NODES)]
    oversized = {
        "op": "all",
        "schema_version": "1",
        "operands": [
            {"op": "all", "schema_version": "1", "operands": leaves[:16]},
            {"op": "all", "schema_version": "1", "operands": leaves[16:]},
        ],
    }
    with pytest.raises(ValidationError, match="structural limits"):
        CONDITION_ADAPTER.validate_python(oversized)


def test_chain_digest_golden_and_canonical_stability() -> None:
    raw = chain_data()
    assert raw["semantic_digest"] == CHAIN_GOLDEN
    assert compute_chain_semantic_digest(
        CanonicalAttackChain.model_validate(raw)
    ) == compute_chain_semantic_digest(raw)
    variants = []
    variants.append({key: raw[key] for key in reversed(raw)})
    nfc = deepcopy(raw)
    nfc["steps"][0]["provenance"]["adaptation_rationale"] = "caf\u00e9"
    nfd = deepcopy(nfc)
    nfd["steps"][0]["provenance"]["adaptation_rationale"] = "cafe\u0301"
    assert compute_chain_semantic_digest(nfc) == compute_chain_semantic_digest(nfd)
    unordered = deepcopy(raw)
    for field in ("mappings", "resource_slots"):
        unordered[field].reverse()
    unordered["steps"][0]["provenance"]["references"].reverse()
    unordered["steps"][0]["execution_requirements"].append(
        {
            "schema_version": "1",
            "requirement_id": "req.extra",
            "kind": "credential",
        }
    )
    unordered["steps"][0]["preconditions"][0]["condition"] = {
        "op": "all",
        "schema_version": "1",
        "operands": [equality("a"), equality("b")],
    }
    reversed_operands = deepcopy(unordered)
    reversed_operands["steps"][0]["preconditions"][0]["condition"]["operands"].reverse()
    reversed_operands["steps"][0]["execution_requirements"].reverse()
    assert compute_chain_semantic_digest(unordered) == compute_chain_semantic_digest(
        reversed_operands
    )
    assert all(
        compute_chain_semantic_digest(v) == raw["semantic_digest"] for v in variants
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c["steps"].reverse(),
        lambda c: c.__setitem__("semantic_revision", 2),
        lambda c: c["taxonomy_context"]["atlas"].__setitem__("release", "v2"),
        lambda c: c["taxonomy_context"]["laaf"].__setitem__("digest", ZERO),
        lambda c: c["taxonomy_context"].__setitem__("mapping_set_digest", ONE),
    ],
)
def test_chain_digest_semantic_sensitivity(mutation: Any) -> None:
    original = chain_data()
    changed = deepcopy(original)
    mutation(changed)
    assert compute_chain_semantic_digest(changed) != original["semantic_digest"]


def test_chain_digest_distinguishes_null_and_omission() -> None:
    raw = chain_data()
    omitted = deepcopy(raw)
    del omitted["steps"][0]["condition"]
    assert compute_chain_semantic_digest(raw) != compute_chain_semantic_digest(omitted)


@pytest.mark.parametrize(
    "path",
    ["consumed", "preconditions", "execution_requirements"],
)
def test_chain_canonical_wire_requires_explicit_empty_fields(path: str) -> None:
    raw = chain_data()
    del raw["steps"][0][path]
    resign_chain(raw)
    with pytest.raises(ValidationError, match=path):
        CanonicalAttackChain.model_validate(raw)


def test_projection_roundtrip_frozen_and_golden() -> None:
    projection = ProjectionSnapshot.model_validate(projection_data())
    assert projection.projection_digest == PROJECTION_GOLDEN
    assert (
        ProjectionSnapshot.model_validate(projection.model_dump(mode="json"))
        == projection
    )
    assert isinstance(projection.selected_steps, tuple)
    with pytest.raises(ValidationError):
        projection.bindings[0].resource_ref.kind = "service"


def test_projection_accepts_selected_conditional_with_true_evidence() -> None:
    raw = projection_data()
    selected = raw["selected_steps"][0]
    selected["requirement"] = "conditional"
    selected["condition"] = equality()
    raw["condition_results"] = [condition_result("step.1", "true")]
    resign_projection(raw)
    projection = ProjectionSnapshot.model_validate(raw)
    assert projection.condition_results[0].result == "true"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["omissions"].append(
            {
                "step_id": "step.1",
                "reason": "not_selected",
                "condition_step_id": None,
            }
        ),
        lambda p: p["selected_steps"].pop(),
        lambda p: p["selected_steps"].append(deepcopy(p["selected_steps"][0])),
        lambda p: p["selected_steps"].reverse(),
        lambda p: p["bindings"].append(deepcopy(p["bindings"][0])),
        lambda p: p["bindings"][0]["resource_ref"].__setitem__("kind", "service"),
        lambda p: p["bindings"][0].__setitem__("slot_id", "unknown"),
        lambda p: p["initial_ingress_reference"].__setitem__(
            "canonical_id", "endpoint.other"
        ),
        lambda p: p["condition_results"].extend(
            [condition_result("step.1", "false"), condition_result("step.1", "true")]
        ),
        lambda p: (
            p["selected_steps"].pop(),
            p["omissions"].append(
                {
                    "step_id": "step.2",
                    "reason": "condition_false",
                    "condition_step_id": None,
                }
            ),
        ),
        lambda p: p["condition_results"].append(condition_result("unknown", "true")),
    ],
)
def test_projection_negative_matrix(mutation: Any) -> None:
    raw = projection_data()
    mutation(raw)
    resign_projection(raw)
    with pytest.raises(ValidationError):
        ProjectionSnapshot.model_validate(raw)


def condition_result(step_id: str, result: str) -> dict[str, Any]:
    return {
        "condition_step_id": step_id,
        "result": result,
        "evidence_refs": [
            {"kind": "state", "ref_id": "evidence.1", "value_type": "boolean"}
        ],
    }


def test_execution_requirement_and_summary_contract() -> None:
    requirement = ExecutionRequirement(
        schema_version="1", requirement_id="req.1", kind="compute"
    )
    assert (
        ExecutionRequirement.model_validate(requirement.model_dump(mode="json"))
        == requirement
    )
    summary = ExecutionRequirementSummary(
        schema_version="1",
        chain_id="chain.1",
        chain_semantic_digest=CHAIN_GOLDEN,
        contributing_step_ids=("step.1",),
        requirements=(requirement,),
    )
    assert summary.chain_semantic_digest == chain_data()["semantic_digest"]
    assert (
        ExecutionRequirementSummary.model_validate(summary.model_dump(mode="json"))
        == summary
    )


@pytest.mark.parametrize("field", ["contributing_step_ids", "requirements"])
def test_execution_summary_rejects_duplicates(field: str) -> None:
    raw = {
        "schema_version": "1",
        "chain_id": "chain.1",
        "chain_semantic_digest": CHAIN_GOLDEN,
        "contributing_step_ids": ["step.1"],
        "requirements": [
            {"schema_version": "1", "requirement_id": "req.1", "kind": "compute"}
        ],
    }
    raw[field] *= 2
    with pytest.raises(ValidationError):
        ExecutionRequirementSummary.model_validate(raw)


class Resolver:
    taxonomy_context = CanonicalAttackChain.model_validate(
        chain_data()
    ).taxonomy_context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return taxonomy == "ATLAS" and identifier == "AML.T0001"


def test_taxonomy_resolver_matching_success_and_pin_mismatch() -> None:
    assert validate_attack_pattern(pattern_data(), Resolver()).id == "AP-T1-01"
    resolver = Resolver()
    resolver.taxonomy_context = resolver.taxonomy_context.model_copy(
        update={"mapping_set_digest": ONE}
    )
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(pattern_data(), resolver)


@pytest.mark.parametrize("scope", ["chain", "step"])
def test_taxonomy_resolver_rejects_unknown_exact_id(scope: str) -> None:
    raw = pattern_data()
    mappings = (
        raw["canonical_chain"]["mappings"]
        if scope == "chain"
        else raw["canonical_chain"]["steps"][0]["mappings"]
    )
    mappings[0]["ids"] = ["AML.UNKNOWN"]
    resign_chain(raw["canonical_chain"])
    with pytest.raises(ValueError, match="unknown ATLAS id"):
        validate_attack_pattern(raw, Resolver())


def test_generated_schema_is_valid_and_accepts_positive_dump() -> None:
    schema = AttackPattern.model_json_schema()
    Draft202012Validator.check_schema(schema)
    assert Draft202012Validator(schema).is_valid(
        AttackPattern.model_validate(pattern_data()).model_dump(mode="json")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.__setitem__("extra", True),
        lambda p: p.pop("canonical_chain"),
        lambda p: p["canonical_chain"]["steps"][0]["produced"][0].pop("kind"),
        lambda p: p["canonical_chain"].__setitem__("semantic_revision", "1"),
        lambda p: p["canonical_chain"].__setitem__("steps", []),
        lambda p: p["canonical_chain"]["steps"][0]["mappings"][0].__setitem__(
            "decision", "invented"
        ),
    ],
)
def test_json_schema_structural_parity(mutation: Any) -> None:
    raw = pattern_data()
    mutation(raw)
    if "canonical_chain" in raw:
        resign_chain(raw["canonical_chain"])
    model_valid = _authoritative_valid(raw)
    schema_valid = Draft202012Validator(AttackPattern.model_json_schema()).is_valid(raw)
    assert model_valid == schema_valid
    assert not model_valid
