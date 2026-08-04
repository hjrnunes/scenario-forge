"""Focused tests for the authoritative attack-pattern contract."""

from copy import deepcopy
from typing import Any
import unicodedata

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.models.attack_pattern import (
    AttackPattern,
    CanonicalAttackChain,
    Condition,
    ConditionEvaluationResult,
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
CHAIN_GOLDEN = "85ca7548621d1fc8285044d454d6c7e6012c6303e4e51fe3f0a63c0f91cbdea7"
PROJECTION_GOLDEN = "a5d528f465191b14c5c6149b5e5844b4c5f6faf1a707dc57c6ddd48eaa7f1ccc"
REFS = {
    "entry_point": {"kind": "entry_point", "entry_point_id": "ep:v1:" + "1" * 32},
    "tool": {"kind": "tool", "tool_id": "tool:v1:" + "2" * 32},
    "integration": {"kind": "integration", "integration_id": "int:v1:" + "3" * 32},
    "trust_boundary": {
        "kind": "trust_boundary",
        "trust_boundary_id": "tb:v1:" + "4" * 32,
    },
}


def fact(value_type: str = "string") -> dict[str, Any]:
    return {
        "namespace": "profile",
        "fact_id": "mode",
        "value_type": value_type,
        "property_path": [],
    }


def equality() -> dict[str, Any]:
    return {"op": "equality", "schema_version": "1", "fact": fact(), "value": "active"}


def step(step_id: str, order: int, attacker: bool) -> dict[str, Any]:
    final = order == 3
    return {
        "step_id": step_id,
        "requirement": "conditional" if order == 2 else "required",
        "condition": equality() if order == 2 else None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "deliver" if attacker else "impact",
        "consumed": [],
        "produced": [
            {"kind": "effect", "ref_id": f"effect.{order}", "value_type": "boolean"}
        ],
        "preconditions": [],
        "observable_postconditions": [
            {
                "postcondition_id": f"post.{order}",
                "description": "observable",
                "security_relevant": final,
                "terminal": final,
            }
        ],
        "order": order,
        "attacker_controlled": attacker,
        "provenance": {
            "tier": "observed",
            "references": [
                {"reference_type": "catalog", "reference_id": f"case-{order}"}
            ],
            "confidence": 90,
            "adaptation_rationale": "represented",
        },
        "mappings": (
            [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}]
            if attacker
            else [{"decision": "not_applicable", "taxonomy": "LAAF"}]
        ),
    }


def resign_chain(raw: dict[str, Any]) -> dict[str, Any]:
    raw["semantic_digest"] = compute_chain_semantic_digest(raw)
    return raw


def chain_data() -> dict[str, Any]:
    return resign_chain(
        {
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
                {"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}
            ],
            "steps": [
                step("step.1", 1, True),
                step("step.2", 2, False),
                step("step.3", 3, False),
            ],
            "earliest_attacker_controlled_step_id": "step.1",
            "resource_slots": [
                {
                    "slot_id": "ingress",
                    "kind": "entry_point",
                    "purpose": "initial_ingress",
                },
                {"slot_id": "tool", "kind": "tool", "purpose": "supporting"},
                {"slot_id": "source", "kind": "integration", "purpose": "supporting"},
                {"slot_id": "boundary", "kind": "trust_boundary", "purpose": "target"},
            ],
            "initial_ingress_slot_id": "ingress",
        }
    )


def pattern_data() -> dict[str, Any]:
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain_data(),
    }


def condition_result(result: str = "true") -> dict[str, Any]:
    return {
        "condition_step_id": "step.2",
        "result": result,
        "evidence": [{"fact": fact(), "status": "known", "value": "active"}],
    }


def resign_projection(raw: dict[str, Any]) -> dict[str, Any]:
    raw["projection_digest"] = compute_projection_digest(raw)
    return raw


def projection_data(result: str = "true") -> dict[str, Any]:
    selected = (
        ["step.1", "step.3"] if result == "false" else ["step.1", "step.2", "step.3"]
    )
    return resign_projection(
        {
            "schema_version": "1",
            "source_chain": chain_data(),
            "selected_step_ids": selected,
            "condition_results": [condition_result(result)],
            "omissions": [{"step_id": "step.2", "reason": "condition_false"}]
            if result == "false"
            else [],
            "bindings": [
                {"slot_id": key, "resource_ref": deepcopy(REFS[kind])}
                for key, kind in (
                    ("ingress", "entry_point"),
                    ("tool", "tool"),
                    ("source", "integration"),
                    ("boundary", "trust_boundary"),
                )
            ],
            "catalog_pin": ONE,
            "pattern_pin": ZERO,
            "capability_fact_snapshot_digest": ONE,
            "projection_digest": ZERO,
        }
    )


def invalid_chain(mutation: Any) -> None:
    raw = chain_data()
    mutation(raw)
    resign_chain(raw)
    with pytest.raises(ValidationError):
        CanonicalAttackChain.model_validate(raw)


def test_roundtrip_digest_stability_and_structural_schema() -> None:
    pattern = AttackPattern.model_validate(pattern_data())
    assert pattern.canonical_chain.semantic_digest == CHAIN_GOLDEN
    assert AttackPattern.model_validate(pattern.model_dump(mode="json")) == pattern
    assert (
        compute_chain_semantic_digest(pattern.canonical_chain)
        == chain_data()["semantic_digest"]
    )
    reordered = {key: chain_data()[key] for key in reversed(chain_data())}
    assert compute_chain_semantic_digest(reordered) == chain_data()["semantic_digest"]
    schema = AttackPattern.model_json_schema()
    Draft202012Validator.check_schema(schema)
    assert Draft202012Validator(schema).is_valid(pattern.model_dump(mode="json"))


def test_chain_digest_normalization_and_semantic_sensitivity() -> None:
    raw = chain_data()
    reordered = deepcopy(raw)
    reordered["mappings"].reverse()
    reordered["resource_slots"].reverse()
    assert compute_chain_semantic_digest(reordered) == raw["semantic_digest"]

    nfc = deepcopy(raw)
    nfd = deepcopy(raw)
    nfc["steps"][0]["provenance"]["adaptation_rationale"] = "caf\u00e9"
    nfd["steps"][0]["provenance"]["adaptation_rationale"] = unicodedata.normalize(
        "NFD", "caf\u00e9"
    )
    assert compute_chain_semantic_digest(nfc) == compute_chain_semantic_digest(nfd)

    for mutation in (
        lambda c: c.update(semantic_revision=2),
        lambda c: c["steps"].reverse(),
        lambda c: c["taxonomy_context"]["atlas"].update(release="v2"),
    ):
        changed = deepcopy(raw)
        mutation(changed)
        assert compute_chain_semantic_digest(changed) != raw["semantic_digest"]


def test_legacy_catalog_stays_isolated() -> None:
    records = load_attack_patterns()
    assert len(records) == 71
    assert all(
        isinstance(validate_legacy_attack_pattern(r), LegacyAttackPatternRecord)
        for r in records.values()
    )
    assert all(
        not Draft202012Validator(AttackPattern.model_json_schema()).is_valid(r)
        for r in records.values()
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c["steps"][0].update(executor_role="system"),
        lambda c: c["steps"][1].update(executor_role="attacker"),
        lambda c: c["steps"][1].update(
            mappings=[{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}]
        ),
        lambda c: c["steps"][1].update(
            mappings=[
                {"decision": "unmapped", "taxonomy": "ATLAS", "rationale": "none"}
            ]
        ),
        lambda c: c["steps"][0].update(
            attacker_controlled=False,
            executor_role="system",
            mappings=[{"decision": "not_applicable", "taxonomy": "ATLAS"}],
        ),
        lambda c: c["steps"][0].update(execution_requirements=[]),
        lambda c: c["resource_slots"][0].update(kind="tool"),
    ],
)
def test_chain_role_start_mapping_and_authored_requirement_negatives(
    mutation: Any,
) -> None:
    invalid_chain(mutation)


def test_condition_evidence_known_unknown_contract() -> None:
    assert ConditionEvaluationResult.model_validate(condition_result()).result == "true"
    unknown = condition_result("unknown")
    unknown["evidence"][0].update(status="unknown", value=None)
    assert ConditionEvaluationResult.model_validate(unknown).result == "unknown"
    for status, value in (("known", None), ("unknown", "active"), ("known", True)):
        raw = condition_result()
        raw["evidence"][0].update(status=status, value=value)
        with pytest.raises(ValidationError):
            ConditionEvaluationResult.model_validate(raw)
    duplicate = condition_result()
    duplicate["evidence"].append(deepcopy(duplicate["evidence"][0]))
    with pytest.raises(ValidationError, match="unique"):
        ConditionEvaluationResult.model_validate(duplicate)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(selected_step_ids=[]),
        lambda p: p.update(
            selected_step_ids=["step.2", "step.3"],
            omissions=[{"step_id": "step.1", "reason": "condition_false"}],
        ),
        lambda p: p.update(
            selected_step_ids=["step.1", "step.2"],
            omissions=[{"step_id": "step.3", "reason": "condition_false"}],
        ),
        lambda p: p["condition_results"][0].update(result="unknown"),
        lambda p: p["condition_results"][0]["evidence"][0]["fact"].update(
            fact_id="unrelated"
        ),
        lambda p: p.update(
            omissions=[{"step_id": "step.2", "reason": "condition_false"}]
        ),
        lambda p: p["omissions"].append(
            {"step_id": "step.1", "reason": "condition_false"}
        ),
        lambda p: p["bindings"].pop(),
        lambda p: p["bindings"].append(deepcopy(p["bindings"][0])),
        lambda p: p["bindings"][0].update(resource_ref=deepcopy(REFS["tool"])),
        lambda p: p["source_chain"]["steps"][0].update(action_kind="prepare"),
    ],
)
def test_projection_source_semantics_negatives(mutation: Any) -> None:
    raw = projection_data()
    mutation(raw)
    resign_projection(raw)
    with pytest.raises(ValidationError):
        ProjectionSnapshot.model_validate(raw)


def test_projection_roundtrip_false_omission_and_digest() -> None:
    assert projection_data()["projection_digest"] == PROJECTION_GOLDEN
    projection = ProjectionSnapshot.model_validate(projection_data("false"))
    assert projection.selected_step_ids == ("step.1", "step.3")
    assert (
        ProjectionSnapshot.model_validate(projection.model_dump(mode="json"))
        == projection
    )
    changed = projection_data()
    changed["source_chain"]["steps"][0]["action_kind"] = "prepare"
    assert compute_projection_digest(changed) != projection_data()["projection_digest"]


@pytest.mark.parametrize(
    "kind,field",
    [
        ("entry_point", "entry_point_id"),
        ("tool", "tool_id"),
        ("integration", "integration_id"),
        ("trust_boundary", "trust_boundary_id"),
    ],
)
def test_resource_reference_domain_patterns(kind: str, field: str) -> None:
    raw = projection_data()
    binding = next(b for b in raw["bindings"] if b["resource_ref"]["kind"] == kind)
    binding["resource_ref"][field] = "arbitrary"
    resign_projection(raw)
    with pytest.raises(ValidationError):
        ProjectionSnapshot.model_validate(raw)


def requirements() -> list[dict[str, Any]]:
    return [
        {
            "schema_version": "1",
            "requirement_id": "r1",
            "kind": "direct_input_control",
            "entry_point_slot_id": "ingress",
        },
        {
            "schema_version": "1",
            "requirement_id": "r2",
            "kind": "upstream_source_influence",
            "source_slot_id": "source",
            "trust_boundary_slot_id": "boundary",
        },
        {
            "schema_version": "1",
            "requirement_id": "r3",
            "kind": "state_changing_tool_fixture",
            "tool_slot_id": "tool",
        },
        {
            "schema_version": "1",
            "requirement_id": "r4",
            "kind": "observation",
            "observation": "tool_invocation",
            "binding_slot_id": "tool",
        },
        {
            "schema_version": "1",
            "requirement_id": "r5",
            "kind": "security_outcome_assertion",
            "source_step_id": "step.3",
            "postcondition_id": "post.3",
        },
    ]


def summary_data() -> dict[str, Any]:
    projection = projection_data()
    return {
        "schema_version": "1",
        "source_projection": projection,
        "projection_digest": projection["projection_digest"],
        "contributing_step_ids": ["step.1"],
        "requirements": requirements(),
    }


def test_every_execution_requirement_union_shape_and_summary() -> None:
    adapter = TypeAdapter(ExecutionRequirement)
    assert [adapter.validate_python(r).kind for r in requirements()] == [
        r["kind"] for r in requirements()
    ]
    summary = ExecutionRequirementSummary.model_validate(summary_data())
    assert (
        ExecutionRequirementSummary.model_validate(summary.model_dump(mode="json"))
        == summary
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.update(projection_digest=ZERO),
        lambda s: s.update(contributing_step_ids=["absent"]),
        lambda s: s["requirements"][0].update(entry_point_slot_id="tool"),
        lambda s: s["requirements"][1].update(trust_boundary_slot_id="source"),
        lambda s: s["requirements"][2].update(tool_slot_id="ingress"),
        lambda s: s["requirements"][3].update(binding_slot_id="absent"),
        lambda s: s["requirements"][4].update(source_step_id="step.2"),
        lambda s: s["requirements"][4].update(postcondition_id="absent"),
        lambda s: s["requirements"][4].update(
            source_step_id="step.1", postcondition_id="post.1"
        ),
        lambda s: s.update(requirements=[]),
    ],
)
def test_execution_summary_projection_pinning_and_refs(mutation: Any) -> None:
    raw = summary_data()
    mutation(raw)
    with pytest.raises(ValidationError):
        ExecutionRequirementSummary.model_validate(raw)


class Resolver:
    taxonomy_context = CanonicalAttackChain.model_validate(
        chain_data()
    ).taxonomy_context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return taxonomy == "ATLAS" and identifier == "AML.T0001"


def test_required_qualification_resolver_ids_and_pins() -> None:
    assert validate_attack_pattern(pattern_data(), Resolver()).id == "AP-T1-01"
    with pytest.raises(TypeError):
        validate_attack_pattern(pattern_data())  # type: ignore[call-arg]
    raw = pattern_data()
    raw["canonical_chain"]["steps"][0]["mappings"][0]["ids"] = ["AML.UNKNOWN"]
    resign_chain(raw["canonical_chain"])
    with pytest.raises(ValueError, match="unknown ATLAS id"):
        validate_attack_pattern(raw, Resolver())
    resolver = Resolver()
    resolver.taxonomy_context = resolver.taxonomy_context.model_copy(
        update={"mapping_set_digest": ONE}
    )
    with pytest.raises(ValueError, match="pins"):
        validate_attack_pattern(pattern_data(), resolver)


def test_condition_ast_stays_discriminated_and_bounded() -> None:
    adapter = TypeAdapter(Condition)
    assert adapter.validate_python(equality()).op == "equality"
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {"op": "all", "schema_version": "1", "operands": [equality()]}
        )
    nested = equality()
    for _ in range(4):
        nested = {"op": "not", "schema_version": "1", "operand": nested}
    with pytest.raises(ValidationError, match="structural limits"):
        adapter.validate_python(nested)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(extra=True),
        lambda p: p.pop("canonical_chain"),
        lambda p: p["canonical_chain"]["steps"][0].pop("executor_role"),
        lambda p: p["canonical_chain"]["steps"][0]["produced"][0].update(
            kind="invented"
        ),
        lambda p: p["canonical_chain"].update(semantic_revision="1"),
    ],
)
def test_generated_schema_structural_negative_parity(mutation: Any) -> None:
    raw = pattern_data()
    mutation(raw)
    if "canonical_chain" in raw:
        resign_chain(raw["canonical_chain"])
    with pytest.raises(ValidationError):
        AttackPattern.model_validate(raw)
    assert not Draft202012Validator(AttackPattern.model_json_schema()).is_valid(raw)
