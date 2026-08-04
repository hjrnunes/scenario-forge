"""Focused tests for deterministic authoritative candidate projection (422o.3)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from scenario_forge.models.attack_pattern import (
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
    compute_chain_semantic_digest,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from scenario_forge.pipeline.projection import (
    ProjectionBudget,
    capture_capability_snapshot,
    project_authoritative_candidates,
    validate_projected_candidate,
)

ZERO = "0" * 64


class TaxonomyResolver:
    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in {
            ("ATLAS", "AML.T0001"),
            ("LAAF", "LAAF.1"),
        }


def _fact() -> dict[str, Any]:
    return {
        "namespace": "profile",
        "fact_id": "mode",
        "value_type": "string",
        "property_path": [],
    }


def _step(step_id: str, order: int, *, conditional: bool = False) -> dict[str, Any]:
    final = order == 3
    attacker = order == 1
    return {
        "step_id": step_id,
        "requirement": "conditional" if conditional else "required",
        "condition": {
            "op": "equality",
            "schema_version": "1",
            "fact": _fact(),
            "value": "active",
        }
        if conditional
        else None,
        "executor_role": "attacker" if attacker else "system",
        "boundary_position": "crossing" if attacker else "inside",
        "action_kind": "deliver" if attacker else "persist" if final else "invoke",
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
            else [{"decision": "not_applicable", "taxonomy": "ATLAS"}]
        ),
    }


def _pattern(*, conditional: bool = True) -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            "laaf": {"release": "unavailable", "digest": ZERO},
            "mapping_set_digest": ZERO,
        },
        "mappings": [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}],
        "steps": [
            _step("step.1", 1),
            _step("step.2", 2, conditional=conditional),
            _step("step.3", 3),
        ],
        "earliest_attacker_controlled_step_id": "step.1",
        "resource_slots": [
            {"slot_id": "ingress", "kind": "entry_point", "purpose": "initial_ingress"},
            {"slot_id": "tool", "kind": "tool", "purpose": "supporting"},
            {"slot_id": "source", "kind": "integration", "purpose": "supporting"},
            {
                "slot_id": "boundary",
                "kind": "trust_boundary",
                "purpose": "intermediate",
            },
        ],
        "initial_ingress_slot_id": "ingress",
    }
    chain["semantic_digest"] = compute_chain_semantic_digest(chain)
    return {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Pattern",
        "description": "Canonical",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "canonical_chain": chain,
    }


def _profile(*, duplicate_resources: bool = False) -> CapabilityProfile:
    tools = [{"name": "writer", "description": "changes state"}]
    integrations = [
        {
            "name": "CRM",
            "integration_type": "api",
            "auth_method": "oauth",
            "data_sensitivity": "high",
        }
    ]
    boundaries = [
        {
            "name": "user-to-agent",
            "from_zone": "input",
            "to_zone": "reasoning",
            "confidence": "explicit",
        }
    ]
    if duplicate_resources:
        tools.append({"name": "sender", "description": "changes state"})
        integrations.append(
            {
                "name": "Queue",
                "integration_type": "message_queue",
                "auth_method": "service_account",
                "data_sensitivity": "medium",
            }
        )
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
            {
                "name": "RAG documents",
                "direction": "input",
                "controllability": "indirect",
            },
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=tools,
        tool_types=[
            {
                "name": item["name"],
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
            for item in tools
        ],
        external_integrations=integrations,
        trust_boundaries=boundaries,
    )


def _evidence(value: str = "active") -> EvaluatedFactEvidence:
    return EvaluatedFactEvidence(
        fact=AuthoritativeFactReference.model_validate(_fact()),
        status="present",
        value=value,
    )


def _project(
    *,
    profile: CapabilityProfile | None = None,
    evidence: tuple[EvaluatedFactEvidence, ...] = (_evidence(),),
    budget: int = 100,
    pattern: dict[str, Any] | None = None,
):
    raw = pattern or _pattern()
    resolver_pattern = raw if "canonical_chain" in raw else _pattern()
    resolver = TaxonomyResolver(
        __import__("scenario_forge.models.attack_pattern", fromlist=["AttackPattern"])
        .AttackPattern.model_validate(resolver_pattern)
        .canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(profile or _profile(), evidence)
    return project_authoritative_candidates(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=budget),
    )


def test_snapshot_is_content_addressed_order_independent_and_qualifies_resources() -> (
    None
):
    profile = _profile()
    first = capture_capability_snapshot(profile, (_evidence(),))
    second = capture_capability_snapshot(
        profile.model_copy(deep=True), tuple(reversed((_evidence(),)))
    )
    assert first.snapshot_digest == second.snapshot_digest
    assert first.capability_fact_snapshot_digest == first.snapshot_digest
    assert first.fact(_evidence().fact) == _evidence()
    for candidate in _project().candidates:
        for binding in candidate.projection.bindings:
            assert first.contains_resource(binding.resource_ref)

    first.profile.kc_subcodes.append("KC2.1")
    with pytest.raises(ValueError, match="changed after capture"):
        first.fact(_evidence().fact)


def test_content_identity_normalizes_canonically_equivalent_unicode() -> None:
    composed = _pattern()
    decomposed = _pattern()
    composed["name"] = "Caf\N{LATIN SMALL LETTER E WITH ACUTE}"
    decomposed["name"] = "Cafe\N{COMBINING ACUTE ACCENT}"
    assert _project(pattern=composed) == _project(pattern=decomposed)


def test_true_and_false_conditions_persist_complete_evidence_and_projection() -> None:
    selected = _project(evidence=(_evidence("active"),)).candidates
    omitted = _project(evidence=(_evidence("inactive"),)).candidates
    assert {r.result for r in selected[0].projection.condition_results} == {"true"}
    assert selected[0].projection.selected_step_ids == ("step.1", "step.2", "step.3")
    assert {r.result for r in omitted[0].projection.condition_results} == {"false"}
    assert omitted[0].projection.selected_step_ids == ("step.1", "step.3")
    assert omitted[0].projection.omissions[0].step_id == "step.2"


def test_unknown_is_typed_unresolved_and_never_becomes_a_candidate() -> None:
    result = _project(evidence=())
    assert result.candidates == ()
    assert result.infeasibilities[0].code == "unresolved_condition"
    assert result.infeasibilities[0].condition_results[0].result == "unknown"


def test_selected_step_preconditions_persist_true_false_and_unknown_evidence() -> None:
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][0]["preconditions"] = [
        {
            "condition_id": "pre.mode",
            "condition": {
                "op": "equality",
                "schema_version": "1",
                "fact": _fact(),
                "value": "active",
            },
        }
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )

    satisfied = _project(pattern=raw, evidence=(_evidence("active"),))
    assert satisfied.candidates[0].precondition_results[0].result == "true"
    duplicate = satisfied.candidates[0].model_dump(mode="json")
    duplicate["precondition_results"].append(
        deepcopy(duplicate["precondition_results"][0])
    )
    with pytest.raises(ValidationError, match="keys must be unique"):
        type(satisfied.candidates[0]).model_validate(duplicate)

    false = _project(pattern=raw, evidence=(_evidence("inactive"),))
    assert false.candidates == ()
    assert false.infeasibilities[0].code == "precondition_not_satisfied"
    assert false.infeasibilities[0].precondition_results[0].result == "false"

    unknown = _project(pattern=raw, evidence=())
    assert unknown.candidates == ()
    assert unknown.infeasibilities[0].code == "unresolved_condition"
    assert unknown.infeasibilities[0].precondition_results[0].result == "unknown"


def test_bindings_exactly_cover_slots_and_support_direct_and_indirect_ingress() -> None:
    result = _project()
    assert {c.ingress_controllability for c in result.candidates} == {
        "direct",
        "indirect",
    }
    for candidate in result.candidates:
        assert {b.slot_id for b in candidate.projection.bindings} == {
            "ingress",
            "tool",
            "source",
            "boundary",
        }
        kinds = {requirement.kind for requirement in candidate.execution_requirements}
        expected = (
            "direct_input_control"
            if candidate.ingress_controllability == "direct"
            else "upstream_source_influence"
        )
        assert expected in kinds


def test_unsupported_binding_is_typed_infeasibility() -> None:
    raw = _pattern()
    raw["canonical_chain"]["resource_slots"].append(
        {"slot_id": "missing", "kind": "entry_point", "purpose": "target"}
    )
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    profile = _profile().model_copy(update={"entry_points": []})
    result = _project(profile=profile, pattern=raw)
    assert result.candidates == ()
    assert {issue.code for issue in result.infeasibilities} == {
        "missing_compatible_resource"
    }


def test_expansion_is_bounded_coverage_aware_stable_and_deduplicated() -> None:
    first = _project(profile=_profile(duplicate_resources=True), budget=3)
    second = _project(profile=_profile(duplicate_resources=True), budget=3)
    assert first.candidates == second.candidates
    assert len(first.candidates) == len({c.candidate_id for c in first.candidates}) == 3
    assert first.limitations[0].code == "candidate_budget_exhausted"
    assert len({c.canonical_ingress.entry_point_id for c in first.candidates}) == 2


def test_execution_requirements_are_complete_versioned_and_digest_verified() -> None:
    indirect = next(
        c for c in _project().candidates if c.ingress_controllability == "indirect"
    )
    assert {r.kind for r in indirect.execution_requirements} == {
        "upstream_source_influence",
        "state_changing_tool_fixture",
        "observation",
        "security_outcome_assertion",
    }
    observations = {
        r.observation
        for r in indirect.execution_requirements
        if r.kind == "observation"
    }
    assert observations == {"model_context", "tool_invocation", "persistent_state"}
    assert indirect.requirement_derivation_version == "1"
    assert len(indirect.execution_requirements_digest) == 64
    forged = indirect.model_dump(mode="json")
    forged["execution_requirements_digest"] = ZERO
    with pytest.raises(ValidationError, match="requirements_digest"):
        type(indirect).model_validate(forged)

    result = _project()
    direct = next(
        candidate
        for candidate in result.candidates
        if candidate.ingress_controllability == "direct"
    )
    forged = indirect.model_dump(mode="json")
    forged["execution_requirements"] = [
        item.model_dump(mode="json") for item in direct.execution_requirements
    ]
    forged["execution_requirements_digest"] = direct.execution_requirements_digest
    forged["complexity_inputs"]["execution_requirement_count"] = len(
        direct.execution_requirements
    )
    structurally_valid = type(indirect).model_validate(forged)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    raw = _pattern()
    resolver = TaxonomyResolver(
        __import__("scenario_forge.models.attack_pattern", fromlist=["AttackPattern"])
        .AttackPattern.model_validate(raw)
        .canonical_chain.taxonomy_context
    )
    with pytest.raises(ValueError, match="requirements do not match"):
        validate_projected_candidate(
            structurally_valid.model_dump(mode="json"),
            snapshot,
            raw,
            resolver,
            expected_catalog_pin=indirect.projection.catalog_pin,
        )

    with pytest.raises(ValueError, match="catalog pin"):
        validate_projected_candidate(
            indirect.model_dump(mode="json"),
            snapshot,
            raw,
            resolver,
            expected_catalog_pin="f" * 64,
        )


def test_candidate_v2_identity_is_stable_and_sensitive_to_every_identity_axis() -> None:
    baseline = _project().candidates
    repeated = _project().candidates
    assert [c.candidate_id for c in baseline] == [c.candidate_id for c in repeated]
    assert all(c.candidate_id.startswith("cand:v2:") for c in baseline)

    changed = _pattern()
    changed["canonical_chain"]["semantic_revision"] = 2
    changed["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        changed["canonical_chain"]
    )
    assert {c.candidate_id for c in _project(pattern=changed).candidates}.isdisjoint(
        {c.candidate_id for c in baseline}
    )

    changed_projection = _project(evidence=(_evidence("inactive"),)).candidates
    assert {c.candidate_id for c in changed_projection}.isdisjoint(
        {c.candidate_id for c in baseline}
    )
    assert len({c.candidate_id for c in baseline}) == 2  # canonical ingress/bindings

    forged = baseline[0].model_dump(mode="json")
    forged["candidate_id"] = "cand:v2:" + "0" * 32
    with pytest.raises(ValidationError, match="candidate_id"):
        type(baseline[0]).model_validate(forged)


def test_projected_mappings_are_cumulative_not_a_technique_subset_axis() -> None:
    candidates = _project().candidates
    assert all(candidate.projected_mappings for candidate in candidates)
    assert all(
        mapping.mapping.taxonomy == "ATLAS"
        for candidate in candidates
        for mapping in candidate.projected_mappings
    )
    assert all(not hasattr(candidate, "technique_ids") for candidate in candidates)
    assert all(not hasattr(candidate, "prompt_emphasis") for candidate in candidates)


def test_legacy_catalog_record_cannot_masquerade_as_projected_candidate() -> None:
    legacy = {
        "id": "AP-T1-01",
        "threat_id": "T1",
        "name": "Legacy",
        "description": "No authoritative chain",
        "prerequisite_capabilities": {"min_zones": ["input"]},
        "kill_chain": [],
    }
    with pytest.raises(ValueError, match="authoritative"):
        _project(pattern=deepcopy(legacy))


def test_kc_all_and_any_prerequisites_are_authoritative_profile_gates() -> None:
    raw = _pattern()
    raw["prerequisite_capabilities"]["kc_requires"] = {
        "all": ["KC5.1"],
        "any": ["KC1.1", "KC2.1"],
    }
    assert _project(pattern=raw).candidates

    raw["prerequisite_capabilities"]["kc_requires"]["all"] = ["KC2.1"]
    result = _project(pattern=raw)
    assert result.candidates == ()
    assert result.infeasibilities[0].code == "incompatible_profile"
    assert "KC2.1" in result.infeasibilities[0].detail

    raw["prerequisite_capabilities"]["kc_requires"] = {
        "all": [],
        "any": ["KC2.1", "KC3.1"],
    }
    result = _project(pattern=raw)
    assert result.candidates == ()
    assert "requires any KC code" in result.infeasibilities[0].detail


@pytest.mark.parametrize("decision", ["exact", "unmapped", "not_applicable"])
def test_initial_v1_rejects_all_laaf_and_never_projects_it_as_semantics(
    decision: str,
) -> None:
    raw = _pattern()
    mapping = {"decision": decision, "taxonomy": "LAAF"}
    if decision == "exact":
        mapping["ids"] = ["LAAF.1"]
    elif decision == "unmapped":
        mapping["rationale"] = "No authoritative taxonomy is available."
    if decision == "not_applicable":
        raw["canonical_chain"]["steps"][-1]["mappings"] = [mapping]
    else:
        raw["canonical_chain"]["mappings"].append(mapping)
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    with pytest.raises(ValueError, match="ATLAS-only"):
        _project(pattern=raw)


def test_catalog_pin_and_candidate_identity_ignore_record_order_and_duplicates() -> (
    None
):
    first = _pattern()
    second = deepcopy(first)
    second["id"] = "AP-T1-02"
    second["canonical_chain"]["pattern_id"] = "AP-T1-02"
    second["canonical_chain"]["chain_id"] = "chain.2"
    second["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        second["canonical_chain"]
    )
    resolver = TaxonomyResolver(
        __import__("scenario_forge.models.attack_pattern", fromlist=["AttackPattern"])
        .AttackPattern.model_validate(first)
        .canonical_chain.taxonomy_context
    )
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    forward = project_authoritative_candidates([first, second], resolver, snapshot)
    reverse = project_authoritative_candidates(
        [second, first, deepcopy(first)], resolver, snapshot
    )
    assert [candidate.candidate_id for candidate in forward.candidates] == [
        candidate.candidate_id for candidate in reverse.candidates
    ]
    bounded = project_authoritative_candidates(
        [second, first], resolver, snapshot, budget=ProjectionBudget(max_candidates=2)
    )
    assert {candidate.pattern_id for candidate in bounded.candidates} == {
        "AP-T1-01",
        "AP-T1-02",
    }
    assert {item.pattern_id for item in bounded.limitations} == {
        "AP-T1-01",
        "AP-T1-02",
    }

    reordered = deepcopy(first)
    reordered["canonical_chain"]["resource_slots"].reverse()
    assert _project(pattern=first) == _project(pattern=reordered)
