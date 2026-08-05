"""Focused tests for deterministic authoritative candidate projection (422o.3)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from scenario_forge.models.attack_pattern import (
    AttackPattern,
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
        "action_kind": "prepare" if attacker else "impact" if final else "observe",
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
        "resource_links": (
            [
                {
                    "slot_id": "ingress",
                    "role": "ingress",
                    "trust_boundary_slot_id": None,
                }
            ]
            if attacker
            else []
        ),
        "observable_outcome_links": (
            # The terminal step is security-relevant; it must carry an
            # explicit outcome link so the security assertion is derived
            # from the link, not from the security_relevant flag alone.
            [
                {
                    "postcondition_id": f"post.{order}",
                    "observation": "model_context",
                    "binding_slot_id": "ingress",
                }
            ]
            if final
            else []
        ),
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
            # ATLAS-only: no LAAF pin exists; the canonical framing of an
            # absent pin is JSON null, so digests cover ``"laaf": None``.
            "laaf": None,
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


def test_bindings_exactly_cover_slots_and_indirect_ingress_fails_closed() -> None:
    result = _project()
    assert {c.ingress_controllability for c in result.candidates} == {"direct"}
    assert {issue.code for issue in result.infeasibilities} == {
        "unsupported_requirement_derivation"
    }
    for candidate in result.candidates:
        assert {b.slot_id for b in candidate.projection.bindings} == {
            "ingress",
            "tool",
            "source",
            "boundary",
        }
        assert {
            requirement.kind for requirement in candidate.execution_requirements
        } == {
            "direct_input_control",
            "observation",
            "security_outcome_assertion",
        }


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
    assert {c.ingress_controllability for c in first.candidates} == {"direct"}
    assert (
        len(
            {
                binding.resource_ref.tool_id
                for candidate in first.candidates
                for binding in candidate.projection.bindings
                if binding.resource_ref.kind == "tool"
            }
        )
        == 2
    )


def test_explicit_execution_requirements_are_versioned_and_digest_verified() -> None:
    direct = _project().candidates[0]
    assert {r.kind for r in direct.execution_requirements} == {
        "direct_input_control",
        "observation",
        "security_outcome_assertion",
    }
    assert direct.requirement_derivation_version == "1"
    assert len(direct.execution_requirements_digest) == 64
    forged = direct.model_dump(mode="json")
    forged["execution_requirements_digest"] = ZERO
    with pytest.raises(ValidationError, match="requirements_digest"):
        type(direct).model_validate(forged)

    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    raw = _pattern()
    resolver = TaxonomyResolver(
        __import__("scenario_forge.models.attack_pattern", fromlist=["AttackPattern"])
        .AttackPattern.model_validate(raw)
        .canonical_chain.taxonomy_context
    )
    with pytest.raises(ValueError, match="catalog pin"):
        validate_projected_candidate(
            direct.model_dump(mode="json"),
            snapshot,
            raw,
            resolver,
            expected_catalog_pin="f" * 64,
        )


@pytest.mark.parametrize("action_kind", ["deliver", "transform", "invoke", "persist"])
def test_unlinked_action_resources_and_observations_are_never_inferred(
    action_kind: str,
) -> None:
    """Action kind alone never produces requirements; only explicit links do."""
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][1]["action_kind"] = action_kind
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    # The candidate succeeds because the first step has an explicit ingress
    # link and the terminal step has an explicit outcome link on its
    # security-relevant postcondition.  Action kind is irrelevant to
    # requirement derivation.
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert {requirement.kind for requirement in candidate.execution_requirements} == {
        "direct_input_control",
        "observation",
        "security_outcome_assertion",
    }
    # No tool-fixture requirements are inferred from action kind.
    assert not any(
        requirement.kind == "state_changing_tool_fixture"
        for requirement in candidate.execution_requirements
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
    assert len({c.candidate_id for c in baseline}) == 1

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
def test_laaf_decisions_fail_closed_without_an_explicit_laaf_pin(
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
    with pytest.raises(ValueError, match="LAAF taxonomy pin"):
        _project(pattern=raw)

    # Normal qualification rejects the same record through the projection
    # boundary even when the resolver itself is valid and ATLAS-only.
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    with pytest.raises(ValueError, match="qualification failed"):
        project_authoritative_candidates([raw], _atlas_only_resolver(), snapshot)


def _atlas_only_resolver() -> TaxonomyResolver:
    """Resolver pinned to the default fixture's ATLAS-only taxonomy context."""
    context = AttackPattern.model_validate(_pattern()).canonical_chain.taxonomy_context
    assert context.laaf is None
    return TaxonomyResolver(context)


def test_serialized_candidate_authority_validation_passes_without_placeholder() -> None:
    candidate = _project().candidates[0]
    chain = candidate.projection.source_chain
    assert chain.taxonomy_context.laaf is None
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    validated = validate_projected_candidate(
        candidate.model_dump(mode="json"),
        snapshot,
        _pattern(),
        _atlas_only_resolver(),
        expected_catalog_pin=candidate.projection.catalog_pin,
    )
    assert validated == candidate


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
    assert bounded.limitations == ()

    reordered = deepcopy(first)
    reordered["canonical_chain"]["resource_slots"].reverse()
    assert _project(pattern=first) == _project(pattern=reordered)

    divergent = deepcopy(first)
    divergent["canonical_chain"]["semantic_revision"] = 2
    divergent["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        divergent["canonical_chain"]
    )
    with pytest.raises(ValueError, match="share one pattern id"):
        project_authoritative_candidates([first, divergent], resolver, snapshot)


# ---------------------------------------------------------------------------
# Adversarial projection tests for explicit canonical linkage (422o.3.1)
# ---------------------------------------------------------------------------


def test_absent_linkage_fails_closed() -> None:
    """Indirect ingress without source_influence linkage fails closed.

    The projection must not produce a candidate when the ingress entry point
    is indirect and no explicit source_influence link provides an alternative
    requirement derivation path.  This is the typed fail-closed behavior for
    unsupported linkage.
    """
    raw = _pattern(conditional=False)
    # The fixture has a direct-ingress entry point.  Replace it with an
    # indirect one to trigger the fail-closed path.
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "indirect"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    result = _project(profile=profile, pattern=raw)
    assert result.candidates == ()
    assert {issue.code for issue in result.infeasibilities} == {
        "unsupported_requirement_derivation"
    }


def test_no_explicit_links_produces_no_observations() -> None:
    """With explicit linkage, only linked postconditions produce observations
    and security assertions.  A security-relevant postcondition without an
    explicit outcome link fails closed at model validation — the security
    assertion cannot be derived from the ``security_relevant`` flag alone.
    """
    raw = _pattern(conditional=False)
    # Remove the terminal step's outcome link while keeping
    # security_relevant=True.  Model validation must reject this: the
    # security-relevant postcondition lacks an observable outcome link.
    raw["canonical_chain"]["steps"][2]["observable_outcome_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    with pytest.raises(ValidationError, match="lacks an observable outcome link"):
        __import__(
            "scenario_forge.models.attack_pattern", fromlist=["AttackPattern"]
        ).AttackPattern.model_validate(raw)


def test_explicit_observable_outcome_link_produces_observation() -> None:
    """An explicit observable_outcome_link produces an ObservationRequirement."""
    raw = _pattern(conditional=False)
    # Add an observable_outcome_link to step 2 (inside, system step).
    raw["canonical_chain"]["steps"][1]["observable_outcome_links"] = [
        {
            "postcondition_id": "post.2",
            "observation": "model_context",
            "binding_slot_id": "ingress",
        }
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "observation" in kinds
    assert "direct_input_control" in kinds
    assert "security_outcome_assertion" in kinds


def test_tool_fixture_link_produces_tool_fixture_requirement() -> None:
    """A tool_fixture resource link produces a StateChangingToolFixtureRequirement."""
    raw = _pattern(conditional=False)
    # Add a tool_fixture link to step 2 (inside, system step).
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {
            "slot_id": "tool",
            "role": "tool_fixture",
            "trust_boundary_slot_id": None,
        }
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "state_changing_tool_fixture" in kinds
    assert "direct_input_control" in kinds
    assert "security_outcome_assertion" in kinds


def test_source_influence_link_produces_upstream_requirement() -> None:
    """A source_influence resource link produces an UpstreamSourceInfluenceRequirement."""
    raw = _pattern(conditional=False)
    # Add a source_influence link to step 2 (inside, system step).
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    # A source_influence chain must not also carry a direct ingress link.
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "upstream_source_influence" in kinds
    assert "direct_input_control" not in kinds
    assert "security_outcome_assertion" in kinds


def test_source_influence_activates_indirect_ingress() -> None:
    """A source_influence link activates a candidate even when the bound
    ingress entry point is indirect.  This is the explicit source-boundary
    to canonical-ingress activation path: no inference from ingress
    controllability, and no direct-input requirement is derived.
    """
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][1]["resource_links"] = [
        {
            "slot_id": "source",
            "role": "source_influence",
            "trust_boundary_slot_id": "boundary",
            "target_ingress_slot_id": "ingress",
        }
    ]
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "indirect"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )
    result = _project(profile=profile, pattern=raw)
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    kinds = {requirement.kind for requirement in candidate.execution_requirements}
    assert "upstream_source_influence" in kinds
    assert "direct_input_control" not in kinds
    assert not any(
        issue.code == "unsupported_requirement_derivation"
        for issue in result.infeasibilities
    )


# ---------------------------------------------------------------------------
# Adversarial tests: activation over selected steps, typed infeasibility
# ---------------------------------------------------------------------------


def test_conditional_activation_omitted_fails_closed() -> None:
    """When the only activation link is on a conditional step that is omitted
    by condition evaluation, the projection must fail closed with a typed
    unsupported-activation issue — not admit indirect ingress."""
    raw = _pattern(conditional=True)
    # The model forbids activation links on conditional steps (no branch
    # semantics), so we test the adjacent failure: remove the ingress link
    # from the required step.1, leaving no activation among selected steps.
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    # step.1 has no ingress link and step.2 has no activation link.
    # No activation among selected steps → typed infeasibility.
    result = _project(pattern=raw)
    assert len(result.candidates) == 0
    assert any(
        issue.code == "unsupported_requirement_derivation"
        and "no activation mechanism" in issue.detail
        for issue in result.infeasibilities
    )


def test_no_selected_activation_produces_typed_infeasibility() -> None:
    """A chain with no activation mechanism among selected steps produces a
    typed unsupported_requirement_derivation issue, not a candidate."""
    raw = _pattern(conditional=False)
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project(pattern=raw)
    assert len(result.candidates) == 0
    assert any(
        issue.code == "unsupported_requirement_derivation"
        and "no activation mechanism" in issue.detail
        for issue in result.infeasibilities
    )


def test_security_assertion_only_from_explicit_outcome_link() -> None:
    """A security-relevant postcondition with an explicit outcome link
    produces a SecurityOutcomeAssertionRequirement.  The assertion is
    traced to the link, not to the security_relevant flag alone."""
    raw = _pattern(conditional=False)
    # The terminal step already has an outcome link from the fixture.
    result = _project(pattern=raw)
    candidate = result.candidates[0]
    sec_reqs = [
        r
        for r in candidate.execution_requirements
        if r.kind == "security_outcome_assertion"
    ]
    assert len(sec_reqs) == 1
    # The observation requirement for the same link should also exist.
    obs_reqs = [r for r in candidate.execution_requirements if r.kind == "observation"]
    assert len(obs_reqs) == 1
