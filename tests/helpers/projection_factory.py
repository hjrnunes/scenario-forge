"""Shared test helpers for constructing valid ProjectionEnvelopeBlocks.

Provides factory functions that build a minimal valid projection block
from an authoritative canonical attack pattern, so that tests which
construct ``ScenarioEnvelope`` directly can satisfy the mandatory
``projection`` field without duplicating the full projection pipeline.
"""

from __future__ import annotations

from typing import Any

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
from scenario_forge.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    AssertionRealizationMapping,
    ProjectionEnvelopeBlock,
)
from scenario_forge.models.scenario import (
    BehaviorAction,
    BehaviorAssertion,
    BehaviorSpec,
)
from scenario_forge.pipeline.projection import (
    ProjectionBudget,
    capture_capability_snapshot,
    compute_derivation_context_digest,
    project_authoritative_candidates,
)

ZERO = "0" * 64


class _TaxonomyResolver:
    """Minimal taxonomy resolver for test fixtures."""

    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in {
            ("ATLAS", "AML.T0001"),
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
        "condition": (
            {
                "op": "equality",
                "schema_version": "1",
                "fact": _fact(),
                "value": "active",
            }
            if conditional
            else None
        ),
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
            [{"slot_id": "ingress", "role": "ingress", "trust_boundary_slot_id": None}]
            if attacker
            else [
                {
                    "slot_id": "tool",
                    "role": "tool_fixture",
                    "trust_boundary_slot_id": None,
                }
            ]
            if order == 2
            else []
        ),
        "observable_outcome_links": (
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


def _pattern() -> dict[str, Any]:
    chain = {
        "schema_version": "v1",
        "pattern_id": "AP-T1-01",
        "chain_id": "chain.1",
        "semantic_revision": 1,
        "semantic_digest": ZERO,
        "taxonomy_context": {
            "atlas": {"release": "v1", "digest": ZERO},
            "laaf": None,
            "mapping_set_digest": ZERO,
        },
        "mappings": [{"decision": "exact", "taxonomy": "ATLAS", "ids": ["AML.T0001"]}],
        "steps": [
            _step("step.1", 1),
            _step("step.2", 2, conditional=True),
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


def _profile() -> CapabilityProfile:
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


def _evidence(value: str = "active") -> EvaluatedFactEvidence:
    return EvaluatedFactEvidence(
        fact=AuthoritativeFactReference.model_validate(_fact()),
        status="present",
        value=value,
    )


def _project():
    """Project candidates and return the first candidate + resolver + snapshot."""
    raw = _pattern()
    pattern = AttackPattern.model_validate(raw)
    resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    batch = project_authoritative_candidates(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=100),
    )
    assert len(batch.candidates) >= 1
    return batch.candidates[0], resolver, snapshot, raw


# Cache the projected candidate to avoid recomputing on every test.
_cached: tuple[Any, ...] | None = None


def _cached_project():
    global _cached
    if _cached is None:
        _cached = _project()
    return _cached


def get_projected_candidate():
    """Return the shared test ProjectedCandidate."""
    return _cached_project()[0]


def get_canonical_ingress_id() -> str:
    """Return the canonical ingress entry_point_id from the test projection."""
    return get_projected_candidate().canonical_ingress.entry_point_id


def make_projection_block(
    *,
    narrative_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    tree_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    behavior_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    assertion_realizations: tuple[AssertionRealizationMapping, ...] | None = None,
) -> ProjectionEnvelopeBlock:
    """Build a valid ProjectionEnvelopeBlock from the shared test projection.

    Defaults to one-to-one realization mappings for all selected steps.
    """
    candidate = get_projected_candidate()
    selected = candidate.projection.selected_step_ids

    if narrative_realizations is None:
        narrative_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id=str(i + 1),
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
    if tree_realizations is None:
        tree_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id=f"n1.{i + 1}",
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
    if behavior_realizations is None:
        behavior_realizations = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.behavior,
                element_id=f"behavior-{i + 1}",
                projected_step_ids=(sid,),
            )
            for i, sid in enumerate(selected)
        )
    if assertion_realizations is None:
        chain = candidate.projection.source_chain
        terminal_step = chain.steps[-1]
        assertion_realizations = (
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=(terminal_step.step_id,),
                projected_postcondition_ids=(
                    terminal_step.observable_postconditions[0].postcondition_id,
                ),
            ),
        )

    return ProjectionEnvelopeBlock(
        projection=candidate.projection,
        canonical_ingress=candidate.canonical_ingress,
        ingress_controllability=candidate.ingress_controllability,
        projected_mappings=candidate.projected_mappings,
        execution_requirements=candidate.execution_requirements,
        requirement_derivation_version=candidate.requirement_derivation_version,
        execution_requirements_digest=candidate.execution_requirements_digest,
        derivation_context_digest=compute_derivation_context_digest(
            candidate.projection.projection_digest,
            candidate.projection.source_chain.pattern_id,
            candidate.ingress_controllability,
        ),
        narrative_realizations=narrative_realizations,
        tree_realizations=tree_realizations,
        behavior_realizations=behavior_realizations,
        assertion_realizations=assertion_realizations,
    )


def get_test_resolver():
    """Return the shared test TaxonomyResolver."""
    return _cached_project()[1]


def get_test_snapshot():
    """Return the shared test CapabilityFactSnapshot."""
    return _cached_project()[2]


def get_test_raw_pattern() -> dict[str, Any]:
    """Return the shared test raw pattern dict."""
    return _cached_project()[3]


def make_behavior_spec(
    gherkin_text: str | None = None,
) -> BehaviorSpec:
    """Build a minimal valid BehaviorSpec for tests that need one.

    Actions and assertions are derived from the shared test projection's
    selected steps and security-relevant postconditions.  The Gherkin
    text is deterministically rendered from the structured actions and
    assertions to prove exact correspondence.
    """
    candidate = get_projected_candidate()
    selected = candidate.projection.selected_step_ids
    chain = candidate.projection.source_chain
    security_pcs = {
        step.step_id: [
            pc.postcondition_id
            for pc in step.observable_postconditions
            if pc.security_relevant
        ]
        for step in chain.steps
        if step.step_id in set(selected)
    }

    actions = [
        BehaviorAction(
            action_id=f"behavior-{i + 1}",
            projected_step_ids=(sid,),
            source_leaf_id=f"n1.{i + 1}",
            gherkin_keyword="When",
            text=f"Action for {sid}",
        )
        for i, sid in enumerate(selected)
    ]

    assertions: list[BehaviorAssertion] = []
    for step_id, pc_ids in security_pcs.items():
        if pc_ids:
            assertions.append(
                BehaviorAssertion(
                    assertion_id=f"assert-{step_id}-{'-'.join(pc_ids)}",
                    source_step_ids=(step_id,),
                    projected_postcondition_ids=tuple(pc_ids),
                    gherkin_keyword="Then",
                    text=f"Verify postconditions for {step_id}",
                )
            )

    # Deterministically render Gherkin from the structured behavior.
    from scenario_forge.pipeline.generate.assembly import (
        render_gherkin_from_behavior_spec,
    )

    # Build zone map from projected steps' boundary positions.
    # Use the narrative zones as a fallback.
    zone_map: dict[str, str] = {}
    for i, action in enumerate(actions):
        # Map behavior action to a zone from the projection step.
        step = next(
            (s for s in chain.steps if s.step_id in action.projected_step_ids),
            None,
        )
        if step is not None:
            if step.boundary_position == "crossing":
                zone_map[action.action_id] = "input"
            elif step.boundary_position == "inside":
                zone_map[action.action_id] = "reasoning"
            elif step.boundary_position == "outside":
                zone_map[action.action_id] = "tool_execution"

    rendered = render_gherkin_from_behavior_spec(actions, assertions, zone_map=zone_map)

    return BehaviorSpec(
        actions=tuple(actions),
        assertions=tuple(assertions),
        gherkin_text=rendered,
    )
