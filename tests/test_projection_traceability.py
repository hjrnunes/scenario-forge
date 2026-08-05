"""Adversarial tests for projection persistence and artifact traceability.

Bead scenario-forge-422o.4: Persist kill-chain projections and enforce
artifact traceability.

Covers:
  - Deep nested mutation detection
  - Omitted/reordered/duplicated projected steps
  - Unprojected security actions
  - Incomplete many-to-many coverage
  - Incorrect resource/ingress binding
  - Forged opaque IDs
  - Postcondition/assertion mismatch
  - OR trees prohibited
  - Verify-only recomputation drift
  - Ingress identity mismatch
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from scenario_forge.models.attack_pattern import (
    AttackPattern,
    AuthoritativeFactReference,
    EntryPointResourceReference,
    EvaluatedFactEvidence,
    compute_chain_semantic_digest,
)
from scenario_forge.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ImpactAction,
    InitialIngressAction,
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
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolationCode,
)
from scenario_forge.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
    ScenarioEnvelope,
)
from scenario_forge.pipeline.projection import (
    ProjectionBudget,
    capture_capability_snapshot,
    project_authoritative_candidates,
)
from scenario_forge.pipeline.projection_validation import (
    validate_projection_traceability,
)

ZERO = "0" * 64


# ---------------------------------------------------------------------------#
# Taxonomy resolver
# ---------------------------------------------------------------------------#


class TaxonomyResolver:
    def __init__(self, context: Any) -> None:
        self.taxonomy_context = context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        return (taxonomy, identifier) in {
            ("ATLAS", "AML.T0001"),
        }


# ---------------------------------------------------------------------------#
# Pattern/chain fixtures
# ---------------------------------------------------------------------------#


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


def _pattern(*, conditional: bool = True) -> dict[str, Any]:
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
    resolver = TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
    batch = project_authoritative_candidates(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=100),
    )
    assert len(batch.candidates) >= 1
    return batch.candidates[0], resolver, snapshot, raw


def _ingress_id() -> str:
    """Get the canonical ingress entry_point_id from the projection."""
    candidate, _, _, _ = _project()
    return candidate.canonical_ingress.entry_point_id


# ---------------------------------------------------------------------------#
# Build a valid ProjectionEnvelopeBlock + ScenarioEnvelope
# ---------------------------------------------------------------------------#


def _make_block(
    *,
    narrative_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    tree_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    behavior_realizations: tuple[ArtifactRealizationMapping, ...] | None = None,
    assertion_realizations: tuple[AssertionRealizationMapping, ...] | None = None,
) -> ProjectionEnvelopeBlock:
    candidate, _, _, _ = _project()
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
        # Map assertions to the terminal step's security-relevant postcondition.
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
        narrative_realizations=narrative_realizations,
        tree_realizations=tree_realizations,
        behavior_realizations=behavior_realizations,
        assertion_realizations=assertion_realizations,
    )


def _make_tree(ingress_id: str) -> AttackTree:
    """Build a minimal valid AND-only attack tree matching the projection."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Achieve attack objective",
        root=AttackTreeNode(
            id="n1",
            label="Attack goal",
            gate=GateType.AND,
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Initial ingress",
                    gate=GateType.LEAF,
                    zone="input",
                    action=InitialIngressAction(entry_point_id=ingress_id),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="System action",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Impact",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=ImpactAction(boundary="internal", target="data integrity"),
                ),
            ],
        ),
    )


def _make_narrative(ingress_id: str) -> NarrativeLayer:
    return NarrativeLayer(
        title="Test scenario",
        summary="Adversarial summary",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1, zone="input", action="gain access", effect="entry"
            ),
            NarrativeStep(
                step_number=2, zone="reasoning", action="exploit", effect="control"
            ),
            NarrativeStep(
                step_number=3, zone="reasoning", action="impact", effect="damage"
            ),
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id=ingress_id,
            responsible_step_number=1,
        ),
    )


def _make_envelope(
    block: ProjectionEnvelopeBlock | None = None,
    *,
    tree: AttackTree | None = None,
    narrative: NarrativeLayer | None = None,
    actor: ActorProfile | None = None,
    initial_entry_point_id: str | None = None,
) -> ScenarioEnvelope:
    if block is None:
        block = _make_block()
    ingress_id = block.canonical_ingress.entry_point_id
    if tree is None:
        tree = _make_tree(ingress_id)
    if narrative is None:
        narrative = _make_narrative(ingress_id)
    if actor is None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["target has chat interface"],
            desires=["steal data"],
            intentions=["prompt injection"],
            resources=["open-source tools"],
            access=ActorAccessProvenance(
                initial_entry_point_id=ingress_id,
                ingress_mode="direct",
                access_class="public",
            ),
        )
    if initial_entry_point_id is None:
        initial_entry_point_id = ingress_id

    from datetime import UTC, datetime

    return ScenarioEnvelope(
        scenario_id="scenario:v2:" + "a" * 64,
        candidate_id="cand:v1:" + "b" * 32,
        version=1,
        generated_at=datetime.now(UTC),
        generator_version="test",
        initial_entry_point_id=initial_entry_point_id,
        actor_profile=actor,
        projection=block,
        narrative=narrative,
        attack_tree=tree,
        behavior_spec="Feature: test",
        faceting=_make_faceting(),
        priority=_make_priority(),
        generation=_make_generation(),
    )


def _make_faceting():
    from scenario_forge.models.scenario import (
        ArchitectureMatch,
        CapabilityProfileRef,
        FacetingMetadata,
        RiskCardRef,
        TaxonomyChain,
    )

    return FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="r1",
            risk_name="Risk",
            risk_description="desc",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="chat",
        ),
        maestro_layers=[3],
    )


def _make_priority():
    from scenario_forge.models.scenario import (
        ArchitectureMatch,
        AttackComplexity,
        LikelihoodLevel,
        Priority,
        PrioritySignals,
        SeverityLevel,
        StructuralExposureSignal,
        TechniqueMaturity,
    )

    return Priority(
        composite=0.5,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )


def _make_generation():
    from scenario_forge.models.scenario import GenerationMetadata

    return GenerationMetadata(model="test", call_metadata=[])


# ---------------------------------------------------------------------------#
# Tests: valid baseline
# ---------------------------------------------------------------------------#


class TestValidBaseline:
    def test_valid_envelope_passes_traceability(self):
        """A well-formed envelope with complete realizations passes validation."""
        envelope = _make_envelope()
        result = validate_projection_traceability(envelope)
        assert result.valid, (
            f"Expected valid, got violations: "
            f"{[(v.code.value, v.stage.value, v.detail) for v in result.violations]}"
        )

    def test_none_projection_returns_valid_empty(self):
        """Envelope without projection returns valid empty result."""
        envelope = _make_envelope()
        envelope.projection = None
        result = validate_projection_traceability(envelope)
        assert result.valid
        assert result.violations == []

    def test_block_is_frozen(self):
        """ProjectionEnvelopeBlock is deeply immutable."""
        block = _make_block()
        with pytest.raises((ValidationError, TypeError)):
            block.projection = None  # type: ignore[misc]

    def test_block_extra_forbid(self):
        """ProjectionEnvelopeBlock rejects extra fields."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
                extra_field="bad",
            )


# ---------------------------------------------------------------------------#
# Tests: deep nested mutation (contract §2)
# ---------------------------------------------------------------------------#


class TestNestedMutation:
    def test_nested_mutation_detected(self):
        """Mutating execution requirements digest after construction is rejected."""
        block = _make_block()
        block_dict = block.model_dump(mode="json")
        # Tamper with the execution requirements digest.
        block_dict["execution_requirements_digest"] = "f" * 64
        with pytest.raises(ValidationError, match="execution_requirements_digest"):
            ProjectionEnvelopeBlock.model_validate(block_dict)

    def test_projection_digest_mutation_detected(self):
        """Mutating the projection_digest field is rejected at model level."""
        block = _make_block()
        block_dict = block.model_dump(mode="json")
        # Tamper with the projection digest.
        block_dict["projection"]["projection_digest"] = "e" * 64
        with pytest.raises(ValidationError, match="projection_digest"):
            ProjectionEnvelopeBlock.model_validate(block_dict)

    def test_nested_requirement_content_mutation_detected(self):
        """Changing execution requirement content is rejected by digest check."""
        block = _make_block()
        block_dict = block.model_dump(mode="json")
        # Tamper with a requirement field — the digest check should catch it.
        if block_dict["execution_requirements"]:
            req = block_dict["execution_requirements"][0]
            if "entry_point_slot_id" in req:
                req["entry_point_slot_id"] = "tampered.slot"
        # The execution_requirements_digest check catches the content change.
        with pytest.raises((ValidationError, ValueError)):
            ProjectionEnvelopeBlock.model_validate(block_dict)


# ---------------------------------------------------------------------------#
# Tests: omitted projected steps (contract §4)
# ---------------------------------------------------------------------------#


class TestOmittedSteps:
    def test_omitted_narrative_step(self):
        """Missing a projected step in narrative realizations is flagged."""
        block = _make_block()
        # Remove the last narrative realization.
        truncated = block.narrative_realizations[:-1]
        block = block.model_copy(
            update={"narrative_realizations": truncated},
        )
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes
        # Verify it's attributed to narrative stage.
        stage = next(
            v.stage
            for v in result.violations
            if v.code == ProjectionTraceabilityViolationCode.incomplete_coverage
        )
        assert stage == ProjectionTraceabilityStage.narrative

    def test_omitted_tree_step(self):
        """Missing a projected step in tree realizations is flagged."""
        block = _make_block()
        truncated = block.tree_realizations[:-1]
        block = block.model_copy(update={"tree_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes

    def test_omitted_behavior_step(self):
        """Missing a projected step in behavior realizations is flagged."""
        block = _make_block()
        truncated = block.behavior_realizations[:-1]
        block = block.model_copy(update={"behavior_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes


# ---------------------------------------------------------------------------#
# Tests: reordered projected steps (contract §5)
# ---------------------------------------------------------------------------#


class TestReorderedSteps:
    def test_reordered_narrative_steps(self):
        """Reordering narrative realizations violates total order."""
        block = _make_block()
        selected = block.selected_step_ids
        # Reverse the narrative realizations — step.3 before step.1.
        reversed_maps = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id=str(i + 1),
                projected_step_ids=(selected[-1 - i],),
            )
            for i in range(len(selected))
        )
        # But we need the element IDs to reference actual narrative steps.
        # Use step numbers that are reversed.
        reversed_maps = tuple(
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id=str(len(selected) - i),
                projected_step_ids=(selected[-1 - i],),
            )
            for i in range(len(selected))
        )
        block = block.model_copy(update={"narrative_realizations": reversed_maps})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.reordered_projected_step in codes


# ---------------------------------------------------------------------------#
# Tests: duplicated projected steps (contract §5)
# ---------------------------------------------------------------------------#


class TestDuplicatedSteps:
    def test_duplicate_element_id_in_narrative(self):
        """Same element_id appearing twice is flagged as duplicate."""
        block = _make_block()
        selected = block.selected_step_ids
        dup = block.narrative_realizations + (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",  # duplicate of first
                projected_step_ids=(selected[1],),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": dup})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.duplicated_projected_step in codes


# ---------------------------------------------------------------------------#
# Tests: unprojected security actions (contract §4)
# ---------------------------------------------------------------------------#


class TestUnprojectedSecurityAction:
    def test_unmapped_security_leaf(self):
        """A security-bearing tree leaf not in realizations is flagged."""
        block = _make_block()
        # Remove the first tree realization (which maps the initial_ingress leaf).
        truncated = block.tree_realizations[1:]
        block = block.model_copy(update={"tree_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.unprojected_security_action in codes


# ---------------------------------------------------------------------------#
# Tests: incomplete many-to-many coverage (contract §5)
# ---------------------------------------------------------------------------#


class TestManyToManyCoverage:
    def test_combine_multiple_steps_in_one_element(self):
        """Combining multiple projected steps in one element is valid."""
        block = _make_block()
        selected = block.selected_step_ids
        # Combine step.1 and step.2 into one narrative element.
        combined = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(selected[0], selected[1]),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="2",
                projected_step_ids=(selected[2],),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": combined})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        # Should be valid — combine preserves order.
        narrative_codes = {
            v.code
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
        }
        assert (
            ProjectionTraceabilityViolationCode.incomplete_coverage
            not in narrative_codes
        )
        assert (
            ProjectionTraceabilityViolationCode.reordered_projected_step
            not in narrative_codes
        )

    def test_split_one_step_across_elements(self):
        """Splitting one projected step across multiple elements is valid."""
        block = _make_block()
        selected = block.selected_step_ids
        # Split step.2 across two narrative elements (shared step).
        split = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(selected[0],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="2",
                projected_step_ids=(selected[1],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="3",
                projected_step_ids=(selected[1],),  # split: shared step
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="4",
                projected_step_ids=(selected[2],),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": split})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        # Split should not trigger reorder (shared step).
        reorder_codes = {
            v.code
            for v in result.violations
            if v.code == ProjectionTraceabilityViolationCode.reordered_projected_step
        }
        assert not reorder_codes


# ---------------------------------------------------------------------------#
# Tests: incorrect resource binding (contract §4)
# ---------------------------------------------------------------------------#


class TestResourceBinding:
    def test_wrong_tool_id_in_tree(self):
        """A tree leaf with a tool_id not in projection bindings is flagged."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        from scenario_forge.models.attack_tree import ToolInvocationAction

        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="wrong tool",
                        gate=GateType.LEAF,
                        zone="tool_execution",
                        action=ToolInvocationAction(
                            tool_id="tool:v1:" + "f" * 32,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                    ),
                ],
            ),
        )
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incorrect_resource_binding in codes


# ---------------------------------------------------------------------------#
# Tests: incorrect ingress binding (contract §7)
# ---------------------------------------------------------------------------#


class TestIngressBinding:
    def test_envelope_ingress_mismatch(self):
        """Envelope initial_entry_point_id mismatching projection is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        envelope = _make_envelope(block, initial_entry_point_id=wrong_id)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes

    def test_actor_ingress_mismatch(self):
        """Actor access initial_entry_point_id mismatch is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["x"],
            desires=["y"],
            intentions=["z"],
            resources=["tools"],
            access=ActorAccessProvenance(
                initial_entry_point_id=wrong_id,
                ingress_mode="direct",
                access_class="public",
            ),
        )
        envelope = _make_envelope(block, actor=actor)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes

    def test_narrative_ingress_mismatch(self):
        """Narrative access_realization initial_entry_point_id mismatch is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        narrative = _make_narrative(block.canonical_ingress.entry_point_id)
        narrative = narrative.model_copy(
            update={
                "access_realization": NarrativeAccessRealization(
                    initial_entry_point_id=wrong_id,
                    responsible_step_number=1,
                )
            }
        )
        envelope = _make_envelope(block, narrative=narrative)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes

    def test_tree_ingress_mismatch(self):
        """Tree leaf with wrong initial_ingress entry_point_id is flagged."""
        block = _make_block()
        wrong_id = "ep:v1:" + "9" * 32
        tree = _make_tree(wrong_id)
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.ingress_identity_mismatch in codes


# ---------------------------------------------------------------------------#
# Tests: forged opaque IDs (contract §3, §9)
# ---------------------------------------------------------------------------#


class TestForgedOpaqueIds:
    def test_forged_step_id_in_narrative(self):
        """A realization mapping claiming an unprojected step is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        forged = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(selected[0],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="2",
                projected_step_ids=(selected[1],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="3",
                projected_step_ids=(selected[2],),
            ),
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="4",
                projected_step_ids=("fake.step.id",),
            ),
        )
        block = block.model_copy(update={"narrative_realizations": forged})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes

    def test_forged_tree_leaf_id(self):
        """A tree realization referencing a nonexistent leaf is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        forged_tree = (
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.attack_tree,
                element_id="n1.nonexistent",
                projected_step_ids=(selected[0],),
            ),
        )
        block = block.model_copy(update={"tree_realizations": forged_tree})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.forged_opaque_id in codes


# ---------------------------------------------------------------------------#
# Tests: postcondition/assertion mismatch (contract §4)
# ---------------------------------------------------------------------------#


class TestPostconditionMismatch:
    def test_assertion_references_nonexistent_postcondition(self):
        """An assertion referencing a nonexistent postcondition is flagged."""
        block = _make_block()
        selected = block.selected_step_ids
        bad_assertions = (
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=(selected[-1],),
                projected_postcondition_ids=("fake.postcondition",),
            ),
        )
        block = block.model_copy(update={"assertion_realizations": bad_assertions})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch
            in codes
        )

    def test_assertion_claims_postcondition_from_wrong_step(self):
        """An assertion claiming a postcondition without listing its step."""
        block = _make_block()
        selected = block.selected_step_ids
        chain = block.projection.source_chain
        # Get a postcondition from step.1 but only list step.3 in source.
        step1 = chain.steps[0]
        bad_assertions = (
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=(selected[-1],),  # step.3
                projected_postcondition_ids=(
                    step1.observable_postconditions[0].postcondition_id,
                ),
            ),
        )
        block = block.model_copy(update={"assertion_realizations": bad_assertions})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert (
            ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch
            in codes
        )

    def test_missing_security_postcondition_assertion(self):
        """Security-relevant postconditions must be covered by assertions."""
        block = _make_block()
        # Empty assertions — terminal step has a security-relevant postcondition.
        block = block.model_copy(update={"assertion_realizations": ()})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.incomplete_coverage in codes


# ---------------------------------------------------------------------------#
# Tests: OR tree prohibited (contract §6)
# ---------------------------------------------------------------------------#


class TestOrTreeProhibited:
    def test_or_node_in_tree(self):
        """An OR node in the attack tree is flagged."""
        block = _make_block()
        ingress_id = block.canonical_ingress.entry_point_id
        tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Attack",
            root=AttackTreeNode(
                id="n1",
                label="goal",
                gate=GateType.AND,
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate=GateType.LEAF,
                        zone="input",
                        action=InitialIngressAction(entry_point_id=ingress_id),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="alternatives",
                        gate=GateType.OR,
                        children=[
                            AttackTreeNode(
                                id="n1.2.1",
                                label="option A",
                                gate=GateType.LEAF,
                                zone="reasoning",
                                action=AiSystemAction(),
                            ),
                            AttackTreeNode(
                                id="n1.2.2",
                                label="option B",
                                gate=GateType.LEAF,
                                zone="reasoning",
                                action=AiSystemAction(),
                            ),
                        ],
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate=GateType.LEAF,
                        zone="reasoning",
                        action=ImpactAction(boundary="internal", target="integrity"),
                    ),
                ],
            ),
        )
        envelope = _make_envelope(block, tree=tree)
        result = validate_projection_traceability(envelope)
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.or_tree_prohibited in codes


# ---------------------------------------------------------------------------#
# Tests: verify-only recomputation drift (contract §2)
# ---------------------------------------------------------------------------#


class TestRecomputationDrift:
    def test_drift_detected_when_source_chain_differs(self):
        """When authoritative pattern is supplied, chain mismatch is flagged."""
        envelope = _make_envelope()
        # Supply a different pattern (different name → different pattern_pin).
        raw = _pattern()
        raw["name"] = "Different Pattern"
        raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
            raw["canonical_chain"]
        )
        pattern = AttackPattern.model_validate(raw)
        resolver = TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        snapshot = capture_capability_snapshot(_profile(), (_evidence(),))
        result = validate_projection_traceability(
            envelope,
            authoritative_pattern=raw,
            taxonomy_resolver=resolver,
            capability_snapshot=snapshot,
            expected_catalog_pin="0" * 64,
        )
        codes = {v.code for v in result.violations}
        assert ProjectionTraceabilityViolationCode.projection_drift in codes

    def test_no_drift_when_authoritative_inputs_match(self):
        """When authoritative inputs match, no drift violations."""
        _candidate, resolver, snapshot, raw = _project()
        envelope = _make_envelope()
        # Compute the expected catalog pin the same way projection does.
        from scenario_forge.pipeline.projection import _content_pin, _pattern_pin

        pattern = AttackPattern.model_validate(raw)
        pp = _pattern_pin(pattern)
        catalog_pin = _content_pin("scenario-forge:authoritative-catalog:v1", [pp])
        result = validate_projection_traceability(
            envelope,
            authoritative_pattern=raw,
            taxonomy_resolver=resolver,
            capability_snapshot=snapshot,
            expected_catalog_pin=catalog_pin,
        )
        drift_codes = {
            v.code
            for v in result.violations
            if v.code
            in (
                ProjectionTraceabilityViolationCode.projection_drift,
                ProjectionTraceabilityViolationCode.requirement_drift,
            )
        }
        assert not drift_codes, (
            f"Expected no drift violations, got: "
            f"{[(v.code.value, v.detail) for v in result.violations if v.code in drift_codes]}"
        )


# ---------------------------------------------------------------------------#
# Tests: typed violation attribution (contract §8)
# ---------------------------------------------------------------------------#


class TestViolationAttribution:
    def test_narrative_violation_attributed_to_narrative_stage(self):
        """Narrative-stage violations are attributed to the narrative stage."""
        block = _make_block()
        truncated = block.narrative_realizations[:-1]
        block = block.model_copy(update={"narrative_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        narrative_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.narrative
        ]
        assert len(narrative_violations) > 0

    def test_tree_violation_attributed_to_tree_stage(self):
        """Tree-stage violations are attributed to the attack_tree stage."""
        block = _make_block()
        truncated = block.tree_realizations[:-1]
        block = block.model_copy(update={"tree_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        tree_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.attack_tree
        ]
        assert len(tree_violations) > 0

    def test_behavior_violation_attributed_to_behavior_stage(self):
        """Behavior-stage violations are attributed to the behavior_spec stage."""
        block = _make_block()
        truncated = block.behavior_realizations[:-1]
        block = block.model_copy(update={"behavior_realizations": truncated})
        envelope = _make_envelope(block)
        result = validate_projection_traceability(envelope)
        behavior_violations = [
            v
            for v in result.violations
            if v.stage == ProjectionTraceabilityStage.behavior_spec
        ]
        assert len(behavior_violations) > 0


# ---------------------------------------------------------------------------#
# Tests: realization mapping model validation
# ---------------------------------------------------------------------------#


class TestRealizationModelValidation:
    def test_artifact_mapping_requires_unique_steps(self):
        """ArtifactRealizationMapping rejects duplicate projected_step_ids."""
        with pytest.raises(ValidationError):
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=("step.1", "step.1"),
            )

    def test_assertion_mapping_requires_unique_postconditions(self):
        """AssertionRealizationMapping rejects duplicate postcondition IDs."""
        with pytest.raises(ValidationError):
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=("step.1",),
                projected_postcondition_ids=("post.1", "post.1"),
            )

    def test_assertion_mapping_requires_unique_source_steps(self):
        """AssertionRealizationMapping rejects duplicate source step IDs."""
        with pytest.raises(ValidationError):
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=("step.1", "step.1"),
                projected_postcondition_ids=("post.1",),
            )

    def test_block_ingress_must_match_projection(self):
        """Block canonical_ingress must match the projection's ingress binding."""
        candidate, _, _, _ = _project()
        wrong_ingress = EntryPointResourceReference(
            kind="entry_point",
            entry_point_id="ep:v1:" + "9" * 32,
        )
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=wrong_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
            )


# ---------------------------------------------------------------------------#
# Schema / model parity and persistence round-trip (contract §1, §2)
# ---------------------------------------------------------------------------#


class TestProjectionEnvelopeBlockSchemaParity:
    """Schema/model parity for ProjectionEnvelopeBlock and related models."""

    def test_block_model_json_schema_is_valid(self):
        """ProjectionEnvelopeBlock generates valid JSON Schema."""
        import jsonschema

        schema = ProjectionEnvelopeBlock.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_block_has_schema_version_const(self):
        """schema_version is a Literal['1'] const."""
        schema = ProjectionEnvelopeBlock.model_json_schema()
        sv = schema["properties"]["schema_version"]
        assert sv.get("const") == "1"

    def test_block_extra_forbid_in_json_schema(self):
        """additionalProperties is False."""
        schema = ProjectionEnvelopeBlock.model_json_schema()
        assert schema.get("additionalProperties") is False

    def test_envelope_schema_includes_projection_defs(self):
        """ScenarioEnvelope JSON schema includes projection-related $defs."""
        from scenario_forge.models.scenario import ScenarioEnvelope

        schema = ScenarioEnvelope.model_json_schema()
        defs = schema.get("$defs", {})
        for name in [
            "ProjectionEnvelopeBlock",
            "ProjectionTraceabilityResult",
            "ProjectionTraceabilityViolation",
            "ArtifactRealizationMapping",
            "AssertionRealizationMapping",
        ]:
            assert name in defs, f"Missing $def: {name}"

    def test_envelope_schema_includes_projection_properties(self):
        """ScenarioEnvelope JSON schema includes projection properties."""
        from scenario_forge.models.scenario import ScenarioEnvelope

        schema = ScenarioEnvelope.model_json_schema()
        props = schema.get("properties", {})
        assert "projection" in props
        assert "projection_traceability" in props

    def test_hand_schema_includes_projection_properties(self):
        """Hand-maintained JSON schema includes projection properties."""
        import json
        from pathlib import Path

        path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        hand = json.loads(path.read_text(encoding="utf-8"))
        props = hand.get("properties", {})
        assert "projection" in props
        assert "projection_traceability" in props
        defs = hand.get("$defs", {})
        for name in [
            "ProjectionEnvelopeBlock",
            "ProjectionTraceabilityResult",
            "ArtifactRealizationMapping",
            "AssertionRealizationMapping",
        ]:
            assert name in defs, f"Missing hand schema $def: {name}"

    def test_violation_code_enum_complete(self):
        """ProjectionTraceabilityViolationCode has all expected codes."""
        expected_codes = {
            "omitted_projected_step",
            "reordered_projected_step",
            "duplicated_projected_step",
            "unprojected_security_action",
            "incomplete_coverage",
            "incorrect_resource_binding",
            "incorrect_ingress_binding",
            "forged_opaque_id",
            "postcondition_assertion_mismatch",
            "or_tree_prohibited",
            "projection_drift",
            "nested_mutation",
            "ingress_identity_mismatch",
            "requirement_drift",
        }
        actual = {c.value for c in ProjectionTraceabilityViolationCode}
        assert actual == expected_codes

    def test_stage_enum_complete(self):
        """ProjectionTraceabilityStage has all expected stages."""
        expected = {"actor_profile", "narrative", "attack_tree", "behavior_spec"}
        actual = {s.value for s in ProjectionTraceabilityStage}
        assert actual == expected


class TestProjectionEnvelopeBlockPersistence:
    """Persistence round-trip and deep mutation tests."""

    def test_round_trip_json(self):
        """Block survives JSON round-trip without drift."""
        block = _make_block()
        data = block.model_dump(mode="json")
        restored = ProjectionEnvelopeBlock.model_validate(data)
        assert restored == block

    def test_round_trip_with_realizations(self):
        """Block with realizations survives JSON round-trip."""
        block = _make_block()
        block = block.model_copy(
            update={
                "narrative_realizations": (
                    ArtifactRealizationMapping(
                        artifact_stage=ArtifactStage.narrative,
                        element_id="1",
                        projected_step_ids=("step.1",),
                    ),
                ),
            }
        )
        data = block.model_dump(mode="json")
        restored = ProjectionEnvelopeBlock.model_validate(data)
        assert restored == block
        assert restored.narrative_realizations == block.narrative_realizations

    def test_round_trip_envelope_with_projection(self):
        """Full envelope with projection survives JSON round-trip."""
        envelope = _make_envelope()
        assert envelope.projection is not None
        data = envelope.model_dump(mode="json")
        restored = ScenarioEnvelope.model_validate(data)
        assert restored.projection == envelope.projection

    def test_nested_mutation_detected_after_round_trip(self):
        """Mutating the JSON data before re-validation is detected."""
        block = _make_block()
        data = block.model_dump(mode="json")
        # Tamper with a step ID in the projection snapshot.
        data["projection"]["selected_step_ids"][0] = "forged.step"
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock.model_validate(data)

    def test_execution_requirements_tamper_detected(self):
        """Tampering with execution requirements is detected by digest."""
        block = _make_block()
        data = block.model_dump(mode="json")
        # Tamper with a requirement field.
        if data["execution_requirements"]:
            data["execution_requirements"][0]["requirement_id"] = "forged.req"
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock.model_validate(data)


class TestAdversarialSchemaValidation:
    """Adversarial tests for the modified public validation surfaces."""

    def test_block_rejects_extra_fields(self):
        """ProjectionEnvelopeBlock rejects unknown fields."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
                unknown_field="evil",
            )

    def test_block_rejects_missing_projection(self):
        """ProjectionEnvelopeBlock rejects missing projection field."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
            )

    def test_block_rejects_missing_canonical_ingress(self):
        """ProjectionEnvelopeBlock rejects missing canonical_ingress."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                ingress_controllability=candidate.ingress_controllability,
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
            )

    def test_block_rejects_wrong_ingress_controllability(self):
        """ProjectionEnvelopeBlock rejects invalid ingress_controllability."""
        candidate, _, _, _ = _project()
        with pytest.raises(ValidationError):
            ProjectionEnvelopeBlock(
                projection=candidate.projection,
                canonical_ingress=candidate.canonical_ingress,
                ingress_controllability="sideways",
                projected_mappings=candidate.projected_mappings,
                execution_requirements=candidate.execution_requirements,
                execution_requirements_digest=candidate.execution_requirements_digest,
            )

    def test_artifact_mapping_rejects_empty_step_ids(self):
        """ArtifactRealizationMapping rejects empty projected_step_ids."""
        with pytest.raises(ValidationError):
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="1",
                projected_step_ids=(),
            )

    def test_artifact_mapping_rejects_empty_element_id(self):
        """ArtifactRealizationMapping rejects empty element_id."""
        with pytest.raises(ValidationError):
            ArtifactRealizationMapping(
                artifact_stage=ArtifactStage.narrative,
                element_id="",
                projected_step_ids=("step.1",),
            )

    def test_assertion_mapping_rejects_empty_postcondition_ids(self):
        """AssertionRealizationMapping rejects empty postcondition IDs."""
        with pytest.raises(ValidationError):
            AssertionRealizationMapping(
                element_id="assert-1",
                source_step_ids=("step.1",),
                projected_postcondition_ids=(),
            )

    def test_traceability_result_rejects_extra_fields(self):
        """ProjectionTraceabilityResult rejects extra fields."""
        from scenario_forge.models.projection_envelope import (
            ProjectionTraceabilityResult,
        )

        with pytest.raises(ValidationError):
            ProjectionTraceabilityResult(
                valid=True,
                violations=[],
                evil_field="bad",
            )

    def test_traceability_violation_rejects_extra_fields(self):
        """ProjectionTraceabilityViolation rejects extra fields."""
        from scenario_forge.models.projection_envelope import (
            ProjectionTraceabilityViolation,
        )

        with pytest.raises(ValidationError):
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.or_tree_prohibited,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail="test",
                evil="bad",
            )

    def test_traceability_violation_requires_detail(self):
        """ProjectionTraceabilityViolation requires non-empty detail."""
        from scenario_forge.models.projection_envelope import (
            ProjectionTraceabilityViolation,
        )

        with pytest.raises(ValidationError):
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.or_tree_prohibited,
                stage=ProjectionTraceabilityStage.attack_tree,
                detail="",
            )

    def test_envelope_with_projection_validates_against_hand_schema(self):
        """An envelope with projection validates against the hand JSON schema."""
        import json
        from pathlib import Path

        import jsonschema

        envelope = _make_envelope()
        path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        hand = json.loads(path.read_text(encoding="utf-8"))
        envelope_dict = envelope.model_dump(mode="json")
        jsonschema.validate(envelope_dict, hand)


class TestValidatorNoProjection:
    """Validator behavior when projection is absent."""

    def test_no_projection_returns_valid(self):
        """Envelope without projection returns valid result."""
        envelope = _make_envelope()
        envelope = envelope.model_copy(update={"projection": None})
        result = validate_projection_traceability(envelope)
        assert result.valid is True
        assert result.violations == []

    def test_none_projection_traceability_field_default(self):
        """projection_traceability defaults to None on ScenarioEnvelope."""
        envelope = _make_envelope()
        assert envelope.projection_traceability is None


class TestComputeExecutionRequirementsDigest:
    """Tests for the public compute_execution_requirements_digest function."""

    def test_digest_matches_candidate(self):
        """Digest matches the one computed during projection."""
        from scenario_forge.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        candidate, _, _, _ = _project()
        digest = compute_execution_requirements_digest(candidate.execution_requirements)
        assert digest == candidate.execution_requirements_digest

    def test_digest_differs_for_different_requirements(self):
        """Different requirements produce different digests."""
        from scenario_forge.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        candidate, _, _, _ = _project()
        original = compute_execution_requirements_digest(
            candidate.execution_requirements
        )
        # Tamper with requirements by passing a dict with wrong ID
        reqs_data = [
            r.model_dump(mode="json") for r in candidate.execution_requirements
        ]
        if reqs_data:
            reqs_data[0]["requirement_id"] = "forged.req"
        tampered = compute_execution_requirements_digest(reqs_data)
        assert tampered != original

    def test_digest_accepts_dicts(self):
        """Digest computation accepts pre-serialized dicts."""
        from scenario_forge.pipeline.projection import (
            compute_execution_requirements_digest,
        )

        candidate, _, _, _ = _project()
        reqs_data = [
            r.model_dump(mode="json") for r in candidate.execution_requirements
        ]
        digest = compute_execution_requirements_digest(reqs_data)
        assert digest == candidate.execution_requirements_digest
