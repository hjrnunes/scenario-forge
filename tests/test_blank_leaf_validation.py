"""Tests for blank-leaf validation (technique annotation floor safety net).

Covers:
- Trees with all leaves annotated pass cleanly
- Leaf nodes without technique_id are flagged
- AND/OR gate nodes without technique_id are NOT flagged (only leaves matter)
- Mixed trees: annotated and blank leaves
- Deep trees with nested blank leaves
- Empty scenario list
- Warning logging on flagged scenarios
"""

from __future__ import annotations

from datetime import datetime

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.scenario import (
    ArchitectureMatch,
    AttackComplexity,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeLayer,
    NarrativeStep,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SeverityLevel,
    StructuralExposureSignal,
    TaxonomyChain,
    TechniqueMaturity,
)
from scenario_forge.pipeline.validation import (
    BlankLeafViolation,
    validate_blank_leaves,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_envelope(
    root: AttackTreeNode,
    scenario_id: str = "AP-T7-01-abc123",
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope with a custom tree root."""
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft a malicious prompt.",
                effect="The system processes the input.",
            ),
        ],
    )

    attack_tree = AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Compromise the system",
        root=root,
    )

    faceting = FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            atlas_technique_ids=["AML.T0054"],
            scenario_seed="AP-T7-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts (zone 1)",
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )

    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Tests: all leaves annotated -> clean
# ---------------------------------------------------------------------------


class TestAllLeavesAnnotated:
    """Trees where every leaf has a technique_id should pass cleanly."""

    def test_simple_tree_all_annotated(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root attack",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Manipulate reasoning output",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0054",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_deep_tree_all_annotated(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Stage 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject via prompt",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0054",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Inject via context",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0054",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Propagate in reasoning",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0054",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_empty_list(self) -> None:
        result = validate_blank_leaves([])
        assert result.clean_count == 0
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: blank leaves are flagged
# ---------------------------------------------------------------------------


class TestBlankLeavesFlagged:
    """Leaf nodes missing technique_id should be flagged."""

    def test_single_blank_leaf(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject prompt payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Propagate to reasoning layer",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id -- blank leaf
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.flagged_count == 1
        assert result.clean_count == 0
        flagged_scenario, violations = result.flagged_scenarios[0]
        assert flagged_scenario.scenario_id == "AP-T7-01-abc123"
        assert len(violations) == 1
        assert violations[0].node_id == "n1.2"
        assert violations[0].zone == "reasoning"

    def test_multiple_blank_leaves(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Craft injection payload",
                    gate=GateType.LEAF,
                    zone="input",
                    # No technique_id
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Effect propagates downstream",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.flagged_count == 1
        _, violations = result.flagged_scenarios[0]
        assert len(violations) == 2
        node_ids = {v.node_id for v in violations}
        assert node_ids == {"n1.1", "n1.2"}

    def test_consequence_leaf_also_flagged(self) -> None:
        """Unlike leaf technique provenance, blank-leaf has NO consequence exemption."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Victim transfers funds to attacker account",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id -- flagged even though it looks like a consequence
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.flagged_count == 1
        _, violations = result.flagged_scenarios[0]
        assert len(violations) == 1
        assert violations[0].node_id == "n1.2"

    def test_deeply_nested_blank_leaf(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Stage 1",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0054",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Manipulate tool execution",
                            gate=GateType.LEAF,
                            zone="tool_execution",
                            # No technique_id
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Stage 2",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0054",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.flagged_count == 1
        _, violations = result.flagged_scenarios[0]
        assert len(violations) == 1
        assert violations[0].node_id == "n1.1.2"
        assert violations[0].label == "Manipulate tool execution"


# ---------------------------------------------------------------------------
# Tests: AND/OR gate nodes without technique_id are NOT flagged
# ---------------------------------------------------------------------------


class TestGateNodesNotFlagged:
    """AND/OR gate nodes without technique_id should NOT be flagged."""

    def test_or_gate_no_technique_id_not_flagged(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root OR gate",
            gate=GateType.OR,
            zone="input",
            # No technique_id on this OR gate -- that's fine
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0054",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_and_gate_no_technique_id_not_flagged(self) -> None:
        root = AttackTreeNode(
            id="n1",
            label="Root AND gate",
            gate=GateType.AND,
            zone="input",
            # No technique_id on this AND gate -- that's fine
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Nested OR",
                    gate=GateType.OR,
                    zone="input",
                    # No technique_id on this OR gate -- also fine
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0054",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Alternative injection",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0054",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Downstream effect",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0054",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_gates_without_technique_leaves_with(self) -> None:
        """Gates without technique_id + all leaves with technique_id = clean."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Sub-gate",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Leaf A",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0054",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Leaf B",
                            gate=GateType.LEAF,
                            zone="reasoning",
                            technique_id="AML.T0054",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Leaf C",
                    gate=GateType.LEAF,
                    zone="tool_execution",
                    technique_id="AML.T0054",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = validate_blank_leaves([scenario])

        assert result.clean_count == 1
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: mixed batch
# ---------------------------------------------------------------------------


class TestMixedBatch:
    """A batch with both clean and flagged scenarios."""

    def test_mixed_batch(self) -> None:
        clean_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Exploit reasoning",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0054",
                ),
            ],
        )
        clean = _make_envelope(clean_root, scenario_id="AP-T7-01-clean1")

        flagged_root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Propagate effect",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    # No technique_id
                ),
            ],
        )
        flagged = _make_envelope(flagged_root, scenario_id="AP-T7-01-flagg1")

        result = validate_blank_leaves([clean, flagged])

        assert result.clean_count == 1
        assert result.flagged_count == 1
        assert result.clean_scenarios[0].scenario_id == "AP-T7-01-clean1"
        assert result.flagged_scenarios[0][0].scenario_id == "AP-T7-01-flagg1"


# ---------------------------------------------------------------------------
# Tests: violation data class
# ---------------------------------------------------------------------------


class TestBlankLeafViolation:
    """Verify violation data class fields."""

    def test_fields(self) -> None:
        v = BlankLeafViolation(
            node_id="n1.2",
            label="Propagate to reasoning",
            zone="reasoning",
        )
        assert v.node_id == "n1.2"
        assert v.label == "Propagate to reasoning"
        assert v.zone == "reasoning"


# ---------------------------------------------------------------------------
# Tests: logging
# ---------------------------------------------------------------------------


class TestLogging:
    """Verify warning logs are emitted for flagged scenarios."""

    def test_warning_logged(self, caplog) -> None:  # type: ignore[no-untyped-def]
        import logging

        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0054",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Effect in reasoning",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root)

        with caplog.at_level(logging.WARNING, logger="scenario_forge.pipeline.validation"):
            validate_blank_leaves([scenario])

        assert any("leaf node(s) without technique_id" in r.message for r in caplog.records)
        assert any("n1.2" in r.message for r in caplog.records)
