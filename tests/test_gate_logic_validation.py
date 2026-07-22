"""Tests for gate-logic consistency validation (scenario-forge-var8).

Covers:
- _has_or_gates: OR-gate detection in attack trees
- _count_or_gates: OR-gate counting
- validate_gate_logic_consistency: backstop validator for OR-gate / Gherkin mismatch
"""

from __future__ import annotations

from datetime import datetime

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
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
    _has_or_gates,
    _count_or_gates,
    validate_gate_logic_consistency,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _leaf(node_id: str, label: str, zone: str, technique_id: str | None = None) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        technique_id=technique_id,
    )


def _and_only_tree() -> AttackTree:
    """Pure AND tree: no OR gates."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                _leaf("n1.1", "Step A", "input", "AML.T0051"),
                _leaf("n1.2", "Step B", "reasoning", "AML.T0054"),
            ],
        ),
    )


def _or_gate_tree() -> AttackTree:
    """Tree with one OR gate."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                _leaf("n1.1", "Step A", "input", "AML.T0051"),
                AttackTreeNode(
                    id="n1.2",
                    label="Choice",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        _leaf("n1.2.1", "Option 1", "reasoning"),
                        _leaf("n1.2.2", "Option 2", "reasoning"),
                    ],
                ),
            ],
        ),
    )


def _dual_or_gate_tree() -> AttackTree:
    """Tree with two OR gates."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Choice A",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        _leaf("n1.1.1", "A1", "input"),
                        _leaf("n1.1.2", "A2", "input"),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Choice B",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        _leaf("n1.2.1", "B1", "reasoning"),
                        _leaf("n1.2.2", "B2", "reasoning"),
                    ],
                ),
            ],
        ),
    )


def _make_scenario(
    tree: AttackTree,
    behavior_spec: str,
    scenario_id: str = "test-scenario-001",
) -> ScenarioEnvelope:
    """Build a minimal ScenarioEnvelope for validation testing."""
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary",
        entry_point="user prompts via chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Submit prompt",
                effect="Prompt accepted",
            ),
        ],
    )

    faceting = FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            atlas_technique_ids=["AML.T0051"],
            scenario_seed="AP-T7-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts via chat",
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
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

    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.actor_profile,
                prompt_tokens=10,
                completion_tokens=10,
                duration_ms=100,
            ),
        ],
    )

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        generated_at=datetime.now(),
        generator_version="0.1.0",
        scenario_seed_metadata={
            "seed_id": tree.seed_id,
            "threat_id": "T7",
        },
        narrative=narrative,
        attack_tree=tree,
        behavior_spec=behavior_spec,
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Tests: _has_or_gates
# ---------------------------------------------------------------------------


class TestHasOrGates:
    def test_and_only_tree(self):
        tree = _and_only_tree()
        assert _has_or_gates(tree.root) is False

    def test_tree_with_or_gate(self):
        tree = _or_gate_tree()
        assert _has_or_gates(tree.root) is True

    def test_leaf_only_tree(self):
        root = _leaf("n1", "Solo", "input", "AML.T0051")
        assert _has_or_gates(root) is False

    def test_or_at_root(self):
        root = AttackTreeNode(
            id="n1",
            label="Root OR",
            gate=GateType.OR,
            zone="input",
            children=[
                _leaf("n1.1", "A", "input"),
                _leaf("n1.2", "B", "input"),
            ],
        )
        assert _has_or_gates(root) is True

    def test_deeply_nested_or(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Mid",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        _leaf("n1.1.1", "Leaf", "input"),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Deep OR",
                            gate=GateType.OR,
                            zone="reasoning",
                            children=[
                                _leaf("n1.1.2.1", "X", "reasoning"),
                                _leaf("n1.1.2.2", "Y", "reasoning"),
                            ],
                        ),
                    ],
                ),
                _leaf("n1.2", "Other", "input"),
            ],
        )
        assert _has_or_gates(root) is True


# ---------------------------------------------------------------------------
# Tests: _count_or_gates
# ---------------------------------------------------------------------------


class TestCountOrGates:
    def test_no_or_gates(self):
        tree = _and_only_tree()
        assert _count_or_gates(tree.root) == 0

    def test_one_or_gate(self):
        tree = _or_gate_tree()
        assert _count_or_gates(tree.root) == 1

    def test_two_or_gates(self):
        tree = _dual_or_gate_tree()
        assert _count_or_gates(tree.root) == 2


# ---------------------------------------------------------------------------
# Tests: validate_gate_logic_consistency
# ---------------------------------------------------------------------------


class TestValidateGateLogicConsistency:
    def test_and_only_tree_clean(self):
        """AND-only tree with single Scenario block passes."""
        gherkin = (
            "Feature: Test\n"
            "  Scenario: Test\n"
            "    When step A\n"
            "    Then result\n"
        )
        scenario = _make_scenario(_and_only_tree(), gherkin)
        result = validate_gate_logic_consistency([scenario])
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_or_tree_single_scenario_flagged(self):
        """OR-gate tree with single Scenario block is flagged."""
        gherkin = (
            "Feature: Test\n"
            "  Scenario: Test\n"
            "    When step A\n"
            "    And option 1\n"
            "    And option 2\n"
            "    Then result\n"
        )
        scenario = _make_scenario(_or_gate_tree(), gherkin)
        result = validate_gate_logic_consistency([scenario])
        assert result.flagged_count == 1
        assert result.clean_count == 0
        violation = result.flagged_scenarios[0][1]
        assert violation.or_gate_count == 1
        assert violation.gherkin_scenario_count == 1

    def test_or_tree_multiple_scenarios_clean(self):
        """OR-gate tree with multiple Scenario blocks passes."""
        gherkin = (
            "Feature: Test\n"
            "  Scenario: Test (Path 1)\n"
            "    When step A\n"
            "    And option 1\n"
            "    Then result\n"
            "\n"
            "  Scenario: Test (Path 2)\n"
            "    When step A\n"
            "    And option 2\n"
            "    Then result\n"
        )
        scenario = _make_scenario(_or_gate_tree(), gherkin)
        result = validate_gate_logic_consistency([scenario])
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_empty_behavior_spec_clean(self):
        """Missing behavior spec is treated as clean (nothing to validate)."""
        scenario = _make_scenario(_or_gate_tree(), "")
        result = validate_gate_logic_consistency([scenario])
        assert result.clean_count == 1
        assert result.flagged_count == 0

    def test_batch_mixed_results(self):
        """Batch with both clean and flagged scenarios."""
        clean_gherkin = (
            "Feature: Test\n"
            "  Scenario: Test\n"
            "    When step\n"
            "    Then result\n"
        )
        flagged_gherkin = (
            "Feature: Test\n"
            "  Scenario: Test\n"
            "    When step A\n"
            "    And option 1\n"
            "    And option 2\n"
            "    Then result\n"
        )
        s1 = _make_scenario(_and_only_tree(), clean_gherkin, "s1")
        s2 = _make_scenario(_or_gate_tree(), flagged_gherkin, "s2")
        result = validate_gate_logic_consistency([s1, s2])
        assert result.clean_count == 1
        assert result.flagged_count == 1

    def test_dual_or_tree_single_scenario_flagged(self):
        """Tree with 2 OR gates and single Scenario is flagged with correct count."""
        gherkin = (
            "Feature: Test\n"
            "  Scenario: Test\n"
            "    When step\n"
            "    Then result\n"
        )
        scenario = _make_scenario(_dual_or_gate_tree(), gherkin)
        result = validate_gate_logic_consistency([scenario])
        assert result.flagged_count == 1
        violation = result.flagged_scenarios[0][1]
        assert violation.or_gate_count == 2
