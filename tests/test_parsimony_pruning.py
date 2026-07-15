"""Tests for parsimony pruning pass.

Covers:
- Trees already within budget pass through unchanged
- Unannotated leaves are pruned before annotated ones
- Single-child gate collapse after pruning
- Budget calculation with 0, 1, 2 techniques
- Cannot prune below minimum viable tree
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
from scenario_forge.pipeline.validation import enforce_parsimony


# ---------------------------------------------------------------------------
# Fixtures: helpers to build minimal valid objects
# ---------------------------------------------------------------------------


def _make_tree(
    root: AttackTreeNode,
    technique_ids: list[str] | None = None,
) -> AttackTree:
    """Build a minimal AttackTree."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )


def _make_envelope(
    root: AttackTreeNode,
    atlas_technique_ids: list[str] | None = None,
    scenario_id: str = "AP-T1-01-abc123",
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
                action="I craft a malicious prompt.",
                effect="The system processes the input.",
            ),
        ],
    )

    attack_tree = _make_tree(root)

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
            agentic_threat_ids=["T1"],
            atlas_technique_ids=atlas_technique_ids,
            scenario_seed="AP-T1-01",
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
# Tests: trees within budget pass unchanged
# ---------------------------------------------------------------------------


class TestCompliantTrees:
    """Trees already within budget should pass through unchanged."""

    def test_small_tree_passes(self) -> None:
        """A 2-leaf tree with 1 technique (budget=3) passes."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root, atlas_technique_ids=["AML.T0051"])
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 0

    def test_exact_budget_passes(self) -> None:
        """A tree at exactly the budget limit passes."""
        # 1 technique -> budget = 2*1+1 = 3 leaves
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Path C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1

    def test_empty_list(self) -> None:
        result = enforce_parsimony([])
        assert len(result.compliant_scenarios) == 0
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 0


# ---------------------------------------------------------------------------
# Tests: unannotated leaves pruned before annotated
# ---------------------------------------------------------------------------


class TestPruningOrder:
    """Unannotated leaves should be pruned; annotated ones preserved."""

    def test_unannotated_leaves_pruned(self) -> None:
        """Excess unannotated leaves are removed."""
        # 1 technique -> budget = 3. Tree has 5 leaves: 1 annotated, 4 unannotated.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Exploit injection",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Reinforce deception",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Generate confirmation",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Maintain polite closure",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Establish trust",
                    gate=GateType.LEAF,
                    zone="input",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 1
        pruned_scenario, pruned_nodes = result.pruned_scenarios[0]
        # Should have pruned 2 leaves (5 - 3 = 2)
        assert len(pruned_nodes) == 2
        # All pruned nodes should be unannotated
        for pn in pruned_nodes:
            assert pn.node_id != "n1.1"  # annotated leaf must survive
        # Annotated leaf must still be in the tree
        from scenario_forge.pipeline.validation import _collect_leaves

        remaining = _collect_leaves(pruned_scenario.attack_tree.root)
        annotated_ids = [leaf.id for leaf in remaining if leaf.technique_id]
        assert "n1.1" in annotated_ids

    def test_annotated_leaves_never_pruned(self) -> None:
        """When all excess leaves have technique_ids, they cannot be pruned."""
        # 1 technique -> budget = 3. All 4 leaves have technique_ids.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                    technique_id="AML.T0051",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.unprunable_scenarios) == 1
        _, actual, budget = result.unprunable_scenarios[0]
        assert actual == 4
        assert budget == 3


# ---------------------------------------------------------------------------
# Tests: single-child gate collapse
# ---------------------------------------------------------------------------


class TestGateCollapse:
    """When pruning leaves a gate with 1 child, it should be collapsed."""

    def test_and_gate_collapses(self) -> None:
        """Pruning one child of a 2-child AND gate collapses the gate."""
        # 1 technique -> budget = 3. Tree has 4 leaves.
        # n1 (OR)
        #   n1.1 (AND)
        #     n1.1.1 LEAF (annotated)
        #     n1.1.2 LEAF (unannotated - will be pruned)
        #   n1.2 LEAF (annotated)
        #   n1.3 LEAF (unannotated)
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Compound attack",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0051",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Reinforce deception",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Direct exploitation",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Maintain closure",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 1
        pruned_scenario, pruned_nodes = result.pruned_scenarios[0]

        # The AND gate n1.1 should have been collapsed
        pruned_root = pruned_scenario.attack_tree.root
        # All children of root should be LEAFs now (n1.1 collapsed to its single child)
        for child in pruned_root.children:
            assert child.gate == GateType.LEAF, (
                f"Expected LEAF but got {child.gate} for {child.id}"
            )


# ---------------------------------------------------------------------------
# Tests: budget calculation
# ---------------------------------------------------------------------------


class TestBudgetCalculation:
    """Budget should scale with technique count."""

    def test_zero_techniques_budget_3(self) -> None:
        """With 0 techniques, fallback budget is 3."""
        # No technique_ids anywhere. 4 leaves > budget 3.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        # Should prune 1 leaf (4 -> 3)
        assert len(result.pruned_scenarios) == 1
        _, pruned_nodes = result.pruned_scenarios[0]
        assert len(pruned_nodes) == 1

    def test_one_technique_budget_3(self) -> None:
        """With 1 technique, budget = 2*1+1 = 3."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1

    def test_two_techniques_budget_5(self) -> None:
        """With 2 techniques, budget = 2*2+1 = 5."""
        # 6 leaves, 2 techniques -> budget 5, need to prune 1
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    technique_id="AML.T0052",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step E",
                    gate=GateType.LEAF,
                    zone="output",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Step F filler",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 1
        _, pruned_nodes = result.pruned_scenarios[0]
        assert len(pruned_nodes) == 1


# ---------------------------------------------------------------------------
# Tests: minimum viable tree
# ---------------------------------------------------------------------------


class TestMinimumViableTree:
    """Cannot prune below minimum viable tree structure."""

    def test_cannot_prune_two_leaf_tree(self) -> None:
        """A 2-leaf tree over budget where both are unannotated cannot
        be pruned further (would leave parent with < 2 children and
        no collapse target)."""
        # 0 techniques -> budget = 3.
        # This tree has only 2 leaves, so it's within budget.
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.compliant_scenarios) == 1

    def test_pruned_tree_is_valid_pydantic(self) -> None:
        """After pruning, the tree should be valid Pydantic."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Step A",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step C filler",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step D filler extra",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 1
        pruned_scenario, _ = result.pruned_scenarios[0]
        # Re-validate with Pydantic
        tree = pruned_scenario.attack_tree
        validated = AttackTree.model_validate(tree.model_dump())
        assert validated.root.id == "n1"

    def test_and_gate_children_preserved(self) -> None:
        """An AND gate must keep at least 2 children.

        If pruning would bring it to 1 child, the gate collapses
        rather than leaving an invalid structure.
        """
        # 1 technique -> budget = 3.
        # n1 (AND)
        #   n1.1 LEAF (annotated)
        #   n1.2 (OR)
        #     n1.2.1 LEAF
        #     n1.2.2 LEAF
        #     n1.2.3 LEAF (excess)
        #   n1.3 LEAF
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Inject payload",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Alternative paths",
                    gate=GateType.OR,
                    zone="reasoning",
                    children=[
                        AttackTreeNode(
                            id="n1.2.1",
                            label="Via prompt",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                        AttackTreeNode(
                            id="n1.2.2",
                            label="Via context",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                        AttackTreeNode(
                            id="n1.2.3",
                            label="Via closure filler",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Exfiltrate data",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 1
        pruned_scenario, pruned_nodes = result.pruned_scenarios[0]

        # After pruning, tree should still be valid
        validated = AttackTree.model_validate(
            pruned_scenario.attack_tree.model_dump()
        )
        # Check all AND/OR gates have >= 2 children
        def check_gates(node: AttackTreeNode) -> None:
            if node.gate in (GateType.AND, GateType.OR):
                assert node.children and len(node.children) >= 2, (
                    f"{node.gate.value} node {node.id} has "
                    f"{len(node.children) if node.children else 0} children"
                )
                for child in node.children:
                    check_gates(child)

        check_gates(validated.root)


# ---------------------------------------------------------------------------
# Tests: AND-gate preference
# ---------------------------------------------------------------------------


class TestAndGatePreference:
    """Leaves under AND gates should be pruned before OR-gate leaves."""

    def test_and_children_pruned_first(self) -> None:
        """When both AND and OR children are candidates, AND is pruned first."""
        # 1 technique -> budget = 3. Tree has 4 leaves.
        # n1 (OR)
        #   n1.1 (AND)
        #     n1.1.1 LEAF (annotated)
        #     n1.1.2 LEAF (unannotated - should be pruned first, AND child)
        #   n1.2 LEAF (unannotated, OR child)
        #   n1.3 LEAF (unannotated, OR child)
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Compound path",
                    gate=GateType.AND,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1.1",
                            label="Inject payload",
                            gate=GateType.LEAF,
                            zone="input",
                            technique_id="AML.T0051",
                        ),
                        AttackTreeNode(
                            id="n1.1.2",
                            label="Reinforce deception",
                            gate=GateType.LEAF,
                            zone="reasoning",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Direct path A",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Direct path B",
                    gate=GateType.LEAF,
                    zone="output",
                ),
            ],
        )
        scenario = _make_envelope(root)
        result = enforce_parsimony([scenario])

        assert len(result.pruned_scenarios) == 1
        _, pruned_nodes = result.pruned_scenarios[0]
        assert len(pruned_nodes) == 1
        # The AND-child should have been pruned
        assert pruned_nodes[0].parent_gate == "AND"
