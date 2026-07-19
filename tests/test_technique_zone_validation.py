"""Tests for technique-zone compatibility validation.

Covers:
1. Leaf with valid technique-zone combo is preserved
2. Leaf with invalid technique-zone combo is stripped (technique_id set to None)
3. Technique not in TECHNIQUE_ZONE_CONSTRAINTS passes (unconstrained)
4. Non-leaf nodes are not affected
5. Function returns correct strip count
6. Realistic tree with mix of valid/invalid leaves
7. Adversarial: all leaves invalid, all stripped
"""

from __future__ import annotations

from scenario_forge.data.atlas import TECHNIQUE_ZONE_CONSTRAINTS
from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.pipeline.generate import (
    _validate_technique_zone_compatibility,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _leaf(
    node_id: str,
    zone: str,
    technique_id: str | None = None,
) -> AttackTreeNode:
    """Create a minimal LEAF node."""
    return AttackTreeNode(
        id=node_id,
        label=f"Leaf {node_id}",
        gate=GateType.LEAF,
        zone=zone,
        technique_id=technique_id,
    )


def _gate(
    node_id: str,
    zone: str,
    gate: GateType,
    children: list[AttackTreeNode],
    technique_id: str | None = None,
) -> AttackTreeNode:
    """Create an AND/OR gate node."""
    return AttackTreeNode(
        id=node_id,
        label=f"Gate {node_id}",
        gate=gate,
        zone=zone,
        children=children,
        technique_id=technique_id,
    )


def _tree(root: AttackTreeNode) -> AttackTree:
    """Wrap a root node in an AttackTree."""
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test goal",
        root=root,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestValidTechniqueZonePreserved:
    """1. Leaf with valid technique-zone combo is preserved."""

    def test_input_zone_with_input_technique(self) -> None:
        # AML.T0054 is valid in {"input", "reasoning"}
        leaf = _leaf("n1.1", "input", technique_id="AML.T0054")
        root = _gate("n1", "input", GateType.OR, [leaf, _leaf("n1.2", "input")])
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 0
        assert tree.root.children[0].technique_id == "AML.T0054"

    def test_reasoning_zone_with_reasoning_technique(self) -> None:
        # AML.T0054 is valid in {"input", "reasoning"}
        leaf = _leaf("n1.1", "reasoning", technique_id="AML.T0054")
        root = _gate(
            "n1", "reasoning", GateType.OR, [leaf, _leaf("n1.2", "reasoning")]
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 0
        assert tree.root.children[0].technique_id == "AML.T0054"

    def test_tool_execution_zone_with_tool_technique(self) -> None:
        # AML.T0053 is valid in {"tool_execution"}
        leaf = _leaf("n1.1", "tool_execution", technique_id="AML.T0053")
        root = _gate(
            "n1",
            "tool_execution",
            GateType.OR,
            [leaf, _leaf("n1.2", "tool_execution")],
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 0
        assert tree.root.children[0].technique_id == "AML.T0053"


class TestInvalidTechniqueZoneStripped:
    """2. Leaf with invalid technique-zone combo is stripped."""

    def test_tool_technique_in_input_zone_stripped(self) -> None:
        # AML.T0053 is only valid in {"tool_execution"}
        leaf = _leaf("n1.1", "input", technique_id="AML.T0053")
        root = _gate("n1", "input", GateType.OR, [leaf, _leaf("n1.2", "input")])
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 1
        assert tree.root.children[0].technique_id is None

    def test_input_technique_in_reasoning_zone_stripped(self) -> None:
        # AML.T0052 is only valid in {"input"}
        leaf = _leaf("n1.1", "reasoning", technique_id="AML.T0052")
        root = _gate(
            "n1", "reasoning", GateType.OR, [leaf, _leaf("n1.2", "reasoning")]
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 1
        assert tree.root.children[0].technique_id is None

    def test_input_technique_in_tool_execution_zone_stripped(self) -> None:
        # AML.T0066 is only valid in {"input"}
        leaf = _leaf("n1.1", "tool_execution", technique_id="AML.T0066")
        root = _gate(
            "n1",
            "tool_execution",
            GateType.OR,
            [leaf, _leaf("n1.2", "tool_execution")],
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 1
        assert tree.root.children[0].technique_id is None


class TestUnconstrainedTechniquePass:
    """3. Technique not in TECHNIQUE_ZONE_CONSTRAINTS passes."""

    def test_unknown_technique_not_stripped(self) -> None:
        # Use a technique ID that is NOT in the constraint map
        fake_technique = "AML.T9999"
        assert fake_technique not in TECHNIQUE_ZONE_CONSTRAINTS

        leaf = _leaf("n1.1", "memory", technique_id=fake_technique)
        root = _gate(
            "n1", "memory", GateType.OR, [leaf, _leaf("n1.2", "memory")]
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 0
        assert tree.root.children[0].technique_id == fake_technique


class TestNonLeafNotAffected:
    """4. Non-leaf nodes (AND/OR gates) are not affected."""

    def test_gate_node_with_technique_not_stripped(self) -> None:
        # AML.T0053 in input zone would be invalid for a leaf,
        # but gates are not checked.
        inner_gate = _gate(
            "n1.1",
            "input",
            GateType.AND,
            [_leaf("n1.1.1", "input"), _leaf("n1.1.2", "input")],
            technique_id="AML.T0053",
        )
        root = _gate(
            "n1", "input", GateType.OR, [inner_gate, _leaf("n1.2", "input")]
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 0
        # The gate's technique_id is untouched
        assert tree.root.children[0].technique_id == "AML.T0053"


class TestStripCountAccuracy:
    """5. Function returns correct strip count."""

    def test_zero_strips(self) -> None:
        leaf = _leaf("n1.1", "input", technique_id="AML.T0054")
        root = _gate("n1", "input", GateType.OR, [leaf, _leaf("n1.2", "input")])
        tree = _tree(root)

        assert _validate_technique_zone_compatibility(tree) == 0

    def test_one_strip(self) -> None:
        leaf = _leaf("n1.1", "input", technique_id="AML.T0053")
        root = _gate("n1", "input", GateType.OR, [leaf, _leaf("n1.2", "input")])
        tree = _tree(root)

        assert _validate_technique_zone_compatibility(tree) == 1

    def test_multiple_strips(self) -> None:
        # AML.T0053 valid only in tool_execution; put two in input zone
        leaf1 = _leaf("n1.1", "input", technique_id="AML.T0053")
        leaf2 = _leaf("n1.2", "reasoning", technique_id="AML.T0053")
        root = _gate("n1", "input", GateType.OR, [leaf1, leaf2])
        tree = _tree(root)

        assert _validate_technique_zone_compatibility(tree) == 2

    def test_no_technique_ids_zero_count(self) -> None:
        leaf1 = _leaf("n1.1", "input")
        leaf2 = _leaf("n1.2", "reasoning")
        root = _gate("n1", "input", GateType.OR, [leaf1, leaf2])
        tree = _tree(root)

        assert _validate_technique_zone_compatibility(tree) == 0


class TestRealisticMixedTree:
    """6. Realistic tree with mix of valid/invalid leaves."""

    def test_mixed_tree(self) -> None:
        # Build a realistic 3-level tree:
        # root (OR, input)
        #   n1.1 (AND, input)
        #     n1.1.1 (LEAF, input, AML.T0054)   -> valid (input in {input, reasoning})
        #     n1.1.2 (LEAF, reasoning, AML.T0054) -> valid
        #   n1.2 (AND, tool_execution)
        #     n1.2.1 (LEAF, tool_execution, AML.T0053) -> valid
        #     n1.2.2 (LEAF, reasoning, AML.T0053)     -> INVALID (reasoning not in {tool_execution})
        #     n1.2.3 (LEAF, tool_execution, AML.T0054) -> INVALID (tool_execution not in {input, reasoning})
        branch1 = _gate(
            "n1.1",
            "input",
            GateType.AND,
            [
                _leaf("n1.1.1", "input", technique_id="AML.T0054"),
                _leaf("n1.1.2", "reasoning", technique_id="AML.T0054"),
            ],
        )
        branch2 = _gate(
            "n1.2",
            "tool_execution",
            GateType.AND,
            [
                _leaf("n1.2.1", "tool_execution", technique_id="AML.T0053"),
                _leaf("n1.2.2", "reasoning", technique_id="AML.T0053"),
                _leaf("n1.2.3", "tool_execution", technique_id="AML.T0054"),
            ],
        )
        root = _gate("n1", "input", GateType.OR, [branch1, branch2])
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        # Two invalid leaves: n1.2.2 and n1.2.3
        assert count == 2

        # Valid leaves preserved
        assert tree.root.children[0].children[0].technique_id == "AML.T0054"
        assert tree.root.children[0].children[1].technique_id == "AML.T0054"
        assert tree.root.children[1].children[0].technique_id == "AML.T0053"

        # Invalid leaves stripped
        assert tree.root.children[1].children[1].technique_id is None
        assert tree.root.children[1].children[2].technique_id is None


class TestAdversarialCases:
    """7. Adversarial/negative cases."""

    def test_all_leaves_invalid_all_stripped(self) -> None:
        # AML.T0053 only valid in tool_execution; place all in input
        leaves = [
            _leaf("n1.1", "input", technique_id="AML.T0053"),
            _leaf("n1.2", "input", technique_id="AML.T0053"),
            _leaf("n1.3", "reasoning", technique_id="AML.T0053"),
        ]
        root = _gate("n1", "input", GateType.OR, leaves)
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 3
        for child in tree.root.children:
            assert child.technique_id is None

    def test_deeply_nested_invalid_leaf(self) -> None:
        # 4 levels deep; only the deepest leaf is invalid
        deep_leaf = _leaf("n1.1.1.1", "memory", technique_id="AML.T0053")
        level3 = _gate(
            "n1.1.1",
            "memory",
            GateType.OR,
            [deep_leaf, _leaf("n1.1.1.2", "memory")],
        )
        level2 = _gate(
            "n1.1",
            "input",
            GateType.OR,
            [level3, _leaf("n1.1.2", "input")],
        )
        root = _gate(
            "n1", "input", GateType.OR, [level2, _leaf("n1.2", "input")]
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 1
        assert (
            tree.root.children[0].children[0].children[0].technique_id is None
        )

    def test_single_leaf_tree_invalid(self) -> None:
        # Edge case: tree is just a single leaf node (root is the leaf).
        # AML.T0053 in input = invalid
        root = AttackTreeNode(
            id="n1",
            label="Single leaf root",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0053",
        )
        tree = _tree(root)

        count = _validate_technique_zone_compatibility(tree)

        assert count == 1
        assert tree.root.technique_id is None
