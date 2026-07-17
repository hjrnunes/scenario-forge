"""Tests for _strip_non_skeleton_techniques post-processing.

Verifies that technique_id values are removed from attack tree leaf nodes
that are not part of the skeleton (pinned) technique set.
"""

from __future__ import annotations

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
from scenario_forge.pipeline.generate import _strip_non_skeleton_techniques


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _leaf(node_id: str, label: str, zone: str = "input", **extra) -> AttackTreeNode:
    return AttackTreeNode(id=node_id, label=label, gate=GateType.LEAF, zone=zone, **extra)


def _gate(
    node_id: str,
    label: str,
    gate: GateType,
    children: list[AttackTreeNode],
    zone: str = "input",
) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id, label=label, gate=gate, zone=zone, children=children
    )


def _tree(root: AttackTreeNode) -> AttackTree:
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Test goal",
        root=root,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStripNonSkeletonTechniques:
    """Tests for _strip_non_skeleton_techniques."""

    def test_non_skeleton_leaf_technique_stripped(self) -> None:
        """Leaves with technique_ids NOT in the skeleton set get stripped."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _leaf("n1.1", "Skeleton leaf", technique_id="AML.T0051"),
                    _leaf("n1.2", "Decorative leaf", technique_id="AML.T0051"),
                ],
            )
        )
        skeleton_ids = {"AML.T0051"}
        stripped = _strip_non_skeleton_techniques(tree, skeleton_ids)

        # Both leaves have the skeleton technique, so neither should be stripped
        assert stripped == 0
        assert tree.root.children[0].technique_id == "AML.T0051"
        assert tree.root.children[1].technique_id == "AML.T0051"

    def test_non_skeleton_technique_id_stripped(self) -> None:
        """A leaf with a technique_id NOT in skeleton set gets stripped."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _leaf("n1.1", "Skeleton leaf", technique_id="AML.T0051"),
                    _leaf("n1.2", "Non-skeleton leaf", technique_id="AML.T0043"),
                ],
            )
        )
        skeleton_ids = {"AML.T0051"}
        stripped = _strip_non_skeleton_techniques(tree, skeleton_ids)

        assert stripped == 1
        assert tree.root.children[0].technique_id == "AML.T0051"
        assert tree.root.children[1].technique_id is None

    def test_skeleton_leaves_retain_technique_id(self) -> None:
        """Leaves whose technique_id IS in the skeleton set are preserved."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _leaf("n1.1", "Pinned leaf A", technique_id="AML.T0051"),
                    _leaf("n1.2", "Pinned leaf B", technique_id="AML.T0043"),
                ],
            )
        )
        skeleton_ids = {"AML.T0051", "AML.T0043"}
        stripped = _strip_non_skeleton_techniques(tree, skeleton_ids)

        assert stripped == 0
        assert tree.root.children[0].technique_id == "AML.T0051"
        assert tree.root.children[1].technique_id == "AML.T0043"

    def test_leaves_without_technique_id_unchanged(self) -> None:
        """Leaves with no technique_id remain unchanged."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _leaf("n1.1", "Leaf with no technique"),
                    _leaf("n1.2", "Another clean leaf"),
                ],
            )
        )
        skeleton_ids = {"AML.T0051"}
        stripped = _strip_non_skeleton_techniques(tree, skeleton_ids)

        assert stripped == 0
        assert tree.root.children[0].technique_id is None
        assert tree.root.children[1].technique_id is None

    def test_empty_skeleton_strips_all_technique_ids(self) -> None:
        """When skeleton set is empty, ALL leaf technique_ids are stripped."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _leaf("n1.1", "Leaf A", technique_id="AML.T0051"),
                    _leaf("n1.2", "Leaf B", technique_id="AML.T0043"),
                ],
            )
        )
        stripped = _strip_non_skeleton_techniques(tree, set())

        assert stripped == 2
        assert tree.root.children[0].technique_id is None
        assert tree.root.children[1].technique_id is None

    def test_deep_tree_strips_nested_non_skeleton_leaves(self) -> None:
        """Non-skeleton technique_ids are stripped from deeply nested leaves."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _gate(
                        "n1.1",
                        "Sub-gate",
                        GateType.OR,
                        [
                            _leaf("n1.1.1", "Deep skeleton", technique_id="AML.T0051"),
                            _leaf("n1.1.2", "Deep decorative", technique_id="AML.T0043"),
                        ],
                    ),
                    _leaf("n1.2", "Top-level decorative", technique_id="AML.T0043"),
                ],
            )
        )
        skeleton_ids = {"AML.T0051"}
        stripped = _strip_non_skeleton_techniques(tree, skeleton_ids)

        assert stripped == 2
        assert tree.root.children[0].children[0].technique_id == "AML.T0051"
        assert tree.root.children[0].children[1].technique_id is None
        assert tree.root.children[1].technique_id is None

    def test_non_leaf_nodes_are_not_affected(self) -> None:
        """AND/OR nodes with technique_ids are left alone (only leaves are stripped)."""
        # While non-leaf nodes normally don't have technique_ids,
        # if they do, the stripper should not touch them (spec says LEAF only).
        inner = _gate(
            "n1.1",
            "Inner gate",
            GateType.OR,
            [
                _leaf("n1.1.1", "Leaf A"),
                _leaf("n1.1.2", "Leaf B"),
            ],
        )
        inner.technique_id = "AML.T0099"

        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    inner,
                    _leaf("n1.2", "Leaf C"),
                ],
            )
        )
        stripped = _strip_non_skeleton_techniques(tree, set())

        # The inner gate node's technique_id should NOT be stripped
        assert tree.root.children[0].technique_id == "AML.T0099"
        assert stripped == 0

    def test_returns_count_of_stripped(self) -> None:
        """The function returns the exact count of stripped technique_ids."""
        tree = _tree(
            _gate(
                "n1",
                "Root",
                GateType.AND,
                [
                    _leaf("n1.1", "Keep", technique_id="AML.T0051"),
                    _leaf("n1.2", "Strip 1", technique_id="AML.T0043"),
                    _leaf("n1.3", "Strip 2", technique_id="AML.T0044"),
                    _leaf("n1.4", "No technique"),
                ],
            )
        )
        skeleton_ids = {"AML.T0051"}
        stripped = _strip_non_skeleton_techniques(tree, skeleton_ids)

        assert stripped == 2
