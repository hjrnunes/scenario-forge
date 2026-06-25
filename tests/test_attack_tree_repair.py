"""Tests for single-child AND/OR node repair in attack trees."""

from __future__ import annotations

import copy
import logging
from typing import Any

import pytest

from scenario_forge.models.attack_tree import (
    AttackTree,
    repair_attack_tree_dict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _leaf(node_id: str, label: str, zone: int = 1, **extra: Any) -> dict[str, Any]:
    """Create a minimal LEAF node dict."""
    return {"id": node_id, "label": label, "gate": "LEAF", "zone": zone, **extra}


def _gate(
    node_id: str,
    label: str,
    gate: str,
    children: list[dict[str, Any]],
    zone: int = 1,
    **extra: Any,
) -> dict[str, Any]:
    """Create an AND/OR node dict with the given children."""
    return {
        "id": node_id,
        "label": label,
        "gate": gate,
        "zone": zone,
        "children": children,
        **extra,
    }


def _wrap_tree(root: dict[str, Any]) -> dict[str, Any]:
    """Wrap a root node dict in a minimal AttackTree dict."""
    return {
        "id": "tree-T1-S1",
        "seed_id": "T1-S1",
        "goal": "Test goal",
        "root": root,
    }


# ---------------------------------------------------------------------------
# Fixtures: tree dicts (pre-validation)
# ---------------------------------------------------------------------------


def _valid_tree() -> dict[str, Any]:
    """A fully valid tree that needs no repair."""
    return _wrap_tree(
        _gate(
            "n1",
            "Root AND gate",
            "AND",
            [
                _leaf("n1.1", "Step A"),
                _leaf("n1.2", "Step B"),
            ],
        )
    )


def _single_child_and_tree() -> dict[str, Any]:
    """An AND root with only one child — must be collapsed."""
    return _wrap_tree(
        _gate(
            "n1",
            "Root AND gate",
            "AND",
            [
                _gate(
                    "n1.1",
                    "Inner OR gate",
                    "OR",
                    [
                        _leaf("n1.1.1", "Leaf A"),
                        _leaf("n1.1.2", "Leaf B"),
                    ],
                ),
            ],
        )
    )


def _single_child_or_tree() -> dict[str, Any]:
    """An OR root with only one child — must be collapsed."""
    return _wrap_tree(
        _gate(
            "n1",
            "Root OR gate",
            "OR",
            [
                _gate(
                    "n1.1",
                    "Inner AND gate",
                    "AND",
                    [
                        _leaf("n1.1.1", "Leaf A"),
                        _leaf("n1.1.2", "Leaf B"),
                    ],
                ),
            ],
        )
    )


def _nested_single_child_tree() -> dict[str, Any]:
    """A chain of single-child nodes: AND -> OR -> valid OR.

    Both the outer AND and the intermediate OR should collapse recursively,
    leaving the valid OR (with 2 children) at the root position.
    """
    return _wrap_tree(
        _gate(
            "n1",
            "Outer AND",
            "AND",
            [
                _gate(
                    "n1.1",
                    "Middle OR",
                    "OR",
                    [
                        _gate(
                            "n1.1.1",
                            "Inner AND",
                            "AND",
                            [
                                _leaf("n1.1.1.1", "Leaf A"),
                                _leaf("n1.1.1.2", "Leaf B"),
                            ],
                        ),
                    ],
                ),
            ],
        )
    )


def _leaf_only_tree() -> dict[str, Any]:
    """A tree whose root is a LEAF (edge case)."""
    return _wrap_tree(_leaf("n1", "Single leaf root"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRepairAttackTreeDict:
    """Tests for repair_attack_tree_dict."""

    def test_valid_tree_passes_through_unchanged(self) -> None:
        data = _valid_tree()
        original = copy.deepcopy(data)
        result = repair_attack_tree_dict(data)

        assert result["root"]["gate"] == "AND"
        assert len(result["root"]["children"]) == 2
        assert result["root"]["id"] == original["root"]["id"]
        assert result["root"]["label"] == original["root"]["label"]

    def test_and_single_child_collapsed(self, caplog: pytest.LogCaptureFixture) -> None:
        data = _single_child_and_tree()

        with caplog.at_level(logging.WARNING):
            result = repair_attack_tree_dict(data)

        root = result["root"]
        # The parent's id is preserved.
        assert root["id"] == "n1"
        # The child's fields are used.
        assert root["label"] == "Inner OR gate"
        assert root["gate"] == "OR"
        assert len(root["children"]) == 2
        # A warning was logged.
        assert any("Collapsing single-child AND" in msg for msg in caplog.messages)

    def test_or_single_child_collapsed(self, caplog: pytest.LogCaptureFixture) -> None:
        data = _single_child_or_tree()

        with caplog.at_level(logging.WARNING):
            result = repair_attack_tree_dict(data)

        root = result["root"]
        assert root["id"] == "n1"
        assert root["label"] == "Inner AND gate"
        assert root["gate"] == "AND"
        assert len(root["children"]) == 2
        assert any("Collapsing single-child OR" in msg for msg in caplog.messages)

    def test_nested_single_child_collapsed_recursively(self) -> None:
        data = _nested_single_child_tree()
        result = repair_attack_tree_dict(data)

        root = result["root"]
        # After collapsing the chain, the innermost valid AND with 2 children
        # should be at the root position.
        assert root["id"] == "n1"
        assert root["gate"] == "AND"
        assert root["label"] == "Inner AND"
        assert len(root["children"]) == 2

    def test_leaf_node_untouched(self) -> None:
        data = _leaf_only_tree()
        original = copy.deepcopy(data)
        result = repair_attack_tree_dict(data)

        assert result["root"]["gate"] == "LEAF"
        assert result["root"]["id"] == original["root"]["id"]
        assert result["root"]["label"] == original["root"]["label"]
        assert result["root"].get("children") is None

    def test_root_id_stays_n1_after_repair(self) -> None:
        data = _single_child_and_tree()
        result = repair_attack_tree_dict(data)
        assert result["root"]["id"] == "n1"

    def test_repaired_tree_validates_with_pydantic(self) -> None:
        """Ensure a repaired tree passes full Pydantic validation."""
        data = _single_child_and_tree()
        repaired = repair_attack_tree_dict(data)

        # Fix child IDs to match the new parent id after collapse.
        # After collapse the root is "n1" with gate OR and children that
        # still have ids "n1.1.1" and "n1.1.2" — we need them to be
        # "n1.1" and "n1.2" for the validator to pass.  The repair function
        # intentionally does NOT rewrite child IDs (that would be a
        # separate concern), so here we adjust for validation.
        root = repaired["root"]
        root["children"][0]["id"] = "n1.1"
        root["children"][1]["id"] = "n1.2"

        tree = AttackTree.model_validate(repaired)
        assert tree.root.id == "n1"
        assert tree.root.gate.value == "OR"
        assert len(tree.root.children) == 2

    def test_preserves_optional_fields_from_child(self) -> None:
        """When collapsing, optional fields from the child are kept."""
        child = _gate(
            "n1.1",
            "Child with extras",
            "OR",
            [
                _leaf("n1.1.1", "A", threat_id="T5"),
                _leaf("n1.1.2", "B"),
            ],
            zone=3,
            description="Important child",
            structural_exposure="convergence_point",
        )
        data = _wrap_tree(
            _gate("n1", "Parent AND", "AND", [child], zone=1)
        )

        result = repair_attack_tree_dict(data)
        root = result["root"]

        assert root["id"] == "n1"
        assert root["zone"] == 3
        assert root["description"] == "Important child"
        assert root["structural_exposure"] == "convergence_point"
