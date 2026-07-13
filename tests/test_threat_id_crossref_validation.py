"""Tests for post-generation threat_id cross-reference validation.

Verifies that _warn_dominant_threat_id_crossref correctly detects trees
where a dominant cross-ref threat_id differs from the scenario's parent
threat (the "everything is T1" pattern).
"""

from __future__ import annotations

import logging

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode
from scenario_forge.pipeline.generate import (
    _collect_threat_ids_from_tree,
    _warn_dominant_threat_id_crossref,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tree(root: AttackTreeNode) -> AttackTree:
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="compromise the system",
        root=root,
    )


def _leaf(node_id: str, threat_id: str | None = None) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=f"Step {node_id}",
        gate="LEAF",
        zone="input",
        threat_id=threat_id,
    )


# ---------------------------------------------------------------------------
# _collect_threat_ids_from_tree
# ---------------------------------------------------------------------------


def test_collect_threat_ids_from_flat_tree():
    """All threat_ids are collected from a simple tree."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id="T7",
        children=[
            _leaf("n1.1", threat_id="T1"),
            _leaf("n1.2", threat_id="T7"),
        ],
    )
    ids = _collect_threat_ids_from_tree(root)
    assert ids == ["T7", "T1", "T7"]


def test_collect_threat_ids_includes_none():
    """Nodes without threat_id contribute None to the list."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id=None,
        children=[
            _leaf("n1.1", threat_id="T1"),
            _leaf("n1.2", threat_id=None),
        ],
    )
    ids = _collect_threat_ids_from_tree(root)
    assert ids == [None, "T1", None]


# ---------------------------------------------------------------------------
# _warn_dominant_threat_id_crossref
# ---------------------------------------------------------------------------


def test_diverse_threat_ids_no_warning(caplog):
    """A tree with diverse threat_ids passes silently."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id="T7",
        children=[
            _leaf("n1.1", threat_id="T1"),
            _leaf("n1.2", threat_id="T2"),
            _leaf("n1.3", threat_id="T3"),
            _leaf("n1.4", threat_id="T7"),
            _leaf("n1.5", threat_id="T5"),
        ],
    )
    tree = _make_tree(root)

    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" not in caplog.text


def test_dominant_crossref_different_from_parent_warns(caplog):
    """4/5 nodes tagged T1 but parent threat is T7 -- triggers warning."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id="T1",
        children=[
            _leaf("n1.1", threat_id="T1"),
            _leaf("n1.2", threat_id="T1"),
            _leaf("n1.3", threat_id="T1"),
            _leaf("n1.4", threat_id="T7"),
        ],
    )
    tree = _make_tree(root)

    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" in caplog.text
    assert "T1" in caplog.text
    assert "T7" in caplog.text
    assert "AP-T7-01-abc123" in caplog.text


def test_dominant_crossref_matches_parent_no_warning(caplog):
    """Most nodes match the parent threat -- passes silently."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id="T7",
        children=[
            _leaf("n1.1", threat_id="T7"),
            _leaf("n1.2", threat_id="T7"),
            _leaf("n1.3", threat_id="T7"),
            _leaf("n1.4", threat_id="T1"),
            _leaf("n1.5", threat_id="T2"),
        ],
    )
    tree = _make_tree(root)

    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" not in caplog.text


def test_all_nodes_null_threat_id_no_warning(caplog):
    """A tree with no threat_ids set passes silently."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id=None,
        children=[
            _leaf("n1.1", threat_id=None),
            _leaf("n1.2", threat_id=None),
        ],
    )
    tree = _make_tree(root)

    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" not in caplog.text


def test_exactly_50_percent_no_warning(caplog):
    """Exactly 50% (not >50%) should not trigger the warning."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id="T1",
        children=[
            _leaf("n1.1", threat_id="T1"),
            _leaf("n1.2", threat_id="T3"),
            _leaf("n1.3", threat_id="T4"),
        ],
    )
    tree = _make_tree(root)

    # 2 out of 4 nodes have T1 = exactly 50%, should not warn
    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" not in caplog.text


def test_mixed_null_and_dominant_crossref(caplog):
    """Null threat_ids are excluded from the ratio; dominant among non-null warns."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="OR",
        zone="input",
        threat_id="T1",
        children=[
            _leaf("n1.1", threat_id="T1"),
            _leaf("n1.2", threat_id=None),
            _leaf("n1.3", threat_id=None),
            _leaf("n1.4", threat_id="T1"),
        ],
    )
    tree = _make_tree(root)

    # 3 out of 3 non-null nodes have T1 = 100%, parent is T7 -> warn
    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" in caplog.text


def test_deep_tree_crossref_validation(caplog):
    """Validation works correctly on deeply nested trees."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate="AND",
        zone="input",
        threat_id="T1",
        children=[
            AttackTreeNode(
                id="n1.1",
                label="Sub-goal A",
                gate="OR",
                zone="reasoning",
                threat_id="T1",
                children=[
                    _leaf("n1.1.1", threat_id="T1"),
                    _leaf("n1.1.2", threat_id="T1"),
                ],
            ),
            _leaf("n1.2", threat_id="T7"),
        ],
    )
    tree = _make_tree(root)

    # 4 out of 5 non-null nodes have T1 = 80%, parent is T7 -> warn
    with caplog.at_level(logging.WARNING):
        _warn_dominant_threat_id_crossref(tree, "T7", "AP-T7-01-abc123")

    assert "threat_id cross-ref anomaly" in caplog.text
    assert "80%" in caplog.text
