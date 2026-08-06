"""Tests for post-generation zone enforcement.

Verifies that _enforce_zones_narrative strips zones/steps not in zones_active,
and that _enforce_zones_attack_tree now validates (rejects) rather than
silently pruning disallowed zones (cmps.9 review correction 4).
"""

from __future__ import annotations

import pytest

from scenario_forge.models.attack_tree import AiSystemAction, AttackTree, AttackTreeNode
from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep
from scenario_forge.pipeline.generate import (
    _enforce_zones_attack_tree,
    _enforce_zones_narrative,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_narrative(
    zone_sequence: list[str],
    step_zones: list[str] | None = None,
) -> NarrativeLayer:
    """Build a minimal NarrativeLayer for testing."""
    if step_zones is None:
        step_zones = zone_sequence
    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=z,
            action=f"action in {z}",
            effect=f"effect in {z}",
            projected_step_ids=(f"step.{i + 1}",),
            canonical_action_kind="prepare",
            canonical_executor_role="attacker",
            canonical_boundary_position="crossing",
        )
        for i, z in enumerate(step_zones)
    ]
    return NarrativeLayer(
        title="Test narrative",
        summary="Summary",
        entry_point="user prompts (zone 1)",
        zone_sequence=zone_sequence,
        steps=steps,
    )


def _make_tree(root: AttackTreeNode) -> AttackTree:
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="compromise the system",
        root=root,
    )


def _leaf(node_id: str, label: str, zone: str) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate="LEAF",
        zone=zone,
        action=AiSystemAction(),
    )


# ---------------------------------------------------------------------------
# _enforce_zones_narrative
# ---------------------------------------------------------------------------


class TestEnforceZonesNarrative:
    def test_none_zones_active_is_noop(self):
        narrative = _make_narrative(["input", "memory", "reasoning"])
        result = _enforce_zones_narrative(narrative, zones_active=None)
        assert result is narrative  # same object, not a copy

    def test_all_zones_allowed(self):
        narrative = _make_narrative(["input", "reasoning"])
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result is narrative  # no change needed

    def test_disallowed_zone_raises_value_error(self):
        """422o.4: disallowed zones are rejected, not stripped."""
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "reasoning"],
            step_zones=["input", "memory", "reasoning"],
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_narrative(narrative, zones_active=["input", "reasoning"])

    def test_disallowed_step_zone_raises_value_error(self):
        """Step with disallowed zone is rejected, not renumbered."""
        narrative = _make_narrative(
            zone_sequence=["input", "reasoning"],
            step_zones=["input", "memory", "reasoning"],
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_narrative(narrative, zones_active=["input", "reasoning"])

    def test_no_renumbering_or_filtering_occurs(self):
        """422o.4: no semantic repair — steps are never renumbered or deleted."""
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "reasoning"],
            step_zones=["input", "memory", "reasoning"],
        )
        with pytest.raises(ValueError):
            _enforce_zones_narrative(narrative, zones_active=["input", "reasoning"])
        # Original narrative is not mutated
        assert [s.step_number for s in narrative.steps] == [1, 2, 3]
        assert len(narrative.steps) == 3

    def test_all_zones_disallowed_raises(self):
        """When all zones are disallowed, raise rather than returning original."""
        narrative = _make_narrative(
            zone_sequence=["memory"],
            step_zones=["memory"],
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_narrative(narrative, zones_active=["input", "reasoning"])

    def test_multiple_disallowed_zones_raises(self):
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "inter_agent", "reasoning"],
            step_zones=["input", "memory", "inter_agent", "reasoning"],
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_narrative(narrative, zones_active=["input", "reasoning"])

    def test_allowed_zones_preserved_unchanged(self):
        """Allowed zones pass through unchanged."""
        narrative = _make_narrative(
            zone_sequence=["reasoning", "input", "reasoning"],
            step_zones=["reasoning", "input"],
        )
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result is narrative
        assert result.zone_sequence == ["reasoning", "input", "reasoning"]


# ---------------------------------------------------------------------------
# _enforce_zones_attack_tree — validation gate, not pruning (cmps.9 review 4)
# ---------------------------------------------------------------------------


class TestEnforceZonesAttackTree:
    def test_none_zones_active_is_noop(self):
        root = _leaf("n1", "root", "input")
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(tree, zones_active=None)
        assert result is tree

    def test_all_zones_allowed(self):
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                _leaf("n1.1", "a", "input"),
                _leaf("n1.2", "b", "reasoning"),
            ],
        )
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])
        assert result is tree

    def test_disallowed_zone_raises_value_error(self):
        """Disallowed zones now raise ValueError instead of being pruned."""
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                _leaf("n1.1", "a", "input"),
                _leaf("n1.2", "b", "memory"),
                _leaf("n1.3", "c", "reasoning"),
            ],
        )
        tree = _make_tree(root)
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])

    def test_root_zone_disallowed_raises_value_error(self):
        root = _leaf("n1", "root", "memory")
        tree = _make_tree(root)
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])

    def test_no_pruning_or_collapse_occurs(self):
        """The tree must not be modified — disallowed zones cause rejection."""
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                _leaf("n1.1", "keep", "input"),
                _leaf("n1.2", "drop", "memory"),
            ],
        )
        tree = _make_tree(root)
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])

    def test_deep_nested_disallowed_zone_raises(self):
        """Nodes deep in the tree with disallowed zones cause rejection."""
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="branch",
                    gate="AND",
                    zone="reasoning",
                    children=[
                        _leaf("n1.1.1", "ok", "input"),
                        _leaf("n1.1.2", "bad", "memory"),
                        _leaf("n1.1.3", "ok2", "reasoning"),
                    ],
                ),
                _leaf("n1.2", "leaf", "input"),
            ],
        )
        tree = _make_tree(root)
        with pytest.raises(ValueError, match="disallowed-zone.*n1.1.2"):
            _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])

    def test_zone_none_nodes_always_allowed(self):
        """Nodes with zone=None (external preconditions/impacts) are valid."""
        from scenario_forge.models.attack_tree import ExternalPreconditionAction

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone=None,
            action=None,
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="external",
                    gate="LEAF",
                    zone=None,
                    action=ExternalPreconditionAction(),
                ),
                _leaf("n1.2", "internal", "input"),
            ],
        )
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(tree, zones_active=["input"])
        assert result is tree  # no violation — zone=None is always allowed
