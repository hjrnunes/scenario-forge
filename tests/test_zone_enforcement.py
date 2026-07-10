"""Tests for post-generation zone enforcement.

Verifies that _enforce_zones_narrative and _enforce_zones_attack_tree
correctly strip zones/steps not in zones_active.
"""

from __future__ import annotations

import logging

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode
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
        result = _enforce_zones_narrative(narrative, zones_active=["input", "reasoning"])
        assert result is narrative  # no change needed

    def test_disallowed_zone_stripped_from_sequence_and_steps(self):
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "reasoning"],
            step_zones=["input", "memory", "reasoning"],
        )
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result.zone_sequence == ["input", "reasoning"]
        assert [s.zone for s in result.steps] == ["input", "reasoning"]

    def test_steps_renumbered_after_filtering(self):
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "reasoning"],
            step_zones=["input", "memory", "reasoning"],
        )
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert [s.step_number for s in result.steps] == [1, 2]

    def test_title_and_metadata_preserved(self):
        narrative = _make_narrative(
            zone_sequence=["input", "memory"],
            step_zones=["input", "memory"],
        )
        result = _enforce_zones_narrative(narrative, zones_active=["input"])
        assert result.title == "Test narrative"
        assert result.summary == "Summary"
        assert result.entry_point == "user prompts (zone 1)"

    def test_warning_logged_on_strip(self, caplog):
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "reasoning"],
            step_zones=["input", "memory", "reasoning"],
        )
        with caplog.at_level(logging.WARNING):
            _enforce_zones_narrative(
                narrative, zones_active=["input", "reasoning"]
            )
        assert any("Stripped disallowed zones from narrative" in m for m in caplog.messages)
        assert any("memory" in m for m in caplog.messages)

    def test_empty_zone_sequence_returns_original(self, caplog):
        """When filtering would empty zone_sequence, return the original."""
        narrative = _make_narrative(
            zone_sequence=["memory"],
            step_zones=["memory"],
        )
        with caplog.at_level(logging.WARNING):
            result = _enforce_zones_narrative(
                narrative, zones_active=["input", "reasoning"]
            )
        # Original is returned unchanged to avoid downstream crashes
        assert result is narrative
        assert any("keeping original narrative unchanged" in m for m in caplog.messages)

    def test_multiple_disallowed_zones(self):
        narrative = _make_narrative(
            zone_sequence=["input", "memory", "inter_agent", "reasoning"],
            step_zones=["input", "memory", "inter_agent", "reasoning"],
        )
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result.zone_sequence == ["input", "reasoning"]
        assert len(result.steps) == 2

    def test_preserves_zone_sequence_order(self):
        narrative = _make_narrative(
            zone_sequence=["reasoning", "memory", "input", "memory", "reasoning"],
            step_zones=["reasoning", "input"],
        )
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result.zone_sequence == ["reasoning", "input", "reasoning"]


# ---------------------------------------------------------------------------
# _enforce_zones_attack_tree
# ---------------------------------------------------------------------------


class TestEnforceZonesAttackTree:
    def test_none_zones_active_is_noop(self):
        root = AttackTreeNode(
            id="n1", label="root", gate="LEAF", zone="input"
        )
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
                AttackTreeNode(id="n1.1", label="a", gate="LEAF", zone="input"),
                AttackTreeNode(id="n1.2", label="b", gate="LEAF", zone="reasoning"),
            ],
        )
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(
            tree, zones_active=["input", "reasoning"]
        )
        assert result is tree

    def test_disallowed_leaf_removed(self):
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(id="n1.1", label="a", gate="LEAF", zone="input"),
                AttackTreeNode(id="n1.2", label="b", gate="LEAF", zone="memory"),
                AttackTreeNode(id="n1.3", label="c", gate="LEAF", zone="reasoning"),
            ],
        )
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(
            tree, zones_active=["input", "reasoning"]
        )
        child_zones = [c.zone for c in result.root.children]
        assert "memory" not in child_zones
        assert set(child_zones) == {"input", "reasoning"}

    def test_single_surviving_child_collapsed(self):
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(id="n1.1", label="keep", gate="LEAF", zone="input"),
                AttackTreeNode(id="n1.2", label="drop", gate="LEAF", zone="memory"),
            ],
        )
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(
            tree, zones_active=["input", "reasoning"]
        )
        # Root should be collapsed to the surviving child
        assert result.root.id == "n1"  # parent id preserved
        assert result.root.label == "keep"  # child content
        assert result.root.gate.value == "LEAF"

    def test_root_zone_disallowed_produces_fallback(self, caplog):
        root = AttackTreeNode(
            id="n1", label="root", gate="LEAF", zone="memory"
        )
        tree = _make_tree(root)
        with caplog.at_level(logging.WARNING):
            result = _enforce_zones_attack_tree(
                tree, zones_active=["input", "reasoning"]
            )
        assert result.root.zone == "input"  # fallback to first allowed zone
        assert any("Entire attack tree removed" in m for m in caplog.messages)

    def test_warning_logged_on_strip(self, caplog):
        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(id="n1.1", label="a", gate="LEAF", zone="input"),
                AttackTreeNode(id="n1.2", label="b", gate="LEAF", zone="memory"),
                AttackTreeNode(id="n1.3", label="c", gate="LEAF", zone="reasoning"),
            ],
        )
        tree = _make_tree(root)
        with caplog.at_level(logging.WARNING):
            _enforce_zones_attack_tree(
                tree, zones_active=["input", "reasoning"]
            )
        assert any("Stripped disallowed zones from attack tree" in m for m in caplog.messages)

    def test_deep_nested_removal(self):
        """Nodes deep in the tree with disallowed zones are removed."""
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
                        AttackTreeNode(
                            id="n1.1.1", label="ok", gate="LEAF", zone="input"
                        ),
                        AttackTreeNode(
                            id="n1.1.2", label="bad", gate="LEAF", zone="memory"
                        ),
                        AttackTreeNode(
                            id="n1.1.3", label="ok2", gate="LEAF", zone="reasoning"
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2", label="leaf", gate="LEAF", zone="input"
                ),
            ],
        )
        tree = _make_tree(root)
        result = _enforce_zones_attack_tree(
            tree, zones_active=["input", "reasoning"]
        )
        # n1.1 should still exist with 2 children (memory one removed)
        branch = result.root.children[0]
        assert branch.gate.value == "AND"
        assert len(branch.children) == 2
        assert all(c.zone in ("input", "reasoning") for c in branch.children)
