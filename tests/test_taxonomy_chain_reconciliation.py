"""Tests for taxonomy chain technique ID reconciliation.

Covers scenario-forge-2w7m: atlas_technique_ids in the taxonomy chain
should reflect actual attack tree content, not blindly inherit from
seed metadata.
"""

from __future__ import annotations

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
from scenario_forge.models.scenario import (
    CallMetadata,
    CallName,
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
)
from scenario_forge.pipeline.generate import _assemble_envelope
from scenario_forge.pipeline.seeds import ScenarioSeed


# ===========================================================================
# Helpers
# ===========================================================================


def _make_seed(
    atlas_technique_ids: list[str] | None = None,
) -> ScenarioSeed:
    """Create a minimal ScenarioSeed."""
    return ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Test Threat",
        attack_pattern_name="Test Attack",
        attack_pattern_description="Test description",
        risk_card_ref=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="Test description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        owasp_llm_ids=["LLM06"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=atlas_technique_ids or [],
        atlas_provenance_ids=atlas_technique_ids or [],
    )


def _make_narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Test Scenario",
        summary="A test summary.",
        entry_point="test entry point (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1, zone="input", action="act", effect="eff"
            ),
        ],
    )


def _make_profile():
    from scenario_forge.models.capability_profile import CapabilityProfile

    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=["test entry point (zone 1)"],
        confidence="high",
    )


def _make_tree(
    technique_ids: list[str | None],
) -> AttackTree:
    """Build an attack tree whose leaves carry the given technique_ids.

    Creates a root AND node with one leaf per entry in *technique_ids*.
    At least two entries are required (AND gate minimum).
    """
    assert len(technique_ids) >= 2, "Need at least 2 technique_ids for AND gate"
    children = []
    for i, tid in enumerate(technique_ids, start=1):
        children.append(
            AttackTreeNode(
                id=f"n1.{i}",
                label=f"Step {i}",
                gate=GateType.LEAF,
                zone="input",
                technique_id=tid,
            )
        )
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="Test goal",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=children,
        ),
    )


def _make_call_metas() -> list[CallMetadata]:
    return [
        CallMetadata(
            call=CallName.narrative, prompt_tokens=10,
            completion_tokens=10, duration_ms=100,
        ),
    ]


# ===========================================================================
# AttackTree.collect_technique_ids tests
# ===========================================================================


class TestCollectTechniqueIds:
    """Tests for AttackTree.collect_technique_ids helper method."""

    def test_collects_from_leaves(self):
        tree = _make_tree(["AML.T0051", "AML.T0054"])
        assert tree.collect_technique_ids() == ["AML.T0051", "AML.T0054"]

    def test_deduplicates(self):
        tree = _make_tree(["AML.T0051", "AML.T0051"])
        assert tree.collect_technique_ids() == ["AML.T0051"]

    def test_skips_none(self):
        tree = _make_tree(["AML.T0051", None])
        assert tree.collect_technique_ids() == ["AML.T0051"]

    def test_all_none_returns_empty(self):
        tree = _make_tree([None, None])
        assert tree.collect_technique_ids() == []

    def test_collects_from_nested_tree(self):
        """technique_ids are collected depth-first from nested nodes."""
        inner_child_1 = AttackTreeNode(
            id="n1.1.1",
            label="Deep leaf 1",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0051",
        )
        inner_child_2 = AttackTreeNode(
            id="n1.1.2",
            label="Deep leaf 2",
            gate=GateType.LEAF,
            zone="reasoning",
            technique_id="AML.T0054",
        )
        inner_node = AttackTreeNode(
            id="n1.1",
            label="Inner AND",
            gate=GateType.AND,
            zone="input",
            technique_id=None,
            children=[inner_child_1, inner_child_2],
        )
        outer_leaf = AttackTreeNode(
            id="n1.2",
            label="Outer leaf",
            gate=GateType.LEAF,
            zone="reasoning",
            technique_id="AML.T0053",
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="Test goal",
            root=AttackTreeNode(
                id="n1",
                label="Root",
                gate=GateType.AND,
                zone="input",
                children=[inner_node, outer_leaf],
            ),
        )
        assert tree.collect_technique_ids() == [
            "AML.T0051", "AML.T0054", "AML.T0053"
        ]


# ===========================================================================
# Taxonomy chain reconciliation tests
# ===========================================================================


class TestTaxonomyChainReconciliation:
    """atlas_technique_ids in taxonomy_chain must reflect tree content."""

    def test_tree_techniques_override_seed(self):
        """When tree has techniques, taxonomy chain uses tree IDs, not seed."""
        seed = _make_seed(atlas_technique_ids=["AML.T0051", "AML.T0054"])
        tree = _make_tree(["AML.T0051", None])  # tree only has T0051

        envelope = _assemble_envelope(
            seed=seed,
            profile=_make_profile(),
            narrative=_make_narrative(),
            attack_tree=tree,
            behavior_spec="Feature: test",
            call_metadata_list=_make_call_metas(),
            model_name="test-model",
            use_case="test",
            notes=[],
        )

        # Should contain only the technique actually in the tree
        assert envelope.faceting.taxonomy_chain.atlas_technique_ids == ["AML.T0051"]

    def test_dropped_technique_not_in_chain(self):
        """When tree drops a seed technique, it must not appear in taxonomy chain."""
        seed = _make_seed(atlas_technique_ids=["AML.T0051", "AML.T0054"])
        # Tree only uses T0054, not T0051
        tree = _make_tree([None, "AML.T0054"])

        envelope = _assemble_envelope(
            seed=seed,
            profile=_make_profile(),
            narrative=_make_narrative(),
            attack_tree=tree,
            behavior_spec="Feature: test",
            call_metadata_list=_make_call_metas(),
            model_name="test-model",
            use_case="test",
            notes=[],
        )

        assert envelope.faceting.taxonomy_chain.atlas_technique_ids == ["AML.T0054"]
        assert "AML.T0051" not in envelope.faceting.taxonomy_chain.atlas_technique_ids

    def test_no_tree_techniques_yields_none(self):
        """When tree has no technique_ids, atlas_technique_ids is None."""
        seed = _make_seed(atlas_technique_ids=["AML.T0051"])
        tree = _make_tree([None, None])

        envelope = _assemble_envelope(
            seed=seed,
            profile=_make_profile(),
            narrative=_make_narrative(),
            attack_tree=tree,
            behavior_spec="Feature: test",
            call_metadata_list=_make_call_metas(),
            model_name="test-model",
            use_case="test",
            notes=[],
        )

        assert envelope.faceting.taxonomy_chain.atlas_technique_ids is None

    def test_seed_with_empty_atlas_and_tree_without_techniques(self):
        """When seed has no atlas_technique_ids and tree has none, result is None."""
        seed = _make_seed(atlas_technique_ids=[])
        tree = _make_tree([None, None])

        envelope = _assemble_envelope(
            seed=seed,
            profile=_make_profile(),
            narrative=_make_narrative(),
            attack_tree=tree,
            behavior_spec="Feature: test",
            call_metadata_list=_make_call_metas(),
            model_name="test-model",
            use_case="test",
            notes=[],
        )

        assert envelope.faceting.taxonomy_chain.atlas_technique_ids is None

    def test_provenance_ids_unchanged(self):
        """atlas_provenance_ids in scenario_seed_metadata should remain from seed."""
        seed = _make_seed(atlas_technique_ids=["AML.T0051", "AML.T0054"])
        tree = _make_tree(["AML.T0051", None])  # tree drops T0054

        envelope = _assemble_envelope(
            seed=seed,
            profile=_make_profile(),
            narrative=_make_narrative(),
            attack_tree=tree,
            behavior_spec="Feature: test",
            call_metadata_list=_make_call_metas(),
            model_name="test-model",
            use_case="test",
            notes=[],
        )

        # atlas_provenance_ids documents where the scenario came from (seed provenance)
        # and should NOT be reconciled with tree content
        assert envelope.scenario_seed_metadata["atlas_provenance_ids"] == [
            "AML.T0051", "AML.T0054"
        ]
        # But taxonomy_chain.atlas_technique_ids should only have what's in tree
        assert envelope.faceting.taxonomy_chain.atlas_technique_ids == ["AML.T0051"]

    def test_tree_all_techniques_present(self):
        """When tree uses all seed techniques, taxonomy chain matches seed."""
        seed = _make_seed(atlas_technique_ids=["AML.T0051", "AML.T0054"])
        tree = _make_tree(["AML.T0051", "AML.T0054"])

        envelope = _assemble_envelope(
            seed=seed,
            profile=_make_profile(),
            narrative=_make_narrative(),
            attack_tree=tree,
            behavior_spec="Feature: test",
            call_metadata_list=_make_call_metas(),
            model_name="test-model",
            use_case="test",
            notes=[],
        )

        assert set(envelope.faceting.taxonomy_chain.atlas_technique_ids) == {
            "AML.T0051", "AML.T0054"
        }
