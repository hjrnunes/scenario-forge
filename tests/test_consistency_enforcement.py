"""Tests for post-generation consistency enforcement passes.

Covers:
- Leaf counting (_count_leaves)
- Parsimony check: tree with exactly budget leaves passes, budget+1 fails
- Zone consistency: missing zone detected, all zones present passes
- Step-node correspondence: ratio below 0.7 fails, at 0.7 passes
- _check_consistency integration: returns all violations at once
- Retry loop behavior in generate_scenario (mocked)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
)
from scenario_forge.pipeline.generate import (
    _check_consistency,
    _count_leaves,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_leaf(node_id: str, zone: str = "input", **kwargs) -> AttackTreeNode:
    """Create a minimal LEAF node."""
    return AttackTreeNode(
        id=node_id,
        label=f"Leaf {node_id}",
        gate=GateType.LEAF,
        zone=zone,
        **kwargs,
    )


def _make_tree(root: AttackTreeNode) -> AttackTree:
    """Build a minimal AttackTree."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )


def _make_narrative(
    zone_sequence: list[str],
    step_count: int = 3,
) -> NarrativeLayer:
    """Build a minimal NarrativeLayer with given zones and step count."""
    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=zone_sequence[i % len(zone_sequence)],
            action=f"Step {i + 1} action.",
            effect=f"Step {i + 1} effect.",
        )
        for i in range(step_count)
    ]
    return NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=zone_sequence,
        steps=steps,
    )


def _make_or_root(*children: AttackTreeNode) -> AttackTreeNode:
    """Create an OR root node with given children."""
    return AttackTreeNode(
        id="n1",
        label="Root",
        gate=GateType.OR,
        zone="input",
        children=list(children),
    )


def _make_and_node(
    node_id: str, *children: AttackTreeNode, zone: str = "input"
) -> AttackTreeNode:
    """Create an AND gate node with given children."""
    return AttackTreeNode(
        id=node_id,
        label=f"AND gate {node_id}",
        gate=GateType.AND,
        zone=zone,
        children=list(children),
    )


# ---------------------------------------------------------------------------
# Tests: _count_leaves
# ---------------------------------------------------------------------------


class TestCountLeaves:
    """Tests for the _count_leaves helper function."""

    def test_single_leaf(self) -> None:
        """A single LEAF node has 1 leaf."""
        leaf = _make_leaf("n1", zone="input")
        # AttackTree requires root id="n1", but _count_leaves works on nodes
        assert _count_leaves(leaf) == 1

    def test_or_with_two_leaves(self) -> None:
        """OR node with 2 LEAF children has 2 leaves."""
        root = _make_or_root(
            _make_leaf("n1.1"),
            _make_leaf("n1.2"),
        )
        assert _count_leaves(root) == 2

    def test_nested_tree(self) -> None:
        """Nested tree: OR -> (AND -> 2 leaves, LEAF) = 3 leaves."""
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
            ),
            _make_leaf("n1.2"),
        )
        assert _count_leaves(root) == 3

    def test_deep_tree(self) -> None:
        """Deeply nested tree counts all leaves correctly."""
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_and_node(
                    "n1.1.1",
                    _make_leaf("n1.1.1.1"),
                    _make_leaf("n1.1.1.2"),
                ),
                _make_leaf("n1.1.2"),
            ),
            _make_leaf("n1.2"),
        )
        assert _count_leaves(root) == 4


# ---------------------------------------------------------------------------
# Tests: parsimony check
# ---------------------------------------------------------------------------


class TestParsimonyCheck:
    """Parsimony enforcement: leaf count vs. budget."""

    def test_exactly_at_budget_passes(self) -> None:
        """Tree with exactly budget leaves produces no parsimony violation."""
        # Budget = 4 (2*1 + 2 for 1 technique)
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
            ),
            _make_and_node(
                "n1.2",
                _make_leaf("n1.2.1"),
                _make_leaf("n1.2.2"),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=4)

        violations = _check_consistency(tree, narrative, parsimony_budget=4)

        assert not any("parsimony" in v for v in violations)

    def test_one_over_budget_fails(self) -> None:
        """Tree with budget+1 leaves triggers parsimony violation."""
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
            ),
            _make_and_node(
                "n1.2",
                _make_leaf("n1.2.1"),
                _make_leaf("n1.2.2"),
                _make_leaf("n1.2.3"),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=5)

        violations = _check_consistency(tree, narrative, parsimony_budget=4)

        parsimony_violations = [v for v in violations if "parsimony" in v]
        assert len(parsimony_violations) == 1
        assert "5 leaves > 4 budget" in parsimony_violations[0]

    def test_under_budget_passes(self) -> None:
        """Tree with fewer leaves than budget produces no parsimony violation."""
        root = _make_or_root(
            _make_leaf("n1.1"),
            _make_leaf("n1.2"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=5)

        assert not any("parsimony" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: zone-sequence consistency
# ---------------------------------------------------------------------------


class TestZoneConsistency:
    """Zone-sequence check: every narrative zone must appear in the tree."""

    def test_all_zones_present_passes(self) -> None:
        """No violation when tree covers all narrative zones."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=2)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        assert not any("zone-sequence" in v for v in violations)

    def test_missing_zone_detected(self) -> None:
        """Violation when narrative zone is missing from tree."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="input"),
        )
        tree = _make_tree(root)
        # Narrative mentions "reasoning" but tree has only "input"
        narrative = _make_narrative(
            ["input", "reasoning"], step_count=2
        )

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        zone_violations = [v for v in violations if "zone-sequence" in v]
        assert len(zone_violations) == 1
        assert "reasoning" in zone_violations[0]

    def test_tree_has_extra_zones_ok(self) -> None:
        """No violation when tree has zones not in narrative (tree can be broader)."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
            _make_leaf("n1.3", zone="tool_execution"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input", "reasoning"], step_count=3)

        violations = _check_consistency(tree, narrative, parsimony_budget=10)

        assert not any("zone-sequence" in v for v in violations)


# ---------------------------------------------------------------------------
# Tests: step-node correspondence
# ---------------------------------------------------------------------------


class TestStepNodeCorrespondence:
    """Step-node correspondence: min/max ratio must meet floor."""

    def test_ratio_at_floor_passes(self) -> None:
        """Ratio exactly at 0.7 floor produces no violation."""
        # 7 steps, 10 leaves -> ratio = 7/10 = 0.7
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                *[_make_leaf(f"n1.1.{i}") for i in range(1, 6)],
            ),
            _make_and_node(
                "n1.2",
                *[_make_leaf(f"n1.2.{i}") for i in range(1, 6)],
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=7)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=20
        )

        assert not any("step-node" in v for v in violations)

    def test_ratio_below_floor_fails(self) -> None:
        """Ratio below 0.7 floor triggers step-node violation."""
        # 2 steps, 10 leaves -> ratio = 2/10 = 0.2
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                *[_make_leaf(f"n1.1.{i}") for i in range(1, 6)],
            ),
            _make_and_node(
                "n1.2",
                *[_make_leaf(f"n1.2.{i}") for i in range(1, 6)],
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=2)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=20
        )

        step_violations = [v for v in violations if "step-node" in v]
        assert len(step_violations) == 1
        assert "0.20 < 0.7 floor" in step_violations[0]

    def test_equal_steps_and_leaves_passes(self) -> None:
        """Ratio of 1.0 (equal steps and leaves) passes."""
        root = _make_or_root(
            _make_leaf("n1.1"),
            _make_leaf("n1.2"),
            _make_leaf("n1.3"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=3)

        violations = _check_consistency(
            tree, narrative, parsimony_budget=10
        )

        assert not any("step-node" in v for v in violations)

    def test_custom_floor(self) -> None:
        """Custom floor value is respected."""
        # 3 steps, 5 leaves -> ratio = 3/5 = 0.6
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                _make_leaf("n1.1.1"),
                _make_leaf("n1.1.2"),
                _make_leaf("n1.1.3"),
            ),
            _make_and_node(
                "n1.2",
                _make_leaf("n1.2.1"),
                _make_leaf("n1.2.2"),
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(["input"], step_count=3)

        # With floor=0.5, ratio 0.6 passes
        violations_low = _check_consistency(
            tree, narrative, parsimony_budget=10, step_node_floor=0.5
        )
        assert not any("step-node" in v for v in violations_low)

        # With floor=0.7, ratio 0.6 fails
        violations_high = _check_consistency(
            tree, narrative, parsimony_budget=10, step_node_floor=0.7
        )
        assert any("step-node" in v for v in violations_high)


# ---------------------------------------------------------------------------
# Tests: _check_consistency integration
# ---------------------------------------------------------------------------


class TestCheckConsistencyIntegration:
    """_check_consistency returns multiple violations when all checks fail."""

    def test_all_checks_fail(self) -> None:
        """All three checks can fail simultaneously."""
        # 10 leaves > budget 4 -> parsimony fails
        # narrative zone "reasoning" missing from tree -> zone fails
        # 2 steps, 10 leaves -> ratio 0.2 < 0.7 -> step-node fails
        root = _make_or_root(
            _make_and_node(
                "n1.1",
                *[_make_leaf(f"n1.1.{i}", zone="input") for i in range(1, 6)],
            ),
            _make_and_node(
                "n1.2",
                *[_make_leaf(f"n1.2.{i}", zone="input") for i in range(1, 6)],
            ),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(
            ["input", "reasoning"], step_count=2
        )

        violations = _check_consistency(tree, narrative, parsimony_budget=4)

        assert len(violations) == 3
        assert any("parsimony" in v for v in violations)
        assert any("zone-sequence" in v for v in violations)
        assert any("step-node" in v for v in violations)

    def test_no_violations(self) -> None:
        """Clean tree/narrative combination produces zero violations."""
        root = _make_or_root(
            _make_leaf("n1.1", zone="input"),
            _make_leaf("n1.2", zone="reasoning"),
            _make_leaf("n1.3", zone="input"),
        )
        tree = _make_tree(root)
        narrative = _make_narrative(
            ["input", "reasoning"], step_count=3
        )

        violations = _check_consistency(tree, narrative, parsimony_budget=5)

        assert violations == []


# ---------------------------------------------------------------------------
# Tests: retry loop in generate_scenario (mocked Call 2)
# ---------------------------------------------------------------------------


class TestConsistencyRetryLoop:
    """Verify the retry loop re-invokes Call 2 on consistency violations."""

    def _make_call_attack_tree_result(
        self, leaf_count: int, zones: list[str]
    ):
        """Build a mock return value for _call_attack_tree."""
        children = [
            _make_leaf(f"n1.{i+1}", zone=zones[i % len(zones)])
            for i in range(leaf_count)
        ]
        root = _make_or_root(*children)
        tree = _make_tree(root)
        result = MagicMock()
        result.content = "mock"
        return tree, result

    @patch("scenario_forge.pipeline.generate._strip_non_skeleton_techniques")
    @patch(
        "scenario_forge.pipeline.generate._warn_dominant_threat_id_crossref"
    )
    @patch("scenario_forge.pipeline.generate._validate_actor_type")
    @patch("scenario_forge.pipeline.generate._assemble_envelope")
    @patch("scenario_forge.pipeline.generate._call_behavior_spec")
    @patch("scenario_forge.pipeline.generate._call_attack_tree")
    @patch("scenario_forge.pipeline.generate._call_narrative")
    @patch("scenario_forge.pipeline.generate._call_actor_profile")
    def test_retry_on_violation_then_clean(
        self,
        mock_call0,
        mock_call1,
        mock_call2,
        mock_call3,
        mock_assemble,
        mock_validate_actor,
        mock_crossref,
        mock_strip,
    ) -> None:
        """Call 2 is retried once when first attempt has violations, second is clean."""
        # First call: 10 leaves with budget 4 -> parsimony violation
        bad_tree, bad_result = self._make_call_attack_tree_result(
            10, ["input", "reasoning"]
        )
        # Second call: 4 leaves -> passes
        good_tree, good_result = self._make_call_attack_tree_result(
            4, ["input", "reasoning"]
        )

        mock_call2.side_effect = [
            (bad_tree, bad_result),
            (good_tree, good_result),
        ]

        # Mock Call 0 (actor profile)
        mock_actor = MagicMock()
        mock_actor.actor_type = "cybercriminal"
        mock_actor.goal_category = None
        mock_result0 = MagicMock()
        mock_call0.return_value = (mock_actor, mock_result0)
        mock_validate_actor.return_value = mock_actor

        # Mock Call 1 (narrative)
        narrative = _make_narrative(["input", "reasoning"], step_count=4)
        mock_result1 = MagicMock()
        mock_call1.return_value = (narrative, mock_result1)

        # Mock Call 3 (behavior spec)
        mock_result3 = MagicMock()
        mock_call3.return_value = ("Feature: test", mock_result3)

        # Mock envelope assembly
        mock_envelope = MagicMock()
        mock_envelope.scenario_id = "AP-T1-01-abc123"
        mock_assemble.return_value = mock_envelope

        mock_strip.return_value = 0

        # Build seed and profile
        seed = MagicMock()
        seed.seed_id = "AP-T1-01"
        seed.threat_id = "T1"
        seed.atlas_technique_ids = ["AML.T0051"]

        profile = MagicMock()
        client = MagicMock()

        from scenario_forge.pipeline.generate import generate_scenario

        envelope, _ = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test system",
            pinned_technique_ids=["AML.T0051"],
        )

        # Call 2 should have been invoked twice (initial + 1 retry)
        assert mock_call2.call_count == 2

    @patch("scenario_forge.pipeline.generate._strip_non_skeleton_techniques")
    @patch(
        "scenario_forge.pipeline.generate._warn_dominant_threat_id_crossref"
    )
    @patch("scenario_forge.pipeline.generate._validate_actor_type")
    @patch("scenario_forge.pipeline.generate._assemble_envelope")
    @patch("scenario_forge.pipeline.generate._call_behavior_spec")
    @patch("scenario_forge.pipeline.generate._call_attack_tree")
    @patch("scenario_forge.pipeline.generate._call_narrative")
    @patch("scenario_forge.pipeline.generate._call_actor_profile")
    def test_no_retry_when_clean(
        self,
        mock_call0,
        mock_call1,
        mock_call2,
        mock_call3,
        mock_assemble,
        mock_validate_actor,
        mock_crossref,
        mock_strip,
    ) -> None:
        """Call 2 is not retried when the first attempt is clean."""
        good_tree, good_result = self._make_call_attack_tree_result(
            3, ["input", "reasoning"]
        )
        mock_call2.return_value = (good_tree, good_result)

        mock_actor = MagicMock()
        mock_actor.actor_type = "cybercriminal"
        mock_actor.goal_category = None
        mock_result0 = MagicMock()
        mock_call0.return_value = (mock_actor, mock_result0)
        mock_validate_actor.return_value = mock_actor

        narrative = _make_narrative(["input", "reasoning"], step_count=3)
        mock_result1 = MagicMock()
        mock_call1.return_value = (narrative, mock_result1)

        mock_result3 = MagicMock()
        mock_call3.return_value = ("Feature: test", mock_result3)

        mock_envelope = MagicMock()
        mock_envelope.scenario_id = "AP-T1-01-abc123"
        mock_assemble.return_value = mock_envelope

        mock_strip.return_value = 0

        seed = MagicMock()
        seed.seed_id = "AP-T1-01"
        seed.threat_id = "T1"
        seed.atlas_technique_ids = ["AML.T0051"]

        profile = MagicMock()
        client = MagicMock()

        from scenario_forge.pipeline.generate import generate_scenario

        envelope, _ = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test system",
            pinned_technique_ids=["AML.T0051"],
        )

        # Call 2 should have been invoked only once
        assert mock_call2.call_count == 1

    @patch("scenario_forge.pipeline.generate._strip_non_skeleton_techniques")
    @patch(
        "scenario_forge.pipeline.generate._warn_dominant_threat_id_crossref"
    )
    @patch("scenario_forge.pipeline.generate._validate_actor_type")
    @patch("scenario_forge.pipeline.generate._assemble_envelope")
    @patch("scenario_forge.pipeline.generate._call_behavior_spec")
    @patch("scenario_forge.pipeline.generate._call_attack_tree")
    @patch("scenario_forge.pipeline.generate._call_narrative")
    @patch("scenario_forge.pipeline.generate._call_actor_profile")
    def test_max_retries_exhausted(
        self,
        mock_call0,
        mock_call1,
        mock_call2,
        mock_call3,
        mock_assemble,
        mock_validate_actor,
        mock_crossref,
        mock_strip,
    ) -> None:
        """All retries exhausted: scenario is kept but Call 2 invoked 3 times total."""
        # All 3 calls return violation (10 leaves > budget 4)
        bad_tree, bad_result = self._make_call_attack_tree_result(
            10, ["input", "reasoning"]
        )
        mock_call2.return_value = (bad_tree, bad_result)

        mock_actor = MagicMock()
        mock_actor.actor_type = "cybercriminal"
        mock_actor.goal_category = None
        mock_result0 = MagicMock()
        mock_call0.return_value = (mock_actor, mock_result0)
        mock_validate_actor.return_value = mock_actor

        narrative = _make_narrative(["input", "reasoning"], step_count=4)
        mock_result1 = MagicMock()
        mock_call1.return_value = (narrative, mock_result1)

        mock_result3 = MagicMock()
        mock_call3.return_value = ("Feature: test", mock_result3)

        mock_envelope = MagicMock()
        mock_envelope.scenario_id = "AP-T1-01-abc123"
        mock_assemble.return_value = mock_envelope

        mock_strip.return_value = 0

        seed = MagicMock()
        seed.seed_id = "AP-T1-01"
        seed.threat_id = "T1"
        seed.atlas_technique_ids = ["AML.T0051"]

        profile = MagicMock()
        client = MagicMock()

        from scenario_forge.pipeline.generate import generate_scenario

        # Should NOT raise — scenario is kept despite violations
        envelope, _ = generate_scenario(
            seed=seed,
            profile=profile,
            client=client,
            use_case="Test system",
            pinned_technique_ids=["AML.T0051"],
        )

        # 1 initial + 2 retries = 3
        assert mock_call2.call_count == 3
