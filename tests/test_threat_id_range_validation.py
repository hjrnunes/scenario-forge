"""Tests for threat_id range validation in _check_tree_threat_ids.

Verifies that the range check flags invalid threat IDs (outside T1-T17)
while accepting valid ones and respecting the T6 cross-ref policy (per-node
threat_id may differ from the scenario-level threat_id).
"""

from __future__ import annotations

from scenario_forge.models.attack_tree import AttackTreeNode, GateType
from scenario_forge.models.scenario import SemanticViolation
from scenario_forge.pipeline.validation import _check_tree_threat_ids


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _leaf(node_id: str, threat_id: str | None = None) -> AttackTreeNode:
    return AttackTreeNode(
        id=node_id,
        label=f"Step {node_id}",
        gate=GateType.LEAF,
        zone="input",
        threat_id=threat_id,
    )


def _run_check(
    root: AttackTreeNode,
    expected_threat: str = "T7",
) -> list[SemanticViolation]:
    """Run _check_tree_threat_ids and return the violations list."""
    violations: list[SemanticViolation] = []
    _check_tree_threat_ids(root, expected_threat, violations)
    return violations


# ---------------------------------------------------------------------------
# Valid threat_ids pass
# ---------------------------------------------------------------------------


class TestValidThreatIds:
    """Valid threat IDs in range T1-T17 produce no violations."""

    def test_t1_passes(self):
        root = _leaf("n1", threat_id="T1")
        violations = _run_check(root)
        assert violations == []

    def test_t7_passes(self):
        root = _leaf("n1", threat_id="T7")
        violations = _run_check(root)
        assert violations == []

    def test_t15_passes(self):
        root = _leaf("n1", threat_id="T15")
        violations = _run_check(root)
        assert violations == []

    def test_t17_passes(self):
        root = _leaf("n1", threat_id="T17")
        violations = _run_check(root)
        assert violations == []

    def test_all_valid_ids_pass(self):
        """Every ID from T1 to T17 passes."""
        for i in range(1, 18):
            root = _leaf("n1", threat_id=f"T{i}")
            violations = _run_check(root)
            assert violations == [], f"T{i} should be valid but got violations"


# ---------------------------------------------------------------------------
# Invalid threat_ids are flagged
# ---------------------------------------------------------------------------


class TestInvalidThreatIds:
    """Invalid threat IDs outside T1-T17 are flagged."""

    def test_t0_flagged(self):
        root = _leaf("n1", threat_id="T0")
        violations = _run_check(root)
        assert len(violations) == 1
        assert violations[0].rule == "threat_id_range"
        assert "T0" in violations[0].message
        assert violations[0].severity == "major"

    def test_t18_flagged(self):
        root = _leaf("n1", threat_id="T18")
        violations = _run_check(root)
        assert len(violations) == 1
        assert violations[0].rule == "threat_id_range"
        assert "T18" in violations[0].message

    def test_t99_flagged(self):
        root = _leaf("n1", threat_id="T99")
        violations = _run_check(root)
        assert len(violations) == 1
        assert "T99" in violations[0].message

    def test_t100_flagged(self):
        """A numerically valid pattern but out of range is still caught."""
        root = _leaf("n1", threat_id="T100")
        violations = _run_check(root)
        assert len(violations) == 1
        assert "T100" in violations[0].message

    def test_violation_includes_node_id(self):
        root = _leaf("n1.99", threat_id="T99")
        violations = _run_check(root)
        assert len(violations) == 1
        assert "n1.99" in violations[0].message


# ---------------------------------------------------------------------------
# Nodes with no threat_id are not flagged
# ---------------------------------------------------------------------------


class TestNullThreatId:
    """Nodes without a threat_id are silently skipped."""

    def test_none_threat_id_passes(self):
        root = _leaf("n1", threat_id=None)
        violations = _run_check(root)
        assert violations == []

    def test_tree_with_all_none_passes(self):
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id=None,
            children=[
                _leaf("n1.1", threat_id=None),
                _leaf("n1.2", threat_id=None),
            ],
        )
        violations = _run_check(root)
        assert violations == []


# ---------------------------------------------------------------------------
# Recursive validation on nested trees
# ---------------------------------------------------------------------------


class TestNestedTreeValidation:
    """The check validates children recursively at all depths."""

    def test_invalid_in_deep_child(self):
        """An invalid threat_id buried in a nested child is caught."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            threat_id="T7",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Sub-goal A",
                    gate=GateType.OR,
                    zone="reasoning",
                    threat_id="T1",
                    children=[
                        _leaf("n1.1.1", threat_id="T99"),
                        _leaf("n1.1.2", threat_id="T3"),
                    ],
                ),
                _leaf("n1.2", threat_id="T7"),
            ],
        )
        violations = _run_check(root)
        assert len(violations) == 1
        assert "n1.1.1" in violations[0].message
        assert "T99" in violations[0].message

    def test_multiple_invalid_across_tree(self):
        """Multiple invalid threat_ids at different depths are all caught."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T0",
            children=[
                _leaf("n1.1", threat_id="T18"),
                _leaf("n1.2", threat_id="T7"),
            ],
        )
        violations = _run_check(root)
        assert len(violations) == 2
        invalid_ids = {v.message.split("'")[3] for v in violations}
        assert invalid_ids == {"T0", "T18"}

    def test_valid_nested_tree_passes(self):
        """A deeply nested tree with all valid threat_ids passes."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            threat_id="T7",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Sub-goal A",
                    gate=GateType.OR,
                    zone="reasoning",
                    threat_id="T1",
                    children=[
                        _leaf("n1.1.1", threat_id="T3"),
                        _leaf("n1.1.2", threat_id="T15"),
                    ],
                ),
                _leaf("n1.2", threat_id="T17"),
            ],
        )
        violations = _run_check(root)
        assert violations == []

    def test_internal_node_invalid_threat_id(self):
        """An internal (non-leaf) node with invalid threat_id is flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            threat_id="T99",
            children=[
                _leaf("n1.1", threat_id="T1"),
                _leaf("n1.2", threat_id="T7"),
            ],
        )
        violations = _run_check(root)
        assert len(violations) == 1
        assert "n1" in violations[0].message
        assert "T99" in violations[0].message


# ---------------------------------------------------------------------------
# T6 cross-ref policy: per-node threat_id != scenario-level is accepted
# ---------------------------------------------------------------------------


class TestT6CrossRefPolicy:
    """Per-node threat_id differing from scenario-level threat is NOT flagged.

    Per ``decision-t6-crossref-policy``, a node's threat_id reflects the
    mechanism, not the scenario-level threat.  The range check validates
    only that the ID is in T1-T17, not that it matches expected_threat.
    """

    def test_different_valid_threat_id_accepted(self):
        """A node with T1 under a T7 scenario passes (valid range)."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T1",
            children=[
                _leaf("n1.1", threat_id="T3"),
                _leaf("n1.2", threat_id="T15"),
            ],
        )
        # expected_threat is T7 but nodes use T1, T3, T15 -- all valid range
        violations = _run_check(root, expected_threat="T7")
        assert violations == []

    def test_all_nodes_different_from_scenario_threat(self):
        """Every node has a different valid threat_id than expected -- no flags."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T2",
            children=[
                _leaf("n1.1", threat_id="T8"),
                _leaf("n1.2", threat_id="T10"),
            ],
        )
        violations = _run_check(root, expected_threat="T7")
        assert violations == []

    def test_mix_of_valid_cross_ref_and_invalid(self):
        """Valid cross-ref nodes pass; only the out-of-range node is flagged."""
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            threat_id="T1",
            children=[
                _leaf("n1.1", threat_id="T3"),
                _leaf("n1.2", threat_id="T99"),
            ],
        )
        violations = _run_check(root, expected_threat="T7")
        assert len(violations) == 1
        assert "T99" in violations[0].message
