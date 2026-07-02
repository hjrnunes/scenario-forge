"""Tests for the cyo/0kv/twz bead cluster.

Covers:
- cyo: HITL failure mechanism language in the Call 1 system prompt.
- 0kv: CJK/non-Latin sanitization of English-language output.
- twz: Priority scoring diversity with varied inputs.
"""

from __future__ import annotations

from scenario_forge.models.scenario import (
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
)
from scenario_forge.pipeline.generate import (
    _CALL1_SYSTEM,
    _compute_priority,
    _sanitize_non_latin,
)
from scenario_forge.pipeline.seeds import ScenarioSeed


# ===========================================================================
# Bead cyo: HITL failure mechanism prompt
# ===========================================================================


class TestHITLFailureMechanism:
    """The Call 1 system prompt must include HITL failure mechanism language."""

    def test_system_prompt_contains_hitl_failure_mechanism(self):
        assert "human-in-the-loop" in _CALL1_SYSTEM.lower()

    def test_system_prompt_mentions_specific_failure_examples(self):
        # Should mention at least some concrete failure mechanisms
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "reviewer fatigue" in prompt_lower
        assert "time pressure" in prompt_lower

    def test_system_prompt_warns_against_bare_assertion(self):
        # Should caution against simply asserting bypass
        assert "simply asserting" in _CALL1_SYSTEM.lower()

    def test_system_prompt_mentions_failure_mechanism(self):
        assert "failure mechanism" in _CALL1_SYSTEM.lower()


# ===========================================================================
# Bead 0kv: CJK output sanitization
# ===========================================================================


class TestCJKSanitization:
    """Tests for _sanitize_non_latin() -- CJK/non-Latin character removal."""

    def test_pure_english_unchanged(self):
        text = "This is a perfectly normal English sentence."
        assert _sanitize_non_latin(text) == text

    def test_cjk_mixed_with_english_stripped(self):
        # Real example from gemma-4-26b output
        result = _sanitize_non_latin("linguistic指令")
        assert result == "linguistic"

    def test_cjk_mid_word_stripped(self):
        result = _sanitize_non_latin("potential泄露 data")
        assert result == "potential data"

    def test_pure_cjk_becomes_empty(self):
        result = _sanitize_non_latin("指令泄露")
        assert result == ""

    def test_preserves_punctuation(self):
        text = "Hello, world! (test-case) [foo] {bar} #123"
        assert _sanitize_non_latin(text) == text

    def test_preserves_numbers(self):
        text = "Zone 1: Input Surfaces"
        assert _sanitize_non_latin(text) == text

    def test_handles_empty_string(self):
        assert _sanitize_non_latin("") == ""

    def test_handles_whitespace_cleanup(self):
        # After removing CJK chars, collapse multiple spaces
        result = _sanitize_non_latin("hello 世界 world")
        assert result == "hello world"

    def test_preserves_newlines(self):
        text = "line one\nline two\nline three"
        assert _sanitize_non_latin(text) == text

    def test_cyrillic_stripped(self):
        result = _sanitize_non_latin("hello мир world")
        assert result == "hello world"

    def test_arabic_stripped(self):
        result = _sanitize_non_latin("hello عالم world")
        assert result == "hello world"

    def test_accented_latin_preserved(self):
        # Accented Latin characters (like in French/Spanish) should be kept
        text = "cafe resume naive"
        assert _sanitize_non_latin(text) == text


# ---------------------------------------------------------------------------
# Helpers for scoring tests
# ---------------------------------------------------------------------------


def _make_seed(
    *,
    impact: str | None = None,
    risk_id: str = "test-risk",
) -> ScenarioSeed:
    """Create a minimal ScenarioSeed for testing."""
    ref_kwargs: dict = {
        "risk_id": risk_id,
        "risk_name": "Test Risk",
        "risk_description": "Test description",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 0.9,
        "grounding_confidence": "high",
    }
    if impact is not None:
        ref_kwargs["impact"] = impact
    return ScenarioSeed(
        seed_id="AP-T1-01",
        threat_id="T1",
        threat_name="Test Threat",
        mechanism_name="Test Attack Pattern",
        mechanism_description="A test description",
        risk_card_ref=RiskCardRef(**ref_kwargs),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        atlas_technique_ids=[],
    )


def _make_narrative(
    *,
    zone_sequence: list[str] | None = None,
    num_steps: int = 3,
) -> NarrativeLayer:
    """Create a minimal NarrativeLayer for testing."""
    zones = zone_sequence or ["input", "reasoning", "tool_execution"]
    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=zones[i % len(zones)],
            action=f"action {i + 1}",
            effect=f"effect {i + 1}",
        )
        for i in range(num_steps)
    ]
    return NarrativeLayer(
        title="Test Scenario",
        summary="A test summary.",
        entry_point="test entry point (zone 1)",
        zone_sequence=zones,
        steps=steps,
    )


def _make_attack_tree(*, depth: int = 3, node_count: int = 5, exposures=None):
    """Create an AttackTree with precise depth and node count for scoring tests.

    Strategy: build a spine of AND nodes to achieve target depth, then
    pad with extra leaf siblings on the root to reach the target node count.
    """
    from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode

    def _build_spine(target_depth: int, prefix: str = "n1") -> AttackTreeNode:
        """Build a linear spine to achieve target depth."""
        node_kwargs: dict = {
            "id": prefix,
            "label": f"Node {prefix}",
            "zone": "input",
        }
        if exposures and prefix == "n1":
            node_kwargs["structural_exposure"] = exposures[0]

        if target_depth <= 1:
            node_kwargs["gate"] = "LEAF"
            return AttackTreeNode(**node_kwargs)

        node_kwargs["gate"] = "AND"
        child1 = _build_spine(target_depth - 1, prefix=f"{prefix}.1")
        child2 = AttackTreeNode(
            id=f"{prefix}.2",
            label=f"Node {prefix}.2",
            gate="LEAF",
            zone="reasoning",
        )
        node_kwargs["children"] = [child1, child2]
        return AttackTreeNode(**node_kwargs)

    root = _build_spine(depth)

    # Count current nodes and pad to reach target
    from scenario_forge.pipeline.generate import _tree_node_count

    current_count = _tree_node_count(root)
    extra_needed = max(0, node_count - current_count)

    # Add extra leaves as siblings of the root's existing children
    if extra_needed > 0 and root.children is not None:
        extra_children = list(root.children)
        next_child_num = len(extra_children) + 1
        for i in range(extra_needed):
            extra_children.append(
                AttackTreeNode(
                    id=f"n1.{next_child_num + i}",
                    label=f"Extra leaf {next_child_num + i}",
                    gate="LEAF",
                    zone=[
                        "input",
                        "reasoning",
                        "tool_execution",
                        "memory",
                        "inter_agent",
                    ][i % 5],
                )
            )
        root = root.model_copy(update={"children": extra_children})

    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Test goal",
        root=root,
    )


# ===========================================================================
# Bead twz: Priority scoring diversity
# ===========================================================================


class TestPriorityScoringDiversity:
    """Verify that the priority scoring formula produces varied scores
    when given varied inputs."""

    def test_different_zone_counts_produce_different_scores(self):
        """Scenarios traversing more zones should score differently."""
        seed = _make_seed()
        n1 = _make_narrative(zone_sequence=["input"])
        n4 = _make_narrative(
            zone_sequence=["input", "reasoning", "tool_execution", "memory"]
        )
        tree = _make_attack_tree(depth=3, node_count=5)

        p1 = _compute_priority(n1, tree, seed)
        p4 = _compute_priority(n4, tree, seed)

        assert p1.composite != p4.composite

    def test_different_tree_depths_produce_different_scores(self):
        """Deeper attack trees should score differently."""
        seed = _make_seed()
        narrative = _make_narrative()
        shallow = _make_attack_tree(depth=2, node_count=3)
        deep = _make_attack_tree(depth=4, node_count=7)

        p_shallow = _compute_priority(narrative, shallow, seed)
        p_deep = _compute_priority(narrative, deep, seed)

        assert p_shallow.composite != p_deep.composite

    def test_different_impact_levels_produce_different_scores(self):
        """Seeds with different risk impact text should score differently."""
        seed_low = _make_seed(impact="minor inconvenience")
        seed_crit = _make_seed(impact="severe data breach, catastrophic loss")
        narrative = _make_narrative()
        tree = _make_attack_tree()

        p_low = _compute_priority(narrative, tree, seed_low)
        p_crit = _compute_priority(narrative, tree, seed_crit)

        assert p_low.composite != p_crit.composite

    def test_structural_exposure_affects_score(self):
        """Structural exposure signals should change the score."""
        seed = _make_seed()
        narrative = _make_narrative()
        tree_none = _make_attack_tree()
        tree_spof = _make_attack_tree(
            exposures=["single_point_of_failure"],
        )

        p_none = _compute_priority(narrative, tree_none, seed)
        p_spof = _compute_priority(narrative, tree_spof, seed)

        assert p_none.composite != p_spof.composite

    def test_varied_batch_produces_varied_scores(self):
        """A batch of scenarios with varied inputs should not all get
        the same score."""
        configs = [
            {"zone_sequence": ["input"], "impact": "minor", "depth": 2, "nodes": 3},
            {
                "zone_sequence": ["input", "reasoning"],
                "impact": None,
                "depth": 3,
                "nodes": 5,
            },
            {
                "zone_sequence": ["input", "reasoning", "tool_execution"],
                "impact": "severe critical",
                "depth": 4,
                "nodes": 7,
            },
            {
                "zone_sequence": ["input", "reasoning", "tool_execution", "memory"],
                "impact": "significant",
                "depth": 5,
                "nodes": 9,
            },
            {
                "zone_sequence": ["input", "tool_execution", "inter_agent"],
                "impact": "catastrophic",
                "depth": 3,
                "nodes": 6,
            },
        ]
        scores = set()
        for cfg in configs:
            seed = _make_seed(impact=cfg["impact"])
            narrative = _make_narrative(zone_sequence=cfg["zone_sequence"])
            tree = _make_attack_tree(depth=cfg["depth"], node_count=cfg["nodes"])
            p = _compute_priority(narrative, tree, seed)
            scores.add(p.composite)

        # At least 3 distinct scores from 5 varied scenarios
        assert len(scores) >= 3, f"Only {len(scores)} distinct scores: {scores}"

    def test_no_attack_tree_does_not_crash(self):
        """Priority computation must work when attack_tree is None."""
        seed = _make_seed()
        narrative = _make_narrative()
        p = _compute_priority(narrative, None, seed)
        assert 0.0 <= p.composite <= 1.0

    def test_score_in_valid_range(self):
        """All computed scores must be in [0.0, 1.0]."""
        seed = _make_seed(impact="catastrophic")
        narrative = _make_narrative(
            zone_sequence=[
                "input",
                "reasoning",
                "tool_execution",
                "memory",
                "inter_agent",
            ]
        )
        tree = _make_attack_tree(depth=5, node_count=10)
        p = _compute_priority(narrative, tree, seed)
        assert 0.0 <= p.composite <= 1.0

    def test_zone_traversal_depth_is_continuous(self):
        """Zone traversal depth should be a continuous signal, not
        just bucketed."""
        seed = _make_seed()
        tree = _make_attack_tree(depth=3, node_count=5)

        # 2 zones vs 3 zones - both "medium" in old bucketing
        n2 = _make_narrative(zone_sequence=["input", "reasoning"])
        n3 = _make_narrative(zone_sequence=["input", "reasoning", "tool_execution"])

        p2 = _compute_priority(n2, tree, seed)
        p3 = _compute_priority(n3, tree, seed)

        assert p2.composite != p3.composite, (
            "2 zones and 3 zones should produce different scores"
        )

    def test_tree_complexity_is_continuous(self):
        """Tree complexity (node count) should produce differentiated scores
        even for similar node counts."""
        seed = _make_seed()
        narrative = _make_narrative()

        t4 = _make_attack_tree(depth=3, node_count=4)
        t7 = _make_attack_tree(depth=3, node_count=7)

        p4 = _compute_priority(narrative, t4, seed)
        p7 = _compute_priority(narrative, t7, seed)

        # Both would have been "medium" in the old bucketed system (4-7 nodes)
        # With continuous scoring, they should differ
        assert p4.composite != p7.composite, (
            "4 nodes and 7 nodes should produce different scores"
        )
