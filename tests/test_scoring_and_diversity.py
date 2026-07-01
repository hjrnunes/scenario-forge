"""Tests for scoring calibration and diversity enforcement.

Covers:
- q7y/9zz: Scoring calibration rubric in Call 1 and Call 2 system prompts.
- etk/cbk: Narrative diversity enforcement via excluded_patterns and
  structural pattern detection.
"""

from __future__ import annotations

from collections import Counter
from unittest.mock import MagicMock

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import (
    AttackComplexity,
    CausalChainReframed,
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
    SeverityLevel,
)
from scenario_forge.pipeline.generate import (
    _CALL1_SYSTEM,
    _CALL2_SYSTEM,
    _heuristic_attack_complexity,
    _heuristic_risk_impact,
    extract_narrative_keywords,
    extract_structural_pattern,
    get_overused_patterns,
    get_overused_structural_patterns,
)
from scenario_forge.pipeline.seeds import ScenarioSeed


# ===========================================================================
# Helpers
# ===========================================================================


def _make_seed() -> ScenarioSeed:
    """Create a minimal ScenarioSeed for testing."""
    return ScenarioSeed(
        seed_id="T1-S1",
        threat_id="T1",
        threat_name="Test Threat",
        mechanism_name="Test Sub-Scenario",
        mechanism_description="A test description",
        risk_card_ref=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="Test description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        atlas_technique_ids=[],
    )


def _make_profile() -> CapabilityProfile:
    """Create a minimal CapabilityProfile for testing."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=[
            "document uploads (zone 1)",
            "API endpoint (zone 1)",
            "admin console (zone 2)",
        ],
        confidence="high",
    )


def _make_narrative(
    *,
    title: str = "Test Scenario",
    summary: str = "A test summary.",
    causal_chain: CausalChainReframed | None = None,
) -> NarrativeLayer:
    """Create a NarrativeLayer for testing."""
    return NarrativeLayer(
        title=title,
        summary=summary,
        entry_point="test entry point (zone 1)",
        zone_sequence=["input", "reasoning", "tool_execution"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="action 1",
                effect="effect 1",
            ),
        ],
        causal_chain_reframed=causal_chain,
    )


# ===========================================================================
# Bead q7y: Scoring calibration rubric in prompts
# ===========================================================================


class TestScoringCalibrationRubric:
    """The Call 1 and Call 2 system prompts must include complexity
    calibration guidance to prevent scoring monoculture."""

    def test_call2_contains_tree_calibration(self):
        """Call 2 system prompt must have Tree Complexity Calibration section."""
        assert "Tree Complexity Calibration" in _CALL2_SYSTEM

    def test_call2_mentions_depth_ranges(self):
        """Call 2 calibration should mention specific depth ranges."""
        prompt_lower = _CALL2_SYSTEM.lower()
        assert "depth 2-3" in prompt_lower or "depth 2" in prompt_lower
        assert "depth 4-5" in prompt_lower or "depth 4" in prompt_lower

    def test_call2_warns_against_uniform_depth(self):
        """Call 2 should warn against same depth for every scenario."""
        prompt_lower = _CALL2_SYSTEM.lower()
        assert "do not default" in prompt_lower



# ===========================================================================
# Bead 9zz: Heuristic scoring spread
# ===========================================================================


def _make_tree_node(node_id: str, children: list[AttackTreeNode] | None = None) -> AttackTreeNode:
    """Build a single attack tree node, LEAF if no children."""
    if children:
        return AttackTreeNode(
            id=node_id, label=f"Node {node_id}", gate=GateType.AND,
            zone="input", children=children,
        )
    return AttackTreeNode(
        id=node_id, label=f"Leaf {node_id}", gate=GateType.LEAF, zone="input",
    )


def _make_tree_simple(nodes: int, depth: int) -> AttackTree:
    """Build a synthetic attack tree with controlled node count and depth.

    Builds a linear chain to reach the target depth. Each AND node gets
    at least 2 children (one chain child + one leaf sibling). Extra nodes
    are added as leaf siblings at the root level.
    """
    if depth <= 1 or nodes <= 1:
        root = _make_tree_node("n1")
        return AttackTree(id="tree-T1-S1", seed_id="T1-S1", goal="Test", root=root)

    # Build a chain to target depth, always ensuring >= 2 children per AND
    def _build(d: int, prefix: str) -> tuple[AttackTreeNode, int]:
        if d >= depth:
            return _make_tree_node(prefix), 1

        # Build chain child for depth
        chain_child, chain_used = _build(d + 1, f"{prefix}.1")
        # Always add a sibling leaf for valid AND gate
        sibling = _make_tree_node(f"{prefix}.2")
        children = [chain_child, sibling]
        total_used = 1 + chain_used + 1  # self + chain subtree + sibling

        return _make_tree_node(prefix, children), total_used

    root, used = _build(1, "n1")

    # Add extra leaf siblings at root level to reach target node count
    if root.children is not None:
        sib_idx = len(root.children) + 1
        while used < nodes:
            root.children.append(_make_tree_node(f"n1.{sib_idx}"))
            used += 1
            sib_idx += 1

    return AttackTree(id="tree-T1-S1", seed_id="T1-S1", goal="Test", root=root)


class TestHeuristicAttackComplexity:
    """Bead 9zz/o3k: attack_complexity three-tier heuristic with low/medium/high spread."""

    # --- Low complexity tier ---

    def test_small_shallow_tree_is_low(self):
        """3 nodes, depth 2 -> low complexity (shallow AND small)."""
        tree = _make_tree_simple(nodes=3, depth=2)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.low

    def test_single_node_tree_is_low(self):
        """1 node, depth 1 -> low complexity (trivial tree)."""
        tree = _make_tree_simple(nodes=1, depth=1)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.low

    def test_four_nodes_depth_two_is_low(self):
        """4 nodes, depth 2 -> low complexity (boundary: depth<=2 AND count<=4)."""
        tree = _make_tree_simple(nodes=4, depth=2)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.low

    # --- Medium complexity tier ---

    def test_medium_tree_is_medium(self):
        """5 nodes, depth 3 -> medium complexity."""
        tree = _make_tree_simple(nodes=5, depth=3)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.medium

    def test_seven_nodes_depth_three_is_medium(self):
        """7 nodes, depth 3 -> medium (below high thresholds)."""
        tree = _make_tree_simple(nodes=7, depth=3)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.medium

    def test_five_nodes_depth_three_is_medium(self):
        """5 nodes, depth 3 -> medium (above low thresholds but below high)."""
        tree = _make_tree_simple(nodes=5, depth=3)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.medium

    # --- High complexity tier ---

    def test_large_deep_tree_is_high(self):
        """10 nodes, depth 4 -> high complexity (both signals)."""
        tree = _make_tree_simple(nodes=10, depth=4)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.high

    def test_deep_tree_is_high(self):
        """5 nodes, depth 4 -> high complexity (depth >= 4 alone suffices).

        Bead o3k: deep trees qualify for high even without many nodes.
        """
        tree = _make_tree_simple(nodes=5, depth=4)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.high

    def test_wide_tree_is_high(self):
        """Wide attack surface with 8+ nodes qualifies as high.

        Bead o3k: node_count >= 8 alone suffices for high complexity.
        Many alternative exploitation paths represent a wide attack surface.
        """
        # Build a wide but shallow tree: 10 nodes, depth 2
        children = [
            AttackTreeNode(id=f"n1.{i}", label=f"Leaf {i}", gate=GateType.LEAF, zone="input")
            for i in range(1, 10)
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, zone="input", children=children,
        )
        tree = AttackTree(id="tree-T1-S1", seed_id="T1-S1", goal="Test", root=root)
        result = _heuristic_attack_complexity(tree)
        # 10 nodes -> high (wide attack surface)
        assert result == AttackComplexity.high

    def test_eight_nodes_boundary_is_high(self):
        """Exactly 8 nodes, depth 3 -> high (node_count >= 8 triggers high)."""
        tree = _make_tree_simple(nodes=8, depth=3)
        result = _heuristic_attack_complexity(tree)
        assert result == AttackComplexity.high

    # --- Narrative fallback (no tree) ---

    def test_no_tree_uses_narrative_fallback(self):
        """Without a tree, narrative zone count determines complexity."""
        narrative_1zone_obj = NarrativeLayer(
            title="T", summary="S", entry_point="ep",
            zone_sequence=["input"],
            steps=[NarrativeStep(step_number=1, zone="input", action="a", effect="e")],
        )
        result = _heuristic_attack_complexity(None, narrative_1zone_obj)
        assert result == AttackComplexity.low

    def test_no_tree_many_zones_is_high(self):
        """Without a tree, 4+ zones -> high complexity."""
        narrative = NarrativeLayer(
            title="T", summary="S", entry_point="ep",
            zone_sequence=["input", "reasoning", "tool_execution", "memory"],
            steps=[NarrativeStep(step_number=1, zone="input", action="a", effect="e")],
        )
        result = _heuristic_attack_complexity(None, narrative)
        assert result == AttackComplexity.high

    def test_no_tree_two_zones_is_medium(self):
        """Without a tree, 2-3 zones -> medium complexity."""
        narrative = NarrativeLayer(
            title="T", summary="S", entry_point="ep",
            zone_sequence=["input", "reasoning"],
            steps=[NarrativeStep(step_number=1, zone="input", action="a", effect="e")],
        )
        result = _heuristic_attack_complexity(None, narrative)
        assert result == AttackComplexity.medium


class TestHeuristicRiskImpact:
    """Bead 9zz: risk_impact should produce spread, not flat medium."""

    def test_catastrophic_impact_text_is_critical(self):
        """Impact text with 'catastrophic' -> critical."""
        seed = _make_seed()
        seed.risk_card_ref.impact = "Catastrophic organizational damage"
        result = _heuristic_risk_impact(seed)
        assert result == SeverityLevel.critical

    def test_minor_impact_text_is_low(self):
        """Impact text with 'minor' -> low."""
        seed = _make_seed()
        seed.risk_card_ref.impact = "Minor inconvenience to a single user"
        result = _heuristic_risk_impact(seed)
        assert result == SeverityLevel.low

    def test_financial_impact_text_is_high(self):
        """Impact text with 'financial' -> high."""
        seed = _make_seed()
        seed.risk_card_ref.impact = "Significant financial losses"
        result = _heuristic_risk_impact(seed)
        assert result == SeverityLevel.high

    def test_generic_impact_text_with_wide_zones_elevates(self):
        """Generic impact text + 4-zone narrative should push toward high."""
        seed = _make_seed()
        seed.risk_card_ref.impact = "Some generic impact description"
        narrative = NarrativeLayer(
            title="T", summary="S", entry_point="ep",
            zone_sequence=["input", "reasoning", "tool_execution", "memory"],
            steps=[NarrativeStep(step_number=1, zone="input", action="a", effect="e")],
        )
        result = _heuristic_risk_impact(seed, narrative)
        # Generic text (0.4) + wide zones (0.3) = 0.7 -> medium
        # But with consequence text or structural exposure, could be higher
        assert result in (SeverityLevel.medium, SeverityLevel.high)

    def test_no_impact_text_is_low(self):
        """No impact text at all -> low (not medium default)."""
        seed = _make_seed()
        seed.risk_card_ref.impact = None
        result = _heuristic_risk_impact(seed)
        assert result == SeverityLevel.low

    def test_consequence_text_contributes(self):
        """Consequence text should contribute to the score."""
        seed = _make_seed()
        seed.risk_card_ref.impact = "Some generic impact"
        seed.risk_card_ref.consequence = "Cascading failure across all systems"
        result = _heuristic_risk_impact(seed)
        # Generic impact (0.4) + cascading consequence (0.4) = 0.8 -> high
        assert result == SeverityLevel.high


# ===========================================================================
# Bead etk: Narrative pattern keyword extraction
# ===========================================================================


class TestExtractNarrativeKeywords:
    """Tests for extract_narrative_keywords()."""

    def test_extracts_from_causal_chain_when_available(self):
        """Should prefer causal chain fields over title/summary."""
        causal = CausalChainReframed(
            threat="I exploit the compliance engine poisoning vulnerability",
            threat_source="I am a sophisticated attacker",
            vulnerability="compliance engine poisoning through data manipulation",
            consequence="reviewer fatigue leads to approval of tainted data",
            impact="data integrity breach across the system",
        )
        narrative = _make_narrative(
            title="Something Completely Different",
            summary="An unrelated summary about cats",
            causal_chain=causal,
        )
        keywords = extract_narrative_keywords(narrative)
        assert len(keywords) > 0
        assert len(keywords) <= 3
        # Should extract from vulnerability/consequence, not title
        assert "cats" not in keywords

    def test_falls_back_to_title_summary_without_causal_chain(self):
        """When no causal chain, should extract from title/summary."""
        narrative = _make_narrative(
            title="RAG Poisoning via SharePoint Integration",
            summary="I exploit the SharePoint integration to poison RAG data stores",
        )
        keywords = extract_narrative_keywords(narrative)
        assert len(keywords) > 0
        assert len(keywords) <= 3
        # Should extract meaningful words from the title/summary
        assert "sharepoint" in keywords or "poisoning" in keywords or "rag" in keywords

    def test_respects_max_keywords(self):
        """Should not return more than max_keywords."""
        narrative = _make_narrative(
            title="Complex Multi-Stage RAG Poisoning Through SharePoint Memory Injection",
            summary="This involves compliance poisoning and reviewer fatigue and memory injection",
        )
        keywords = extract_narrative_keywords(narrative, max_keywords=2)
        assert len(keywords) <= 2

    def test_filters_stop_words(self):
        """Should not include common stop words in results."""
        narrative = _make_narrative(
            title="The Attack On The System",
            summary="The attacker uses the system to attack the zone",
        )
        keywords = extract_narrative_keywords(narrative)
        # None of the stop words should appear
        stop_words = {"the", "and", "system", "attack", "attacker", "zone"}
        for kw in keywords:
            assert kw not in stop_words

    def test_returns_empty_list_for_minimal_narrative(self):
        """Should handle narratives with very short text gracefully."""
        narrative = _make_narrative(title="A", summary="B")
        keywords = extract_narrative_keywords(narrative)
        # Short tokens (< 3 chars) are filtered out
        assert isinstance(keywords, list)

    def test_keywords_are_lowercased(self):
        """All returned keywords should be lowercase."""
        narrative = _make_narrative(
            title="RAG POISONING via SHAREPOINT",
            summary="I exploit the SHAREPOINT integration",
        )
        keywords = extract_narrative_keywords(narrative)
        for kw in keywords:
            assert kw == kw.lower()


# ===========================================================================
# Bead etk: get_overused_patterns
# ===========================================================================


class TestGetOverusedPatterns:
    """Tests for get_overused_patterns()."""

    def test_empty_counter_returns_empty(self):
        """No patterns tracked -> none overused."""
        assert get_overused_patterns(Counter()) == []

    def test_below_threshold_returns_empty(self):
        """Patterns at or below threshold are not overused."""
        counts = Counter({"poisoning": 2, "injection": 1})
        result = get_overused_patterns(counts, threshold=2)
        assert result == []

    def test_above_threshold_detected(self):
        """Patterns above threshold are flagged."""
        counts = Counter({"poisoning": 5, "injection": 3, "fatigue": 1})
        result = get_overused_patterns(counts, threshold=2)
        assert "poisoning" in result
        assert "injection" in result
        assert "fatigue" not in result

    def test_max_five_patterns_returned(self):
        """Should return at most 5 patterns even if more are overused."""
        counts = Counter({f"pattern{i}": 10 for i in range(10)})
        result = get_overused_patterns(counts, threshold=2)
        assert len(result) <= 5

    def test_ordered_by_frequency(self):
        """Returned patterns should be ordered by count (most frequent first)."""
        counts = Counter({"rare": 3, "common": 10, "medium": 5})
        result = get_overused_patterns(counts, threshold=2)
        assert result[0] == "common"
        assert result[1] == "medium"
        assert result[2] == "rare"


# ===========================================================================
# Bead etk: Prompt includes excluded_patterns
# ===========================================================================


class TestNarrativePatternDiversityPrompt:
    """Tests that excluded_patterns are injected into the Call 1 prompt."""

    def test_prompt_includes_excluded_patterns(self):
        """When excluded_patterns is provided, the prompt contains them."""
        from scenario_forge.pipeline.generate import (
            Call1Response,
            _call_narrative,
        )

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = Call1Response(
            title="Test",
            summary="Test summary",
            entry_point="API endpoint (zone 1)",
            zone_sequence=["input", "reasoning"],
            steps=[
                {
                    "step_number": 1,
                    "zone": "input",
                    "action": "test",
                    "effect": "test",
                }
            ],
        )
        mock_client.complete.return_value = mock_result

        seed = _make_seed()
        profile = _make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            excluded_patterns=["poisoning", "fatigue", "compliance"],
        )

        call_args = mock_client.complete.call_args
        user_prompt = call_args.kwargs.get("user_prompt") or call_args[1].get(
            "user_prompt"
        )
        if user_prompt is None:
            user_prompt = (
                call_args[0][1]
                if len(call_args[0]) > 1
                else call_args.kwargs["user_prompt"]
            )
        assert "Attack Pattern Diversity" in user_prompt
        assert "poisoning" in user_prompt
        assert "fatigue" in user_prompt
        assert "compliance" in user_prompt
        assert "DIFFERENT" in user_prompt

    def test_prompt_no_pattern_section_when_no_patterns(self):
        """When excluded_patterns is None/empty, no pattern section in prompt."""
        from scenario_forge.pipeline.generate import (
            Call1Response,
            _call_narrative,
        )

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = Call1Response(
            title="Test",
            summary="Test summary",
            entry_point="document uploads (zone 1)",
            zone_sequence=["input", "reasoning"],
            steps=[
                {
                    "step_number": 1,
                    "zone": "input",
                    "action": "test",
                    "effect": "test",
                }
            ],
        )
        mock_client.complete.return_value = mock_result

        seed = _make_seed()
        profile = _make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            excluded_patterns=None,
        )

        call_args = mock_client.complete.call_args
        user_prompt = call_args.kwargs.get("user_prompt") or call_args[1].get(
            "user_prompt"
        )
        if user_prompt is None:
            user_prompt = (
                call_args[0][1]
                if len(call_args[0]) > 1
                else call_args.kwargs["user_prompt"]
            )
        assert "Attack Pattern Diversity" not in user_prompt


# ===========================================================================
# Bead cbk: Structural attack pattern extraction
# ===========================================================================


class TestExtractStructuralPattern:
    """Tests for extract_structural_pattern() — detects the attack phase
    sequence (e.g., 'inject->hallucinate->persist->bypass') rather than
    surface keywords."""

    def test_classic_poison_hallucinate_persist_bypass(self):
        """The canonical convergence pattern should be detected."""
        narrative = NarrativeLayer(
            title="Test",
            summary="Test summary",
            entry_point="ep",
            zone_sequence=["input", "reasoning", "memory", "reasoning"],
            steps=[
                NarrativeStep(step_number=1, zone="input", action="I poison the API data with false information", effect="tainted data"),
                NarrativeStep(step_number=2, zone="reasoning", action="The model starts to hallucinate and produce false outputs", effect="wrong output"),
                NarrativeStep(step_number=3, zone="memory", action="False data persists in long-term memory", effect="permanent taint"),
                NarrativeStep(step_number=4, zone="reasoning", action="I bypass the human reviewer through fatigue", effect="approved"),
            ],
        )
        pattern = extract_structural_pattern(narrative)
        assert "poison" in pattern
        assert "hallucinate" in pattern
        assert "persist" in pattern
        assert "bypass" in pattern

    def test_simple_inject_exfiltrate(self):
        """A simple two-phase attack: inject then exfiltrate."""
        narrative = NarrativeLayer(
            title="Test",
            summary="S",
            entry_point="ep",
            zone_sequence=["input", "tool_execution"],
            steps=[
                NarrativeStep(step_number=1, zone="input", action="I inject a malicious prompt", effect="accepted"),
                NarrativeStep(step_number=2, zone="tool_execution", action="I exfiltrate sensitive data via the tool output", effect="data stolen"),
            ],
        )
        pattern = extract_structural_pattern(narrative)
        assert pattern == "inject->exfiltrate"

    def test_collapses_consecutive_duplicates(self):
        """Multiple consecutive steps of the same phase should collapse."""
        narrative = NarrativeLayer(
            title="Test",
            summary="S",
            entry_point="ep",
            zone_sequence=["input", "input", "tool_execution"],
            steps=[
                NarrativeStep(step_number=1, zone="input", action="I inject payload A", effect="partial"),
                NarrativeStep(step_number=2, zone="input", action="I inject payload B to reinforce", effect="full"),
                NarrativeStep(step_number=3, zone="tool_execution", action="I exfiltrate the result", effect="done"),
            ],
        )
        pattern = extract_structural_pattern(narrative)
        assert pattern == "inject->exfiltrate"

    def test_unrecognized_actions_become_other(self):
        """Steps with no recognized phase keywords become 'other'."""
        narrative = NarrativeLayer(
            title="Test",
            summary="S",
            entry_point="ep",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(step_number=1, zone="input", action="I do something unusual and novel", effect="unclear"),
            ],
        )
        pattern = extract_structural_pattern(narrative)
        assert pattern == "other"

    def test_probe_escalate_exfiltrate(self):
        """A reconnaissance-first attack pattern."""
        narrative = NarrativeLayer(
            title="Test",
            summary="S",
            entry_point="ep",
            zone_sequence=["input", "reasoning", "tool_execution"],
            steps=[
                NarrativeStep(step_number=1, zone="input", action="I probe the API to enumerate endpoints", effect="map"),
                NarrativeStep(step_number=2, zone="reasoning", action="I escalate privileges via admin misconfiguration", effect="admin"),
                NarrativeStep(step_number=3, zone="tool_execution", action="I exfiltrate the full database", effect="stolen"),
            ],
        )
        pattern = extract_structural_pattern(narrative)
        assert pattern == "probe->escalate->exfiltrate"


class TestGetOverusedStructuralPatterns:
    """Tests for get_overused_structural_patterns()."""

    def test_empty_counter_returns_empty(self):
        counts = Counter()
        assert get_overused_structural_patterns(counts) == []

    def test_below_threshold_returns_empty(self):
        counts = Counter({"inject->exfiltrate": 2, "poison->bypass": 1})
        assert get_overused_structural_patterns(counts, threshold=2) == []

    def test_above_threshold_detected(self):
        counts = Counter({
            "poison->hallucinate->persist->bypass": 5,
            "inject->exfiltrate": 3,
            "probe->escalate": 1,
        })
        result = get_overused_structural_patterns(counts, threshold=2)
        assert "poison->hallucinate->persist->bypass" in result
        assert "inject->exfiltrate" in result
        assert "probe->escalate" not in result

    def test_max_three_returned(self):
        counts = Counter({f"pattern{i}->step": 10 for i in range(10)})
        result = get_overused_structural_patterns(counts, threshold=2)
        assert len(result) <= 3

    def test_other_only_pattern_excluded(self):
        """Patterns that are just 'other' should not be flagged."""
        counts = Counter({"other": 10})
        result = get_overused_structural_patterns(counts, threshold=2)
        assert result == []


class TestStructuralPatternPromptInjection:
    """Tests that excluded_structural_patterns are injected into the Call 1 prompt."""

    def test_prompt_includes_structural_exclusions(self):
        """When excluded_structural_patterns is provided, prompt includes the section."""
        from scenario_forge.pipeline.generate import (
            Call1Response,
            _call_narrative,
        )

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = Call1Response(
            title="Test",
            summary="Test summary",
            entry_point="API endpoint (zone 1)",
            zone_sequence=["input", "reasoning"],
            steps=[
                {
                    "step_number": 1,
                    "zone": "input",
                    "action": "test",
                    "effect": "test",
                }
            ],
        )
        mock_client.complete.return_value = mock_result

        seed = _make_seed()
        profile = _make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            excluded_structural_patterns=["poison->hallucinate->persist->bypass"],
        )

        call_args = mock_client.complete.call_args
        user_prompt = call_args.kwargs.get("user_prompt") or call_args[1].get(
            "user_prompt"
        )
        if user_prompt is None:
            user_prompt = (
                call_args[0][1]
                if len(call_args[0]) > 1
                else call_args.kwargs["user_prompt"]
            )
        assert "Structural Attack Pattern Diversity" in user_prompt
        assert "poison" in user_prompt.lower()
        assert "bypass" in user_prompt.lower()
        assert "fundamentally different" in user_prompt.lower()

    def test_prompt_no_structural_section_when_none(self):
        """When no structural patterns excluded, section absent from prompt."""
        from scenario_forge.pipeline.generate import (
            Call1Response,
            _call_narrative,
        )

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = Call1Response(
            title="Test",
            summary="Test summary",
            entry_point="document uploads (zone 1)",
            zone_sequence=["input", "reasoning"],
            steps=[
                {
                    "step_number": 1,
                    "zone": "input",
                    "action": "test",
                    "effect": "test",
                }
            ],
        )
        mock_client.complete.return_value = mock_result

        seed = _make_seed()
        profile = _make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            excluded_structural_patterns=None,
        )

        call_args = mock_client.complete.call_args
        user_prompt = call_args.kwargs.get("user_prompt") or call_args[1].get(
            "user_prompt"
        )
        if user_prompt is None:
            user_prompt = (
                call_args[0][1]
                if len(call_args[0]) > 1
                else call_args.kwargs["user_prompt"]
            )
        assert "Structural Attack Pattern Diversity" not in user_prompt
