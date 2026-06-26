"""Tests for the q7y/etk bead cluster.

Covers:
- q7y: Scoring calibration rubric in Call 1 and Call 2 system prompts.
- etk: Narrative diversity enforcement via excluded_patterns.
"""

from __future__ import annotations

from collections import Counter
from unittest.mock import MagicMock

from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import (
    CausalChainReframed,
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
)
from scenario_forge.pipeline.generate import (
    _CALL1_SYSTEM,
    _CALL2_SYSTEM,
    extract_narrative_keywords,
    get_overused_patterns,
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
        sub_scenario_name="Test Sub-Scenario",
        sub_scenario_description="A test description",
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
        zones_active=[1, 2, 3],
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
        zone_sequence=[1, 2, 3],
        steps=[
            NarrativeStep(
                step_number=1,
                zone=1,
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

    def test_call1_contains_complexity_calibration(self):
        """Call 1 system prompt must have an Attack Complexity Calibration section."""
        assert "Attack Complexity Calibration" in _CALL1_SYSTEM

    def test_call1_mentions_low_complexity(self):
        """Rubric must give an example of LOW complexity."""
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "low complexity" in prompt_lower

    def test_call1_mentions_high_complexity(self):
        """Rubric must give an example of HIGH complexity."""
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "high complexity" in prompt_lower

    def test_call1_mentions_critical_complexity(self):
        """Rubric must mention CRITICAL complexity for extreme cases."""
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "critical complexity" in prompt_lower

    def test_call1_contains_anchor_examples(self):
        """The rubric should include concrete anchor examples."""
        prompt_lower = _CALL1_SYSTEM.lower()
        # Should mention specific attack types as examples
        assert "prompt injection" in prompt_lower
        assert "supply-chain" in prompt_lower or "supply chain" in prompt_lower

    def test_call1_warns_against_default_medium(self):
        """Prompt should warn against defaulting to medium for everything."""
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "do not default" in prompt_lower

    def test_call1_instructs_zone_sequence_matching(self):
        """Prompt should instruct matching zone_sequence length to complexity."""
        prompt_lower = _CALL1_SYSTEM.lower()
        assert "zone_sequence" in prompt_lower

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
            zone_sequence=[1, 2],
            steps=[
                {
                    "step_number": 1,
                    "zone": 1,
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
            zone_sequence=[1, 2],
            steps=[
                {
                    "step_number": 1,
                    "zone": 1,
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
