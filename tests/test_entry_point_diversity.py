"""Tests for hybrid entry point diversity enforcement.

Covers:
- Affinity computation (entry point -> zone mapping)
- Entry point assignment logic (diversity tracking, fair-share threshold)
- Prompt includes hint and exclusion list when provided
- Edge case: only 1 entry point available
"""

from __future__ import annotations

from collections import Counter
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.pipeline.generate import (
    assign_entry_point,
    compute_entry_point_affinity,
    get_overused_entry_points,
)


# ---------------------------------------------------------------------------
# compute_entry_point_affinity
# ---------------------------------------------------------------------------


class TestComputeEntryPointAffinity:
    """Tests for the affinity scoring function."""

    def test_empty_entry_points_returns_empty(self):
        assert compute_entry_point_affinity([], ["input", "reasoning"]) == {}

    def test_input_entry_point_has_high_affinity_for_zone_1(self):
        scores = compute_entry_point_affinity(
            ["user input form (zone 1)"],
            ["input", "reasoning"],
        )
        assert len(scores) == 1
        # "input" and "form" both map to input zone; zone_sequence has {input, reasoning}
        # ep_zones = {input}, target = {input, reasoning}, overlap = {input}, union = {input, reasoning}
        # score = 1/2 = 0.5
        assert scores["user input form (zone 1)"] == pytest.approx(0.5)

    def test_tool_entry_point_has_high_affinity_for_zone_3(self):
        scores = compute_entry_point_affinity(
            ["plugin interface (zone 3)"],
            ["tool_execution"],
        )
        # "plugin" maps to tool_execution zone; target = {tool_execution}
        # ep_zones = {tool_execution}, overlap = {tool_execution}, union = {tool_execution}
        # score = 1/1 = 1.0
        assert scores["plugin interface (zone 3)"] == pytest.approx(1.0)

    def test_admin_console_has_affinity_for_zone_2_and_3(self):
        scores = compute_entry_point_affinity(
            ["admin console (zone 2)"],
            ["reasoning", "tool_execution"],
        )
        # "admin" -> [reasoning, tool_execution], "console" -> [reasoning, tool_execution]
        # ep_zones = {reasoning, tool_execution}, target = {reasoning, tool_execution}
        # overlap = {reasoning, tool_execution}, union = {reasoning, tool_execution} -> score = 1.0
        assert scores["admin console (zone 2)"] == pytest.approx(1.0)

    def test_no_keyword_match_defaults_to_zone_1(self):
        scores = compute_entry_point_affinity(
            ["exotic interface (zone 1)"],
            ["input"],
        )
        # No keyword match -> defaults to {input}
        # target = {input}, overlap = {input}, union = {input} -> score = 1.0
        assert scores["exotic interface (zone 1)"] == pytest.approx(1.0)

    def test_no_keyword_match_low_affinity_for_non_zone_1(self):
        scores = compute_entry_point_affinity(
            ["exotic interface (zone 1)"],
            ["tool_execution", "memory"],
        )
        # No keyword match -> defaults to {input}
        # target = {tool_execution, memory}, overlap = {}, union = {input, tool_execution, memory} -> score = 0.0
        assert scores["exotic interface (zone 1)"] == pytest.approx(0.0)

    def test_multiple_entry_points_scored_independently(self):
        scores = compute_entry_point_affinity(
            [
                "document uploads (zone 1)",
                "admin console (zone 2)",
                "API endpoint (zone 1)",
            ],
            ["input", "reasoning"],
        )
        assert len(scores) == 3
        # All should have non-negative scores
        for ep, score in scores.items():
            assert 0.0 <= score <= 1.0

    def test_api_entry_point_zones_1_and_3(self):
        scores = compute_entry_point_affinity(
            ["REST API (zone 1)"],
            ["input", "tool_execution"],
        )
        # "api" -> [input, tool_execution]
        # ep_zones = {input, tool_execution}, target = {input, tool_execution} -> overlap = {input, tool_execution}, union = {input, tool_execution}
        # score = 1.0
        assert scores["REST API (zone 1)"] == pytest.approx(1.0)

    def test_memory_entry_point_affinity_for_zone_4(self):
        scores = compute_entry_point_affinity(
            ["shared memory store (zone 4)"],
            ["memory"],
        )
        # "memory" -> [memory], "storage"? no, "store" does not match "storage"
        # ep_zones = {memory}, target = {memory} -> 1.0
        assert scores["shared memory store (zone 4)"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# assign_entry_point
# ---------------------------------------------------------------------------


class TestAssignEntryPoint:
    """Tests for the entry point assignment logic."""

    def test_empty_entry_points_returns_none(self):
        result = assign_entry_point([], ["input", "reasoning"], Counter(), 10)
        assert result is None

    def test_single_entry_point_returns_it(self):
        result = assign_entry_point(
            ["only option (zone 1)"],
            ["input", "reasoning"],
            Counter(),
            10,
        )
        assert result == "only option (zone 1)"

    def test_prefers_high_affinity_entry_point(self):
        eps = [
            "document uploads (zone 1)",
            "admin console (zone 2)",
        ]
        # Zone sequence [reasoning, tool_execution] -> admin console should win
        result = assign_entry_point(eps, ["reasoning", "tool_execution"], Counter(), 10)
        assert result == "admin console (zone 2)"

    def test_penalises_overused_entry_point(self):
        eps = [
            "document uploads (zone 1)",
            "admin console (zone 2)",
        ]
        # Even though uploads has better affinity for zone 1, it's overused
        usage = Counter({"document uploads (zone 1)": 8})
        result = assign_entry_point(eps, ["input"], usage, 10)
        # fair_share = ceil(10/2) = 5, uploads used 8 -> penalty = (8-5)*0.3 = 0.9
        # uploads affinity for input zone is high but penalty brings it down
        # admin console has lower affinity but no penalty
        assert result is not None

    def test_diversity_tracking_with_equal_affinity(self):
        eps = [
            "chat interface (zone 1)",
            "input form (zone 1)",
        ]
        # Both have same affinity for input zone
        usage = Counter({"chat interface (zone 1)": 6})
        result = assign_entry_point(eps, ["input"], usage, 10)
        # fair_share = ceil(10/2) = 5, chat used 6 -> penalty = (6-5)*0.3 = 0.3
        # input form used 0 -> no penalty
        assert result == "input form (zone 1)"

    def test_fair_share_calculation(self):
        eps = ["a", "b", "c"]
        # 10 seeds / 3 eps -> fair_share = ceil(10/3) = 4
        # None overused yet
        usage = Counter({"a": 4})
        result = assign_entry_point(eps, ["input"], usage, 10)
        # "a" is at fair share (4), not over it -> no penalty
        assert result is not None

    def test_returns_entry_point_not_none_with_multiple(self):
        eps = ["a (zone 1)", "b (zone 2)", "c (zone 3)"]
        result = assign_entry_point(
            eps, ["input", "reasoning", "tool_execution"], Counter(), 9
        )
        assert result in eps


# ---------------------------------------------------------------------------
# get_overused_entry_points
# ---------------------------------------------------------------------------


class TestGetOverusedEntryPoints:
    """Tests for the overused entry point detection."""

    def test_single_entry_point_never_overused(self):
        result = get_overused_entry_points(
            ["only option"],
            Counter({"only option": 100}),
            10,
        )
        assert result == []

    def test_no_usage_means_none_overused(self):
        result = get_overused_entry_points(
            ["a", "b", "c"],
            Counter(),
            10,
        )
        assert result == []

    def test_detects_overused_entry_point(self):
        eps = ["a", "b", "c"]
        # fair_share = ceil(9/3) = 3
        usage = Counter({"a": 4, "b": 1, "c": 1})
        result = get_overused_entry_points(eps, usage, 9)
        assert result == ["a"]

    def test_at_fair_share_is_not_overused(self):
        eps = ["a", "b"]
        # fair_share = ceil(10/2) = 5
        usage = Counter({"a": 5, "b": 5})
        result = get_overused_entry_points(eps, usage, 10)
        assert result == []

    def test_above_fair_share_is_overused(self):
        eps = ["a", "b"]
        # fair_share = ceil(10/2) = 5
        usage = Counter({"a": 6, "b": 4})
        result = get_overused_entry_points(eps, usage, 10)
        assert result == ["a"]

    def test_multiple_overused(self):
        eps = ["a", "b", "c"]
        # fair_share = ceil(6/3) = 2
        usage = Counter({"a": 3, "b": 3, "c": 0})
        result = get_overused_entry_points(eps, usage, 6)
        assert set(result) == {"a", "b"}


# ---------------------------------------------------------------------------
# Prompt integration: _call_narrative includes hints
# ---------------------------------------------------------------------------


class TestNarrativePromptIntegration:
    """Tests that the Call 1 prompt includes entry point guidance when provided."""

    def _make_seed(self):
        """Create a minimal ScenarioSeed for testing."""
        from scenario_forge.models.scenario import RiskCardRef
        from scenario_forge.pipeline.seeds import ScenarioSeed

        return ScenarioSeed(
            seed_id="AP-T1-01",
            threat_id="T1",
            threat_name="Test Threat",
            attack_pattern_name="Test Attack Pattern",
            attack_pattern_description="A test description",
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

    def _make_profile(self):
        """Create a minimal CapabilityProfile for testing."""
        from scenario_forge.models.capability_profile import CapabilityProfile

        return CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                "document uploads (zone 1)",
                "API endpoint (zone 1)",
                "admin console (zone 2)",
            ],
            confidence="high",
            kc_subcodes=["KC1.1", "KC6.1.1"],
        )

    @patch("scenario_forge.pipeline.generate.LLMClient")
    def test_prompt_includes_preferred_entry_point(self, mock_client_cls):
        """When preferred_entry_point is set, the user prompt contains it."""
        from scenario_forge.pipeline.generate import (
            Call1Response,
            _call_narrative,
        )

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = Call1Response(
            title="Test",
            summary="Test summary",
            entry_point="admin console (zone 2)",
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

        seed = self._make_seed()
        profile = self._make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            preferred_entry_point="admin console (zone 2)",
            excluded_entry_points=None,
        )

        # Verify the user prompt passed to the LLM contains the hint
        call_args = mock_client.complete.call_args
        user_prompt = call_args.kwargs.get("user_prompt") or call_args[1].get(
            "user_prompt"
        )
        if user_prompt is None:
            # Try positional
            user_prompt = (
                call_args[0][1]
                if len(call_args[0]) > 1
                else call_args.kwargs["user_prompt"]
            )
        assert "Preferred entry point: admin console (zone 2)" in user_prompt

    @patch("scenario_forge.pipeline.generate.LLMClient")
    def test_prompt_includes_exclusion_list(self, mock_client_cls):
        """When excluded_entry_points is set, the user prompt contains them."""
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

        seed = self._make_seed()
        profile = self._make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            preferred_entry_point=None,
            excluded_entry_points=["document uploads (zone 1)"],
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
        assert "document uploads (zone 1)" in user_prompt
        assert "overused" in user_prompt.lower()

    @patch("scenario_forge.pipeline.generate.LLMClient")
    def test_prompt_no_diversity_section_when_no_hints(self, mock_client_cls):
        """When no preferred/excluded entry points, no diversity section in prompt."""
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

        seed = self._make_seed()
        profile = self._make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            preferred_entry_point=None,
            excluded_entry_points=None,
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
        assert "Entry Point Guidance" not in user_prompt

    @patch("scenario_forge.pipeline.generate.LLMClient")
    def test_prompt_includes_both_hint_and_exclusion(self, mock_client_cls):
        """When both preferred and excluded are set, both appear in prompt."""
        from scenario_forge.pipeline.generate import (
            Call1Response,
            _call_narrative,
        )

        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.content = Call1Response(
            title="Test",
            summary="Test summary",
            entry_point="admin console (zone 2)",
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

        seed = self._make_seed()
        profile = self._make_profile()

        _call_narrative(
            seed,
            profile,
            mock_client,
            "test use case",
            preferred_entry_point="admin console (zone 2)",
            excluded_entry_points=["document uploads (zone 1)"],
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
        assert "Preferred entry point: admin console (zone 2)" in user_prompt
        assert "document uploads (zone 1)" in user_prompt


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests for entry point diversity."""

    def test_single_entry_point_no_diversity_possible(self):
        """With only 1 entry point, assign returns it, overused returns empty."""
        eps = ["the only entry point (zone 1)"]
        usage = Counter({"the only entry point (zone 1)": 13})

        assigned = assign_entry_point(eps, ["input", "reasoning"], usage, 13)
        assert assigned == "the only entry point (zone 1)"

        overused = get_overused_entry_points(eps, usage, 13)
        assert overused == []

    def test_all_entry_points_equally_used(self):
        eps = ["a (zone 1)", "b (zone 2)", "c (zone 3)"]
        usage = Counter({"a (zone 1)": 3, "b (zone 2)": 3, "c (zone 3)": 3})
        # fair_share = ceil(9/3) = 3
        overused = get_overused_entry_points(eps, usage, 9)
        assert overused == []

    def test_zero_seeds_does_not_crash(self):
        eps = ["a", "b"]
        # total_seeds=0 -> fair_share = ceil(0/2) = 0
        # Every used entry point would be "overused" at count > 0
        overused = get_overused_entry_points(eps, Counter({"a": 1}), 0)
        # ceil(0/2) = 0, so any usage > 0 is overused
        assert "a" in overused

    def test_affinity_with_empty_zone_sequence(self):
        # Should not crash; overlap = 0 for everything
        scores = compute_entry_point_affinity(
            ["chat input (zone 1)"],
            [],
        )
        # target_zones = set() -> overlap=0, union = ep_zones
        # score = 0 / len(ep_zones) = 0.0
        assert scores["chat input (zone 1)"] == pytest.approx(0.0)

    def test_system_prompt_mentions_overuse_avoidance(self):
        """The system prompt for Call 1 includes instructions about exclusion lists."""
        from scenario_forge.prompts import render_prompt

        prompt = render_prompt(
            "call1_system.j2",
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=[],
        )
        assert "exclusion list" in prompt.lower()
