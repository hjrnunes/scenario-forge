"""Tests for title diversity enforcement (613l).

Covers:
- Part A: prior_titles parameter in _call_narrative / generate_scenario
- Part B: Strengthened title instruction in call1_system.j2
- Part C: title_uniqueness metric uses mean-of-top-k instead of max
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from scenario_forge.eval.diversity import title_uniqueness
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.generate import _call_narrative
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

# Default kwargs for rendering call1_system.j2 (requires profile variables)
_CALL1_SYS_DEFAULTS = dict(
    has_persistent_memory=False,
    multi_agent=False,
    hitl=False,
    zones_active=["input", "reasoning", "tool_execution"],
    kc_subcodes=[],
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=[
            EntryPoint(name="user prompts via chat", direction="input"),
            EntryPoint(name="RAG knowledge base", direction="input"),
        ],
        confidence=ConfidenceLevel.high,
    )


def _make_seed() -> ScenarioSeed:
    return ScenarioSeed(
        seed_id="AP-T7-01",
        threat_id="T7",
        threat_name="Misaligned Behavior",
        threat_description="Agent acts against user interests",
        attack_pattern_name="RAG Poisoning",
        attack_pattern_description="Attacker poisons RAG data",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description for risk-1",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0051.001"],
    )


def _make_scenario(title: str) -> dict[str, Any]:
    """Build a minimal scenario dict with a given title."""
    return {
        "scenario_id": "AP-T7-01-abc123",
        "narrative": {
            "title": title,
            "summary": "Test summary.",
            "entry_point": "user prompts",
            "zone_sequence": ["input", "reasoning"],
            "steps": [],
        },
    }


def _make_mock_client(title: str = "Test Title") -> MagicMock:
    """Create a mock LLM client that returns a Call1Response-shaped result."""
    mock_response = MagicMock()
    mock_response.title = title
    mock_response.summary = "Test summary"
    mock_response.entry_point = "user prompts via chat"
    mock_response.zone_sequence = ["input", "reasoning"]

    step = MagicMock()
    step.step_number = 1
    step.zone = "input"
    step.action = "Craft adversarial prompt"
    step.effect = "Agent compromised"
    step.control_point = None
    mock_response.steps = [step]

    result = MagicMock()
    result.content = mock_response
    result.prompt_tokens = 100
    result.completion_tokens = 50
    result.duration_ms = 1000
    result.system_prompt = "system"
    result.user_prompt = "user"

    client = MagicMock()
    client.complete.return_value = result
    return client


# ===========================================================================
# Part A: prior_titles parameter
# ===========================================================================


class TestPriorTitlesInNarrative:
    """Test that _call_narrative accepts and uses prior_titles."""

    def test_prior_titles_appear_in_prompt(self):
        """When prior_titles is non-empty, they appear in the user prompt."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()
        prior = [
            "Memory Poisoning Attack on LLM Agent",
            "Tool Execution Bypass via Injection",
        ]

        _call_narrative(
            seed, profile, client, "test use case",
            pinned_entry_point="user prompts via chat",
            prior_titles=prior,
        )

        # Extract the user_prompt from the client.complete call
        call_kwargs = client.complete.call_args
        user_prompt = call_kwargs.kwargs.get("user_prompt") or call_kwargs[1].get(
            "user_prompt", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else ""
        )

        assert "Previously Generated Titles" in user_prompt
        assert "Memory Poisoning Attack on LLM Agent" in user_prompt
        assert "Tool Execution Bypass via Injection" in user_prompt

    def test_empty_prior_titles_no_section(self):
        """When prior_titles is empty or None, no title diversity section appears."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()

        _call_narrative(
            seed, profile, client, "test use case",
            pinned_entry_point="user prompts via chat",
            prior_titles=None,
        )

        call_kwargs = client.complete.call_args
        user_prompt = call_kwargs.kwargs.get("user_prompt") or call_kwargs[1].get(
            "user_prompt", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else ""
        )

        assert "Previously Generated Titles" not in user_prompt

    def test_empty_list_prior_titles_no_section(self):
        """When prior_titles is an empty list, no title diversity section appears."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()

        _call_narrative(
            seed, profile, client, "test use case",
            pinned_entry_point="user prompts via chat",
            prior_titles=[],
        )

        call_kwargs = client.complete.call_args
        user_prompt = call_kwargs.kwargs.get("user_prompt") or call_kwargs[1].get(
            "user_prompt", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else ""
        )

        assert "Previously Generated Titles" not in user_prompt

    def test_prior_titles_numbered_list(self):
        """Prior titles should appear as a numbered list."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()
        prior = ["Title Alpha", "Title Beta", "Title Gamma"]

        _call_narrative(
            seed, profile, client, "test use case",
            pinned_entry_point="user prompts via chat",
            prior_titles=prior,
        )

        call_kwargs = client.complete.call_args
        user_prompt = call_kwargs.kwargs.get("user_prompt") or call_kwargs[1].get(
            "user_prompt", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else ""
        )

        assert "1. Title Alpha" in user_prompt
        assert "2. Title Beta" in user_prompt
        assert "3. Title Gamma" in user_prompt

    def test_prior_titles_contains_anti_formulaic_instruction(self):
        """The diversity section should warn against formulaic patterns."""
        seed = _make_seed()
        profile = _make_profile()
        client = _make_mock_client()

        _call_narrative(
            seed, profile, client, "test use case",
            pinned_entry_point="user prompts via chat",
            prior_titles=["Some Title"],
        )

        call_kwargs = client.complete.call_args
        user_prompt = call_kwargs.kwargs.get("user_prompt") or call_kwargs[1].get(
            "user_prompt", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else ""
        )

        assert "[Mechanism] for [Goal]" in user_prompt


# ===========================================================================
# Part B: Strengthened title instruction in call1_system.j2
# ===========================================================================


class TestCall1SystemTitleInstruction:
    """Test that the call1_system.j2 template has a strengthened title instruction."""

    def test_title_instruction_contains_uniqueness_language(self):
        """The system prompt should contain uniqueness guidance for titles."""
        rendered = render_prompt("call1_system.j2", **_CALL1_SYS_DEFAULTS)
        assert "MUST be unique" in rendered

    def test_title_instruction_warns_against_formulaic_patterns(self):
        """The system prompt should warn against formulaic title patterns."""
        rendered = render_prompt("call1_system.j2", **_CALL1_SYS_DEFAULTS)
        assert "[Mechanism] for [Goal]" in rendered

    def test_title_instruction_suggests_varied_structures(self):
        """The system prompt should suggest varied sentence structures."""
        rendered = render_prompt("call1_system.j2", **_CALL1_SYS_DEFAULTS)
        assert "noun phrases" in rendered

    def test_old_weak_instruction_removed(self):
        """The old weak instruction should no longer be present."""
        rendered = render_prompt("call1_system.j2", **_CALL1_SYS_DEFAULTS)
        assert "should be specific to the use case, not a generic restatement" not in rendered


# ===========================================================================
# Part C: title_uniqueness metric — mean-of-top-k
# ===========================================================================


class TestTitleUniquenessMetric:
    """Test the improved title_uniqueness metric using mean-of-top-k."""

    def test_one_duplicate_pair_among_many_not_zero(self):
        """One duplicate pair among many diverse titles should NOT score 0.0.

        This is the core regression: the old max-based metric would return 0.0
        because max_sim = 1.0 for the duplicate pair. The new mean-of-top-k
        should produce a positive score because the other pairs are diverse.
        """
        scenarios = [
            _make_scenario("Same Title Here"),
            _make_scenario("Same Title Here"),
            _make_scenario("Memory Poisoning Attack on LLM Agent"),
            _make_scenario("Tool Execution Bypass via Injection"),
            _make_scenario("Credential Theft through Social Engineering"),
            _make_scenario("Supply Chain Backdoor Insertion"),
            _make_scenario("Agent Reasoning Manipulation Exploit"),
        ]
        result = title_uniqueness(scenarios)
        # Must NOT be 0.0 — one duplicate among 7 titles
        assert result > 0.0
        # But should be penalized (not perfect)
        assert result < 1.0

    def test_all_identical_titles_near_zero(self):
        """All identical titles should score near 0.0."""
        scenarios = [
            _make_scenario("Same Title"),
            _make_scenario("Same Title"),
            _make_scenario("Same Title"),
            _make_scenario("Same Title"),
        ]
        result = title_uniqueness(scenarios)
        assert result == 0.0

    def test_all_unique_titles_near_one(self):
        """All unique titles should score near 1.0."""
        scenarios = [
            _make_scenario("Alpha Beta Gamma"),
            _make_scenario("Delta Epsilon Zeta"),
            _make_scenario("Eta Theta Iota"),
            _make_scenario("Kappa Lambda Mu"),
        ]
        result = title_uniqueness(scenarios)
        assert result > 0.8

    def test_single_scenario(self):
        """Single scenario should return 1.0."""
        scenarios = [_make_scenario("Only Title")]
        result = title_uniqueness(scenarios)
        assert result == 1.0

    def test_empty_scenarios(self):
        """Empty scenario list should return 1.0."""
        result = title_uniqueness([])
        assert result == 1.0

    def test_two_identical_titles(self):
        """Two identical titles — only one pair, which is the max and the mean."""
        scenarios = [
            _make_scenario("Duplicate Title"),
            _make_scenario("Duplicate Title"),
        ]
        result = title_uniqueness(scenarios)
        assert result == 0.0

    def test_two_completely_different_titles(self):
        """Two completely different titles should score high."""
        scenarios = [
            _make_scenario("Alpha Beta Gamma"),
            _make_scenario("Delta Epsilon Zeta"),
        ]
        result = title_uniqueness(scenarios)
        assert result > 0.8

    def test_metric_monotonicity_more_duplicates_lower_score(self):
        """More duplicate pairs should produce a lower score."""
        # Two duplicates among 6
        scenarios_few_dups = [
            _make_scenario("Dup Title"),
            _make_scenario("Dup Title"),
            _make_scenario("Unique Alpha Title"),
            _make_scenario("Unique Beta Title"),
            _make_scenario("Unique Gamma Title"),
            _make_scenario("Unique Delta Title"),
        ]
        # Four duplicates (two pairs) among 6
        scenarios_more_dups = [
            _make_scenario("Dup Title A"),
            _make_scenario("Dup Title A"),
            _make_scenario("Dup Title B"),
            _make_scenario("Dup Title B"),
            _make_scenario("Unique Alpha Title"),
            _make_scenario("Unique Beta Title"),
        ]
        score_few = title_uniqueness(scenarios_few_dups)
        score_more = title_uniqueness(scenarios_more_dups)
        assert score_few > score_more

    def test_adversarial_formulaic_titles_penalized(self):
        """Formulaic '[X] for [Y]' titles sharing structure should be penalized."""
        scenarios = [
            _make_scenario("Poisoning for Exfiltration"),
            _make_scenario("Injection for Manipulation"),
            _make_scenario("Spoofing for Escalation"),
            _make_scenario("Flooding for Disruption"),
        ]
        result = title_uniqueness(scenarios)
        # These share structural pattern "X for Y" but different words,
        # so they should score reasonably (Jaccard on tokens is moderate)
        assert result > 0.3
