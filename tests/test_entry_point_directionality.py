"""Tests for entry point directionality enforcement in narrative generation.

Covers:
- _lookup_entry_point_direction helper
- Direction variable passed to Call 0 template (call0_user.j2)
- Direction variable passed to Call 1 template (call1_user.j2)
- INPUT direction renders correct constraint text
- OUTPUT direction renders correct constraint text
- BIDIRECTIONAL direction renders correct constraint text
- None direction renders no constraint text
"""

from __future__ import annotations

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.generate import _lookup_entry_point_direction
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_profile(
    entry_points: list[EntryPoint] | None = None,
) -> CapabilityProfile:
    """Create a CapabilityProfile with configurable entry points."""
    if entry_points is None:
        entry_points = [
            EntryPoint(name="user prompts via chat", direction="input"),
            EntryPoint(name="RAG knowledge-grounding system", direction="input"),
            EntryPoint(name="backend API calls", direction="output"),
            EntryPoint(name="admin console", direction="bidirectional"),
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=entry_points,
        confidence=ConfidenceLevel.high,
    )


def _make_seed() -> ScenarioSeed:
    """Create a minimal ScenarioSeed for template rendering."""
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


# ---------------------------------------------------------------------------
# _lookup_entry_point_direction
# ---------------------------------------------------------------------------


class TestLookupEntryPointDirection:
    """Tests for the direction lookup helper."""

    def test_returns_none_when_name_is_none(self):
        profile = _make_profile()
        assert _lookup_entry_point_direction(profile, None) is None

    def test_returns_input_for_input_entry_point(self):
        profile = _make_profile()
        result = _lookup_entry_point_direction(
            profile, "RAG knowledge-grounding system"
        )
        assert result == "input"

    def test_returns_output_for_output_entry_point(self):
        profile = _make_profile()
        result = _lookup_entry_point_direction(profile, "backend API calls")
        assert result == "output"

    def test_returns_bidirectional_for_bidirectional_entry_point(self):
        profile = _make_profile()
        result = _lookup_entry_point_direction(profile, "admin console")
        assert result == "bidirectional"

    def test_returns_none_when_name_not_found(self):
        profile = _make_profile()
        result = _lookup_entry_point_direction(profile, "nonexistent entry point")
        assert result is None

    def test_exact_name_match_required(self):
        """Partial matches should not count -- exact name required."""
        profile = _make_profile()
        result = _lookup_entry_point_direction(profile, "RAG knowledge")
        assert result is None


# ---------------------------------------------------------------------------
# Call 0 template: direction constraint rendering
# ---------------------------------------------------------------------------


class TestCall0DirectionRendering:
    """Tests that call0_user.j2 renders direction constraints correctly."""

    def _render_call0(
        self,
        pinned_entry_point: str | None = None,
        pinned_entry_point_direction: str | None = None,
    ) -> str:
        seed = _make_seed()
        profile = _make_profile()
        return render_prompt(
            "call0_user.j2",
            use_case="A financial chatbot",
            seed=seed,
            profile=profile,
            technique_context="",
            technique_framing_0="",
            goal_section="",
            diversity_section="",
            pinned_entry_point=pinned_entry_point,
            pinned_entry_point_direction=pinned_entry_point_direction,
            pinned_technique_count=1,
            kc_definitions="",
        )

    def test_input_direction_renders_input_constraint(self):
        prompt = self._render_call0(
            pinned_entry_point="RAG knowledge-grounding system",
            pinned_entry_point_direction="input",
        )
        assert "Entry point direction: INPUT" in prompt
        assert "can send data into the system" in prompt.lower()
        assert "malicious input" in prompt.lower()

    def test_output_direction_renders_output_constraint(self):
        prompt = self._render_call0(
            pinned_entry_point="backend API calls",
            pinned_entry_point_direction="output",
        )
        assert "Entry point direction: OUTPUT" in prompt
        assert "misusing this output channel" in prompt.lower()

    def test_bidirectional_direction_renders_constraint(self):
        prompt = self._render_call0(
            pinned_entry_point="admin console",
            pinned_entry_point_direction="bidirectional",
        )
        assert "Entry point direction: BIDIRECTIONAL" in prompt
        assert "both send data" in prompt.lower()

    def test_none_direction_renders_no_direction_constraint(self):
        prompt = self._render_call0(
            pinned_entry_point="admin console",
            pinned_entry_point_direction=None,
        )
        assert "Entry point direction:" not in prompt

    def test_no_pinned_entry_point_renders_no_constraint(self):
        prompt = self._render_call0(
            pinned_entry_point=None,
            pinned_entry_point_direction=None,
        )
        assert "Entry point direction:" not in prompt
        assert "Entry point constraint" not in prompt

    def test_input_direction_mentions_rag_poisoning_pattern(self):
        """INPUT direction should mention upstream data source exploitation."""
        prompt = self._render_call0(
            pinned_entry_point="RAG knowledge-grounding system",
            pinned_entry_point_direction="input",
        )
        assert "upstream data sources" in prompt.lower() or "retrieval ranking" in prompt.lower()

    def test_pinned_entry_point_still_renders_mandatory_constraint(self):
        """The existing entry point constraint should still appear."""
        prompt = self._render_call0(
            pinned_entry_point="RAG knowledge-grounding system",
            pinned_entry_point_direction="input",
        )
        assert "Entry point constraint (MANDATORY)" in prompt
        assert "RAG knowledge-grounding system" in prompt


# ---------------------------------------------------------------------------
# Call 1 template: direction constraint rendering
# ---------------------------------------------------------------------------


class TestCall1DirectionRendering:
    """Tests that call1_user.j2 renders direction constraints correctly."""

    def _render_call1(
        self,
        pinned_entry_point: str | None = None,
        pinned_entry_point_direction: str | None = None,
    ) -> str:
        seed = _make_seed()
        profile = _make_profile()
        return render_prompt(
            "call1_user.j2",
            use_case="A financial chatbot",
            seed=seed,
            profile=profile,
            owasp_llm_formatted="LLM01: Prompt Injection",
            technique_context="",
            technique_framing="",
            actor_section="",
            diversity_section="",
            pattern_section="",
            structural_section="",
            pinned_entry_point=pinned_entry_point,
            pinned_entry_point_direction=pinned_entry_point_direction,
            kc_definitions="",
        )

    def test_input_direction_renders_input_constraint(self):
        prompt = self._render_call1(
            pinned_entry_point="RAG knowledge-grounding system",
            pinned_entry_point_direction="input",
        )
        assert "Entry point direction: INPUT" in prompt
        assert "can send data into the system" in prompt.lower()
        assert "malicious input" in prompt.lower()

    def test_input_direction_mentions_indirect_injection_for_rag(self):
        """INPUT direction should mention indirect injection for RAG entry points."""
        prompt = self._render_call1(
            pinned_entry_point="RAG knowledge-grounding system",
            pinned_entry_point_direction="input",
        )
        assert (
            "indirect injection surface" in prompt.lower()
            or "upstream data sources" in prompt.lower()
        )

    def test_output_direction_renders_output_constraint(self):
        prompt = self._render_call1(
            pinned_entry_point="backend API calls",
            pinned_entry_point_direction="output",
        )
        assert "Entry point direction: OUTPUT" in prompt
        assert "misusing this output channel" in prompt.lower()

    def test_bidirectional_direction_renders_constraint(self):
        prompt = self._render_call1(
            pinned_entry_point="admin console",
            pinned_entry_point_direction="bidirectional",
        )
        assert "Entry point direction: BIDIRECTIONAL" in prompt
        assert "both send data" in prompt.lower()

    def test_none_direction_renders_no_direction_constraint(self):
        prompt = self._render_call1(
            pinned_entry_point="admin console",
            pinned_entry_point_direction=None,
        )
        assert "Entry point direction:" not in prompt

    def test_no_pinned_entry_point_renders_no_direction_block(self):
        prompt = self._render_call1(
            pinned_entry_point=None,
            pinned_entry_point_direction=None,
        )
        assert "Entry point direction:" not in prompt

    def test_input_direction_mentions_upstream_exploitation(self):
        """INPUT direction should describe upstream data exploitation patterns."""
        prompt = self._render_call1(
            pinned_entry_point="RAG knowledge-grounding system",
            pinned_entry_point_direction="input",
        )
        lower = prompt.lower()
        assert (
            "upstream data sources" in lower
            or "retrieval ranking" in lower
            or "what gets retrieved" in lower
        )
