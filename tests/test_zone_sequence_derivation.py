"""Tests for zone_sequence derivation from narrative steps.

Verifies that zone_sequence is derived deterministically from step zone
fields rather than taken verbatim from the LLM response.

Covers:
  1. zone_sequence is derived from steps, not from the LLM field
  2. Consecutive duplicate zones are collapsed
  3. Non-consecutive duplicates (revisitations) are preserved
  4. The zone_active filtering still works on derived zone_sequence
"""

from __future__ import annotations

import logging

from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep
from scenario_forge.pipeline.generate import (
    Call1Response,
    Call1Step,
    _derive_zone_sequence,
    _enforce_zones_narrative,
    _map_call1_to_narrative,
)


# ---------------------------------------------------------------------------
# _derive_zone_sequence unit tests
# ---------------------------------------------------------------------------


class TestDeriveZoneSequence:
    """Unit tests for the _derive_zone_sequence helper."""

    def test_simple_sequence_no_duplicates(self):
        """Distinct zones pass through unchanged."""
        steps = [
            Call1Step(step_number=1, zone="input", action="a", effect="e"),
            Call1Step(step_number=2, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=3, zone="tool_execution", action="a", effect="e"),
        ]
        assert _derive_zone_sequence(steps) == [
            "input",
            "reasoning",
            "tool_execution",
        ]

    def test_consecutive_duplicates_collapsed(self):
        """Consecutive duplicate zones are collapsed to one."""
        steps = [
            Call1Step(step_number=1, zone="input", action="a", effect="e"),
            Call1Step(step_number=2, zone="input", action="a", effect="e"),
            Call1Step(step_number=3, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=4, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=5, zone="tool_execution", action="a", effect="e"),
        ]
        assert _derive_zone_sequence(steps) == [
            "input",
            "reasoning",
            "tool_execution",
        ]

    def test_non_consecutive_duplicates_preserved(self):
        """Non-consecutive duplicates (revisitations) are preserved."""
        steps = [
            Call1Step(step_number=1, zone="input", action="a", effect="e"),
            Call1Step(step_number=2, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=3, zone="tool_execution", action="a", effect="e"),
            Call1Step(step_number=4, zone="reasoning", action="a", effect="e"),
        ]
        assert _derive_zone_sequence(steps) == [
            "input",
            "reasoning",
            "tool_execution",
            "reasoning",
        ]

    def test_single_step(self):
        """Single step produces a single-element sequence."""
        steps = [
            Call1Step(step_number=1, zone="input", action="a", effect="e"),
        ]
        assert _derive_zone_sequence(steps) == ["input"]

    def test_all_same_zone(self):
        """All steps in the same zone collapse to one."""
        steps = [
            Call1Step(step_number=i, zone="reasoning", action="a", effect="e")
            for i in range(1, 6)
        ]
        assert _derive_zone_sequence(steps) == ["reasoning"]

    def test_empty_steps(self):
        """Empty step list produces empty sequence."""
        assert _derive_zone_sequence([]) == []

    def test_complex_revisitation_pattern(self):
        """Complex pattern with multiple revisitations and consecutive runs."""
        steps = [
            Call1Step(step_number=1, zone="input", action="a", effect="e"),
            Call1Step(step_number=2, zone="input", action="a", effect="e"),
            Call1Step(step_number=3, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=4, zone="tool_execution", action="a", effect="e"),
            Call1Step(step_number=5, zone="tool_execution", action="a", effect="e"),
            Call1Step(step_number=6, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=7, zone="reasoning", action="a", effect="e"),
            Call1Step(step_number=8, zone="memory", action="a", effect="e"),
        ]
        assert _derive_zone_sequence(steps) == [
            "input",
            "reasoning",
            "tool_execution",
            "reasoning",
            "memory",
        ]

    def test_works_with_narrative_steps(self):
        """Also works with NarrativeStep objects (not just Call1Step)."""
        steps = [
            NarrativeStep(step_number=1, zone="input", action="a", effect="e"),
            NarrativeStep(step_number=2, zone="reasoning", action="a", effect="e"),
            NarrativeStep(step_number=3, zone="input", action="a", effect="e"),
        ]
        assert _derive_zone_sequence(steps) == ["input", "reasoning", "input"]


# ---------------------------------------------------------------------------
# _map_call1_to_narrative derivation (integration)
# ---------------------------------------------------------------------------


class TestMapCall1UsesDerivation:
    """Verify _map_call1_to_narrative derives zone_sequence from steps."""

    def test_derived_sequence_ignores_llm_field(self):
        """The LLM's zone_sequence field is ignored; steps drive derivation."""
        resp = Call1Response(
            title="Test",
            summary="Summary",
            entry_point="user input",
            # LLM produced a collapsed sequence (the bug we're fixing)
            zone_sequence=["input", "reasoning", "tool_execution"],
            steps=[
                Call1Step(step_number=1, zone="input", action="a", effect="e"),
                Call1Step(step_number=2, zone="reasoning", action="a", effect="e"),
                Call1Step(step_number=3, zone="tool_execution", action="a", effect="e"),
                # LLM collapsed this revisitation in zone_sequence
                Call1Step(step_number=4, zone="reasoning", action="a", effect="e"),
            ],
        )
        narrative = _map_call1_to_narrative(resp)
        # Derived sequence preserves the revisitation
        assert narrative.zone_sequence == [
            "input",
            "reasoning",
            "tool_execution",
            "reasoning",
        ]

    def test_derived_sequence_collapses_consecutive(self):
        """Consecutive duplicates in steps are collapsed in derived sequence."""
        resp = Call1Response(
            title="Test",
            summary="Summary",
            entry_point="user input",
            zone_sequence=["input", "reasoning"],
            steps=[
                Call1Step(step_number=1, zone="input", action="a", effect="e"),
                Call1Step(step_number=2, zone="input", action="a", effect="e"),
                Call1Step(step_number=3, zone="reasoning", action="a", effect="e"),
                Call1Step(step_number=4, zone="reasoning", action="a", effect="e"),
            ],
        )
        narrative = _map_call1_to_narrative(resp)
        assert narrative.zone_sequence == ["input", "reasoning"]

    def test_derived_sequence_matches_steps_not_llm(self):
        """When LLM zone_sequence differs from steps, steps win."""
        resp = Call1Response(
            title="Test",
            summary="Summary",
            entry_point="user input",
            # LLM hallucinated a zone not in any step
            zone_sequence=["input", "memory", "reasoning"],
            steps=[
                Call1Step(step_number=1, zone="input", action="a", effect="e"),
                Call1Step(step_number=2, zone="reasoning", action="a", effect="e"),
            ],
        )
        narrative = _map_call1_to_narrative(resp)
        # Derived from steps only -- memory is NOT included
        assert narrative.zone_sequence == ["input", "reasoning"]


# ---------------------------------------------------------------------------
# Zone-active filtering on derived zone_sequence
# ---------------------------------------------------------------------------


class TestZoneActiveFilteringOnDerived:
    """Verify _enforce_zones_narrative works correctly on derived zone_sequence."""

    def _make_narrative_from_steps(self, step_zones: list[str]) -> NarrativeLayer:
        """Build a NarrativeLayer with zone_sequence derived from step_zones."""
        steps = [
            NarrativeStep(
                step_number=i + 1,
                zone=z,
                action=f"action in {z}",
                effect=f"effect in {z}",
            )
            for i, z in enumerate(step_zones)
        ]
        # Derive zone_sequence from steps (same logic as production code)
        zone_seq: list[str] = []
        for s in steps:
            if not zone_seq or zone_seq[-1] != s.zone:
                zone_seq.append(s.zone)
        return NarrativeLayer(
            title="Test",
            summary="Summary",
            entry_point="user input",
            zone_sequence=zone_seq,
            steps=steps,
        )

    def test_derived_zone_sequence_filtered_by_zones_active(self):
        """Derived zone_sequence is filtered by zones_active."""
        narrative = self._make_narrative_from_steps(
            ["input", "reasoning", "memory", "reasoning"]
        )
        assert narrative.zone_sequence == [
            "input",
            "reasoning",
            "memory",
            "reasoning",
        ]
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result.zone_sequence == ["input", "reasoning", "reasoning"]
        assert all(s.zone in ("input", "reasoning") for s in result.steps)

    def test_derived_with_revisitation_filtered(self):
        """Revisitation pattern survives zone-active filtering when zones are allowed."""
        narrative = self._make_narrative_from_steps(
            ["input", "reasoning", "tool_execution", "reasoning"]
        )
        assert narrative.zone_sequence == [
            "input",
            "reasoning",
            "tool_execution",
            "reasoning",
        ]
        result = _enforce_zones_narrative(
            narrative,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        # Everything is allowed, so unchanged
        assert result.zone_sequence == [
            "input",
            "reasoning",
            "tool_execution",
            "reasoning",
        ]

    def test_filtering_preserves_allowed_revisitations(self):
        """Filtering out a zone between two allowed zones keeps both."""
        narrative = self._make_narrative_from_steps(["input", "memory", "input"])
        assert narrative.zone_sequence == ["input", "memory", "input"]
        result = _enforce_zones_narrative(
            narrative, zones_active=["input", "reasoning"]
        )
        assert result.zone_sequence == ["input", "input"]
        assert [s.zone for s in result.steps] == ["input", "input"]

    def test_empty_after_filtering_returns_original(self, caplog):
        """When all derived zones are disallowed, original is returned."""
        narrative = self._make_narrative_from_steps(["memory", "inter_agent"])
        with caplog.at_level(logging.WARNING):
            result = _enforce_zones_narrative(
                narrative, zones_active=["input", "reasoning"]
            )
        assert result is narrative
        assert any("keeping original narrative unchanged" in m for m in caplog.messages)

    def test_none_zones_active_passes_through(self):
        """zones_active=None means no filtering."""
        narrative = self._make_narrative_from_steps(
            ["input", "reasoning", "memory", "reasoning"]
        )
        result = _enforce_zones_narrative(narrative, zones_active=None)
        assert result is narrative
