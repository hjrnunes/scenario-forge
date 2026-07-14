"""Tests for cap_scenarios_per_pattern post-filter capping.

Covers:
  - No cap (default pipeline behavior unchanged when function is not called).
  - Cap applied -- group is truncated to the cap.
  - Entry-point diversity prioritisation -- unique entry points are kept first.
  - Cap larger than group size -- no effect.
"""

from __future__ import annotations

import logging

import pytest

from scenario_forge.models.capability_profile import ConfidenceLevel
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import FilteredSeed, cap_scenarios_per_pattern


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ref(risk_id: str = "risk-1") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_filtered_seed(
    seed_id: str = "AP-T7-01",
    threat_id: str = "T7",
    pinned_entry_point: str = "user prompts (input)",
    pinned_technique_ids: tuple[str, ...] = ("AML.T0051",),
) -> FilteredSeed:
    return FilteredSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        pinned_entry_point=pinned_entry_point,
        pinned_technique_ids=pinned_technique_ids,
        pinned_technique_names=tuple(f"Name-{t}" for t in pinned_technique_ids),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCapScenariosPerPattern:
    """cap_scenarios_per_pattern() post-filter capping."""

    def test_no_cap_default_unchanged(self):
        """When the function is not called, the list is unchanged (simulated
        by calling with a cap larger than any group)."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2"),
            _make_filtered_seed("AP-T2-01", pinned_entry_point="ep1"),
        ]
        # Cap of 100 -- larger than any group -- should return all seeds.
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=100)
        assert len(result) == 3

    def test_cap_truncates_group(self):
        """A group of 5 seeds capped to 2 returns exactly 2 for that group."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep3"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep4"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep5"),
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=2)
        assert len(result) == 2
        # All should be from the same seed_id.
        assert all(fs.seed_id == "AP-T7-01" for fs in result)

    def test_cap_preserves_other_groups(self):
        """Capping only affects groups that exceed the cap; others pass through."""
        seeds = [
            # Group 1: 4 seeds (will be capped to 2)
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep3"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep4"),
            # Group 2: 1 seed (below cap)
            _make_filtered_seed("AP-T2-01", pinned_entry_point="ep1"),
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=2)
        # 2 from first group + 1 from second group = 3
        assert len(result) == 3
        group1 = [fs for fs in result if fs.seed_id == "AP-T7-01"]
        group2 = [fs for fs in result if fs.seed_id == "AP-T2-01"]
        assert len(group1) == 2
        assert len(group2) == 1

    def test_entry_point_diversity_prioritisation(self):
        """When capping, seeds with unique entry points are kept first."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1", pinned_technique_ids=("AML.T0051",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1", pinned_technique_ids=("AML.T0054",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2", pinned_technique_ids=("AML.T0051",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1", pinned_technique_ids=("AML.T0053",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep3", pinned_technique_ids=("AML.T0051",)),
        ]
        # Cap to 3: should pick the 3 unique entry points (ep1, ep2, ep3)
        # rather than the first 3 in order (which would be ep1, ep1, ep2).
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=3)
        assert len(result) == 3
        entry_points = {fs.pinned_entry_point for fs in result}
        assert entry_points == {"ep1", "ep2", "ep3"}

    def test_entry_point_diversity_fills_remaining_slots(self):
        """After picking one per unique entry point, remaining slots fill from leftovers."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1", pinned_technique_ids=("AML.T0051",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1", pinned_technique_ids=("AML.T0054",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2", pinned_technique_ids=("AML.T0051",)),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1", pinned_technique_ids=("AML.T0053",)),
        ]
        # Cap to 3: 2 unique entry points (ep1, ep2) + 1 remaining slot
        # filled from remainder (ep1 duplicate).
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=3)
        assert len(result) == 3
        entry_points = [fs.pinned_entry_point for fs in result]
        assert "ep1" in entry_points
        assert "ep2" in entry_points

    def test_cap_larger_than_group_no_effect(self):
        """Cap larger than any group size has no effect -- all seeds pass through."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2"),
            _make_filtered_seed("AP-T2-01", pinned_entry_point="ep1"),
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=10)
        assert len(result) == len(seeds)
        # Order preserved within groups.
        seed_ids = [fs.seed_id for fs in result]
        assert seed_ids.count("AP-T7-01") == 2
        assert seed_ids.count("AP-T2-01") == 1

    def test_cap_of_1_keeps_one_per_pattern(self):
        """Cap of 1 keeps exactly one seed per attack pattern."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep3"),
            _make_filtered_seed("AP-T2-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T2-01", pinned_entry_point="ep2"),
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=1)
        assert len(result) == 2
        seed_ids = {fs.seed_id for fs in result}
        assert seed_ids == {"AP-T7-01", "AP-T2-01"}

    def test_empty_input_returns_empty(self):
        """Empty input returns empty output."""
        result = cap_scenarios_per_pattern([], max_per_pattern=3)
        assert result == []

    def test_invalid_max_per_pattern_raises(self):
        """max_per_pattern < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_per_pattern must be >= 1"):
            cap_scenarios_per_pattern([], max_per_pattern=0)

    def test_logs_warning_for_capped_groups(self, caplog):
        """A warning is logged for each capped group."""
        seeds = [
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep1"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep2"),
            _make_filtered_seed("AP-T7-01", pinned_entry_point="ep3"),
            _make_filtered_seed("AP-T2-01", pinned_entry_point="ep1"),
        ]
        with caplog.at_level(logging.WARNING):
            cap_scenarios_per_pattern(seeds, max_per_pattern=2)

        # Should warn about AP-T7-01 (3 -> 2) but not AP-T2-01 (1 <= 2).
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "AP-T7-01" in warnings[0].message
        assert "from 3 to 2" in warnings[0].message
        assert "--max-scenarios-per-pattern" in warnings[0].message
