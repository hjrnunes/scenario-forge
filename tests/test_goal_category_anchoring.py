"""Tests for compute_compatible_goal_ids (i7q8 bead).

Covers:
- IN-2 excluded when no output zone
- AB-2 excluded when no code-gen capability (tool_execution not in zones)
- T15 excludes AB-8, AB-9
- Non-affected threats still have full sub-goal pools
- Integration with select_attack_goal (narrowed pool, fair-share still works)
"""

from __future__ import annotations

from collections import Counter

import pytest

from scenario_forge.pipeline.generate import (
    _THREAT_GOAL_EXCLUSIONS,
    compute_compatible_goal_ids,
    filter_sub_goals_by_zones,
    get_all_sub_goals,
    load_attack_goals_taxonomy,
    select_attack_goal,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sub_goal(goal_id: str, name: str = "Test Goal") -> dict:
    """Create a minimal sub-goal dict for testing."""
    return {
        "id": goal_id,
        "name": name,
        "description": f"Description for {goal_id}",
        "sources": ["test"],
        "category_id": goal_id.split("-")[0].upper() if "-" in goal_id else "unknown",
        "category_name": "Test Category",
        "category_description": "Test category description",
    }


def _make_sub_goals_with_ids(*ids: str) -> list[dict]:
    """Create a list of sub-goals with the given IDs."""
    return [_make_sub_goal(gid) for gid in ids]


# ---------------------------------------------------------------------------
# Architectural exclusion: IN-2 (Disinformation) requires output zone
# ---------------------------------------------------------------------------


class TestIN2OutputZone:
    """IN-2 should be excluded when 'output' is not in zones_active."""

    def test_in2_excluded_without_output_zone(self):
        goals = _make_sub_goals_with_ids("IN-1", "IN-2", "IN-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning"],
        )
        result_ids = {g["id"] for g in result}
        assert "IN-2" not in result_ids
        assert "IN-1" in result_ids
        assert "IN-3" in result_ids

    def test_in2_kept_with_output_zone(self):
        goals = _make_sub_goals_with_ids("IN-1", "IN-2", "IN-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output"],
        )
        result_ids = {g["id"] for g in result}
        assert "IN-2" in result_ids

    def test_in2_excluded_tool_execution_only(self):
        """No output zone even with tool_execution present."""
        goals = _make_sub_goals_with_ids("IN-2", "AB-2")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        # IN-2 excluded (no output), AB-2 kept (tool_execution present)
        assert "IN-2" not in result_ids
        assert "AB-2" in result_ids


# ---------------------------------------------------------------------------
# Architectural exclusion: AB-2 (Malware Gen) requires code gen capability
# ---------------------------------------------------------------------------


class TestAB2CodeGenCapability:
    """AB-2 should be excluded when no code generation capability (tool_execution)."""

    def test_ab2_excluded_without_tool_execution(self):
        goals = _make_sub_goals_with_ids("AB-1", "AB-2", "AB-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids
        assert "AB-1" in result_ids
        assert "AB-3" in result_ids

    def test_ab2_kept_with_tool_execution(self):
        goals = _make_sub_goals_with_ids("AB-1", "AB-2", "AB-3")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" in result_ids

    def test_ab2_excluded_consumer_chatbot_zones(self):
        """Klarna-type consumer chatbot: input + reasoning only."""
        goals = _make_sub_goals_with_ids("AB-2", "PR-1", "AV-1")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids


# ---------------------------------------------------------------------------
# Threat-specific exclusions: T15 excludes AB-8, AB-9
# ---------------------------------------------------------------------------


class TestT15Exclusions:
    """T15 (Human Manipulation) excludes AB-8 and AB-9."""

    def test_t15_excludes_ab8(self):
        goals = _make_sub_goals_with_ids("AB-5", "AB-8", "AB-9", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" not in result_ids

    def test_t15_excludes_ab9(self):
        goals = _make_sub_goals_with_ids("AB-5", "AB-8", "AB-9", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-9" not in result_ids

    def test_t15_keeps_ab5(self):
        """AB-5 (Human Manipulation) should NOT be excluded for T15."""
        goals = _make_sub_goals_with_ids("AB-5", "AB-8", "AB-9")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-5" in result_ids

    def test_non_t15_keeps_ab8_ab9(self):
        """Other threats should NOT exclude AB-8 or AB-9."""
        goals = _make_sub_goals_with_ids("AB-8", "AB-9", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" in result_ids
        assert "AB-9" in result_ids


# ---------------------------------------------------------------------------
# Non-affected threats keep full pools
# ---------------------------------------------------------------------------


class TestNonAffectedThreats:
    """Threats not in exclusion rules keep their full sub-goal pools."""

    def test_t2_full_pool(self):
        goals = _make_sub_goals_with_ids("IN-2", "AB-2", "AB-8", "AB-9", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T2",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        assert len(result) == len(goals)

    def test_t7_full_pool_with_all_zones(self):
        goals = _make_sub_goals_with_ids("IN-2", "AB-2", "PR-1", "AV-1")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        assert len(result) == len(goals)

    def test_none_threat_id(self):
        goals = _make_sub_goals_with_ids("IN-2", "AB-2", "AB-8", "AB-9")
        result = compute_compatible_goal_ids(
            threat_id=None,
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        assert len(result) == len(goals)


# ---------------------------------------------------------------------------
# Combined exclusions (architectural + threat-specific)
# ---------------------------------------------------------------------------


class TestCombinedExclusions:
    """Architectural and threat-specific exclusions stack."""

    def test_t15_plus_no_output_zone(self):
        """T15 excludes AB-8/AB-9; no output zone excludes IN-2."""
        goals = _make_sub_goals_with_ids("IN-2", "AB-8", "AB-9", "PR-1", "AV-1")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning"],
        )
        result_ids = {g["id"] for g in result}
        assert "IN-2" not in result_ids
        assert "AB-8" not in result_ids
        assert "AB-9" not in result_ids
        assert "PR-1" in result_ids
        assert "AV-1" in result_ids

    def test_t15_plus_no_tool_execution(self):
        """T15 excludes AB-8/AB-9; no tool_execution excludes AB-2."""
        goals = _make_sub_goals_with_ids("AB-2", "AB-8", "AB-9", "AB-5")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-2" not in result_ids
        assert "AB-8" not in result_ids
        assert "AB-9" not in result_ids
        assert "AB-5" in result_ids


# ---------------------------------------------------------------------------
# Safety: fallback when all goals would be excluded
# ---------------------------------------------------------------------------


class TestFallbackSafety:
    """If all goals would be excluded, return the original list."""

    def test_all_excluded_falls_back(self):
        """When exclusions would empty the pool, return original."""
        goals = _make_sub_goals_with_ids("IN-2", "AB-2")
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=goals,
            zones_active=["input", "reasoning"],  # no output, no tool_execution
        )
        # Both IN-2 and AB-2 would be excluded, so falls back to original
        assert len(result) == 2

    def test_empty_input_returns_empty(self):
        result = compute_compatible_goal_ids(
            threat_id="T7",
            sub_goals=[],
            zones_active=["input", "reasoning"],
        )
        assert result == []


# ---------------------------------------------------------------------------
# Integration: narrowed pool with select_attack_goal
# ---------------------------------------------------------------------------


class TestIntegrationWithSelectAttackGoal:
    """compute_compatible_goal_ids narrows the pool, fair-share still works."""

    def test_fair_share_respects_narrowed_pool(self):
        """select_attack_goal picks from the narrowed pool."""
        goals = _make_sub_goals_with_ids("AB-5", "AB-8", "AB-9", "PR-1")
        narrowed = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        # AB-8, AB-9 excluded; pool is {AB-5, PR-1}
        assert len(narrowed) == 2
        usage = Counter()
        selected = select_attack_goal(narrowed, usage, total_seeds=4)
        assert selected["id"] in {"AB-5", "PR-1"}

    def test_full_taxonomy_integration(self):
        """End-to-end: load taxonomy, filter, narrow, select."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        zone_filtered = filter_sub_goals_by_zones(
            all_goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        narrowed = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=zone_filtered,
            zones_active=["input", "reasoning"],
        )
        # AB-8, AB-9 excluded by T15; IN-2 excluded by no output zone;
        # AB-2 excluded by no tool_execution
        excluded_ids = {g["id"] for g in zone_filtered} - {g["id"] for g in narrowed}
        # At minimum, AB-8 and AB-9 should be excluded (T15 rule)
        assert "AB-8" not in {g["id"] for g in narrowed} or "AB-8" not in {g["id"] for g in zone_filtered}
        assert "AB-9" not in {g["id"] for g in narrowed} or "AB-9" not in {g["id"] for g in zone_filtered}

        # Selection should work
        if narrowed:
            usage = Counter()
            selected = select_attack_goal(narrowed, usage, total_seeds=10, threat_id="T15")
            assert selected["id"] not in {"AB-8", "AB-9"}


# ---------------------------------------------------------------------------
# _THREAT_GOAL_EXCLUSIONS constant integrity
# ---------------------------------------------------------------------------


class TestThreatGoalExclusionsConstant:
    def test_t15_has_expected_exclusions(self):
        assert _THREAT_GOAL_EXCLUSIONS["T15"] == {"AB-8", "AB-9"}

    def test_only_t15_defined(self):
        """Only T15 has threat-specific exclusions initially."""
        assert set(_THREAT_GOAL_EXCLUSIONS.keys()) == {"T15"}
