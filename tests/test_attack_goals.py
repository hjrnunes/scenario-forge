"""Tests for attack goals taxonomy loading, filtering, and selection.

Covers:
- m86: Integrate attack goals taxonomy for actor profile diversity.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from scenario_forge.pipeline.generate import (
    _build_attack_goal_context_block,
    filter_sub_goals_by_zones,
    get_all_sub_goals,
    load_attack_goals_taxonomy,
    select_attack_goal,
)


# ---------------------------------------------------------------------------
# Taxonomy loading
# ---------------------------------------------------------------------------


class TestLoadAttackGoalsTaxonomy:
    """Test taxonomy loading from the JSON data file."""

    def test_loads_successfully(self) -> None:
        taxonomy = load_attack_goals_taxonomy()
        assert "version" in taxonomy
        assert "categories" in taxonomy
        assert taxonomy["version"] == "1.0"

    def test_has_four_categories(self) -> None:
        taxonomy = load_attack_goals_taxonomy()
        assert len(taxonomy["categories"]) == 4
        category_ids = {c["id"] for c in taxonomy["categories"]}
        assert category_ids == {"availability", "integrity", "privacy", "abuse"}

    def test_has_27_sub_goals(self) -> None:
        taxonomy = load_attack_goals_taxonomy()
        all_sub_goals = get_all_sub_goals(taxonomy)
        assert len(all_sub_goals) == 27

    def test_sub_goals_have_required_fields(self) -> None:
        taxonomy = load_attack_goals_taxonomy()
        all_sub_goals = get_all_sub_goals(taxonomy)
        for sg in all_sub_goals:
            assert "id" in sg, f"Sub-goal missing 'id': {sg}"
            assert "name" in sg, f"Sub-goal missing 'name': {sg}"
            assert "description" in sg, f"Sub-goal missing 'description': {sg}"
            assert "sources" in sg, f"Sub-goal missing 'sources': {sg}"
            assert len(sg["sources"]) > 0, f"Sub-goal has no sources: {sg['id']}"

    def test_sub_goals_enriched_with_category(self) -> None:
        taxonomy = load_attack_goals_taxonomy()
        all_sub_goals = get_all_sub_goals(taxonomy)
        for sg in all_sub_goals:
            assert "category_id" in sg
            assert "category_name" in sg
            assert "category_description" in sg

    def test_sub_goal_ids_are_unique(self) -> None:
        taxonomy = load_attack_goals_taxonomy()
        all_sub_goals = get_all_sub_goals(taxonomy)
        ids = [sg["id"] for sg in all_sub_goals]
        assert len(ids) == len(set(ids)), f"Duplicate sub-goal IDs: {ids}"

    def test_custom_path(self, tmp_path: Path) -> None:
        """Loading from a custom path works."""
        import json

        custom_taxonomy = {
            "version": "test",
            "categories": [
                {
                    "id": "test",
                    "name": "Test",
                    "description": "Test category",
                    "source": "test",
                    "sub_goals": [
                        {
                            "id": "T-1",
                            "name": "Test Goal",
                            "description": "A test goal.",
                            "sources": ["test source"],
                        }
                    ],
                }
            ],
        }
        path = tmp_path / "test-taxonomy.json"
        path.write_text(json.dumps(custom_taxonomy))

        result = load_attack_goals_taxonomy(path)
        assert result["version"] == "test"
        assert len(get_all_sub_goals(result)) == 1


# ---------------------------------------------------------------------------
# Zone-based filtering
# ---------------------------------------------------------------------------


class TestFilterSubGoalsByZones:
    """Test that sub-goals are correctly filtered based on system capabilities."""

    @pytest.fixture()
    def all_sub_goals(self) -> list[dict]:
        taxonomy = load_attack_goals_taxonomy()
        return get_all_sub_goals(taxonomy)

    def test_full_system_keeps_all(self, all_sub_goals: list[dict]) -> None:
        """A system with all zones, memory, HITL, and multi-agent keeps all goals."""
        filtered = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=["input", "reasoning", "tool_execution", "memory", "inter_agent"],
            has_persistent_memory=True,
            hitl=True,
            multi_agent=True,
        )
        assert len(filtered) == 27

    def test_minimal_system_filters(self, all_sub_goals: list[dict]) -> None:
        """A minimal system (input + reasoning only, no memory, no HITL, no multi-agent)
        should filter out sub-goals requiring memory, tool_execution, inter_agent, HITL."""
        filtered = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        filtered_ids = {sg["id"] for sg in filtered}

        # IN-5 requires memory
        assert "IN-5" not in filtered_ids
        # PR-5 requires memory
        assert "PR-5" not in filtered_ids
        # IN-3 requires tool_execution
        assert "IN-3" not in filtered_ids
        # AB-3 requires tool_execution
        assert "AB-3" not in filtered_ids
        # AV-5 requires inter_agent
        assert "AV-5" not in filtered_ids
        # AB-7 requires multi_agent
        assert "AB-7" not in filtered_ids
        # AV-4 requires HITL
        assert "AV-4" not in filtered_ids

        # These should remain (no special requirements or only need input/reasoning)
        assert "AV-1" in filtered_ids  # Service Denial — no zone requirement
        assert "IN-1" in filtered_ids  # Output Manipulation — no zone requirement
        assert "PR-1" in filtered_ids  # Data Exfiltration — no zone requirement
        assert "AB-1" in filtered_ids  # Safety Bypass — no zone requirement

    def test_memory_zone_enables_memory_goals(self, all_sub_goals: list[dict]) -> None:
        """Adding memory zone and persistent memory enables IN-5 and PR-5."""
        filtered = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=True,
            hitl=False,
            multi_agent=False,
        )
        filtered_ids = {sg["id"] for sg in filtered}
        assert "IN-5" in filtered_ids
        assert "PR-5" in filtered_ids

    def test_memory_zone_without_persistent_memory(self, all_sub_goals: list[dict]) -> None:
        """Memory zone without has_persistent_memory=True still filters memory-dependent goals."""
        filtered = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        filtered_ids = {sg["id"] for sg in filtered}
        assert "IN-5" not in filtered_ids
        assert "PR-5" not in filtered_ids

    def test_hitl_enables_alert_saturation(self, all_sub_goals: list[dict]) -> None:
        """AV-4 (Alert/Response Saturation) requires HITL."""
        filtered_without = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=False,
            multi_agent=False,
        )
        filtered_with = filter_sub_goals_by_zones(
            all_sub_goals,
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            hitl=True,
            multi_agent=False,
        )
        without_ids = {sg["id"] for sg in filtered_without}
        with_ids = {sg["id"] for sg in filtered_with}
        assert "AV-4" not in without_ids
        assert "AV-4" in with_ids


# ---------------------------------------------------------------------------
# Goal selection diversity
# ---------------------------------------------------------------------------


class TestSelectAttackGoal:
    """Test fair-share goal selection."""

    @pytest.fixture()
    def sample_goals(self) -> list[dict]:
        return [
            {"id": "AV-1", "name": "Service Denial", "description": "...",
             "category_id": "availability", "category_name": "Availability Disruption",
             "category_description": "..."},
            {"id": "IN-1", "name": "Output Manipulation", "description": "...",
             "category_id": "integrity", "category_name": "Integrity Violation",
             "category_description": "..."},
            {"id": "PR-1", "name": "Data Exfiltration", "description": "...",
             "category_id": "privacy", "category_name": "Privacy Compromise",
             "category_description": "..."},
        ]

    def test_selects_unused_first(self, sample_goals: list[dict]) -> None:
        """With empty usage counts, any goal can be selected."""
        usage = Counter()
        result = select_attack_goal(sample_goals, usage, total_seeds=10)
        assert result["id"] in {"AV-1", "IN-1", "PR-1"}

    def test_avoids_overused(self, sample_goals: list[dict]) -> None:
        """With one goal already used, selects from unused ones."""
        usage = Counter({"AV-1": 5, "IN-1": 5})
        result = select_attack_goal(sample_goals, usage, total_seeds=10)
        assert result["id"] == "PR-1"

    def test_cycles_through_all(self, sample_goals: list[dict]) -> None:
        """Over multiple selections, all goals get used before any repeats."""
        usage: Counter[str] = Counter()
        selected_ids: list[str] = []

        for _ in range(6):
            goal = select_attack_goal(sample_goals, usage, total_seeds=6)
            selected_ids.append(goal["id"])
            usage[goal["id"]] += 1

        # Each of the 3 goals should be selected exactly 2 times
        counts = Counter(selected_ids)
        assert all(c == 2 for c in counts.values())

    def test_empty_sub_goals_raises(self) -> None:
        """Empty sub-goals list raises ValueError."""
        with pytest.raises(ValueError, match="No attack goal sub-goals available"):
            select_attack_goal([], Counter(), total_seeds=10)

    def test_diversity_over_batch(self) -> None:
        """Simulating a batch of 27 seeds, each of the 27 goals is used exactly once."""
        taxonomy = load_attack_goals_taxonomy()
        all_goals = get_all_sub_goals(taxonomy)
        usage: Counter[str] = Counter()
        selected: list[str] = []

        for _ in range(27):
            goal = select_attack_goal(all_goals, usage, total_seeds=27)
            selected.append(goal["id"])
            usage[goal["id"]] += 1

        # Perfect diversity: each goal used exactly once
        assert len(set(selected)) == 27
        assert all(c == 1 for c in Counter(selected).values())


# ---------------------------------------------------------------------------
# Context block generation
# ---------------------------------------------------------------------------


class TestBuildAttackGoalContextBlock:
    """Test the prompt context block builder."""

    def test_contains_required_elements(self) -> None:
        sub_goal = {
            "id": "PR-1",
            "name": "Data Exfiltration",
            "description": "Extract sensitive user data from the system.",
            "category_id": "privacy",
            "category_name": "Privacy Compromise",
            "category_description": "Attacks aimed at learning information.",
        }
        block = _build_attack_goal_context_block(sub_goal)

        assert "Privacy Compromise" in block
        assert "Attacks aimed at learning information." in block
        assert "PR-1" in block
        assert "Data Exfiltration" in block
        assert "Extract sensitive user data" in block
        assert "MANDATORY" in block
        assert "desires" in block.lower()

    def test_block_is_nonempty(self) -> None:
        sub_goal = {
            "id": "AV-1",
            "name": "Service Denial",
            "description": "Render the model unusable.",
            "category_id": "availability",
            "category_name": "Availability Disruption",
            "category_description": "Attacks that degrade function.",
        }
        block = _build_attack_goal_context_block(sub_goal)
        assert len(block) > 100  # Should be substantial
