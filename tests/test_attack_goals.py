"""Tests for attack goals taxonomy loading, filtering, and selection.

Covers:
- m86: Integrate attack goals taxonomy for actor profile diversity.
- scenario-forge-smd: Threat-goal affinity weighted selection.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from scenario_forge.data.loaders import (
    load_attack_goals_taxonomy,
    load_threat_goal_affinity,
)
from scenario_forge.pipeline.generate import (
    _build_attack_goal_context_block,
    filter_sub_goals_by_zones,
    get_all_sub_goals,
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
            zones_active=[
                "input",
                "reasoning",
                "tool_execution",
                "memory",
                "inter_agent",
            ],
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

    def test_memory_zone_without_persistent_memory(
        self, all_sub_goals: list[dict]
    ) -> None:
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
            {
                "id": "AV-1",
                "name": "Service Denial",
                "description": "...",
                "category_id": "availability",
                "category_name": "Availability Disruption",
                "category_description": "...",
            },
            {
                "id": "IN-1",
                "name": "Output Manipulation",
                "description": "...",
                "category_id": "integrity",
                "category_name": "Integrity Violation",
                "category_description": "...",
            },
            {
                "id": "PR-1",
                "name": "Data Exfiltration",
                "description": "...",
                "category_id": "privacy",
                "category_name": "Privacy Compromise",
                "category_description": "...",
            },
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
        assert "SHOULD" in block
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


# ---------------------------------------------------------------------------
# Threat-goal affinity map
# ---------------------------------------------------------------------------


class TestLoadThreatGoalAffinity:
    """Test loading and validation of the threat-goal affinity YAML."""

    def test_loads_successfully(self) -> None:
        affinity = load_threat_goal_affinity()
        assert isinstance(affinity, dict)
        assert len(affinity) == 17  # T1 through T17

    def test_all_threat_ids_present(self) -> None:
        affinity = load_threat_goal_affinity()
        for i in range(1, 18):
            assert f"T{i}" in affinity, f"Missing threat ID T{i}"

    def test_entries_have_required_keys(self) -> None:
        affinity = load_threat_goal_affinity()
        for tid, entry in affinity.items():
            assert "primary" in entry, f"{tid} missing 'primary'"
            assert "secondary" in entry, f"{tid} missing 'secondary'"
            assert "excluded" in entry, f"{tid} missing 'excluded'"

    def test_category_ids_are_valid(self) -> None:
        """All category IDs in the affinity map reference real categories."""
        valid_cats = {"availability", "integrity", "privacy", "abuse"}
        affinity = load_threat_goal_affinity()
        for tid, entry in affinity.items():
            for tier in ("primary", "secondary", "excluded"):
                for cat in entry[tier]:
                    assert cat in valid_cats, (
                        f"{tid}.{tier} references unknown category '{cat}'"
                    )

    def test_every_threat_has_at_least_one_primary(self) -> None:
        affinity = load_threat_goal_affinity()
        for tid, entry in affinity.items():
            assert len(entry["primary"]) > 0, f"{tid} has no primary categories"

    def test_no_overlap_between_primary_and_excluded(self) -> None:
        affinity = load_threat_goal_affinity()
        for tid, entry in affinity.items():
            overlap = set(entry["primary"]) & set(entry["excluded"])
            assert not overlap, (
                f"{tid} has overlap between primary and excluded: {overlap}"
            )

    def test_custom_path(self, tmp_path: Path) -> None:
        """Loading from a custom path works."""
        import yaml as _yaml

        custom = {
            "version": "test",
            "affinities": {
                "T99": {
                    "primary": ["integrity"],
                    "secondary": ["abuse"],
                    "excluded": ["availability"],
                },
            },
        }
        path = tmp_path / "test-affinity.yaml"
        path.write_text(_yaml.dump(custom))

        result = load_threat_goal_affinity(path)
        assert "T99" in result
        assert result["T99"]["primary"] == ["integrity"]


# ---------------------------------------------------------------------------
# Affinity-aware goal selection
# ---------------------------------------------------------------------------


class TestSelectAttackGoalWithAffinity:
    """Test that threat_id steers goal selection toward affinity tiers."""

    @pytest.fixture()
    def mixed_goals(self) -> list[dict]:
        """Goals spanning all four categories."""
        return [
            {
                "id": "AV-1",
                "name": "Service Denial",
                "description": "...",
                "category_id": "availability",
                "category_name": "Availability Disruption",
                "category_description": "...",
            },
            {
                "id": "IN-1",
                "name": "Output Manipulation",
                "description": "...",
                "category_id": "integrity",
                "category_name": "Integrity Violation",
                "category_description": "...",
            },
            {
                "id": "IN-5",
                "name": "Memory/State Poisoning",
                "description": "...",
                "category_id": "integrity",
                "category_name": "Integrity Violation",
                "category_description": "...",
            },
            {
                "id": "PR-1",
                "name": "Data Exfiltration",
                "description": "...",
                "category_id": "privacy",
                "category_name": "Privacy Compromise",
                "category_description": "...",
            },
            {
                "id": "AB-1",
                "name": "Safety Bypass",
                "description": "...",
                "category_id": "abuse",
                "category_name": "Abuse",
                "category_description": "...",
            },
        ]

    def test_picks_from_primary_for_T1(self, mixed_goals: list[dict]) -> None:
        """T1 (Memory Poisoning): primary=[integrity], excluded=[availability].
        Should pick from integrity goals, never availability."""
        usage: Counter[str] = Counter()
        selected_cats = set()
        for _ in range(20):
            goal = select_attack_goal(
                mixed_goals, usage, total_seeds=20, threat_id="T1"
            )
            selected_cats.add(goal["category_id"])
            usage[goal["id"]] += 1

        # Must never pick availability (excluded for T1)
        assert "availability" not in selected_cats
        # Must have picked integrity at least once (primary)
        assert "integrity" in selected_cats

    def test_never_picks_excluded_for_T4(self, mixed_goals: list[dict]) -> None:
        """T4 (Resource Overload): excluded=[integrity, privacy].
        Should only pick availability or abuse."""
        usage: Counter[str] = Counter()
        for _ in range(30):
            goal = select_attack_goal(
                mixed_goals, usage, total_seeds=30, threat_id="T4"
            )
            assert goal["category_id"] not in ("integrity", "privacy"), (
                f"T4 should never pick {goal['category_id']} goal {goal['id']}"
            )
            usage[goal["id"]] += 1

    def test_none_threat_id_preserves_original_behavior(
        self, mixed_goals: list[dict]
    ) -> None:
        """With threat_id=None, all goals are eligible (backwards-compatible)."""
        usage: Counter[str] = Counter()
        selected_cats = set()
        for _ in range(50):
            goal = select_attack_goal(
                mixed_goals, usage, total_seeds=50, threat_id=None
            )
            selected_cats.add(goal["category_id"])
            usage[goal["id"]] += 1

        # All four categories should appear
        assert selected_cats == {"availability", "integrity", "privacy", "abuse"}

    def test_unknown_threat_id_preserves_original_behavior(
        self, mixed_goals: list[dict]
    ) -> None:
        """An unknown threat_id falls back to unweighted fair-share."""
        usage: Counter[str] = Counter()
        selected_cats = set()
        for _ in range(50):
            goal = select_attack_goal(
                mixed_goals, usage, total_seeds=50, threat_id="T99"
            )
            selected_cats.add(goal["category_id"])
            usage[goal["id"]] += 1

        assert selected_cats == {"availability", "integrity", "privacy", "abuse"}

    def test_falls_back_to_secondary_when_primary_exhausted(self) -> None:
        """When primary goals are above fair-share ceiling, secondary goals are used."""
        # T8: primary=[abuse], secondary=[integrity], excluded=[availability, privacy]
        goals = [
            {
                "id": "AB-1",
                "name": "Safety Bypass",
                "description": "...",
                "category_id": "abuse",
                "category_name": "Abuse",
                "category_description": "...",
            },
            {
                "id": "IN-1",
                "name": "Output Manipulation",
                "description": "...",
                "category_id": "integrity",
                "category_name": "Integrity Violation",
                "category_description": "...",
            },
            {
                "id": "AV-1",
                "name": "Service Denial",
                "description": "...",
                "category_id": "availability",
                "category_name": "Availability Disruption",
                "category_description": "...",
            },
            {
                "id": "PR-1",
                "name": "Data Exfiltration",
                "description": "...",
                "category_id": "privacy",
                "category_name": "Privacy Compromise",
                "category_description": "...",
            },
        ]

        # Pre-load usage so AB-1 is above fair-share ceiling
        # total_seeds=4, 1 primary goal → ceiling = ceil(4/1) = 4
        # Set AB-1 to 4 uses to trigger fallback
        usage: Counter[str] = Counter({"AB-1": 4})

        goal = select_attack_goal(goals, usage, total_seeds=4, threat_id="T8")
        # Should pick from secondary (integrity), not excluded (availability/privacy)
        assert goal["category_id"] == "integrity", (
            f"Expected secondary fallback to integrity, got {goal['category_id']}"
        )

    def test_empty_sub_goals_raises_with_threat_id(self) -> None:
        """Empty sub-goals list raises ValueError even with threat_id."""
        with pytest.raises(ValueError, match="No attack goal sub-goals available"):
            select_attack_goal([], Counter(), total_seeds=10, threat_id="T1")
