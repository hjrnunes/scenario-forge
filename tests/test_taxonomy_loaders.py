"""Tests for taxonomy loaders moved to data.loaders (bead 8bt5).

Verifies that load_attack_goals_taxonomy and load_threat_goal_affinity
are importable from data.loaders, return correct types, cache properly,
and accept an explicit path parameter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scenario_forge.data.loaders import (
    _load_attack_goals_taxonomy_cached,
    _load_threat_goal_affinity_cached,
    load_attack_goals_taxonomy,
    load_threat_goal_affinity,
)


class TestLoadAttackGoalsTaxonomy:
    """Tests for load_attack_goals_taxonomy in data.loaders."""

    def test_importable_from_data_loaders(self):
        """Function is importable from scenario_forge.data.loaders."""
        assert callable(load_attack_goals_taxonomy)

    def test_returns_dict_with_expected_keys(self):
        """Returns a dict with 'version' and 'categories' keys."""
        result = load_attack_goals_taxonomy()
        assert isinstance(result, dict)
        assert "version" in result
        assert "categories" in result

    def test_cache_returns_same_object(self):
        """Second call returns the exact same object (cache hit)."""
        first = load_attack_goals_taxonomy()
        second = load_attack_goals_taxonomy()
        assert first is second

    def test_explicit_path(self, tmp_path: Path):
        """Loading from an explicit path works."""
        data = {"version": "test", "categories": []}
        p = tmp_path / "goals.json"
        p.write_text(json.dumps(data))

        result = load_attack_goals_taxonomy(path=p)
        assert result == data

    def test_categories_are_list(self):
        """The 'categories' value is a list."""
        result = load_attack_goals_taxonomy()
        assert isinstance(result["categories"], list)
        assert len(result["categories"]) > 0


class TestLoadThreatGoalAffinity:
    """Tests for load_threat_goal_affinity in data.loaders."""

    def test_importable_from_data_loaders(self):
        """Function is importable from scenario_forge.data.loaders."""
        assert callable(load_threat_goal_affinity)

    def test_returns_dict(self):
        """Returns a dict keyed by threat IDs."""
        result = load_threat_goal_affinity()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_values_have_affinity_keys(self):
        """Each threat entry has 'primary', 'secondary', 'excluded' keys."""
        result = load_threat_goal_affinity()
        for threat_id, entry in result.items():
            assert "primary" in entry, f"{threat_id} missing 'primary'"
            assert "secondary" in entry, f"{threat_id} missing 'secondary'"
            assert "excluded" in entry, f"{threat_id} missing 'excluded'"

    def test_cache_returns_same_object(self):
        """Second call returns the exact same object (cache hit)."""
        first = load_threat_goal_affinity()
        second = load_threat_goal_affinity()
        assert first is second

    def test_explicit_path(self, tmp_path: Path):
        """Loading from an explicit path works."""
        data = {
            "affinities": {
                "T99": {
                    "primary": ["CAT-A"],
                    "secondary": ["CAT-B"],
                    "excluded": [],
                }
            }
        }
        p = tmp_path / "affinity.yaml"
        p.write_text(yaml.dump(data))

        result = load_threat_goal_affinity(path=p)
        assert result == data["affinities"]


@pytest.fixture(autouse=True)
def _clear_lru_caches():
    """Clear LRU caches before each test to ensure isolation."""
    _load_attack_goals_taxonomy_cached.cache_clear()
    _load_threat_goal_affinity_cached.cache_clear()
    yield
    _load_attack_goals_taxonomy_cached.cache_clear()
    _load_threat_goal_affinity_cached.cache_clear()
