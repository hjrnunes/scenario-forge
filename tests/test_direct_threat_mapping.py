"""Tests for the direct T-threat mapping path (bypassing LLM hop).

Verifies that agentic-only threats (T7-T10, T14-T16) are reachable
through the direct capability-profile-matching path when they have
no t_to_llm cross-reference.
"""

from __future__ import annotations

import pytest

from scenario_forge.models import CapabilityProfile
from scenario_forge.pipeline.threats import (
    _build_direct_t_mappings,
    _build_t_to_atlas_index,
    _matches_profile_directly,
    _resolve_direct_threats,
)


# ---------------------------------------------------------------------------
# Fixtures: minimal cross-taxonomy data with t_direct section
# ---------------------------------------------------------------------------

CROSS_TAXONOMY_WITH_DIRECT = {
    "t_to_llm": [
        {"source": "T1", "target": "LLM04"},
        {"source": "T6", "target": "LLM01"},
    ],
    "t_direct": [
        {
            "source": "T7",
            "source_name": "Misaligned & Deceptive Behaviors",
            "profile_match": {"min_zones": ["input", "reasoning"]},
        },
        {
            "source": "T8",
            "source_name": "Repudiation & Untraceability",
            "profile_match": {"min_zones": ["input", "reasoning"]},
        },
        {
            "source": "T9",
            "source_name": "Identity Spoofing & Impersonation",
            "profile_match": {"min_zones": ["input", "reasoning", "tool_execution"]},
        },
        {
            "source": "T10",
            "source_name": "Overwhelming Human in the Loop",
            "profile_match": {"min_zones": ["input", "reasoning"], "requires_hitl": True},
        },
        {
            "source": "T14",
            "source_name": "Human Attacks on Multi-Agent Systems",
            "profile_match": {
                "min_zones": ["input", "reasoning", "inter_agent"],
                "requires_multi_agent": True,
            },
        },
        {
            "source": "T15",
            "source_name": "Human Manipulation",
            "profile_match": {"min_zones": ["input", "reasoning"]},
        },
        {
            "source": "T16",
            "source_name": "Insecure Inter-Agent Protocol Abuse",
            "profile_match": {
                "min_zones": ["input", "reasoning", "tool_execution", "inter_agent"],
                "requires_multi_agent": True,
            },
        },
    ],
}


# ---------------------------------------------------------------------------
# Helpers: profile builders
# ---------------------------------------------------------------------------


def _minimal_profile(**overrides) -> CapabilityProfile:
    """Build a minimal capability profile with optional overrides."""
    defaults = dict(
        zones_active=["input", "reasoning"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=["user prompts (zone 1)"],
        confidence="medium",
    )
    defaults.update(overrides)
    return CapabilityProfile(**defaults)


def _full_profile() -> CapabilityProfile:
    """Build a fully-featured capability profile (all zones, all flags)."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        has_persistent_memory=True,
        multi_agent=True,
        hitl=True,
        entry_points=["user prompts (zone 1)", "API calls (zone 3)"],
        confidence="high",
    )


# ---------------------------------------------------------------------------
# Tests: _build_direct_t_mappings
# ---------------------------------------------------------------------------


class TestBuildDirectTMappings:
    def test_extracts_all_entries(self) -> None:
        mappings = _build_direct_t_mappings(CROSS_TAXONOMY_WITH_DIRECT)
        assert len(mappings) == 7

    def test_returns_empty_when_no_t_direct(self) -> None:
        mappings = _build_direct_t_mappings({"t_to_llm": []})
        assert mappings == []

    def test_returns_empty_for_empty_dict(self) -> None:
        mappings = _build_direct_t_mappings({})
        assert mappings == []

    def test_preserves_source_ids(self) -> None:
        mappings = _build_direct_t_mappings(CROSS_TAXONOMY_WITH_DIRECT)
        ids = {m["source"] for m in mappings}
        assert ids == {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}


# ---------------------------------------------------------------------------
# Tests: _matches_profile_directly
# ---------------------------------------------------------------------------


class TestMatchesProfileDirectly:
    """Tests for capability profile matching against direct T-threat mappings."""

    def test_minimal_profile_matches_zones_1_2_only(self) -> None:
        """Minimal profile (zones 1,2) should match T7, T8, T15 but not T9."""
        profile = _minimal_profile()

        # T7: min_zones [1,2] — should match
        t7 = CROSS_TAXONOMY_WITH_DIRECT["t_direct"][0]
        assert _matches_profile_directly(t7, profile) is True

        # T9: min_zones [1,2,3] — should NOT match (no zone 3)
        t9 = CROSS_TAXONOMY_WITH_DIRECT["t_direct"][2]
        assert _matches_profile_directly(t9, profile) is False

    def test_hitl_required_but_missing(self) -> None:
        """T10 requires HITL; profile without HITL should not match."""
        profile = _minimal_profile(hitl=False)
        t10 = CROSS_TAXONOMY_WITH_DIRECT["t_direct"][3]
        assert _matches_profile_directly(t10, profile) is False

    def test_hitl_required_and_present(self) -> None:
        """T10 requires HITL; profile with HITL should match."""
        profile = _minimal_profile(hitl=True)
        t10 = CROSS_TAXONOMY_WITH_DIRECT["t_direct"][3]
        assert _matches_profile_directly(t10, profile) is True

    def test_multi_agent_required_but_missing(self) -> None:
        """T14 requires multi_agent; profile without it should not match."""
        profile = _minimal_profile(
            zones_active=["input", "reasoning", "inter_agent"],
            multi_agent=True,
        )
        # T14 should match with zones 1,2,5 and multi_agent=true
        t14 = CROSS_TAXONOMY_WITH_DIRECT["t_direct"][4]
        assert _matches_profile_directly(t14, profile) is True

        # But without multi_agent, should not match
        # (can't set multi_agent=False with zone 5 due to validator,
        # so test without zone 5)
        profile_no_ma = _minimal_profile(multi_agent=False)
        assert _matches_profile_directly(t14, profile_no_ma) is False

    def test_t16_requires_zones_and_multi_agent(self) -> None:
        """T16 requires zones 1,2,3,5 AND multi_agent=true."""
        # Full profile should match
        profile_full = _full_profile()
        t16 = CROSS_TAXONOMY_WITH_DIRECT["t_direct"][6]
        assert _matches_profile_directly(t16, profile_full) is True

        # Missing zone 5 should not match
        profile_no_5 = _minimal_profile(zones_active=["input", "reasoning", "tool_execution"])
        assert _matches_profile_directly(t16, profile_no_5) is False

    def test_full_profile_matches_all(self) -> None:
        """A fully-featured profile should match all direct mappings."""
        profile = _full_profile()
        for mapping in CROSS_TAXONOMY_WITH_DIRECT["t_direct"]:
            assert _matches_profile_directly(mapping, profile) is True, (
                f"Expected {mapping['source']} to match full profile"
            )

    def test_empty_profile_match_spec(self) -> None:
        """A mapping with empty profile_match should always match."""
        mapping = {"source": "TX", "profile_match": {}}
        profile = _minimal_profile()
        assert _matches_profile_directly(mapping, profile) is True

    def test_missing_profile_match_key(self) -> None:
        """A mapping without profile_match key should always match."""
        mapping = {"source": "TX"}
        profile = _minimal_profile()
        assert _matches_profile_directly(mapping, profile) is True


# ---------------------------------------------------------------------------
# Tests: _resolve_direct_threats
# ---------------------------------------------------------------------------


class TestResolveDirectThreats:
    """Tests for resolving which direct-path threats apply to a profile."""

    def test_minimal_profile_gets_t7_t8_t15(self) -> None:
        """Minimal profile should resolve T7, T8, T15 (always-in-scope, zones 1+2)."""
        profile = _minimal_profile()
        # All three are "always in scope" in threat_gating
        in_scope = {"T7", "T8", "T15", "T6"}
        result = _resolve_direct_threats(
            CROSS_TAXONOMY_WITH_DIRECT, profile, in_scope
        )
        assert result == {"T7", "T8", "T15"}

    def test_full_profile_gets_all_seven(self) -> None:
        """Full profile with all flags should resolve all 7 direct threats."""
        profile = _full_profile()
        in_scope = {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}
        result = _resolve_direct_threats(
            CROSS_TAXONOMY_WITH_DIRECT, profile, in_scope
        )
        assert result == {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}

    def test_gating_filters_out_threats(self) -> None:
        """Threats that don't pass gating should not be resolved even if profile matches."""
        profile = _full_profile()
        # Only T7 and T8 pass gating
        in_scope = {"T7", "T8"}
        result = _resolve_direct_threats(
            CROSS_TAXONOMY_WITH_DIRECT, profile, in_scope
        )
        assert result == {"T7", "T8"}

    def test_no_direct_section_yields_empty(self) -> None:
        """Cross-taxonomy without t_direct should yield empty set."""
        profile = _full_profile()
        result = _resolve_direct_threats(
            {"t_to_llm": []}, profile, {"T7", "T8"}
        )
        assert result == set()

    def test_zone_3_profile_adds_t9(self) -> None:
        """Profile with zone 3 should also resolve T9."""
        profile = _minimal_profile(zones_active=["input", "reasoning", "tool_execution"])
        in_scope = {"T7", "T8", "T9", "T15"}
        result = _resolve_direct_threats(
            CROSS_TAXONOMY_WITH_DIRECT, profile, in_scope
        )
        assert "T9" in result
        assert "T7" in result

    def test_hitl_profile_adds_t10(self) -> None:
        """Profile with HITL should also resolve T10."""
        profile = _minimal_profile(hitl=True)
        in_scope = {"T7", "T8", "T10", "T15"}
        result = _resolve_direct_threats(
            CROSS_TAXONOMY_WITH_DIRECT, profile, in_scope
        )
        assert "T10" in result

    def test_multi_agent_profile_adds_t14(self) -> None:
        """Profile with multi_agent + zone 5 should resolve T14."""
        profile = _minimal_profile(
            zones_active=["input", "reasoning", "inter_agent"],
            multi_agent=True,
        )
        in_scope = {"T7", "T8", "T14", "T15"}
        result = _resolve_direct_threats(
            CROSS_TAXONOMY_WITH_DIRECT, profile, in_scope
        )
        assert "T14" in result


# ---------------------------------------------------------------------------
# Tests: integration with real cross-taxonomy YAML
# ---------------------------------------------------------------------------


class TestDirectMappingYAMLIntegration:
    """Tests that the actual cross-taxonomy-mappings.yaml contains valid t_direct data."""

    @pytest.fixture()
    def cross_taxonomy(self) -> dict:
        import yaml
        from pathlib import Path

        yaml_path = (
            Path(__file__).resolve().parents[1]
            / "data"
            / "taxonomies"
            / "mappings"
            / "cross-taxonomy-mappings.yaml"
        )
        with open(yaml_path) as f:
            return yaml.safe_load(f)

    def test_t_direct_section_exists(self, cross_taxonomy: dict) -> None:
        assert "t_direct" in cross_taxonomy
        assert len(cross_taxonomy["t_direct"]) == 7

    def test_all_agentic_only_threats_have_direct_mapping(
        self, cross_taxonomy: dict
    ) -> None:
        """Every threat listed in agentic_only_threats must have a t_direct entry."""
        agentic_only_ids = {
            t["id"] for t in cross_taxonomy["agentic_only_threats"]["threats"]
        }
        direct_ids = {m["source"] for m in cross_taxonomy["t_direct"]}
        assert agentic_only_ids == direct_ids

    def test_all_direct_entries_have_profile_match(
        self, cross_taxonomy: dict
    ) -> None:
        for mapping in cross_taxonomy["t_direct"]:
            assert "profile_match" in mapping, (
                f"{mapping['source']} missing profile_match"
            )
            assert "min_zones" in mapping["profile_match"], (
                f"{mapping['source']} missing min_zones in profile_match"
            )

    def test_full_profile_resolves_all_seven(
        self, cross_taxonomy: dict
    ) -> None:
        """Full profile with all in-scope threats should resolve all 7 direct threats."""
        profile = _full_profile()
        in_scope = {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}
        result = _resolve_direct_threats(cross_taxonomy, profile, in_scope)
        assert result == {"T7", "T8", "T9", "T10", "T14", "T15", "T16"}

    def test_minimal_profile_resolves_subset(
        self, cross_taxonomy: dict
    ) -> None:
        """Minimal profile should only resolve threats matching zones 1+2."""
        profile = _minimal_profile()
        in_scope = {"T7", "T8", "T15"}
        result = _resolve_direct_threats(cross_taxonomy, profile, in_scope)
        # T7, T8, T15 require only zones [1,2]
        assert result == {"T7", "T8", "T15"}
        # T9, T10, T14, T16 should NOT be resolved (profile mismatch or not in scope)

    def test_t_to_atlas_section_exists(self, cross_taxonomy: dict) -> None:
        """The t_to_atlas section must exist with entries for all 17 T-threats."""
        assert "t_to_atlas" in cross_taxonomy
        t_ids = {m["source"] for m in cross_taxonomy["t_to_atlas"]}
        expected = {f"T{i}" for i in range(1, 18)}
        assert t_ids == expected, f"Missing T-threats: {expected - t_ids}"

    def test_t_to_atlas_all_entries_have_targets(
        self, cross_taxonomy: dict
    ) -> None:
        """Every t_to_atlas entry must have non-empty targets list."""
        for mapping in cross_taxonomy["t_to_atlas"]:
            assert mapping.get("targets"), (
                f"{mapping['source']} has empty targets"
            )
            assert all(
                t.startswith("AML.T") for t in mapping["targets"]
            ), f"{mapping['source']} has non-ATLAS technique ID in targets"

    def test_build_t_to_atlas_index(self, cross_taxonomy: dict) -> None:
        """_build_t_to_atlas_index produces a correct index."""
        index = _build_t_to_atlas_index(cross_taxonomy)
        # All 17 T-threats should have entries
        assert len(index) == 17
        # T6 should map to prompt injection techniques
        assert "AML.T0051.000" in index["T6"]
        assert "AML.T0054" in index["T6"]
        # T4 should map to DoS/cost techniques
        assert "AML.T0029" in index["T4"]
        assert "AML.T0034" in index["T4"]
