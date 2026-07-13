"""Tests for derive_zones_from_kc() and mismatch validation.

Covers:
  - Zone derivation from KC sub-codes
  - Mismatch validation logging on CapabilityProfile and Stage1Profile
  - Consistency with kc-threat-mapping.yaml taxonomy data
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    VALID_KC_SUBCODES,
    derive_zones_from_kc,
)


# ---------------------------------------------------------------------------
# derive_zones_from_kc unit tests
# ---------------------------------------------------------------------------


class TestDeriveZonesBasic:
    """Minimal KC set produces baseline zones."""

    def test_derive_zones_basic(self):
        """KC1.1 alone -> ['input', 'reasoning']."""
        result = derive_zones_from_kc(["KC1.1"])
        assert result == ["input", "reasoning"]

    def test_derive_zones_empty_list(self):
        """Empty KC list still returns baseline zones."""
        result = derive_zones_from_kc([])
        assert result == ["input", "reasoning"]

    def test_derive_zones_kc3_stays_baseline(self):
        """KC3.* codes don't add zones beyond baseline."""
        result = derive_zones_from_kc(["KC1.1", "KC3.1", "KC3.2"])
        assert result == ["input", "reasoning"]


class TestDeriveZonesMemory:
    """KC4.3-KC4.6 activate the memory zone; KC4.1/KC4.2 do not."""

    def test_derive_zones_with_memory(self):
        """KC4.4 (cross-agent, cross-session) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.4"])
        assert "memory" in result

    def test_derive_zones_session_memory_no_zone_kc4_1(self):
        """KC4.1 (in-agent session-only) -> no 'memory' zone."""
        result = derive_zones_from_kc(["KC1.1", "KC4.1"])
        assert "memory" not in result
        assert result == ["input", "reasoning"]

    def test_derive_zones_session_memory_no_zone_kc4_2(self):
        """KC4.2 (cross-agent session-only) -> no 'memory' zone."""
        result = derive_zones_from_kc(["KC1.1", "KC4.2"])
        assert "memory" not in result
        assert result == ["input", "reasoning"]

    def test_derive_zones_kc4_3_activates_memory(self):
        """KC4.3 (in-agent cross-session) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.3"])
        assert "memory" in result

    def test_derive_zones_kc4_5_activates_memory(self):
        """KC4.5 (in-agent cross-user) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.5"])
        assert "memory" in result

    def test_derive_zones_kc4_6_activates_memory(self):
        """KC4.6 (cross-agent cross-user) -> includes 'memory'."""
        result = derive_zones_from_kc(["KC1.1", "KC4.6"])
        assert "memory" in result


class TestDeriveZonesToolExecution:
    """KC5.* and KC6.* activate tool_execution zone."""

    def test_derive_zones_kc5(self):
        """KC5.1 -> includes 'tool_execution'."""
        result = derive_zones_from_kc(["KC1.1", "KC5.1"])
        assert "tool_execution" in result

    def test_derive_zones_kc6(self):
        """KC6.2.2 -> includes 'tool_execution'."""
        result = derive_zones_from_kc(["KC1.1", "KC6.2.2"])
        assert "tool_execution" in result

    def test_derive_zones_kc6_all_variants(self):
        """All KC6 sub-codes activate tool_execution."""
        kc6_codes = [c for c in sorted(VALID_KC_SUBCODES) if c.startswith("KC6.")]
        for code in kc6_codes:
            result = derive_zones_from_kc(["KC1.1", code])
            assert "tool_execution" in result, f"{code} should activate tool_execution"


class TestDeriveZonesInterAgent:
    """KC2.3 activates inter_agent zone."""

    def test_derive_zones_inter_agent(self):
        """KC2.3 -> includes 'inter_agent'."""
        result = derive_zones_from_kc(["KC1.1", "KC2.3"])
        assert "inter_agent" in result

    def test_derive_zones_kc2_1_no_inter_agent(self):
        """KC2.1 (predefined workflows) -> no 'inter_agent'."""
        result = derive_zones_from_kc(["KC1.1", "KC2.1"])
        assert "inter_agent" not in result

    def test_derive_zones_kc2_2_no_inter_agent(self):
        """KC2.2 (hierarchical planning) -> no 'inter_agent'."""
        result = derive_zones_from_kc(["KC1.1", "KC2.2"])
        assert "inter_agent" not in result


class TestDeriveZonesFull:
    """All zones active with appropriate KC codes."""

    def test_derive_zones_full(self):
        """All four optional zones activated by appropriate codes."""
        result = derive_zones_from_kc([
            "KC1.1",     # baseline
            "KC2.3",     # inter_agent
            "KC4.4",     # memory
            "KC5.1",     # tool_execution
        ])
        assert result == [
            "input", "inter_agent", "memory", "reasoning", "tool_execution",
        ]

    def test_derive_zones_result_is_sorted(self):
        """Output is always sorted alphabetically."""
        result = derive_zones_from_kc(["KC6.7", "KC4.6", "KC2.3", "KC1.1"])
        assert result == sorted(result)


# ---------------------------------------------------------------------------
# Consistency with taxonomy data
# ---------------------------------------------------------------------------


class TestDeriveZonesMatchesRealData:
    """Verify derive_zones_from_kc is consistent with kc-threat-mapping.yaml."""

    def test_derive_zones_matches_real_data(self):
        """Every KC sub-code in the taxonomy maps to the expected zone(s).

        The mapping rules:
        - KC1.*/KC3.* -> input + reasoning (baseline)
        - KC2.1/KC2.2 -> reasoning (baseline only)
        - KC2.3 -> inter_agent
        - KC4.1/KC4.2 -> baseline only (session memory)
        - KC4.3-KC4.6 -> memory
        - KC5.* -> tool_execution
        - KC6.* -> tool_execution
        """
        mapping_path = (
            Path(__file__).resolve().parent.parent
            / "data" / "taxonomies" / "mappings" / "kc-threat-mapping.yaml"
        )
        with open(mapping_path) as f:
            taxonomy = yaml.safe_load(f)

        # Expected zone activation per KC category
        expected_extra_zones: dict[str, set[str]] = {
            "KC1.": set(),             # baseline only
            "KC2.1": set(),            # baseline only
            "KC2.2": set(),            # baseline only
            "KC2.3": {"inter_agent"},
            "KC3.": set(),             # baseline only
            "KC4.1": set(),            # session-only, no zone
            "KC4.2": set(),            # session-only, no zone
            "KC4.3": {"memory"},
            "KC4.4": {"memory"},
            "KC4.5": {"memory"},
            "KC4.6": {"memory"},
            "KC5.": {"tool_execution"},
            "KC6.": {"tool_execution"},
        }

        all_kc_codes = [entry["kc_subcode"] for entry in taxonomy["kc_subcodes"]]

        for kc_code in all_kc_codes:
            derived = set(derive_zones_from_kc([kc_code]))
            baseline = {"input", "reasoning"}

            # Find the expected extra zones for this code
            extra = None
            # Try exact match first, then prefix match
            if kc_code in expected_extra_zones:
                extra = expected_extra_zones[kc_code]
            else:
                for prefix, zones in expected_extra_zones.items():
                    if kc_code.startswith(prefix):
                        extra = zones
                        break

            assert extra is not None, f"No mapping rule found for {kc_code}"
            expected = baseline | extra
            assert derived == expected, (
                f"{kc_code}: derived {sorted(derived)} != expected {sorted(expected)}"
            )


# ---------------------------------------------------------------------------
# Mismatch validation logging
# ---------------------------------------------------------------------------


class TestMismatchValidationCapabilityProfile:
    """Verify CapabilityProfile logs a warning on zones_active mismatch."""

    def test_matching_zones_no_warning(self, caplog):
        """No warning when zones_active matches KC-derived zones."""
        with caplog.at_level(logging.WARNING, logger="scenario_forge.models.capability_profile"):
            CapabilityProfile(
                zones_active=["input", "reasoning", "tool_execution"],
                has_persistent_memory=False,
                multi_agent=False,
                hitl=False,
                entry_points=["user input (zone 1)"],
                confidence="medium",
                kc_subcodes=["KC1.1", "KC5.1"],
            )
        mismatch_logs = [r for r in caplog.records if "mismatch" in r.message]
        assert len(mismatch_logs) == 0

    def test_mismatched_zones_warns(self, caplog):
        """Warning logged when zones_active differs from KC-derived zones."""
        with caplog.at_level(logging.WARNING, logger="scenario_forge.models.capability_profile"):
            CapabilityProfile(
                zones_active=["input", "memory", "reasoning", "tool_execution"],
                has_persistent_memory=True,
                multi_agent=False,
                hitl=False,
                entry_points=["user input (zone 1)"],
                confidence="medium",
                # KC5.1 -> tool_execution, but no KC4.3+ for memory
                kc_subcodes=["KC1.1", "KC5.1"],
            )
        mismatch_logs = [r for r in caplog.records if "mismatch" in r.message]
        assert len(mismatch_logs) == 1
        assert "memory" in mismatch_logs[0].message

    def test_no_warning_when_kc_subcodes_empty(self, caplog):
        """No mismatch check when kc_subcodes is empty."""
        with caplog.at_level(logging.WARNING, logger="scenario_forge.models.capability_profile"):
            CapabilityProfile(
                zones_active=["input", "memory", "reasoning"],
                has_persistent_memory=True,
                multi_agent=False,
                hitl=False,
                entry_points=["user input (zone 1)"],
                confidence="medium",
                kc_subcodes=[],
            )
        mismatch_logs = [r for r in caplog.records if "mismatch" in r.message]
        assert len(mismatch_logs) == 0

    def test_mismatch_does_not_raise(self):
        """Mismatch is observation-only -- no exception raised."""
        # Should succeed without error despite mismatch
        profile = CapabilityProfile(
            zones_active=["input", "memory", "reasoning", "tool_execution"],
            has_persistent_memory=True,
            multi_agent=False,
            hitl=False,
            entry_points=["user input (zone 1)"],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1"],  # KC-derived: no memory
        )
        assert "memory" in profile.zones_active


class TestMismatchValidationStage1Profile:
    """Verify Stage1Profile logs a warning on zones_active mismatch."""

    def test_matching_zones_no_warning(self, caplog):
        """No warning when zones_active matches KC-derived zones."""
        with caplog.at_level(logging.WARNING, logger="scenario_forge.models.capability_profile"):
            Stage1Profile(
                zones_active=["input", "reasoning"],
                has_persistent_memory=False,
                multi_agent=False,
                hitl=False,
                entry_points=["user input (zone 1)"],
                confidence="medium",
                kc_subcodes=["KC1.1"],
            )
        mismatch_logs = [r for r in caplog.records if "mismatch" in r.message]
        assert len(mismatch_logs) == 0

    def test_mismatched_zones_warns(self, caplog):
        """Warning logged when zones_active differs from KC-derived zones."""
        with caplog.at_level(logging.WARNING, logger="scenario_forge.models.capability_profile"):
            Stage1Profile(
                zones_active=["input", "reasoning", "tool_execution"],
                has_persistent_memory=False,
                multi_agent=False,
                hitl=False,
                entry_points=["user input (zone 1)"],
                confidence="medium",
                # KC1.1 only -> no tool_execution zone
                kc_subcodes=["KC1.1"],
            )
        mismatch_logs = [r for r in caplog.records if "mismatch" in r.message]
        assert len(mismatch_logs) == 1
        assert "tool_execution" in mismatch_logs[0].message
