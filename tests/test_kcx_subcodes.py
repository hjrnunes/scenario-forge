"""Tests for KCX (scenario-forge extension) sub-codes.

KCX-prefixed codes are scenario-forge-specific extensions — NOT from OWASP.
They gate attack patterns that require structural privilege infrastructure
most AI systems lack.

Covers:
  - KCX codes pass the kc_subcodes validator on both models
  - KCX codes in attack pattern prerequisites cause filtering
  - KCX codes in profile allow T3 patterns through gating
  - KCX codes coexist with standard KC codes
  - Unknown non-KCX codes still rejected
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scenario_forge.data.threat_gating import (
    _evaluate_prerequisite_capabilities,
    _filter_attack_patterns,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    KCX_PREFIX,
    KCX_SUBCODES,
    Stage1Profile,
    VALID_KC_SUBCODES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_profile_data(**overrides) -> dict:
    """Minimal valid CapabilityProfile payload."""
    data = {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": True,
        "entry_points": ["user input (input)"],
        "confidence": "high",
    }
    data.update(overrides)
    return data


def _base_stage1_data(**overrides) -> dict:
    """Minimal valid Stage1Profile payload (no zones_active field)."""
    data = {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": True,
        "entry_points": ["user input (input)"],
        "confidence": "high",
    }
    data.update(overrides)
    return data


def _make_profile(
    *,
    kc_subcodes: list[str] | None = None,
    zones_active: list[str] | None = None,
    has_persistent_memory: bool = False,
    multi_agent: bool = False,
    hitl: bool = False,
) -> CapabilityProfile:
    """Build a CapabilityProfile with sensible defaults for testing."""
    if zones_active is None:
        zones = ["input", "reasoning", "tool_execution"]
        if has_persistent_memory:
            zones.append("memory")
        if multi_agent:
            zones.append("inter_agent")
    else:
        zones = zones_active
    if kc_subcodes is None:
        kc_subcodes = ["KC1.1", "KC6.1.1"]
    return CapabilityProfile(
        zones_active=zones,
        has_persistent_memory=has_persistent_memory,
        multi_agent=multi_agent,
        hitl=hitl,
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=kc_subcodes,
    )


# Synthetic T3 attack patterns matching real YAML structure

_AP_T3_01 = {
    "id": "AP-T3-01",
    "threat_id": "T3",
    "name": "Temporary privilege retention via misconfiguration exploitation",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "requires_tool_execution": True,
        "kc_requires": {
            "all": ["KCX-PRIV"],
            "any": ["KC6.1.2", "KC6.2.2", "KC6.3.2", "KC6.5"],
        },
    },
}

_AP_T3_02 = {
    "id": "AP-T3-02",
    "threat_id": "T3",
    "name": "Cross-boundary authorization escalation",
    "description": "...",
    "prerequisite_capabilities": {
        "min_zones": ["input", "reasoning", "tool_execution"],
        "requires_tool_execution": True,
        "kc_requires": {
            "any": ["KC6.1.2", "KC6.2.2", "KC6.5", "KCX-XAUTH"],
        },
    },
}


# ---------------------------------------------------------------------------
# KCX validation on CapabilityProfile
# ---------------------------------------------------------------------------


class TestKCXValidation:
    """KCX-prefixed codes pass the kc_subcodes validator."""

    def test_kcx_priv_accepted(self):
        p = CapabilityProfile(
            **_base_profile_data(kc_subcodes=["KC1.1", "KCX-PRIV"])
        )
        assert "KCX-PRIV" in p.kc_subcodes

    def test_kcx_xauth_accepted(self):
        p = CapabilityProfile(
            **_base_profile_data(kc_subcodes=["KC1.1", "KCX-XAUTH"])
        )
        assert "KCX-XAUTH" in p.kc_subcodes

    def test_both_kcx_codes_accepted(self):
        p = CapabilityProfile(
            **_base_profile_data(kc_subcodes=["KC1.1", "KCX-PRIV", "KCX-XAUTH"])
        )
        assert "KCX-PRIV" in p.kc_subcodes
        assert "KCX-XAUTH" in p.kc_subcodes

    def test_kcx_mixed_with_standard_codes(self):
        codes = ["KC1.1", "KC6.1.2", "KCX-PRIV", "KC6.2.2"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert set(codes).issubset(set(p.kc_subcodes))

    def test_arbitrary_kcx_prefix_accepted(self):
        """Any KCX- prefixed code passes validation (future extensibility)."""
        p = CapabilityProfile(
            **_base_profile_data(kc_subcodes=["KC1.1", "KCX-FUTURE"])
        )
        assert "KCX-FUTURE" in p.kc_subcodes

    def test_invalid_non_kcx_code_still_rejected(self):
        """Non-KCX, non-standard codes are still rejected."""
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            CapabilityProfile(
                **_base_profile_data(kc_subcodes=["KC1.1", "KC99.1"])
            )

    def test_kcx_codes_sorted_with_standard(self):
        """KCX codes sort correctly alongside standard KC codes."""
        codes = ["KCX-PRIV", "KC1.1", "KC6.1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert p.kc_subcodes == sorted(set(codes))

    def test_kcx_codes_deduplicated(self):
        codes = ["KCX-PRIV", "KC1.1", "KCX-PRIV"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert p.kc_subcodes.count("KCX-PRIV") == 1


# ---------------------------------------------------------------------------
# KCX validation on Stage1Profile
# ---------------------------------------------------------------------------


class TestKCXStage1Validation:
    """KCX codes pass Stage1Profile validation and promotion."""

    def test_stage1_accepts_kcx_codes(self):
        s = Stage1Profile(
            **_base_stage1_data(kc_subcodes=["KC1.1", "KCX-PRIV"])
        )
        assert "KCX-PRIV" in s.kc_subcodes

    def test_stage1_to_capability_profile_preserves_kcx(self):
        s = Stage1Profile(
            **_base_stage1_data(kc_subcodes=["KC1.1", "KCX-PRIV", "KCX-XAUTH"])
        )
        p = s.to_capability_profile()
        assert "KCX-PRIV" in p.kc_subcodes
        assert "KCX-XAUTH" in p.kc_subcodes

    def test_stage1_rejects_invalid_non_kcx(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            Stage1Profile(
                **_base_stage1_data(kc_subcodes=["KC1.1", "INVALID"])
            )


# ---------------------------------------------------------------------------
# KCX gating: T3 patterns filtered when profile lacks KCX codes
# ---------------------------------------------------------------------------


class TestKCXGatingFiltering:
    """KCX codes in attack pattern prerequisites cause filtering."""

    def test_t3_01_filtered_without_kcx_priv_or_kc6(self):
        """AP-T3-01 requires KCX-PRIV (all) AND one of KC6.x (any).
        Profile with only KC6.1.1 (limited API) lacks both."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        result = _filter_attack_patterns([_AP_T3_01], profile)
        assert "AP-T3-01" not in result

    def test_t3_01_filtered_without_kcx_priv(self):
        """AP-T3-01 requires KCX-PRIV (all). Profile with KC6.1.2 but
        without KCX-PRIV is filtered -- the headline fix for phantom
        privilege scenarios on static-capability systems."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.2"])
        result = _filter_attack_patterns([_AP_T3_01], profile)
        assert "AP-T3-01" not in result

    def test_t3_01_filtered_with_kcx_priv_but_no_kc6(self):
        """AP-T3-01 requires KCX-PRIV (all) AND one of KC6.x (any).
        Profile with KCX-PRIV but no qualifying KC6 code is filtered."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KCX-PRIV"])
        result = _filter_attack_patterns([_AP_T3_01], profile)
        assert "AP-T3-01" not in result

    def test_t3_02_filtered_without_kcx_xauth_or_kc6(self):
        """AP-T3-02 requires KCX-XAUTH or KC6.1.2/KC6.2.2/KC6.5.
        Profile with only KC6.1.1 (limited API) lacks all of them."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        result = _filter_attack_patterns([_AP_T3_02], profile)
        assert "AP-T3-02" not in result

    def test_t3_01_passes_with_kcx_priv_and_kc6(self):
        """AP-T3-01 passes when profile has both KCX-PRIV and a KC6 code."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.2", "KCX-PRIV"])
        result = _filter_attack_patterns([_AP_T3_01], profile)
        assert "AP-T3-01" in result

    def test_t3_02_passes_with_kcx_xauth(self):
        """AP-T3-02 passes when profile has KCX-XAUTH."""
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1", "KCX-XAUTH"])
        result = _filter_attack_patterns([_AP_T3_02], profile)
        assert "AP-T3-02" in result


# ---------------------------------------------------------------------------
# KCX gating: prerequisite evaluation
# ---------------------------------------------------------------------------


class TestKCXPrerequisiteEvaluation:
    """Verify kc_requires any/all logic works with KCX codes."""

    def test_any_passes_with_kcx_code(self):
        profile = _make_profile(kc_subcodes=["KC1.1", "KCX-PRIV"])
        prereqs = {"kc_requires": {"any": ["KCX-PRIV", "KC6.2.2"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is True

    def test_any_fails_without_kcx_code(self):
        profile = _make_profile(kc_subcodes=["KC1.1", "KC6.1.1"])
        prereqs = {"kc_requires": {"any": ["KCX-PRIV"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is False

    def test_all_passes_with_kcx_code(self):
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC2.3", "KCX-XAUTH"],
            multi_agent=True,
        )
        prereqs = {"kc_requires": {"all": ["KC2.3", "KCX-XAUTH"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is True

    def test_all_fails_missing_kcx_code(self):
        profile = _make_profile(
            kc_subcodes=["KC1.1", "KC2.3"],
            multi_agent=True,
        )
        prereqs = {"kc_requires": {"all": ["KC2.3", "KCX-XAUTH"]}}
        assert _evaluate_prerequisite_capabilities(prereqs, profile) is False


# ---------------------------------------------------------------------------
# KCX constants
# ---------------------------------------------------------------------------


class TestKCXConstants:
    """Verify KCX constants are properly defined."""

    def test_kcx_prefix_value(self):
        assert KCX_PREFIX == "KCX-"

    def test_kcx_subcodes_contains_priv(self):
        assert "KCX-PRIV" in KCX_SUBCODES

    def test_kcx_subcodes_contains_xauth(self):
        assert "KCX-XAUTH" in KCX_SUBCODES

    def test_kcx_subcodes_not_in_valid_kc_subcodes(self):
        """KCX codes are NOT in the OWASP VALID_KC_SUBCODES set."""
        for code in KCX_SUBCODES:
            assert code not in VALID_KC_SUBCODES

    def test_all_kcx_codes_start_with_prefix(self):
        for code in KCX_SUBCODES:
            assert code.startswith(KCX_PREFIX)
