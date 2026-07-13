"""Tests for KC sub-code field on CapabilityProfile and Stage1Profile."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    VALID_KC_SUBCODES,
)


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


class TestKCSubcodesValidation:

    def test_valid_kc_subcodes_accepted(self):
        codes = ["KC1.1", "KC4.3", "KC6.1.1"]
        p = CapabilityProfile(**_base_profile_data(
            kc_subcodes=codes,
            has_persistent_memory=True,  # KC4.3 derives memory zone
        ))
        assert set(p.kc_subcodes) == set(codes)

    def test_invalid_kc_subcode_rejected(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            CapabilityProfile(**_base_profile_data(kc_subcodes=["KC99.1"]))

    def test_empty_kc_subcodes_accepted(self):
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=[]))
        assert p.kc_subcodes == []

    def test_default_kc_subcodes_is_empty(self):
        p = CapabilityProfile(**_base_profile_data())
        assert p.kc_subcodes == []

    def test_kc_subcodes_deduplicated_and_sorted(self):
        codes = ["KC6.1.1", "KC1.1", "KC6.1.1", "KC1.1"]
        p = CapabilityProfile(**_base_profile_data(kc_subcodes=codes))
        assert p.kc_subcodes == ["KC1.1", "KC6.1.1"]

    def test_all_valid_subcodes_accepted(self):
        p = CapabilityProfile(
            **_base_profile_data(
                kc_subcodes=list(VALID_KC_SUBCODES),
                has_persistent_memory=True,  # KC4.3+ derives memory zone
                multi_agent=True,            # KC2.3 derives inter_agent zone
            )
        )
        assert set(p.kc_subcodes) == VALID_KC_SUBCODES

    def test_mixed_valid_and_invalid_rejected(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            CapabilityProfile(
                **_base_profile_data(kc_subcodes=["KC1.1", "KC0.0"])
            )


class TestStage1ProfileKCSubcodes:

    def test_stage1_accepts_kc_subcodes(self):
        codes = ["KC1.1", "KC5.2", "KC6.1.1"]
        s = Stage1Profile(**_base_stage1_data(kc_subcodes=codes))
        assert set(s.kc_subcodes) == set(codes)

    def test_stage1_to_capability_profile_preserves_kc_subcodes(self):
        codes = ["KC1.1", "KC4.3", "KC6.2.2"]
        s = Stage1Profile(**_base_stage1_data(
            kc_subcodes=codes,
            has_persistent_memory=True,  # KC4.3 derives memory zone
        ))
        p = s.to_capability_profile()
        assert p.kc_subcodes == sorted(codes)

    def test_stage1_default_kc_subcodes(self):
        s = Stage1Profile(**_base_stage1_data())
        assert s.kc_subcodes == []
        p = s.to_capability_profile()
        assert p.kc_subcodes == []

    def test_stage1_invalid_kc_subcode_rejected(self):
        with pytest.raises(ValidationError, match="Invalid KC sub-code"):
            Stage1Profile(**_base_stage1_data(kc_subcodes=["INVALID"]))


class TestBackwardCompatibility:

    def test_profile_without_kc_subcodes_field(self):
        data = _base_profile_data()
        data.pop("kc_subcodes", None)
        p = CapabilityProfile(**data)
        assert p.kc_subcodes == []

    def test_serialization_roundtrip(self):
        codes = ["KC1.1", "KC2.3", "KC6.4"]
        p = CapabilityProfile(**_base_profile_data(
            kc_subcodes=codes,
            multi_agent=True,  # KC2.3 derives inter_agent zone
        ))
        dumped = p.model_dump(mode="json")
        p2 = CapabilityProfile(**dumped)
        assert p2.kc_subcodes == p.kc_subcodes
        assert p2.zones_active == p.zones_active

    def test_serialization_roundtrip_empty_kc(self):
        p = CapabilityProfile(**_base_profile_data())
        dumped = p.model_dump(mode="json", exclude_none=True)
        p2 = CapabilityProfile(**dumped)
        assert p2.kc_subcodes == []
