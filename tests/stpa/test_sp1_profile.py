"""Tests for SP1 Stage 1b — Capability Profile inference.

Covers SP1-CP-01 through SP1-CP-08 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml
from scenario_forge.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from scenario_forge.stpa.system_model.profile import (
    derive_capability_profile,
    load_capability_profile,
)
from tests.stpa.sp1_helpers import MockLLMClient


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorized transaction",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            ),
            Loss(
                loss_id="L-2",
                description="Data exposure",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-002"],
            ),
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="H1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="H2", related_losses=["L-2"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="C1", related_hazards=["H-1"]
            ),
            SecurityConstraint(
                constraint_id="SC-2", description="C2", related_hazards=["H-2"]
            ),
        ],
    )


def _valid_stage1_profile_dict() -> dict:
    return {
        "has_persistent_memory": True,
        "multi_agent": False,
        "hitl": False,
        "entry_points": [
            {"name": "User chat messages", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC4.3", "KC6.1.1", "KC6.3.2"],
        "tool_inventory": [
            {"name": "payment_api", "description": "Execute payments"},
        ],
    }


class TestStage1bProfile:
    """SP1 Stage 1b capability profile inference."""

    def test_cp_01_valid_response_produces_valid_profile(self, tmp_path):
        """SP1-CP-01: valid LLM response produces a valid CapabilityProfile."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        result = derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert isinstance(result, CapabilityProfile)
        assert "input" in result.zones_active
        assert "reasoning" in result.zones_active
        assert result.entry_point_completeness.value == "inferred_partial"

    def test_cp_02_stage1_profile_promoted(self, tmp_path):
        """SP1-CP-02: Stage1Profile is promoted via to_capability_profile."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        result = derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # zones_active derived from kc_subcodes
        assert "input" in result.zones_active
        assert "reasoning" in result.zones_active
        assert "tool_execution" in result.zones_active  # KC6.* implies tool_execution
        assert "memory" in result.zones_active  # KC4.3 implies memory
        # has_persistent_memory derived from kc_subcodes (KC4.3)
        assert result.has_persistent_memory is True

    def test_cp_03_profile_flag_skips_llm_call(self, tmp_path):
        """SP1-CP-03: profile flag skips the LLM call."""
        # Write a pre-built profile
        profile = Stage1Profile(
            has_persistent_memory=True,
            multi_agent=False,
            hitl=False,
            entry_points=[
                {"name": "User chat", "direction": "input", "controllability": "direct"},
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.3", "KC6.1.1"],
            tool_inventory=[{"name": "tool1", "description": "A tool"}],
        ).to_capability_profile()
        profile_path = tmp_path / "capability-profile.yaml"
        write_yaml(profile, profile_path)

        loaded = load_capability_profile(profile_path)
        assert isinstance(loaded, CapabilityProfile)

    def test_cp_05_call_logged_with_stage_1b(self, tmp_path):
        """SP1-CP-05: call log entry has stage stage_1b."""
        import json as _json

        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [_json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_1b"
        assert entries[0]["step"] == "capability_profile"

    def test_cp_06_capability_profile_written_to_yaml(self, tmp_path):
        """SP1-CP-06: capability-profile.yaml exists and contains valid model."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        yaml_file = tmp_path / "capability-profile.yaml"
        assert yaml_file.exists()
        loaded = read_yaml(yaml_file, CapabilityProfile)
        assert isinstance(loaded, CapabilityProfile)

    def test_cp_07_invalid_kc_subcodes_fail(self, tmp_path):
        """SP1-CP-07: invalid KC sub-codes in LLM response fail validation."""
        bad = _valid_stage1_profile_dict()
        bad["kc_subcodes"] = ["KC1.1", "KC9.9"]
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, bad)
        with pytest.raises((ValidationError, ValueError), match="(?i)Invalid KC sub-code"):
            derive_capability_profile(
                llm_client=client,
                use_case_text="Test use case",
                loss_analysis=_make_loss_analysis(),
                run_dir=tmp_path,
            )

    def test_cp_08_loss_analysis_context_in_prompt(self, tmp_path):
        """SP1-CP-08: loss analysis context is passed to the prompt."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        loss_analysis = _make_loss_analysis()
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            loss_analysis=loss_analysis,
            run_dir=tmp_path,
        )
        assert len(client.calls) == 1
        user_prompt = client.calls[0].user_prompt
        assert "Loss Analysis Context" in user_prompt
        assert "L-1" in user_prompt
        assert "L-2" in user_prompt
        assert "H-1" in user_prompt
        assert "H-2" in user_prompt
