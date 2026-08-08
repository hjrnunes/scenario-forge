"""Tests for SP1 Stage 1a — Loss Analysis derivation.

Covers SP1-LA-01 through SP1-LA-12 from the Gherkin feature file.
"""

from __future__ import annotations


import pytest
from pydantic import ValidationError

from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.models.loss_analysis import (
    LossAnalysis,
    LossProvenance,
)
from scenario_forge.stpa.system_model.loss_analysis import derive_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient


def _valid_loss_analysis_dict() -> dict:
    """Build a valid LossAnalysis dict for LLM mock responses."""
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized financial transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            },
            {
                "loss_id": "L-2",
                "description": "Data exposure",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-002"],
            },
        ],
        "use_case_losses": [
            {
                "loss_id": "L-3",
                "description": "Loss of customer trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            },
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended payment",
                "related_losses": ["L-1", "L-3"],
            },
            {
                "hazard_id": "H-2",
                "description": "Agent exposes data",
                "related_losses": ["L-2"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "description": "Must confirm before payment",
                "related_hazards": ["H-1"],
            },
            {
                "constraint_id": "SC-2",
                "description": "Must not expose data",
                "related_hazards": ["H-2"],
            },
        ],
    }


def _make_risk_cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="Prompt injection",
            risk_description="Risk of prompt injection",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]


class TestStage1aLossAnalysis:
    """SP1 Stage 1a loss analysis derivation."""

    def test_la_01_valid_response_produces_valid_loss_analysis(self, tmp_path):
        """SP1-LA-01: valid LLM response produces a valid LossAnalysis."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result, LossAnalysis)
        # Passes foundation validation (no exception raised by construction)
        assert len(result.risk_card_losses) == 2
        assert len(result.use_case_losses) == 1

    def test_la_02_risk_card_losses_have_correct_provenance(self, tmp_path):
        """SP1-LA-02: risk-card-derived losses have correct provenance."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        for loss in result.risk_card_losses:
            assert loss.provenance == LossProvenance.risk_card
            assert len(loss.source_risk_cards) > 0

    def test_la_03_use_case_losses_have_correct_provenance(self, tmp_path):
        """SP1-LA-03: use-case-derived losses have correct provenance."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        for loss in result.use_case_losses:
            assert loss.provenance == LossProvenance.use_case
            assert len(loss.source_risk_cards) == 0

    def test_la_04_invalid_hazard_reference_fails(self, tmp_path):
        """SP1-LA-04: hazard referencing non-existent loss fails."""
        bad = _valid_loss_analysis_dict()
        bad["hazards"][0]["related_losses"] = ["L-99"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, bad)
        with pytest.raises((ValidationError, ValueError), match="related_losses"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_04b_invalid_constraint_reference_fails(self, tmp_path):
        """SP1-LA-04: constraint referencing non-existent hazard fails."""
        bad = _valid_loss_analysis_dict()
        bad["security_constraints"][0]["related_hazards"] = ["H-99"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, bad)
        with pytest.raises((ValidationError, ValueError), match="related_hazards"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_05_risk_card_loss_missing_source_fails(self, tmp_path):
        """SP1-LA-05: risk-card loss with empty source_risk_cards fails."""
        bad = _valid_loss_analysis_dict()
        bad["risk_card_losses"][0]["source_risk_cards"] = []
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, bad)
        with pytest.raises((ValidationError, ValueError), match="source_risk_cards"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_06_use_case_loss_with_source_fails(self, tmp_path):
        """SP1-LA-06: use-case loss having source_risk_cards fails."""
        bad = _valid_loss_analysis_dict()
        bad["use_case_losses"][0]["source_risk_cards"] = ["atlas-001"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, bad)
        with pytest.raises((ValidationError, ValueError), match="source_risk_cards"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_07_duplicate_loss_ids_fails(self, tmp_path):
        """SP1-LA-07: duplicate loss IDs fail."""
        bad = _valid_loss_analysis_dict()
        bad["risk_card_losses"][1]["loss_id"] = "L-1"
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, bad)
        with pytest.raises((ValidationError, ValueError), match="(?i)duplicate"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_make_risk_cards(),
                run_dir=tmp_path,
            )

    def test_la_08_call_logged_with_stage_1a(self, tmp_path):
        """SP1-LA-08: call log entry has stage stage_1a and step loss_analysis."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        import json as _json

        entries = [_json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_1a"
        assert entries[0]["step"] == "loss_analysis"

    def test_la_09_loss_analysis_written_to_yaml(self, tmp_path):
        """SP1-LA-09: loss-analysis.yaml exists and contains valid model."""
        from scenario_forge.stpa.infra.yaml_io import read_yaml

        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        yaml_file = tmp_path / "loss-analysis.yaml"
        assert yaml_file.exists()
        loaded = read_yaml(yaml_file, LossAnalysis)
        assert isinstance(loaded, LossAnalysis)
        assert len(loaded.risk_card_losses) == 2

    def test_la_10_both_loss_types_coexist(self, tmp_path):
        """SP1-LA-10: both risk-card and use-case losses can coexist."""
        client = MockLLMClient()
        data = _valid_loss_analysis_dict()
        data["use_case_losses"].append(
            {
                "loss_id": "L-4",
                "description": "Regulatory non-compliance",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        )
        client.set_response_for(LossAnalysis, data)
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert len(result.risk_card_losses) == 2
        assert len(result.use_case_losses) == 2
        loss_ids = {loss.loss_id for loss in result.risk_card_losses + result.use_case_losses}
        assert {"L-1", "L-2", "L-3", "L-4"} == loss_ids

    def test_la_11_every_hazard_links_to_loss(self, tmp_path):
        """SP1-LA-11: every hazard links to at least one loss."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        all_loss_ids = {loss.loss_id for loss in result.risk_card_losses + result.use_case_losses}
        for hazard in result.hazards:
            assert len(hazard.related_losses) >= 1
            for ref in hazard.related_losses:
                assert ref in all_loss_ids

    def test_la_12_every_constraint_links_to_hazard(self, tmp_path):
        """SP1-LA-12: every security constraint links to at least one hazard."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())
        result = derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        all_hazard_ids = {h.hazard_id for h in result.hazards}
        for sc in result.security_constraints:
            assert len(sc.related_hazards) >= 1
            for ref in sc.related_hazards:
                assert ref in all_hazard_ids
