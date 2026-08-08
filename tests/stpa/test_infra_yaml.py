"""Tests for STPA infra YAML I/O (InfraYAML-01 through InfraYAML-04)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml
from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from scenario_forge.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def _minimal_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss of user data",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def _minimal_control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Process state"),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            )
        ],
    )


class TestInfraYAML:
    """YAML read/write helpers."""

    def test_yaml_01_write_yaml_serializes_model(self, tmp_path):
        """InfraYAML-01: write_yaml produces a YAML file with model data."""
        model = _minimal_loss_analysis()
        path = tmp_path / "loss_analysis.yaml"
        write_yaml(model, path)
        assert path.exists()
        text = path.read_text()
        assert "L-1" in text

    def test_yaml_02_read_yaml_loads_into_model(self, tmp_path):
        """InfraYAML-02: read_yaml loads YAML into a Pydantic model."""
        model = _minimal_loss_analysis()
        path = tmp_path / "loss_analysis.yaml"
        write_yaml(model, path)
        loaded = read_yaml(path, LossAnalysis)
        assert isinstance(loaded, LossAnalysis)
        all_losses = loaded.risk_card_losses + loaded.use_case_losses
        assert all_losses[0].loss_id == "L-1"

    def test_yaml_03_round_trip_preserves_data(self, tmp_path):
        """InfraYAML-03: YAML round-trip preserves model data."""
        original = _minimal_control_structure()
        path = tmp_path / "control_structure.yaml"
        write_yaml(original, path)
        loaded = read_yaml(path, ControlStructure)
        assert loaded.responsibilities[0].resp_id == "RESP-1"
        assert loaded.responsibilities[0].process_model_parts[0].pm_id == "PM-1-1"

    def test_yaml_04_read_yaml_on_invalid_data_raises(self, tmp_path):
        """InfraYAML-04: read_yaml on invalid data raises validation error."""
        invalid_yaml = """
risk_card_losses: []
use_case_losses:
  - loss_id: L-1
    description: Loss
    provenance: use_case
hazards:
  - hazard_id: H-1
    description: Hazard
    related_losses: ["L-99"]
security_constraints: []
"""
        path = tmp_path / "invalid.yaml"
        path.write_text(invalid_yaml)
        with pytest.raises(ValidationError):
            read_yaml(path, LossAnalysis)
