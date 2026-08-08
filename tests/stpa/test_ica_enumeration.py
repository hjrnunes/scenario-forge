"""Tests for ICAEnumeration boundary schema validation.

Covers ICAEnumeration-01 through ICAEnumeration-10 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from scenario_forge.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from scenario_forge.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def _make_control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
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


def _make_ica(
    ica_id: str = "RESP-1:CA-1-1:NOT_PROVIDED:1",
    related_hazards: list[str] | None = None,
    related_constraints: list[str] | None = None,
) -> ICA:
    return ICA(
        ica_id=ica_id,
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Scenario",
        related_hazards=related_hazards or ["H-1"],
        related_constraints=related_constraints or ["SC-1"],
    )


def _make_slot(
    slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    is_na: bool = False,
    icas: list[ICA] | None = None,
    na_justification: str | None = None,
    uca_type: UCAType = UCAType.not_provided,
) -> ICASlot:
    return ICASlot(
        slot_id=slot_id,
        responsibility="RESP-1",
        coordination_link=None,
        control_action="CA-1-1",
        uca_type=uca_type,
        is_na=is_na,
        icas=icas if icas is not None else ([] if is_na else [_make_ica()]),
        na_justification=na_justification,
    )


class TestICAEnumerationValidation:
    """ICAEnumeration boundary schema validation rules."""

    def test_ica_01_valid_slot_with_ica_passes(self):
        """ICA-01: valid slot with ICA passes validation."""
        la = _make_loss_analysis()
        cs = _make_control_structure()
        enum = ICAEnumeration(slots=[_make_slot(is_na=False)])
        enum.validate_against(la, cs)

    def test_ica_02_valid_na_slot_passes(self):
        """ICA-02: valid N/A slot passes validation."""
        la = _make_loss_analysis()
        cs = _make_control_structure()
        enum = ICAEnumeration(
            slots=[
                _make_slot(
                    is_na=True,
                    icas=[],
                    na_justification="no hazardous context",
                )
            ]
        )
        enum.validate_against(la, cs)

    def test_ica_03_na_slot_without_justification_fails(self):
        """ICA-03: N/A slot without na_justification fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[],
                na_justification=None,
            )
        assert "na_justification" in str(exc_info.value)

    def test_ica_04_na_slot_with_icas_fails(self):
        """ICA-04: N/A slot with ICAs fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[_make_ica()],
                na_justification="none",
            )
        assert "icas" in str(exc_info.value)

    def test_ica_05_non_na_slot_with_empty_icas_fails(self):
        """ICA-05: non-N/A slot with empty ICAs fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[],
            )
        assert "icas" in str(exc_info.value)

    def test_ica_06_non_na_slot_with_justification_fails(self):
        """ICA-06: non-N/A slot with na_justification fails."""
        with pytest.raises(ValidationError) as exc_info:
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[_make_ica()],
                na_justification="should not be here",
            )
        assert "na_justification" in str(exc_info.value)

    def test_ica_07_ica_referencing_nonexistent_hazard_fails(self):
        """ICA-07: ICA referencing non-existent hazard fails."""
        la = _make_loss_analysis()
        cs = _make_control_structure()
        enum = ICAEnumeration(
            slots=[
                _make_slot(
                    icas=[_make_ica(related_hazards=["H-99"])],
                )
            ]
        )
        with pytest.raises(ValueError, match="related_hazards"):
            enum.validate_against(la, cs)

    def test_ica_08_ica_referencing_nonexistent_constraint_fails(self):
        """ICA-08: ICA referencing non-existent constraint fails."""
        la = _make_loss_analysis()
        cs = _make_control_structure()
        enum = ICAEnumeration(
            slots=[
                _make_slot(
                    icas=[_make_ica(related_constraints=["SC-99"])],
                )
            ]
        )
        with pytest.raises(ValueError, match="related_constraints"):
            enum.validate_against(la, cs)

    def test_ica_09_duplicate_slot_ids_fail(self):
        """ICA-09: duplicate slot IDs fail."""
        with pytest.raises(ValidationError) as exc_info:
            ICAEnumeration(
                slots=[
                    _make_slot(slot_id="RESP-1:CA-1-1:NOT_PROVIDED"),
                    _make_slot(slot_id="RESP-1:CA-1-1:NOT_PROVIDED"),
                ]
            )
        assert "duplicate" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "uca_type",
        [
            UCAType.not_provided,
            UCAType.incorrect,
            UCAType.wrong_timing,
            UCAType.wrong_duration,
        ],
    )
    def test_ica_10_all_uca_types_accepted(self, uca_type):
        """ICA-10: all UCA types are accepted."""
        la = _make_loss_analysis()
        cs = _make_control_structure()
        slot = _make_slot(uca_type=uca_type)
        enum = ICAEnumeration(slots=[slot])
        enum.validate_against(la, cs)
