"""Tests for SP1 Stage 2 — Control Structure derivation.

Covers SP1-S2-01 through SP1-S2-15 from the Gherkin feature file.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.control_structure import (
    ControlStructure,
    ReferenceType,
)
from scenario_forge.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from scenario_forge.stpa.system_model.control_structure import (
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from tests.stpa.sp1_helpers import MockLLMClient

PROMPTS_DIR = (
    __import__("scenario_forge").stpa.system_model.control_structure.PROMPTS_DIR
)


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss 1",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard 1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="Hazard 2", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="Constraint 1", related_hazards=["H-1"]
            ),
            SecurityConstraint(
                constraint_id="SC-2", description="Constraint 2", related_hazards=["H-2"]
            ),
        ],
    )


def _valid_requirement_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity before executing payments",
                "classification": "control",
                "source_constraint": "SC-1",
            },
            {
                "req_id": "REQ-2",
                "description": "Must not expose raw payment data",
                "classification": "constraint",
                "source_constraint": "SC-2",
            },
        ]
    }


def _valid_responsibility_set_dict() -> dict:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Payment authorization controller",
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must verify user identity"}
                ],
                "process_model_parts": [
                    {
                        "pm_id": "PM-1-1",
                        "description": "User intent and payment request state",
                        "feedback_source": {
                            "type": "controlled_process",
                            "id": "CP-1",
                        },
                    }
                ],
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Execute payment transaction",
                        "target": {"type": "controlled_process", "id": "CP-1"},
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Transaction result",
                        "updates": "PM-1-1",
                        "source": {"type": "controlled_process", "id": "CP-1"},
                    }
                ],
            },
            {
                "resp_id": "RESP-2",
                "description": "Output verification controller",
                "responsibility_constraints": [],
                "process_model_parts": [
                    {"pm_id": "PM-2-1", "description": "Response content state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-2-1", "description": "Send response to user"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-2-1",
                        "description": "Response delivery confirmation",
                        "updates": "PM-2-1",
                        "source": {"type": "responsibility", "id": "RESP-2"},
                    }
                ],
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Payment transaction system"}
        ],
    }


def _valid_control_structure_dict() -> dict:
    rs = _valid_responsibility_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": rs["controlled_processes"],
        "coordination_links": [
            {
                "link_id": "CL-1",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-2-1",
                "coordination_mechanism": {
                    "cm_id": "CM-1",
                    "description": "Shared response state",
                    "payload": "Response content status",
                },
                "description": "Payment controller coordinates with output controller",
            }
        ],
    }


class TestRequirementSet:
    """SP1-S2-01 through SP1-S2-04: RequirementSet model and Call 1."""

    def test_s2_01_valid_requirement_set(self):
        """SP1-S2-01: valid RequirementSet with REQ-1 and REQ-2."""
        rs = RequirementSet.model_validate(_valid_requirement_set_dict())
        assert len(rs.requirements) == 2
        for req in rs.requirements:
            assert req.req_id
            assert req.description
            assert req.classification in ("control", "constraint")
            assert req.source_constraint

    def test_s2_02_requirements_classified(self):
        """SP1-S2-02: REQ-1 is control, REQ-2 is constraint."""
        rs = RequirementSet.model_validate(_valid_requirement_set_dict())
        assert rs.requirements[0].classification == "control"
        assert rs.requirements[1].classification == "constraint"

    @pytest.mark.parametrize("bad_class", ["enforcement", "policy"])
    def test_s2_03_invalid_classification_fails(self, bad_class):
        """SP1-S2-03: invalid classification fails."""
        bad = _valid_requirement_set_dict()
        bad["requirements"][0]["classification"] = bad_class
        with pytest.raises((ValidationError, ValueError), match="classification"):
            RequirementSet.model_validate(bad)

    def test_s2_04_source_constraint_references(self):
        """SP1-S2-04: each requirement references a source constraint."""
        rs = RequirementSet.model_validate(_valid_requirement_set_dict())
        assert rs.requirements[0].source_constraint == "SC-1"
        assert rs.requirements[1].source_constraint == "SC-2"


class TestResponsibilitySet:
    """SP1-S2-06 through SP1-S2-08: ResponsibilitySet model and Call 2."""

    def test_s2_06_valid_responsibility_set(self):
        """SP1-S2-06: valid ResponsibilitySet with RESP-1 and RESP-2."""
        rset = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        assert len(rset.responsibilities) == 2
        for resp in rset.responsibilities:
            assert len(resp.process_model_parts) >= 1
            assert len(resp.control_actions) >= 1
            assert len(resp.feedback_channels) >= 1

    def test_s2_07_controlled_processes_identified(self):
        """SP1-S2-07: controlled process CP-1 is identified."""
        rset = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        cp_ids = {cp.cp_id for cp in rset.controlled_processes}
        assert "CP-1" in cp_ids

    def test_s2_08_element_refs_are_valid(self):
        """SP1-S2-08: ElementRef references point to valid responsibilities or CPs."""
        rset = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        resp_ids = {r.resp_id for r in rset.responsibilities}
        cp_ids = {cp.cp_id for cp in rset.controlled_processes}

        for resp in rset.responsibilities:
            for fb in resp.feedback_channels:
                if fb.source.type == ReferenceType.responsibility:
                    assert fb.source.id in resp_ids
                elif fb.source.type == ReferenceType.controlled_process:
                    assert fb.source.id in cp_ids
            for ca in resp.control_actions:
                if ca.target is not None:
                    if ca.target.type == ReferenceType.responsibility:
                        assert ca.target.id in resp_ids
                    elif ca.target.type == ReferenceType.controlled_process:
                        assert ca.target.id in cp_ids


class TestStage2CallLogging:
    """SP1-S2-05, S2-09, S2-12: call logging for each Stage 2 call."""

    def test_s2_05_call_1_logged(self, tmp_path):
        """SP1-S2-05: Call 1 logged with stage stage_2 and step call_1_requirements."""
        client = MockLLMClient()
        client.set_response_for(LossAnalysis, {
            "risk_card_losses": [],
            "use_case_losses": [{"loss_id": "L-1", "description": "L", "provenance": "use_case", "source_risk_cards": []}],
            "hazards": [{"hazard_id": "H-1", "description": "H", "related_losses": ["L-1"]}],
            "security_constraints": [{"constraint_id": "SC-1", "description": "C", "related_hazards": ["H-1"]}],
        })
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        call1 = [e for e in entries if e["step"] == "call_1_requirements"]
        assert len(call1) == 1
        assert call1[0]["stage"] == "stage_2"

    def test_s2_09_call_2_logged(self, tmp_path):
        """SP1-S2-09: Call 2 logged with stage stage_2 and step call_2_responsibilities."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        call2 = [e for e in entries if e["step"] == "call_2_responsibilities"]
        assert len(call2) == 1
        assert call2[0]["stage"] == "stage_2"

    def test_s2_12_call_3_logged(self, tmp_path):
        """SP1-S2-12: Call 3 logged with stage stage_2 and step call_3_connections."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        call3 = [e for e in entries if e["step"] == "call_3_connections"]
        assert len(call3) == 1
        assert call3[0]["stage"] == "stage_2"


class TestStage2Derivation:
    """SP1-S2-10, S2-11, S2-13: Call 3 output and file writing."""

    def test_s2_10_call_3_produces_valid_control_structure(self, tmp_path):
        """SP1-S2-10: Call 3 produces a valid ControlStructure."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        cs = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert isinstance(cs, ControlStructure)
        assert len(cs.responsibilities) == 2

    def test_s2_11_coordination_links_identified(self, tmp_path):
        """SP1-S2-11: coordination links are identified in Call 3."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        cs = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert len(cs.coordination_links) == 1
        cl = cs.coordination_links[0]
        assert cl.link_id == "CL-1"
        assert cl.source == "RESP-1"
        assert cl.target == "RESP-2"

    def test_s2_13_control_structure_written_to_yaml(self, tmp_path):
        """SP1-S2-13: control-structure.yaml exists and contains valid model."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        yaml_file = tmp_path / "control-structure.yaml"
        assert yaml_file.exists()
        loaded = read_yaml(yaml_file, ControlStructure)
        assert isinstance(loaded, ControlStructure)


class TestStage2PromptPassing:
    """SP1-S2-14, S2-15: prompts receive data from previous calls."""

    def test_s2_14_call_2_receives_requirements_from_call_1(self, tmp_path):
        """SP1-S2-14: Call 2 user prompt contains requirements from Call 1."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # Call 2 is the second call
        call2 = client.calls[1]
        assert "REQ-1" in call2.user_prompt
        assert "REQ-2" in call2.user_prompt

    def test_s2_15_call_3_receives_responsibilities_from_call_2(self, tmp_path):
        """SP1-S2-15: Call 3 user prompt contains responsibilities and CPs from Call 2."""
        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_requirement_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
        client.set_response_for(ControlStructure, _valid_control_structure_dict())

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # Call 3 is the third call
        call3 = client.calls[2]
        assert "RESP-1" in call3.user_prompt
        assert "RESP-2" in call3.user_prompt
        assert "CP-1" in call3.user_prompt
