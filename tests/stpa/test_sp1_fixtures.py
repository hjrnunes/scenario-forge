"""SP1 fixture integration tests.

Verifies that the Klarna fixtures can feed into the SP1 pipeline:
  FIX-01: loss_analysis_klarna.yaml feeds Stage 2 and the resulting
          ControlStructure passes structural heuristics.
  FIX-02: control_structure_klarna.yaml runs through the completeness
          critic and produces a valid CriticFindings model.
"""

from __future__ import annotations

from pathlib import Path

from scenario_forge.stpa.infra.yaml_io import read_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model.control_structure import (
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from scenario_forge.stpa.system_model.critic import CriticFindings, run_completeness_critic
from scenario_forge.stpa.system_model.heuristics import run_heuristics
from scenario_forge.models.capability_profile import Stage1Profile
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "scenario_forge"
    / "stpa"
    / "fixtures"
)


def _valid_req_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity",
                "classification": "control",
                "source_constraint": "SC-1",
            }
        ]
    }


def _valid_resp_set_dict() -> dict:
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "responsibility_constraints": [
                    {"rc_id": "SC-1", "description": "Must confirm before action"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-1-1", "description": "Execute action"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Action result",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
            }
        ],
        "controlled_processes": [],
    }


def _valid_cs_dict() -> dict:
    """Mock CS that references SC-1, SC-2, SC-3 for Klarna LA hazard tracing."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Authorization controller",
                "responsibility_constraints": [
                    {"rc_id": "SC-1", "description": "Must confirm before action"},
                    {"rc_id": "SC-2", "description": "Must protect data"},
                    {"rc_id": "SC-3", "description": "Must audit actions"},
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-1-1", "description": "Execute action"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Action result",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
            }
        ],
        "controlled_processes": [],
        "coordination_links": [],
    }


def _valid_critic_findings_dict() -> dict:
    return {
        "gaps": [],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "present",
            "Context management": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop": "absent_justified",
        },
        "taxonomy_probe_results": {},
    }


def _valid_stage1_profile_dict() -> dict:
    return {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [{"name": "tool1", "description": "A tool"}],
    }


class TestSP1FixtureIntegration:
    """SP1-FIX-01 and SP1-FIX-02: fixture integration with the SP1 pipeline."""

    def test_sp1_fixture_01_loss_analysis_feeds_stage2(self, tmp_path):
        """SP1-FIX-01: loss_analysis_klarna.yaml feeds Stage 2 and CS passes heuristics."""
        la_path = FIXTURES_DIR / "loss_analysis_klarna.yaml"
        loss_analysis = read_yaml(la_path, LossAnalysis)
        assert isinstance(loss_analysis, LossAnalysis)

        client = MockLLMClient()
        client.set_response_for(RequirementSet, _valid_req_set_dict())
        client.set_response_for(ResponsibilitySet, _valid_resp_set_dict())
        client.set_response_for(ControlStructure, _valid_cs_dict())

        control_structure = derive_control_structure(
            llm_client=client,
            use_case_text="Klarna payment agent use case",
            loss_analysis=loss_analysis,
            run_dir=tmp_path,
        )
        assert isinstance(control_structure, ControlStructure)

        # Verify the control structure passes structural heuristics
        # when checked with the loss analysis
        result = run_heuristics(control_structure, loss_analysis)
        assert result.errors == [], (
            f"Expected no heuristic errors but got: {result.errors}"
        )

    def test_sp1_fixture_02_control_structure_runs_critic(self, tmp_path):
        """SP1-FIX-02: control_structure_klarna.yaml runs through critic."""
        cs_path = FIXTURES_DIR / "control_structure_klarna.yaml"
        control_structure = read_yaml(cs_path, ControlStructure)
        assert isinstance(control_structure, ControlStructure)

        client = MockLLMClient()
        client.set_response_for(CriticFindings, _valid_critic_findings_dict())

        profile = Stage1Profile(**_valid_stage1_profile_dict()).to_capability_profile()

        findings = run_completeness_critic(
            llm_client=client,
            control_structure=control_structure,
            capability_profile=profile,
            use_case_text="Klarna payment agent use case",
            run_dir=tmp_path,
        )
        assert isinstance(findings, CriticFindings)
        # CriticFindings is valid (either with gaps or confirming completeness)
        assert hasattr(findings, "gaps")
        assert hasattr(findings, "checklist_results")
        assert hasattr(findings, "taxonomy_probe_results")
