"""Tests for SP1 run orchestration.

Covers SP1-RUN-01 through SP1-RUN-14 from the Gherkin feature file.
"""

from __future__ import annotations

import json


from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
)
from scenario_forge.models.risk_card import RiskCard
from scenario_forge.stpa.infra.yaml_io import write_yaml
from scenario_forge.stpa.models.control_structure import ControlStructure
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model.critic import CriticFindings
from scenario_forge.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import MockLLMClient


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


def _valid_loss_analysis_dict() -> dict:
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Unauthorized transaction",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [
            {
                "loss_id": "L-2",
                "description": "Loss of trust",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Agent executes unintended action",
                "related_losses": ["L-1", "L-2"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "description": "Must confirm before action",
                "related_hazards": ["H-1"],
            }
        ],
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


def _valid_requirement_set_dict() -> dict:
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


def _valid_responsibility_set_dict() -> dict:
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


def _valid_control_structure_dict() -> dict:
    rs = _valid_responsibility_set_dict()
    return {
        "responsibilities": rs["responsibilities"],
        "controlled_processes": [],
        "coordination_links": [],
    }


def _valid_critic_findings_dict() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            },
            {
                "gap_type": "missing_feedback",
                "description": "Missing outcome feedback",
                "related_attack_path": "Attacker exploits unchecked output",
                "suggested_remedy": "Add outcome verification",
            },
        ],
        "checklist_results": {
            "Input validation": "present",
            "Authorization": "present",
            "Action selection": "present",
            "Outcome verification": "absent_justified",
            "Context management": "present",
            "Multi-agent coordination": "absent_justified",
            "Human-in-the-loop": "absent_justified",
        },
        "taxonomy_probe_results": {},
    }


def _setup_mock_client(
    critic_findings: dict | None = None,
    revised_cs: dict | None = None,
) -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all stages."""
    client = MockLLMClient()

    # Stage 1a: LossAnalysis
    client.set_response_for(LossAnalysis, _valid_loss_analysis_dict())

    # Stage 1b: Stage1Profile
    from scenario_forge.models.capability_profile import Stage1Profile as S1P

    client.set_response_for(S1P, _valid_stage1_profile_dict())

    # Stage 2 Call 1: RequirementSet
    from scenario_forge.stpa.system_model.control_structure import (
        RequirementSet,
        ResponsibilitySet,
    )

    client.set_response_for(RequirementSet, _valid_requirement_set_dict())

    # Stage 2 Call 2: ResponsibilitySet
    client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())

    # Stage 2 Call 3: ControlStructure
    client.set_response_for(ControlStructure, _valid_control_structure_dict())

    # Critic: CriticFindings
    if critic_findings is not None:
        client.set_response_for(CriticFindings, critic_findings)
    else:
        # No unjustified gaps → no revision
        no_gap = _valid_critic_findings_dict()
        no_gap["gaps"] = []
        no_gap["checklist_results"] = {
            k: "present" if "absent_unjustified" not in v else "present"
            for k, v in _valid_critic_findings_dict()["checklist_results"].items()
        }
        client.set_response_for(CriticFindings, no_gap)

    # Revision: ControlStructure (if needed)
    if revised_cs is not None:
        # Need to use a queue for the second ControlStructure response
        # The first CS response is for Call 3, the second for revision
        client.set_response_queue([
            _valid_control_structure_dict(),  # Call 3
            revised_cs,  # Revision
        ])
        # Clear the response_map for ControlStructure so the queue is used
        client._response_map.pop(ControlStructure, None)

    return client


class TestRunOrchestration:
    """SP1-RUN-01 through SP1-RUN-14."""

    def test_run_01_full_run_produces_all_artifacts(self, tmp_path):
        """SP1-RUN-01: full run produces all three output artifacts."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert (tmp_path / "loss-analysis.yaml").exists()
        assert (tmp_path / "capability-profile.yaml").exists()
        assert (tmp_path / "control-structure.yaml").exists()

    def test_run_02_stages_execute_in_order(self, tmp_path):
        """SP1-RUN-02: stages execute in order 1a then 1b then 2."""
        client = _setup_mock_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        assert isinstance(result.loss_analysis, LossAnalysis)
        assert isinstance(result.capability_profile, CapabilityProfile)
        assert isinstance(result.control_structure, ControlStructure)
        # Verify call order by checking call log stages
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stages = [e["stage"] for e in entries]
        assert "stage_1a" in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages
        # Stage 1a should come before stage_1b
        assert stages.index("stage_1a") < stages.index("stage_1b")
        # Stage 1b should come before stage_2
        assert stages.index("stage_1b") < stages.index("stage_2")

    def test_run_03_all_calls_logged(self, tmp_path):
        """SP1-RUN-03: all LLM calls logged to calls.jsonl."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stages = {e["stage"] for e in entries}
        assert "stage_1a" in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages

    def test_run_04_run_manifest_written(self, tmp_path):
        """SP1-RUN-04: run manifest is written with stage_summary."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        assert manifest_file.exists()
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "stage_summary" in manifest
        assert "stage_1a" in manifest["stage_summary"]
        assert "stage_2" in manifest["stage_summary"]

    def test_run_05_manifest_records_critic_findings(self, tmp_path):
        """SP1-RUN-05: run manifest records critic findings count."""
        client = _setup_mock_client(critic_findings=_valid_critic_findings_dict())
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "critic_findings" in manifest
        assert len(manifest["critic_findings"]) == 2

    def test_run_06_manifest_records_input_hashes(self, tmp_path):
        """SP1-RUN-06: run manifest records input hashes."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "input_hashes" in manifest
        assert "use_case_text" in manifest["input_hashes"]
        assert "risk_extraction" in manifest["input_hashes"]

    def test_run_07_manifest_records_prompt_hashes(self, tmp_path):
        """SP1-RUN-07: run manifest records prompt hashes."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest_file = tmp_path / "run-manifest.yaml"
        import yaml

        manifest = yaml.safe_load(manifest_file.read_text())
        assert "prompt_hashes" in manifest
        assert "stage1a_system.j2" in manifest["prompt_hashes"]
        assert "critic_system.j2" in manifest["prompt_hashes"]

    def test_run_08_stage_2_receives_loss_analysis_and_profile(self, tmp_path):
        """SP1-RUN-08: Stage 2 Call 1 receives security constraints from loss analysis."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        # Find the call_1_requirements call (Stage 2 Call 1)
        call1 = None
        for call in client.calls:
            if "SC-1" in call.user_prompt:
                call1 = call
                break
        assert call1 is not None
        assert "SC-1" in call1.user_prompt

    def test_run_09_prompt_templates_exist(self):
        """SP1-RUN-09: all 14 prompt template files exist."""
        from scenario_forge.stpa.system_model.control_structure import PROMPTS_DIR

        expected = [
            "stage1a_system.j2", "stage1a_user.j2",
            "stage1b_system.j2", "stage1b_user.j2",
            "stage2_call1_system.j2", "stage2_call1_user.j2",
            "stage2_call2_system.j2", "stage2_call2_user.j2",
            "stage2_call3_system.j2", "stage2_call3_user.j2",
            "critic_system.j2", "critic_user.j2",
            "revision_system.j2", "revision_user.j2",
        ]
        for name in expected:
            assert (PROMPTS_DIR / name).exists(), f"Missing template: {name}"

    def test_run_10_module_layout(self):
        """SP1-RUN-10: all modules exist and are importable."""
        from scenario_forge.stpa.system_model import (
            loss_analysis,
            profile,
            control_structure,
            critic,
            heuristics,
            run,
        )
        assert loss_analysis is not None
        assert profile is not None
        assert control_structure is not None
        assert critic is not None
        assert heuristics is not None
        assert run is not None

    def test_run_11_internal_models_defined(self):
        """SP1-RUN-11: internal models are defined."""
        from scenario_forge.stpa.system_model import (
            RequirementSet,
            Requirement,
            ResponsibilitySet,
            CriticFindings,
            CriticGap,
        )
        assert RequirementSet is not None
        assert Requirement is not None
        assert ResponsibilitySet is not None
        assert CriticFindings is not None
        assert CriticGap is not None

    def test_run_12_profile_flag_skips_stage_1b(self, tmp_path):
        """SP1-RUN-12: run with profile flag skips Stage 1b LLM call."""
        # Write a pre-built profile
        profile = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=[
                {"name": "User chat", "direction": "input", "controllability": "direct"},
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC5.1", "KC6.1.1"],
            tool_inventory=[{"name": "tool1", "description": "A tool"}],
        ).to_capability_profile()
        profile_path = tmp_path / "capability-profile.yaml"
        write_yaml(profile, profile_path)

        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
            profile_path=profile_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stage_1b_entries = [e for e in entries if e["stage"] == "stage_1b"]
        assert len(stage_1b_entries) == 0

    def test_run_13_temperature_is_0_4(self, tmp_path):
        """SP1-RUN-13: all Stage 2 LLM calls use temperature 0.4."""
        client = _setup_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_make_risk_cards(),
            run_dir=tmp_path,
        )
        # All calls should have temperature 0.4
        for call in client.calls:
            assert call.temperature == 0.4

    def test_run_14_existing_tests_unaffected(self):
        """SP1-RUN-14: existing pipeline tests are unaffected (module imports work)."""
        # Just verify the import doesn't break anything
        from scenario_forge.stpa.system_model import run_sp1 as _run

        assert _run is not None
