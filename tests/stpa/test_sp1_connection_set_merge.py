"""Unit tests for SP1 Stage 2 Call 3 ConnectionSet merge.

Covers ConnSet-01 through ConnSet-11 from the Gherkin feature file:
  tests/stpa/features/sp1_connection_set_merge.feature
"""

from __future__ import annotations

import json

import pytest

from scenario_forge.stpa.infra.yaml_io import read_yaml
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
from scenario_forge.stpa.system_model.control_structure import (
    ConnectionAssignment,
    ConnectionSet,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
    merge_connection_set,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="C", related_hazards=["H-1"]
            ),
            SecurityConstraint(
                constraint_id="SC-2", description="C2", related_hazards=["H-1"]
            ),
        ],
    )


def _valid_requirement_set_dict() -> dict:
    return {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Verify user identity",
                "classification": "control",
                "source_constraint": "SC-1",
            },
            {
                "req_id": "REQ-2",
                "description": "Must not expose data",
                "classification": "constraint",
                "source_constraint": "SC-2",
            },
        ]
    }


def _valid_responsibility_set_dict() -> dict:
    """ResponsibilitySet where FB-1-1 has no source and CA-1-1 has no target."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Payment authorization controller",
                "responsibility_constraints": [
                    {"rc_id": "RC-1-1", "description": "Must verify user identity"}
                ],
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "User intent state"}
                ],
                "control_actions": [
                    {"ca_id": "CA-1-1", "description": "Execute payment"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "Transaction result",
                        "updates": "PM-1-1",
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
                    {"ca_id": "CA-2-1", "description": "Send response"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-2-1",
                        "description": "Response confirmation",
                        "updates": "PM-2-1",
                        "source": {"type": "responsibility", "id": "RESP-2"},
                    }
                ],
            },
        ],
        "controlled_processes": [],
    }


def _valid_connection_set_dict() -> dict:
    """ConnectionSet with coordination links, controlled processes, and assignments."""
    return {
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
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Payment transaction system"}
        ],
        "connection_assignments": [
            {
                "element_id": "FB-1-1",
                "source": {"type": "controlled_process", "id": "CP-1"},
            },
            {
                "element_id": "CA-1-1",
                "target": {"type": "controlled_process", "id": "CP-1"},
            },
        ],
    }


def _setup_mock_client() -> MockLLMClient:
    """Set up a mock LLM client with valid responses for all three Stage 2 calls."""
    client = MockLLMClient()
    client.set_response_for(RequirementSet, _valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, _valid_responsibility_set_dict())
    client.set_response_for(ConnectionSet, _valid_connection_set_dict())
    return client


# ---------------------------------------------------------------------------
# ConnSet-01: Call 3 produces a ConnectionSet
# ---------------------------------------------------------------------------


class TestConnSet01Call3ProducesConnectionSet:
    """ConnSet-01: Call 3 produces a ConnectionSet (not ControlStructure)."""

    def test_connset_01_call_3_response_format_is_connection_set(self, tmp_path):
        """Call 3 uses ConnectionSet as the response format."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # The third call (Call 3) should have response_format=ConnectionSet
        call3 = client.calls[2]
        assert call3.response_format is ConnectionSet


# ---------------------------------------------------------------------------
# ConnSet-02: ConnectionSet contains the expected outputs
# ---------------------------------------------------------------------------


class TestConnSet02ConnectionSetContents:
    """ConnSet-02: ConnectionSet contains coordination links, CPs, and assignments."""

    def test_connset_02_contains_coordination_links_cps_and_assignments(self, tmp_path):
        """ConnectionSet has CL-1, CP-1, and assignment for FB-1-1."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        # Parse the Call 3 response to verify it's a valid ConnectionSet
        # The merge produces the final ControlStructure — verify via the output
        cs = read_yaml(tmp_path / "control-structure.yaml", ControlStructure)
        # Coordination link CL-1 present
        cl_ids = {cl.link_id for cl in cs.coordination_links}
        assert "CL-1" in cl_ids
        # Controlled process CP-1 present
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-1" in cp_ids
        # FB-1-1 has source set (from connection assignment)
        for resp in cs.responsibilities:
            for fb in resp.feedback_channels:
                if fb.fb_id == "FB-1-1":
                    assert fb.source is not None
                    assert fb.source.id == "CP-1"


# ---------------------------------------------------------------------------
# ConnSet-03: merge produces a valid ControlStructure
# ---------------------------------------------------------------------------


class TestConnSet03MergeProducesValidControlStructure:
    """ConnSet-03: merge produces a valid ControlStructure."""

    def test_connset_03_merge_produces_valid_control_structure(self, tmp_path):
        """Full Stage 2 derivation produces a valid ControlStructure."""
        client = _setup_mock_client()
        cs = derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert isinstance(cs, ControlStructure)
        # Foundation validation passes (no exception raised by construction)
        assert len(cs.responsibilities) == 2


# ---------------------------------------------------------------------------
# ConnSet-04: connection assignment updates feedback source by element ID
# ---------------------------------------------------------------------------


class TestConnSet04FeedbackSourceUpdate:
    """ConnSet-04: connection assignment updates feedback source by element ID."""

    def test_connset_04_feedback_source_set_by_assignment(self):
        """Merge sets FB-1-1 source to CP-1 via connection assignment."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet.model_validate(_valid_connection_set_dict())
        cs = merge_connection_set(resp_set, conn_set)

        for resp in cs.responsibilities:
            for fb in resp.feedback_channels:
                if fb.fb_id == "FB-1-1":
                    assert fb.source is not None
                    assert fb.source.type == ReferenceType.controlled_process
                    assert fb.source.id == "CP-1"
                    return
        pytest.fail("FB-1-1 not found in any responsibility")


# ---------------------------------------------------------------------------
# ConnSet-05: connection assignment updates control action target by element ID
# ---------------------------------------------------------------------------


class TestConnSet05ControlActionTargetUpdate:
    """ConnSet-05: connection assignment updates control action target by element ID."""

    def test_connset_05_ca_target_set_by_assignment(self):
        """Merge sets CA-1-1 target to CP-1 via connection assignment."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet.model_validate(_valid_connection_set_dict())
        cs = merge_connection_set(resp_set, conn_set)

        for resp in cs.responsibilities:
            for ca in resp.control_actions:
                if ca.ca_id == "CA-1-1":
                    assert ca.target is not None
                    assert ca.target.type == ReferenceType.controlled_process
                    assert ca.target.id == "CP-1"
                    return
        pytest.fail("CA-1-1 not found in any responsibility")


# ---------------------------------------------------------------------------
# ConnSet-06: coordination links appear in the final ControlStructure
# ---------------------------------------------------------------------------


class TestConnSet06CoordinationLinksInFinalCS:
    """ConnSet-06: coordination links appear in the final ControlStructure."""

    def test_connset_06_coordination_link_present(self):
        """Merge includes coordination link CL-1 from ConnectionSet."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet.model_validate(_valid_connection_set_dict())
        cs = merge_connection_set(resp_set, conn_set)

        assert len(cs.coordination_links) == 1
        cl = cs.coordination_links[0]
        assert cl.link_id == "CL-1"
        assert cl.source == "RESP-1"
        assert cl.target == "RESP-2"


# ---------------------------------------------------------------------------
# ConnSet-07: controlled processes appear in the final ControlStructure
# ---------------------------------------------------------------------------


class TestConnSet07ControlledProcessesInFinalCS:
    """ConnSet-07: controlled processes appear in the final ControlStructure."""

    def test_connset_07_controlled_process_present(self):
        """Merge includes controlled process CP-1 from ConnectionSet."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet.model_validate(_valid_connection_set_dict())
        cs = merge_connection_set(resp_set, conn_set)

        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        assert "CP-1" in cp_ids


# ---------------------------------------------------------------------------
# ConnSet-07a: merge with unmatched and None assignments is a no-op
# ---------------------------------------------------------------------------


class TestConnSet07aMergeEdgeCases:
    """Edge cases: assignments with None source/target or unmatched element IDs."""

    def test_merge_ignores_assignment_with_none_source_and_target(self):
        """Assignment with both source and target None is a no-op."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet(
            connection_assignments=[
                ConnectionAssignment(element_id="FB-1-1"),  # no source, no target
            ],
        )
        cs = merge_connection_set(resp_set, conn_set)
        # FB-1-1 source should remain None (not set)
        for resp in cs.responsibilities:
            for fb in resp.feedback_channels:
                if fb.fb_id == "FB-1-1":
                    assert fb.source is None

    def test_merge_ignores_assignment_with_unmatched_element_id(self):
        """Assignment whose element_id matches no FB or CA is silently ignored."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet(
            connection_assignments=[
                ConnectionAssignment(
                    element_id="FB-9-9",
                    source={"type": "controlled_process", "id": "CP-1"},
                ),
            ],
        )
        cs = merge_connection_set(resp_set, conn_set)
        # No feedback channel should have a source set from this unmatched assignment
        for resp in cs.responsibilities:
            for fb in resp.feedback_channels:
                if fb.fb_id == "FB-1-1":
                    assert fb.source is None

    def test_merge_assignment_source_only_does_not_set_ca_target(self):
        """Assignment with source but no target sets FB source but not CA target."""
        resp_set = ResponsibilitySet.model_validate(_valid_responsibility_set_dict())
        conn_set = ConnectionSet(
            controlled_processes=[
                {"cp_id": "CP-1", "description": "Payment system"},
            ],
            connection_assignments=[
                ConnectionAssignment(
                    element_id="FB-1-1",
                    source={"type": "controlled_process", "id": "CP-1"},
                ),
            ],
        )
        cs = merge_connection_set(resp_set, conn_set)
        for resp in cs.responsibilities:
            for fb in resp.feedback_channels:
                if fb.fb_id == "FB-1-1":
                    assert fb.source is not None
                    assert fb.source.id == "CP-1"
            for ca in resp.control_actions:
                if ca.ca_id == "CA-1-1":
                    assert ca.target is None


# ---------------------------------------------------------------------------
# ConnSet-08: Call 3 is logged with correct stage and step
# ---------------------------------------------------------------------------


class TestConnSet08Call3Logging:
    """ConnSet-08: Call 3 logged with stage stage_2 and step call_3_connections."""

    def test_connset_08_call_3_logged(self, tmp_path):
        """Call 3 is logged with stage=stage_2 and step=call_3_connections."""
        client = _setup_mock_client()
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


# ---------------------------------------------------------------------------
# ConnSet-09: control structure is written to control-structure.yaml
# ---------------------------------------------------------------------------


class TestConnSet09ControlStructureWrittenToYaml:
    """ConnSet-09: control-structure.yaml exists and contains valid model."""

    def test_connset_09_yaml_written_and_valid(self, tmp_path):
        """control-structure.yaml is written and contains a valid ControlStructure."""
        client = _setup_mock_client()
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
        assert len(loaded.responsibilities) == 2


# ---------------------------------------------------------------------------
# ConnSet-10: Call 3 user prompt contains responsibilities from Call 2
# ---------------------------------------------------------------------------


class TestConnSet10Call3PromptContainsResponsibilities:
    """ConnSet-10: Call 3 user prompt contains responsibilities and CPs from Call 2."""

    def test_connset_10_call_3_prompt_has_resp_data(self, tmp_path):
        """Call 3 user prompt contains RESP-1, RESP-2 from Call 2."""
        client = _setup_mock_client()
        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        call3 = client.calls[2]
        assert "RESP-1" in call3.user_prompt
        assert "RESP-2" in call3.user_prompt


# ---------------------------------------------------------------------------
# ConnSet-11: revision still uses ControlStructure as response format
# ---------------------------------------------------------------------------


class TestConnSet11RevisionUsesControlStructure:
    """ConnSet-11: revision still uses ControlStructure as response format."""

    def test_connset_11_revision_uses_control_structure(self, tmp_path):
        """run_revision uses response_format=ControlStructure, not ConnectionSet."""
        client = MockLLMClient()
        revised_cs_dict = {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Controller 1",
                    "process_model_parts": [
                        {"pm_id": "PM-1-1", "description": "State 1"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-1-1", "description": "Action 1"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-1-1",
                            "description": "FB 1",
                            "updates": "PM-1-1",
                            "source": {"type": "responsibility", "id": "RESP-1"},
                        }
                    ],
                },
            ],
        }
        client.set_response_for(ControlStructure, revised_cs_dict)

        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Controller",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-1-1", description="State")
                    ],
                    control_actions=[
                        ControlAction(ca_id="CA-1-1", description="Action")
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="FB",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-1"
                            ),
                        )
                    ],
                )
            ],
        )
        findings = CriticFindings(
            gaps=[
                {
                    "gap_type": "missing_responsibility",
                    "description": "Missing validation",
                    "related_attack_path": "Attack",
                    "suggested_remedy": "Add validation",
                }
            ],
            checklist_results={"Input validation": "absent_unjustified"},
            taxonomy_probe_results={},
        )
        revised, warnings = run_revision(
            llm_client=client,
            control_structure=cs,
            critic_findings=findings,
            use_case_text="Test",
            run_dir=tmp_path,
        )
        assert isinstance(revised, ControlStructure)
        # The revision call used response_format=ControlStructure
        assert client.calls[0].response_format is ControlStructure
