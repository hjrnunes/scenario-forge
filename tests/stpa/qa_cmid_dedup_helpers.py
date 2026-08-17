"""Shared fixtures for the revision cm_id dedup QA suite.

Provides builders for pre-revision ControlStructure shapes, mock LLM
clients, RevisionDelta dicts, and full-SP1-run mock clients.  All
fixtures use public model constructors and the MockLLMClient from
sp1_helpers — no project-internal APIs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from scenario_forge.models.capability_profile import Stage1Profile
from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from scenario_forge.stpa.models.loss_analysis import LossAnalysis
from scenario_forge.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    run_revision,
)
from scenario_forge.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    valid_loss_analysis_dict,
    valid_requirement_set_dict,
    valid_stage1_profile_dict,
)

# ---------------------------------------------------------------------------
# Pre-revision ControlStructure builders
# ---------------------------------------------------------------------------

_RESP_1 = {
    "resp_id": "RESP-1",
    "description": "Controller 1",
    "process_model_parts": [
        {"pm_id": "PM-1-1", "description": "State 1"}
    ],
}

_RESP_2 = {
    "resp_id": "RESP-2",
    "description": "Controller 2",
    "process_model_parts": [
        {"pm_id": "PM-2-1", "description": "State 2"}
    ],
}

_CONTROL_ELEMENT_SET = {
    "control_actions": [
        {"ca_id": "CA-1-1", "description": "Action 1"},
        {"ca_id": "CA-2-1", "description": "Action 2"},
    ],
    "feedback_channels": [
        {
            "fb_id": "FB-1-1",
            "description": "FB 1",
            "updates": "PM-1-1",
            "source": {"type": "responsibility", "id": "RESP-1"},
        },
        {
            "fb_id": "FB-2-1",
            "description": "FB 2",
            "updates": "PM-2-1",
            "source": {"type": "responsibility", "id": "RESP-2"},
        },
    ],
    "controlled_processes": [],
}


def _cl(
    link_id: str,
    cm_id: str,
    *,
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
    description: str = "shared validation",
    payload: str = "sync-message",
    mech_desc: str = "Shared validation gate",
) -> dict:
    """Build a coordination link dict."""
    return {
        "link_id": link_id,
        "source": source,
        "target": target,
        "shared_pm": shared_pm,
        "coordination_mechanism": {
            "cm_id": cm_id,
            "description": mech_desc,
            "payload": payload,
        },
        "description": description,
    }


def _two_cl_dict(link_id_1: str = "CL-1", cm_id_1: str = "CM-1",
                 link_id_2: str = "CL-2", cm_id_2: str = "CM-2") -> dict:
    """Build a coordination link dict pair for ConnectionSet."""
    return [
        _cl(link_id_1, cm_id_1, source="RESP-1", target="RESP-2",
            shared_pm="PM-2-1", description="Coordination link 1",
            payload="Payload", mech_desc="Shared state"),
        _cl(link_id_2, cm_id_2, source="RESP-2", target="RESP-1",
            shared_pm="PM-1-1", description="Coordination link 2",
            payload="Payload 2", mech_desc="Shared state 2"),
    ]


def make_pre_revision_cs() -> ControlStructure:
    """Build a CS with RESP-1/RESP-2 and two coordination links CL-1/CM-1, CL-2/CM-2."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action 1")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State 2")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-2-1", description="Action 2")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="FB 2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-2-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Shared state",
                    payload="Payload",
                ),
                description="Coordination link 1",
            ),
            CoordinationLink(
                link_id="CL-2",
                source="RESP-2",
                target="RESP-1",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-2",
                    description="Shared state 2",
                    payload="Payload 2",
                ),
                description="Coordination link 2",
            ),
        ],
    )


def make_critic_findings_with_gaps() -> CriticFindings:
    """CriticFindings with unjustified gaps (triggers revision)."""
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing input validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            ),
        ],
        checklist_results={
            "Input validation": "absent_unjustified",
        },
        taxonomy_probe_results={},
    )


def make_delta_dict(
    *,
    new_responsibilities: list | None = None,
    modified_responsibilities: list | None = None,
    new_controlled_processes: list | None = None,
    new_coordination_links: list | None = None,
) -> dict:
    """Build a RevisionDelta dict."""
    return {
        "new_responsibilities": new_responsibilities or [],
        "new_controlled_processes": new_controlled_processes or [],
        "new_coordination_links": new_coordination_links or [],
        "modified_responsibilities": modified_responsibilities or [],
    }


def cl_dict(
    link_id: str,
    cm_id: str,
    *,
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
    description: str = "shared validation gate",
    payload: str = "sync-message",
    mech_desc: str = "Shared validation gate",
) -> dict:
    """Build a coordination link dict for RevisionDelta."""
    return _cl(
        link_id, cm_id,
        source=source, target=target, shared_pm=shared_pm,
        description=description, payload=payload, mech_desc=mech_desc,
    )


def run_rev(delta_dict: dict) -> tuple[ControlStructure, list[str]]:
    """Run revision with the two-CL fixture and return (cs, warnings)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        client = MockLLMClient()
        client.set_response_for(RevisionDelta, delta_dict)
        return run_revision(
            llm_client=client,
            control_structure=make_pre_revision_cs(),
            critic_findings=make_critic_findings_with_gaps(),
            use_case_text="Test use case",
            run_dir=Path(tmpdir),
        )


def make_degradation_delta() -> dict:
    """Build a delta whose new responsibility reuses an existing PM id.

    Triggers a ValidationError inside _merge_revision_delta.
    """
    return make_delta_dict(
        new_responsibilities=[
            {
                "resp_id": "RESP-3",
                "description": "Dup PM",
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "Dup"}
                ],
                "control_actions": [
                    {"ca_id": "CA-3-1", "description": "Act"}
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-3-1",
                        "description": "FB",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-3"},
                    }
                ],
            }
        ]
    )


# ---------------------------------------------------------------------------
# Full SP1 run mock client
# ---------------------------------------------------------------------------

def _two_resp_set_dict() -> dict:
    """ResponsibilitySet dict with RESP-1 and RESP-2 (RCs and PMs only)."""
    return {
        "responsibilities": [_RESP_1, _RESP_2],
    }


def _two_cl_coordination_analysis_dict() -> dict:
    """CoordinationAnalysis dict with CL-1/CM-1 and CL-2/CM-2."""
    return {
        "coordination_links": _two_cl_dict(),
        "integrity_findings": [],
    }


def _critic_with_unjustified_gaps() -> dict:
    """CriticFindings dict that triggers revision."""
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation responsibility",
            },
        ],
        "checklist_results": {
            "Input validation": "absent_unjustified",
        },
        "taxonomy_probe_results": {},
    }


def setup_airbnb_sp1_mock_client() -> MockLLMClient:
    """Set up a mock LLM client for a full SP1 run that produces the Airbnb
    collision shape during revision.

    Stages 1a, 1b, 2 (calls 1-3) produce valid artifacts with two
    coordination links (CL-1/CM-1, CL-2/CM-2).  The critic finds
    unjustified gaps.  The revision returns CL-3 with cm_id CM-1
    (the exact Airbnb collision shape).
    """
    client = MockLLMClient()
    client.set_response_for(LossAnalysis, valid_loss_analysis_dict())
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, _two_resp_set_dict())
    client.set_response_for(ControlElementSet, _CONTROL_ELEMENT_SET)
    client.set_response_for(CoordinationAnalysis, _two_cl_coordination_analysis_dict())
    client.set_response_for(CriticFindings, _critic_with_unjustified_gaps())
    client.set_response_for(
        RevisionDelta,
        make_delta_dict(
            new_coordination_links=[
                cl_dict("CL-3", "CM-1")
            ]
        ),
    )
    return client


def setup_degradation_sp1_mock_client() -> MockLLMClient:
    """Set up a mock LLM client for a full SP1 run where revision causes a
    merge ValidationError (duplicate pm_id from a new responsibility).

    The degradation guard should catch it and the pipeline should
    complete with the pre-revision ControlStructure.
    """
    client = MockLLMClient()
    client.set_response_for(LossAnalysis, valid_loss_analysis_dict())
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(RequirementSet, valid_requirement_set_dict())
    client.set_response_for(ResponsibilitySet, _two_resp_set_dict())
    client.set_response_for(ControlElementSet, _CONTROL_ELEMENT_SET)
    client.set_response_for(CoordinationAnalysis, _two_cl_coordination_analysis_dict())
    client.set_response_for(CriticFindings, _critic_with_unjustified_gaps())
    client.set_response_for(RevisionDelta, make_degradation_delta())
    return client


def run_full_sp1(client: MockLLMClient) -> tuple[Path, Any]:
    """Run the full SP1 pipeline with the given mock client.

    Returns (run_dir, result) where run_dir is the temporary directory
    and result is the SP1RunResult.
    """
    tmpdir = tempfile.mkdtemp(prefix="qa_cmid_sp1_")
    run_dir = Path(tmpdir)
    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case for cm_id dedup QA",
        risk_cards=make_risk_cards(),
        run_dir=run_dir,
    )
    return run_dir, result
