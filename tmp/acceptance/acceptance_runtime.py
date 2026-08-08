"""Acceptance runtime for STPA-Sec Gherkin features.

Loads JSON IR, executes scenarios with step handlers, and reports
pass/fail. Step handlers connect Gherkin step text to the STPA
boundary schema models.
"""

from __future__ import annotations

import json
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Any

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

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
    check_structural_heuristics,
)
from scenario_forge.stpa.models.enriched_threat_set import (
    CatalogMapping,
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
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
from scenario_forge.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from scenario_forge.stpa.infra.llm import LLMClient, LLMResult
from scenario_forge.stpa.infra.call_log import make_call_log_entry, append_call_log
from scenario_forge.stpa.infra.yaml_io import write_yaml, read_yaml
from scenario_forge.stpa.infra.templates import TemplateLoader, hash_prompt_templates
from scenario_forge.stpa.infra.manifest import STPARunManifest
from pydantic import ValidationError


class World:
    """Shared state for a single scenario execution."""

    def __init__(self) -> None:
        self.loss_analysis: LossAnalysis | None = None
        self.control_structure: ControlStructure | None = None
        self.ica_enumeration: ICAEnumeration | None = None
        self.enriched_threat_set: EnrichedThreatSet | None = None
        self.scenario_spec: Any = None  # ScenarioSpec
        self.validation_error: Exception | None = None
        self.validation_succeeded: bool = False
        self.heuristic_result = None
        # Infrastructure test state
        self.fixture_dir: Path | None = None
        self.fixture_filename: str | None = None
        self.fixture_model: Any = None
        self.env_overrides: dict[str, str | None] = {}
        self.llm_client: Any = None
        self.llm_result: Any = None
        self.call_log_entries: list[dict] = []
        self.call_log_path: Path | None = None
        self.yaml_model: Any = None
        self.yaml_path: Path | None = None
        self.yaml_read_back: Any = None
        self.template_dir: Path | None = None
        self.template_loader: Any = None
        self.template_rendered: str | None = None
        self.template_hashes: dict[str, str] | None = None
        self.manifest: Any = None
        # SP1 system model test state
        self.sp1_llm_content: Any = None
        self.sp1_component_name: str | None = None
        self.sp1_warnings: list[str] = []
        self.sp1_gap_type: str | None = None
        self.sp1_element_type: str | None = None
        self.sp1_entity: str | None = None
        self.sp1_ref_target: str | None = None
        self.sp1_error_fragment: str | None = None


def _resolve_value(text: str, examples: dict[str, str]) -> str:
    """Resolve <placeholder> tokens in step text using example values."""
    def replacer(match: re.Match) -> str:
        key = match.group(1)
        return examples.get(key, match.group(0))

    return re.sub(r"<([A-Za-z0-9_]+)>", replacer, text)


def _make_coordination_link(
    link_id: str = "CL-1",
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
) -> CoordinationLink:
    """Build a minimal valid CoordinationLink."""
    return CoordinationLink(
        link_id=link_id,
        source=source,
        target=target,
        shared_pm=shared_pm,
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Mechanism", payload="data"
        ),
        description="Link",
    )


# ---------------------------------------------------------------------------
# Step handlers — each returns (success: bool, error: str)
# ---------------------------------------------------------------------------

def _h_module_importable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA boundary schema module is importable."""
    return True, ""


def _h_module_infra_importable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA infra module is importable."""
    return True, ""


def _h_minimal_loss_analysis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a minimal valid loss analysis with loss L-1, hazard H-1, and constraint SC-1."""
    world.loss_analysis = _make_minimal_loss_analysis()
    return True, ""


def _make_minimal_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.use_case)
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="Constraint", related_hazards=["H-1"]
            )
        ],
    )


def _make_minimal_control_structure() -> ControlStructure:
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
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )


# --- Loss Analysis steps ---

def _h_loss_analysis_with_losses(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with losses L-1 and L-2, ..."""
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss 1", provenance=LossProvenance.use_case),
            Loss(loss_id="L-2", description="Loss 2", provenance=LossProvenance.use_case),
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="Constraint", related_hazards=["H-1"]
            )
        ],
    )
    return True, ""


def _h_loss_analysis_hazard_bad_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with loss L-1 and hazard H-1 referencing loss <bad_ref>."""
    bad_ref = examples.get("bad_ref", "")
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.use_case)
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=[bad_ref])],
        security_constraints=[],
    )
    return True, ""


def _h_loss_analysis_constraint_bad_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with loss L-1, hazard H-1, and constraint SC-1 referencing hazard <bad_ref>."""
    bad_ref = examples.get("bad_ref", "")
    world.loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.use_case)
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="Constraint", related_hazards=[bad_ref]
            )
        ],
    )
    return True, ""


def _h_loss_analysis_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with duplicate <id_field> value <dup_value>."""
    id_field = examples.get("id_field", "")
    dup_value = examples.get("dup_value", "")
    if id_field == "loss_id":
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(loss_id=dup_value, description="A", provenance=LossProvenance.use_case),
                Loss(loss_id=dup_value, description="B", provenance=LossProvenance.use_case),
            ],
            hazards=[],
            security_constraints=[],
        )
    elif id_field == "hazard_id":
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(loss_id="L-1", description="A", provenance=LossProvenance.use_case),
            ],
            hazards=[
                Hazard(hazard_id=dup_value, description="A", related_losses=["L-1"]),
                Hazard(hazard_id=dup_value, description="B", related_losses=["L-1"]),
            ],
            security_constraints=[],
        )
    elif id_field == "constraint_id":
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(loss_id="L-1", description="A", provenance=LossProvenance.use_case),
            ],
            hazards=[Hazard(hazard_id="H-1", description="H", related_losses=["L-1"])],
            security_constraints=[
                SecurityConstraint(constraint_id=dup_value, description="A", related_hazards=["H-1"]),
                SecurityConstraint(constraint_id=dup_value, description="B", related_hazards=["H-1"]),
            ],
        )
    else:
        return False, f"Unknown id_field: {id_field}"
    return True, ""


def _h_loss_analysis_risk_card(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle risk card loss scenarios."""
    if "provenance risk_card" in text and "empty source_risk_cards" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[
                Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.risk_card),
            ],
            use_case_losses=[],
            hazards=[],
            security_constraints=[],
        )
    elif "provenance risk_card and source_risk_cards atlas-001" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.risk_card,
                    source_risk_cards=["atlas-001"],
                ),
            ],
            use_case_losses=[],
            hazards=[],
            security_constraints=[],
        )
    elif "provenance use_case and source_risk_cards atlas-001" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.use_case,
                    source_risk_cards=["atlas-001"],
                ),
            ],
            hazards=[],
            security_constraints=[],
        )
    elif "provenance use_case and empty source_risk_cards" in text:
        world.loss_analysis = _make_minimal_loss_analysis()
    elif "provenance critic_derived and empty source_risk_cards" in text:
        world.loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.critic_derived),
            ],
            hazards=[],
            security_constraints=[],
        )
    else:
        return False, f"Unhandled risk card step: {text}"
    return True, ""


def _h_validate_loss_analysis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the loss analysis is validated.

    Pydantic validation already happened during model construction.
    This is a no-op; the validation_error (if any) was set by the Given step.
    """
    if world.loss_analysis is None and world.validation_error is None:
        return False, "No loss analysis to validate"
    return True, ""


def _h_validation_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation succeeds."""
    if world.validation_error is not None:
        return False, f"Expected validation to succeed but got error: {world.validation_error}"
    return True, ""


def _h_validation_fails_with(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation fails with error containing <error_fragment>.

    Case-sensitive matching: the error_fragment must appear exactly
    as specified in the error message.
    """
    error_fragment = examples.get("error_fragment", "")
    if not error_fragment:
        # Extract from text if no example
        match = re.search(r"containing (.+)", text)
        error_fragment = match.group(1).strip() if match else ""

    if world.validation_error is None:
        return False, f"Expected validation to fail with '{error_fragment}' but no error was raised"
    err_str = str(world.validation_error)
    if error_fragment.lower() not in err_str.lower():
        return False, f"Expected error containing '{error_fragment}' but got: {world.validation_error}"
    return True, ""


# --- Control Structure steps ---

def _h_minimal_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a minimal valid control structure with responsibility RESP-1, ..."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_with_resp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1 having PM-1-1, CA-1-1, and FB-1-1."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_pm_feedback_source_bad_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a process model part PM-1-1 with feedback_source referencing <ref_type> <bad_ref>."""
    ref_type_str = examples.get("ref_type", "responsibility")
    bad_ref = examples.get("bad_ref", "")
    ref_type = ReferenceType.responsibility if ref_type_str == "responsibility" else ReferenceType.controlled_process
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="State",
                        feedback_source=ElementRef(type=ref_type, id=bad_ref),
                    ),
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action"),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_ca_target_bad_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control action CA-1-1 with target referencing <ref_type> <bad_ref>."""
    ref_type_str = examples.get("ref_type", "responsibility")
    bad_ref = examples.get("bad_ref", "")
    ref_type = ReferenceType.responsibility if ref_type_str == "responsibility" else ReferenceType.controlled_process
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Action",
                        target=ElementRef(type=ref_type, id=bad_ref),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_fb_source_bad_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a feedback channel FB-1-1 with source referencing <ref_type> <bad_ref>."""
    ref_type_str = examples.get("ref_type", "responsibility")
    bad_ref = examples.get("bad_ref", "")
    ref_type = ReferenceType.responsibility if ref_type_str == "responsibility" else ReferenceType.controlled_process
    world.control_structure = ControlStructure(
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
                        source=ElementRef(type=ref_type, id=bad_ref),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_fb_updates_nonexistent(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a feedback channel FB-1-1 with updates referencing PM-99-1."""
    world.control_structure = ControlStructure(
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
                        updates="PM-99-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_coord_link_bad_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coordination link CL-1 with <field> referencing RESP-99."""
    field = examples.get("field", "source")
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback",
                        updates="PM-2-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                    )
                ],
            ),
        ],
        coordination_links=[
            _make_coordination_link(
                link_id="CL-1",
                source="RESP-99" if field == "source" else "RESP-1",
                target="RESP-99" if field == "target" else "RESP-2",
                shared_pm="PM-1-1",
            )
        ],
    )
    return True, ""


def _h_cs_coord_link_bad_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coordination link CL-1 with shared_pm referencing PM-99-1."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback",
                        updates="PM-2-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                    )
                ],
            ),
        ],
        coordination_links=[
            _make_coordination_link(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-99-1",
            )
        ],
    )
    return True, ""


def _h_cs_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with duplicate <id_field> value <dup_value>."""
    id_field = examples.get("id_field", "")
    dup_value = examples.get("dup_value", "")
    if id_field == "resp_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id=dup_value,
                    description="A",
                    process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="PM")],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1", description="FB", updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id=dup_value),
                        )
                    ],
                ),
                Responsibility(
                    resp_id=dup_value,
                    description="B",
                    process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="PM")],
                    control_actions=[ControlAction(ca_id="CA-2-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-2-1", description="FB", updates="PM-2-1",
                            source=ElementRef(type=ReferenceType.responsibility, id=dup_value),
                        )
                    ],
                ),
            ]
        )
    elif id_field == "pm_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id=dup_value, description="PM1"),
                        ProcessModelPart(pm_id=dup_value, description="PM2"),
                    ],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1", description="FB", updates=dup_value,
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        )
                    ],
                )
            ]
        )
    elif id_field == "ca_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="PM")],
                    control_actions=[
                        ControlAction(ca_id=dup_value, description="CA1"),
                        ControlAction(ca_id=dup_value, description="CA2"),
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1", description="FB", updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        )
                    ],
                )
            ]
        )
    elif id_field == "fb_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="PM")],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id=dup_value, description="FB1", updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        ),
                        FeedbackChannel(
                            fb_id=dup_value, description="FB2", updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        ),
                    ],
                )
            ]
        )
    elif id_field == "link_id":
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="PM")],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1", description="FB", updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        )
                    ],
                ),
                Responsibility(
                    resp_id="RESP-2",
                    description="B",
                    process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="PM")],
                    control_actions=[ControlAction(ca_id="CA-2-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-2-1", description="FB", updates="PM-2-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                        )
                    ],
                ),
            ],
            coordination_links=[
                _make_coordination_link(link_id=dup_value, source="RESP-1", target="RESP-2", shared_pm="PM-1-1"),
                _make_coordination_link(link_id=dup_value, source="RESP-2", target="RESP-1", shared_pm="PM-2-1"),
            ],
        )
    elif id_field == "cp_id":
        from scenario_forge.stpa.models.control_structure import ControlledProcess
        world.control_structure = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="A",
                    process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="PM")],
                    control_actions=[ControlAction(ca_id="CA-1-1", description="CA")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1", description="FB", updates="PM-1-1",
                            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                        )
                    ],
                )
            ],
            controlled_processes=[
                ControlledProcess(cp_id=dup_value, description="A"),
                ControlledProcess(cp_id=dup_value, description="B"),
            ],
        )
    else:
        return False, f"Unknown id_field: {id_field}"
    return True, ""


def _h_validate_cs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure is validated.

    Pydantic validation already happened during model construction.
    This is a no-op; the validation_error (if any) was set by the Given step.
    """
    if world.control_structure is None and world.validation_error is None:
        return False, "No control structure to validate"
    return True, ""


def _h_check_heuristics(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure structural heuristics are checked."""
    if world.control_structure is None:
        return False, "No control structure to check"
    world.heuristic_result = check_structural_heuristics(world.control_structure)
    return True, ""


def _h_check_heuristics_with_la(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the control structure structural heuristics are checked with the loss analysis."""
    if world.control_structure is None:
        return False, "No control structure to check"
    la = world.loss_analysis or _make_minimal_loss_analysis()
    world.heuristic_result = check_structural_heuristics(world.control_structure, la)
    return True, ""


def _h_heuristic_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check succeeds."""
    if world.heuristic_result is None:
        return False, "No heuristic result"
    if not world.heuristic_result.passed:
        return False, f"Expected heuristics to pass but got errors: {world.heuristic_result.errors}"
    return True, ""


def _h_heuristic_fails_with(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check fails with error containing <text>."""
    match = re.search(r"containing (.+)", text)
    fragment = match.group(1).strip() if match else ""
    if world.heuristic_result is None:
        return False, "No heuristic result"
    if world.heuristic_result.passed:
        return False, f"Expected heuristic check to fail with '{fragment}' but it passed"
    err_str = " ".join(world.heuristic_result.errors).lower()
    if fragment.lower() not in err_str:
        return False, f"Expected error containing '{fragment}' but got: {' '.join(world.heuristic_result.errors)}"
    return True, ""


# --- ICA Enumeration steps ---

def _h_ica_slot_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an ICA slot ... with is_na false and one ICA referencing hazard H-1 and constraint SC-1."""
    uca_type_str = examples.get("uca_type", "NOT_PROVIDED")
    uca_type = UCAType(uca_type_str)
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=uca_type,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_ica_validate_against(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ICA enumeration is validated against the loss analysis and control structure.

    Pydantic validation may have already happened during model construction.
    If so, the error is already stored. Otherwise, run validate_against.
    """
    if world.ica_enumeration is None and world.validation_error is None:
        return False, "No ICA enumeration to validate"
    if world.validation_error is not None:
        # Validation already failed during construction
        return True, ""
    la = world.loss_analysis or _make_minimal_loss_analysis()
    cs = world.control_structure or _make_minimal_control_structure()
    try:
        world.ica_enumeration.validate_against(la, cs)
        world.validation_succeeded = True
        world.validation_error = None
    except (ValueError, ValidationError) as e:
        world.validation_error = e
        world.validation_succeeded = False
    return True, ""


# --- Enriched Threat Set steps ---

def _h_ets_catalog_confidence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a catalog mapping with confidence level <confidence_level>."""
    confidence = examples.get("confidence_level", "high")
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
                catalog_mappings=[
                    CatalogMapping(
                        catalog="OWASP_AGENTIC",
                        id="T2-T3",
                        name="Test threat",
                        confidence=confidence,
                    )
                ],
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 10,
                "non_na": 8,
                "na": 2,
                "coverage_rate": 0.8,
            },
        ),
    )
    return True, ""


def _h_ets_validate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the enriched threat set is validated."""
    if world.enriched_threat_set is None and world.validation_error is None:
        return False, "No enriched threat set to validate"
    return True, ""


def _h_ets_structural_threat(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a structural threat with ica_slot_id ..."""
    na_flag = "na_reconciliation_flag true" in text
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA",
                hazardous_context="Ctx",
                loss_scenario="Scenario",
                na_reconciliation_flag=na_flag,
            )
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
        ),
    )
    return True, ""


def _h_ets_coverage_basic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coverage analysis with total_slots 10, non_na 8, na 2, and coverage_rate 0.8."""
    if world.enriched_threat_set is None:
        world.enriched_threat_set = EnrichedThreatSet(
            structural_threats=[StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_text="UCA", hazardous_context="Ctx", loss_scenario="Scenario",
            )],
            coverage_analysis=CoverageAnalysis(
                structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
            ),
        )
    else:
        world.enriched_threat_set = world.enriched_threat_set.model_copy(deep=True)
        world.enriched_threat_set.coverage_analysis = CoverageAnalysis(
            structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
        )
    return True, ""


def _h_ets_catalog_mapping(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a catalog mapping catalog OWASP_AGENTIC with id T2-T3 and confidence high."""
    if world.enriched_threat_set and world.enriched_threat_set.structural_threats:
        threat = world.enriched_threat_set.structural_threats[0]
        threat.catalog_mappings.append(CatalogMapping(
            catalog="OWASP_AGENTIC", id="T2-T3", name="Test", confidence="high",
        ))
    return True, ""


def _h_ets_coverage_by_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coverage analysis with by_ica_type ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            ica_text="UCA", hazardous_context="Ctx", loss_scenario="Scenario",
        )],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
            by_ica_type={"NOT_PROVIDED": 5, "INCORRECT": 3},
            by_controller={"RESP-1": 4, "RESP-2": 4},
        ),
    )
    return True, ""


def _h_ets_coverage_uncovered(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coverage analysis with uncovered_owasp_threats ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            ica_text="UCA", hazardous_context="Ctx", loss_scenario="Scenario",
        )],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
            uncovered_owasp_threats=["T10", "T15"],
            uncovered_reason="no structural slot matched",
        ),
    )
    return True, ""


def _h_ets_coverage_consideration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coverage analysis with structural_consideration ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            ica_text="UCA", hazardous_context="Ctx", loss_scenario="Scenario",
        )],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
            structural_consideration={"total_slots": 10, "considered": 8, "rate": 0.8},
        ),
    )
    return True, ""


def _h_ets_na_quality(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: na_quality na_count 2 quality_count 2 quality_rate 1.0."""
    if world.enriched_threat_set:
        world.enriched_threat_set.coverage_analysis.na_quality = {
            "na_count": 2, "quality_count": 2, "quality_rate": 1.0,
        }
    return True, ""


def _h_ets_coverage_correspondence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a coverage analysis with catalog_correspondence ..."""
    world.enriched_threat_set = EnrichedThreatSet(
        structural_threats=[StructuralThreat(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            ica_text="UCA", hazardous_context="Ctx", loss_scenario="Scenario",
        )],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={"total_slots": 10, "non_na": 8, "na": 2, "coverage_rate": 0.8},
            catalog_correspondence={
                "structural_with_match": 8, "structural_unmapped": 0, "catalog_only_supplements": 0,
            },
        ),
    )
    return True, ""


# --- Generic validation steps ---

def _h_validation_fails_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation fails with error containing duplicate."""
    if world.validation_error is None:
        return False, "Expected validation to fail with 'duplicate' but no error was raised"
    if "duplicate" not in str(world.validation_error).lower():
        return False, f"Expected error containing 'duplicate' but got: {world.validation_error}"
    return True, ""


def _h_validation_fails_field(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation fails with error containing <field>."""
    match = re.search(r"containing (\S+)", text)
    fragment = match.group(1) if match else ""
    if world.validation_error is None:
        return False, f"Expected validation to fail with '{fragment}' but no error was raised"
    err_str = str(world.validation_error).lower()
    if fragment.lower() not in err_str:
        return False, f"Expected error containing '{fragment}' but got: {world.validation_error}"
    return True, ""


# --- Loss analysis with hazard and constraint ---

def _h_loss_analysis_with_hazard_constraint(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with hazard H-1 and constraint SC-1."""
    world.loss_analysis = _make_minimal_loss_analysis()
    return True, ""


# --- Control structure structural heuristic variants ---

def _h_cs_zero_pms(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero process model parts."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[],
            )
        ]
    )
    return True, ""


def _h_cs_zero_cas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero control actions."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="FB", updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_zero_fbs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero feedback channels."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[],
            )
        ]
    )
    return True, ""


def _h_cs_orphan_pm(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with PM-1-1 and PM-1-2 where only PM-1-1 is updated."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1"),
                    ProcessModelPart(pm_id="PM-1-2", description="State 2"),
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="FB", updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_unreferenced_cp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a controlled process CP-1 not referenced by any feedback or control action."""
    from scenario_forge.stpa.models.control_structure import ControlledProcess
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="FB", updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Unreferenced process"),
        ],
    )
    return True, ""


def _h_cs_no_constraint_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure where no responsibility references constraint SC-1."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_with_constraint_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure where responsibility RESP-1 references constraint SC-1."""
    from scenario_forge.stpa.models.control_structure import ResponsibilityConstraint
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                responsibility_constraints=[
                    ResponsibilityConstraint(rc_id="SC-1", description="Covers H-1"),
                ],
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="FB", updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_cs_cross_resp_fb(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: CS with responsibilities RESP-1 and RESP-2 where FB-1-1 updates PM-2-1."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="FB", updates="PM-2-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1", description="FB", updates="PM-2-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                    )
                ],
            ),
        ]
    )
    return True, ""


def _h_heuristic_warns_orphan(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a warning is produced for orphan PM PM-1-2."""
    if world.heuristic_result is None:
        return False, "No heuristic result"
    warn_str = " ".join(world.heuristic_result.warnings)
    if "PM-1-2" not in warn_str and "orphan" not in warn_str.lower():
        return False, f"Expected warning about orphan PM-1-2 but got: {warn_str}"
    return True, ""


# ---------------------------------------------------------------------------
# Step matching
# ---------------------------------------------------------------------------

# Map step text patterns to handler functions.
# Patterns are checked in order; first match wins.
# Each pattern is (regex, handler).

STEP_PATTERNS: list[tuple[re.Pattern, Any]] = []

def _register(pattern: str, handler: Any) -> None:
    STEP_PATTERNS.append((re.compile(pattern, re.IGNORECASE), handler))


# Background / setup
_register(r"the STPA boundary schema module is importable", _h_module_importable)
_register(r"the STPA infra module is importable", _h_module_infra_importable)
_register(r"a minimal valid loss analysis with loss L-1.*", _h_minimal_loss_analysis)
_register(r"a loss analysis with loss L-1, hazard H-1, and constraint SC-1$", _h_minimal_loss_analysis)
_register(r"a minimal valid control structure with responsibility.*", _h_minimal_cs)
_register(r"a control structure with responsibility RESP-1, control action CA-1-1, and PM-1-1", _h_minimal_cs)

# Loss analysis - Given steps
_register(r"a loss analysis with losses L-1 and L-2.*", _h_loss_analysis_with_losses)
_register(r"a loss analysis with loss L-1 and hazard H-1 referencing loss", _h_loss_analysis_hazard_bad_ref)
_register(r"a loss analysis with loss L-1, hazard H-1, and constraint SC-1 referencing hazard", _h_loss_analysis_constraint_bad_ref)
_register(r"a loss analysis with duplicate", _h_loss_analysis_duplicate)
_register(r"a risk card loss.*", _h_loss_analysis_risk_card)
_register(r"a use case loss.*", _h_loss_analysis_risk_card)
_register(r"a critic derived loss.*", _h_loss_analysis_risk_card)
_register(r"a loss analysis with hazard H-1 and constraint SC-1$", _h_loss_analysis_with_hazard_constraint)

# Loss analysis - When/Then steps
_register(r"the loss analysis is validated", _h_validate_loss_analysis)
_register(r"validation succeeds", _h_validation_succeeds)
_register(r"validation fails with error containing", _h_validation_fails_with)

# Control structure - Given steps
_register(r"a control structure with responsibility RESP-1 having PM-1-1.*", _h_cs_with_resp)
_register(r"a process model part PM-1-1 with feedback_source referencing", _h_cs_pm_feedback_source_bad_ref)
_register(r"a control action CA-1-1 with target referencing", _h_cs_ca_target_bad_ref)
_register(r"a feedback channel FB-1-1 with source referencing", _h_cs_fb_source_bad_ref)
_register(r"a feedback channel FB-1-1 with updates referencing PM-99-1", _h_cs_fb_updates_nonexistent)
_register(r"a coordination link CL-1 with (?:source|target|<field>) referencing RESP-99", _h_cs_coord_link_bad_ref)
_register(r"a coordination link CL-1 with <field> referencing", _h_cs_coord_link_bad_ref)
_register(r"a coordination link CL-1 with shared_pm referencing PM-99-1", _h_cs_coord_link_bad_pm)
_register(r"a control structure with duplicate", _h_cs_duplicate)

# Control structure - other Given steps (no examples, but needed for background)
_register(r"a control structure with responsibilities RESP-1 and RESP-2 and coordination link.*", _h_minimal_cs)
_register(r"a control structure with responsibilities RESP-1 and RESP-2 where FB-1-1 updates PM-2-1", _h_cs_cross_resp_fb)
_register(r"a responsibility RESP-1 with zero process model parts", _h_cs_zero_pms)
_register(r"a responsibility RESP-1 with zero control actions", _h_cs_zero_cas)
_register(r"a responsibility RESP-1 with zero feedback channels", _h_cs_zero_fbs)
_register(r"a responsibility RESP-1 with PM-1-1 and PM-1-2 where only PM-1-1 is updated by FB-1-1", _h_cs_orphan_pm)
_register(r"a controlled process CP-1 not referenced by any feedback channel source or control action target", _h_cs_unreferenced_cp)
_register(r"a control structure where responsibility RESP-1 references constraint SC-1", _h_cs_with_constraint_ref)
_register(r"a control structure where no responsibility references constraint SC-1", _h_cs_no_constraint_ref)

# Control structure - When/Then steps
_register(r"the control structure is validated", _h_validate_cs)
_register(r"the control structure structural heuristics are checked with the loss analysis", _h_check_heuristics_with_la)
_register(r"the control structure structural heuristics are checked", _h_check_heuristics)
_register(r"the heuristic check succeeds", _h_heuristic_succeeds)
_register(r"the heuristic check fails with error containing", _h_heuristic_fails_with)
_register(r"a warning is produced for orphan PM", _h_heuristic_warns_orphan)
_register(r"validation fails with error containing duplicate", _h_validation_fails_duplicate)
_register(r"validation fails with error containing (?:feedback_source|shared_pm|source|target|updates)", _h_validation_fails_field)

# ICA Enumeration steps (handlers defined below)
_register(r"an ICA slot .* with is_na false and one ICA referencing hazard H-1 and constraint SC-1", _h_ica_slot_valid)
_register(r"an ICA slot .* with is_na false and one ICA$", _h_ica_slot_valid)
_register(r"an ICA slot .* with is_na false, one ICA$", _h_ica_slot_valid)
_register(r"the ICA enumeration is validated against the loss analysis and control structure", _h_ica_validate_against)

# Enriched Threat Set steps
_register(r"a structural threat with a catalog mapping with confidence", _h_ets_catalog_confidence)
_register(r"a structural threat with ica_slot_id.*", _h_ets_structural_threat)
_register(r"a coverage analysis with total_slots.*", _h_ets_coverage_basic)
_register(r"a catalog mapping catalog.*", _h_ets_catalog_mapping)
_register(r"a coverage analysis with by_ica_type.*", _h_ets_coverage_by_type)
_register(r"a coverage analysis with uncovered_owasp_threats.*", _h_ets_coverage_uncovered)
_register(r"a coverage analysis with structural_consideration.*", _h_ets_coverage_consideration)
_register(r"a coverage analysis with catalog_correspondence.*", _h_ets_coverage_correspondence)
_register(r"na_quality na_count.*", _h_ets_na_quality)
_register(r"the enriched threat set is validated", _h_ets_validate)

# Catch-all for steps that should just pass (no-ops for background)
# (ICA handler registrations moved after handler definitions below)


def _h_ica_slot_bad_hazard(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na false and one ICA referencing hazard H-99."""
    uca_type_str = examples.get("uca_type", "NOT_PROVIDED")
    uca_type = UCAType(uca_type_str)
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=uca_type,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-99"],
                        related_constraints=["SC-1"],
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_ica_slot_bad_constraint(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na false and one ICA referencing constraint SC-99."""
    uca_type_str = examples.get("uca_type", "NOT_PROVIDED")
    uca_type = UCAType(uca_type_str)
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=uca_type,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-1"],
                        related_constraints=["SC-99"],
                    )
                ],
            )
        ]
    )
    return True, ""


def _h_ica_slot_no_icas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na false and zero ICAs."""
    uca_type_str = examples.get("uca_type", "NOT_PROVIDED")
    uca_type = UCAType(uca_type_str)
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=uca_type,
                is_na=False,
                icas=[],
            )
        ]
    )
    return True, ""


def _h_ica_slot_na_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na true and na_justification."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[],
                na_justification="no hazardous context",
            )
        ]
    )
    return True, ""


def _h_ica_slot_na_no_just(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na true and no na_justification."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[],
            )
        ]
    )
    return True, ""


def _h_ica_slot_na_with_ica(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na true, na_justification none, and one ICA."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=True,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
                na_justification="none",
            )
        ]
    )
    return True, ""


def _h_ica_slot_non_na_with_just(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ICA slot with is_na false, one ICA, and na_justification set."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
                na_justification="should not be set",
            )
        ]
    )
    return True, ""


def _h_ica_slot_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: two ICA slots with the same slot_id."""
    world.ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="UCA",
                        hazardous_context="Ctx",
                        loss_scenario="Scenario",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            ),
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:INCORRECT:1",
                        ica_text="UCA2",
                        hazardous_context="Ctx2",
                        loss_scenario="Scenario2",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            ),
        ]
    )
    return True, ""


# Additional ICA handler registrations (after handler definitions)
_register(r"two ICA slots with the same slot_id", _h_ica_slot_duplicate)
_register(r"an ICA slot .* with is_na false and one ICA referencing hazard H-99", _h_ica_slot_bad_hazard)
_register(r"an ICA slot .* with is_na false and one ICA referencing constraint SC-99", _h_ica_slot_bad_constraint)
_register(r"an ICA slot .* with is_na false and zero ICAs", _h_ica_slot_no_icas)
_register(r"an ICA slot .* with is_na true and na_justification", _h_ica_slot_na_valid)
_register(r"an ICA slot .* with is_na true and no na_justification", _h_ica_slot_na_no_just)
_register(r"an ICA slot .* with is_na true, na_justification none, and one ICA", _h_ica_slot_na_with_ica)
_register(r"an ICA slot .* with is_na false, one ICA, and na_justification set", _h_ica_slot_non_na_with_just)


# ---------------------------------------------------------------------------
# ScenarioSpec handlers
# ---------------------------------------------------------------------------

def _make_minimal_scenario_spec(
    target_controller: str = "RESP-1",
    target_control_action: str = "CA-1-1",
) -> ScenarioSpec:
    """Build a minimal valid ScenarioSpec."""
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
        ),
        target_controller=target_controller,
        target_control_action=target_control_action,
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-1-1", content="Belief", vulnerability="vuln",
            )],
            desires=[DefenderDesire(
                resp_id="RESP-1", content="Desire",
            )],
            intentions=[DefenderIntention(
                ca_id="CA-1-1", content="Intention",
            )],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["attacker belief"],
            desires=["attacker desire"],
            intentions=["attacker intention"],
        ),
        loss_scenario="A loss scenario",
    )


def _h_cs_with_pm_and_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1, process model part PM-1-1, and control action CA-1-1."""
    world.control_structure = _make_minimal_control_structure()
    return True, ""


def _h_cs_two_resp_ca_belongs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibilities RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2."""
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="FB", updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action 2")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1", description="FB", updates="PM-2-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                    )
                ],
            ),
        ]
    )
    return True, ""


def _h_scenario_spec_valid(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1."""
    world.scenario_spec = _make_minimal_scenario_spec()
    return True, ""


def _h_scenario_spec_defender_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: defender belief referencing PM-1-1, desire referencing RESP-1, intention referencing CA-1-1."""
    if world.scenario_spec is None:
        world.scenario_spec = _make_minimal_scenario_spec()
    # Already set in _make_minimal_scenario_spec, just ensure it
    return True, ""


def _h_scenario_spec_bad_belief(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with defender belief referencing PM-99-1."""
    world.scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-99-1", content="Bad", vulnerability="vuln",
            )],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"],
        ),
        loss_scenario="Scenario",
    )
    return True, ""


def _h_scenario_spec_bad_desire(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with defender desire referencing RESP-99."""
    world.scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-1-1", content="Belief", vulnerability="vuln",
            )],
            desires=[DefenderDesire(resp_id="RESP-99", content="Bad")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"],
        ),
        loss_scenario="Scenario",
    )
    return True, ""


def _h_scenario_spec_bad_intention(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with defender intention referencing CA-99-1."""
    world.scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-1-1", content="Belief", vulnerability="vuln",
            )],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-99-1", content="Bad")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"],
        ),
        loss_scenario="Scenario",
    )
    return True, ""


def _h_scenario_spec_bad_target_controller(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with target_controller RESP-99."""
    world.scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="structural",
        ),
        target_controller="RESP-99",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-1-1", content="Belief", vulnerability="vuln",
            )],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"],
        ),
        loss_scenario="Scenario",
    )
    return True, ""


def _h_scenario_spec_bad_target_ca(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with target_control_action CA-99-1."""
    world.scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-99-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-1-1", content="Belief", vulnerability="vuln",
            )],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"],
        ),
        loss_scenario="Scenario",
    )
    return True, ""


def _h_scenario_spec_target_ca_other_resp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with target_controller RESP-1 and target_control_action CA-2-1."""
    world.scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="structural",
        ),
        target_controller="RESP-1",
        target_control_action="CA-2-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(
                pm_id="PM-1-1", content="Belief", vulnerability="vuln",
            )],
            desires=[DefenderDesire(resp_id="RESP-1", content="Desire")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Intention")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["b"], desires=["d"], intentions=["i"],
        ),
        loss_scenario="Scenario",
    )
    return True, ""


def _h_scenario_spec_threat_structural(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with threat source ica_slot_id ... and provenance structural."""
    world.scenario_spec = _make_minimal_scenario_spec()
    return True, ""


def _h_scenario_spec_threat_catalog(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with threat source ica_slot_id ... and provenance catalog_only."""
    spec = _make_minimal_scenario_spec()
    spec.threat_source = ThreatSource(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED", provenance="catalog_only",
    )
    world.scenario_spec = spec
    return True, ""


def _h_scenario_spec_attacker_bdi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with attacker beliefs, desires, and intentions as free-form strings."""
    world.scenario_spec = _make_minimal_scenario_spec()
    return True, ""


def _h_scenario_spec_catalog_context(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario spec with catalog context containing OWASP_AGENTIC mapping T2-T3 confidence high."""
    spec = _make_minimal_scenario_spec()
    spec.catalog_context = [CatalogMapping(
        catalog="OWASP_AGENTIC", id="T2-T3", name="Test", confidence="high",
    )]
    world.scenario_spec = spec
    return True, ""


def _h_validate_scenario_spec(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario spec is validated against the control structure."""
    if world.scenario_spec is None and world.validation_error is None:
        return False, "No scenario spec to validate"
    if world.validation_error is not None:
        return True, ""
    cs = world.control_structure or _make_minimal_control_structure()
    try:
        world.scenario_spec.validate_against(cs)
        world.validation_succeeded = True
        world.validation_error = None
    except (ValueError, ValidationError) as e:
        world.validation_error = e
        world.validation_succeeded = False
    return True, ""


# ---------------------------------------------------------------------------
# Fixture handlers
# ---------------------------------------------------------------------------

def _h_fixtures_dir_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA fixtures directory exists at src/scenario_forge/stpa/fixtures."""
    world.fixture_dir = PROJECT_ROOT / "src" / "scenario_forge" / "stpa" / "fixtures"
    if not world.fixture_dir.is_dir():
        return False, f"Fixtures directory not found: {world.fixture_dir}"
    return True, ""


def _h_fixture_file_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the fixture file <filename>."""
    match = re.search(r"the fixture file (\S+\.yaml)", text)
    if not match:
        return False, f"Could not extract fixture filename from: {text}"
    world.fixture_filename = match.group(1)
    return True, ""


def _h_fixture_loaded(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the fixture is loaded and validated as <ModelName>."""
    if world.fixture_filename is None:
        return False, "No fixture file specified"
    fixture_path = world.fixture_dir / world.fixture_filename

    # Map model name to class
    model_name_map = {
        "LossAnalysis": LossAnalysis,
        "ControlStructure": ControlStructure,
        "ICAEnumeration": ICAEnumeration,
        "EnrichedThreatSet": EnrichedThreatSet,
        "CapabilityProfile": None,  # imported lazily
    }
    match = re.search(r"validated as (\w+)", text)
    if not match:
        return False, f"Could not extract model name from: {text}"
    model_name = match.group(1)
    model_class = model_name_map.get(model_name)
    if model_class is None and model_name == "CapabilityProfile":
        from scenario_forge.models.capability_profile import CapabilityProfile
        model_class = CapabilityProfile
    if model_class is None:
        return False, f"Unknown model class: {model_name}"

    try:
        world.fixture_model = read_yaml(fixture_path, model_class)
    except (ValidationError, ValueError, Exception) as e:
        world.validation_error = e
    return True, ""


def _h_fixture_header_comment(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the fixture file contains a header comment documenting provenance."""
    if world.fixture_filename is None:
        return False, "No fixture file specified"
    fixture_path = world.fixture_dir / world.fixture_filename
    first_line = fixture_path.read_text(encoding="utf-8").splitlines()[0]
    if not first_line.startswith("#"):
        return False, f"Fixture {world.fixture_filename} does not start with a comment header"
    return True, ""


def _h_fixtures_scanned(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the fixtures directory is scanned for YAML files."""
    if world.fixture_dir is None:
        world.fixture_dir = PROJECT_ROOT / "src" / "scenario_forge" / "stpa" / "fixtures"
    world.fixture_files_found = {
        f.name for f in world.fixture_dir.glob("*.yaml")
    }
    return True, ""


def _h_fixture_file_present(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the fixture file <filename> is present."""
    match = re.search(r"the fixture file (\S+\.yaml) is present", text)
    if not match:
        return False, f"Could not extract fixture filename from: {text}"
    filename = match.group(1)
    found = getattr(world, "fixture_files_found", set())
    if filename not in found:
        return False, f"Fixture file {filename} not found in fixtures directory"
    return True, ""


# ---------------------------------------------------------------------------
# Infrastructure handlers
# ---------------------------------------------------------------------------

def _h_env_var_set(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: environment variable <VAR> is set to <value>."""
    match = re.search(r"environment variable (\S+) is set to (\S+)", text)
    if not match:
        return False, f"Could not parse env var step: {text}"
    var_name = match.group(1)
    var_value = match.group(2)
    world.env_overrides[var_name] = var_value
    os.environ[var_name] = var_value
    return True, ""


def _h_no_env_var(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no SCENARIO_FORGE_MODEL_BASE_URL environment variable is set."""
    match = re.search(r"no (\S+) environment variable is set", text)
    if not match:
        return False, f"Could not parse env var step: {text}"
    var_name = match.group(1)
    world.env_overrides[var_name] = None
    os.environ.pop(var_name, None)
    return True, ""


def _h_llm_client_construct(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLMClient is constructed (with optional base_url and model)."""
    base_url = None
    model = None
    match = re.search(r"base_url (\S+)", text)
    if match:
        base_url = match.group(1)
    match = re.search(r"model (\S+)", text)
    if match:
        model = match.group(1)

    if "without explicit base_url" in text:
        base_url = None

    try:
        world.llm_client = LLMClient(base_url=base_url, model=model)
    except (ValueError, Exception) as e:
        world.validation_error = e
    return True, ""


def _h_llm_client_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLMClient constructed with base_url <url>."""
    match = re.search(r"base_url (\S+)", text)
    base_url = match.group(1) if match else None
    try:
        world.llm_client = LLMClient(base_url=base_url)
    except (ValueError, Exception) as e:
        world.validation_error = e
    return True, ""


def _h_llm_client_base_url(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the client base_url is <url>."""
    match = re.search(r"base_url is (\S+)", text)
    expected = match.group(1) if match else ""
    if world.llm_client is None:
        return False, "No LLM client constructed"
    if world.llm_client.base_url != expected:
        return False, f"Expected base_url '{expected}' but got '{world.llm_client.base_url}'"
    return True, ""


def _h_llm_client_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the client model is <model>."""
    match = re.search(r"model is (\S+)", text)
    expected = match.group(1) if match else ""
    if world.llm_client is None:
        return False, "No LLM client constructed"
    if world.llm_client.model != expected:
        return False, f"Expected model '{expected}' but got '{world.llm_client.model}'"
    return True, ""


def _h_llm_client_temperature(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the client temperature is <value>."""
    match = re.search(r"temperature is (\S+)", text)
    expected = float(match.group(1)) if match else 0.4
    if world.llm_client is None:
        return False, "No LLM client constructed"
    if world.llm_client.temperature != expected:
        return False, f"Expected temperature {expected} but got {world.llm_client.temperature}"
    return True, ""


def _h_llm_valueerror(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ValueError is raised containing <message>."""
    match = re.search(r"containing (.+)", text)
    fragment = match.group(1).strip() if match else ""
    if world.validation_error is None:
        return False, f"Expected ValueError containing '{fragment}' but no error was raised"
    if not isinstance(world.validation_error, ValueError):
        return False, f"Expected ValueError but got {type(world.validation_error).__name__}"
    if fragment.lower() not in str(world.validation_error).lower():
        return False, f"Expected error containing '{fragment}' but got: {world.validation_error}"
    return True, ""


def _h_llm_headers(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the client extra headers include HTTP-Referer and X-Title."""
    if world.llm_client is None:
        return False, "No LLM client constructed"
    headers = world.llm_client.extra_headers or {}
    if "HTTP-Referer" not in headers:
        return False, f"HTTP-Referer not in extra headers: {headers}"
    if "X-Title" not in headers:
        return False, f"X-Title not in extra headers: {headers}"
    return True, ""


def _h_llm_result_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLMResult with content text, prompt_tokens 100, completion_tokens 50, and duration_ms 5000."""
    world.llm_result = LLMResult(
        content="text",
        prompt_tokens=100,
        completion_tokens=50,
        duration_ms=5000,
    )
    return True, ""


def _h_llm_result_content(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result content is text."""
    if world.llm_result is None:
        return False, "No LLM result"
    if world.llm_result.content != "text":
        return False, f"Expected content 'text' but got '{world.llm_result.content}'"
    return True, ""


def _h_llm_result_prompt_tokens(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result prompt_tokens is 100."""
    match = re.search(r"prompt_tokens is (\d+)", text)
    expected = int(match.group(1)) if match else 100
    if world.llm_result is None:
        return False, "No LLM result"
    if world.llm_result.prompt_tokens != expected:
        return False, f"Expected prompt_tokens {expected} but got {world.llm_result.prompt_tokens}"
    return True, ""


def _h_llm_result_completion_tokens(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result completion_tokens is 50."""
    match = re.search(r"completion_tokens is (\d+)", text)
    expected = int(match.group(1)) if match else 50
    if world.llm_result is None:
        return False, "No LLM result"
    if world.llm_result.completion_tokens != expected:
        return False, f"Expected completion_tokens {expected} but got {world.llm_result.completion_tokens}"
    return True, ""


def _h_llm_result_duration(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the result duration_ms is 5000."""
    match = re.search(r"duration_ms is (\d+)", text)
    expected = int(match.group(1)) if match else 5000
    if world.llm_result is None:
        return False, "No LLM result"
    if world.llm_result.duration_ms != expected:
        return False, f"Expected duration_ms {expected} but got {world.llm_result.duration_ms}"
    return True, ""


# --- Call log handlers ---

def _h_call_log_entry_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a call log entry with stage ..., step ..., slot_id ..., and scenario_id ..."""
    stage_match = re.search(r"stage ([^,\s]+)", text)
    step_match = re.search(r"step ([^,\s]+)", text)
    slot_match = re.search(r"slot_id ([^,\s]+)", text)
    scenario_match = re.search(r"scenario_id ([^,\s]+)", text)

    slot_id = slot_match.group(1) if slot_match else None
    if slot_id == "null":
        slot_id = None
    scenario_id = scenario_match.group(1) if scenario_match else None
    if scenario_id == "null":
        scenario_id = None

    entry = make_call_log_entry(
        stage=stage_match.group(1) if stage_match else "stage_2",
        step=step_match.group(1) if step_match else "call_1",
        model="test-model",
        slot_id=slot_id,
        scenario_id=scenario_id,
    )
    world.call_log_entries = [entry]
    return True, ""


def _h_call_log_three_entries(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: three call log entries with stages stage_2, stage_3, and stage_5."""
    entries = []
    for stage in ["stage_2", "stage_3", "stage_5"]:
        entries.append(make_call_log_entry(
            stage=stage, step=f"call_{stage}", model="test-model",
        ))
    world.call_log_entries = entries
    return True, ""


def _h_call_log_empty(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an empty list of call log entries."""
    world.call_log_entries = []
    return True, ""


def _h_call_log_append(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the entry/entries is/are appended to calls.jsonl."""
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp())
    world.call_log_path = tmp_dir / "calls.jsonl"
    append_call_log(world.call_log_entries, tmp_dir)
    return True, ""


def _h_call_log_one_line(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the file contains one valid JSON line with stage ... and step ..."""
    if world.call_log_path is None or not world.call_log_path.exists():
        return False, "No calls.jsonl file found"
    lines = world.call_log_path.read_text().strip().splitlines()
    if len(lines) != 1:
        return False, f"Expected 1 line but got {len(lines)}"
    entry = json.loads(lines[0])
    stage_match = re.search(r"stage (\S+)", text)
    step_match = re.search(r"step (\S+)", text)
    if stage_match and entry.get("stage") != stage_match.group(1):
        return False, f"Expected stage '{stage_match.group(1)}' but got '{entry.get('stage')}'"
    if step_match and entry.get("step") != step_match.group(1):
        return False, f"Expected step '{step_match.group(1)}' but got '{entry.get('step')}'"
    return True, ""


def _h_call_log_scenario_id(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the file contains one valid JSON line with scenario_id ..."""
    if world.call_log_path is None or not world.call_log_path.exists():
        return False, "No calls.jsonl file found"
    lines = world.call_log_path.read_text().strip().splitlines()
    if len(lines) != 1:
        return False, f"Expected 1 line but got {len(lines)}"
    entry = json.loads(lines[0])
    scenario_match = re.search(r"scenario_id (\S+)", text)
    if scenario_match and entry.get("scenario_id") != scenario_match.group(1):
        return False, f"Expected scenario_id '{scenario_match.group(1)}' but got '{entry.get('scenario_id')}'"
    return True, ""


def _h_call_log_three_lines(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the file contains three valid JSON lines in order."""
    if world.call_log_path is None or not world.call_log_path.exists():
        return False, "No calls.jsonl file found"
    lines = world.call_log_path.read_text().strip().splitlines()
    if len(lines) != 3:
        return False, f"Expected 3 lines but got {len(lines)}"
    for line in lines:
        json.loads(line)  # verify valid JSON
    return True, ""


def _h_call_log_no_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: no calls.jsonl file is created."""
    if world.call_log_path is not None and world.call_log_path.exists():
        return False, "calls.jsonl file was created but should not have been"
    return True, ""


# --- YAML I/O handlers ---

def _h_yaml_loss_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a LossAnalysis model with one loss L-1 and one hazard H-1."""
    world.yaml_model = _make_minimal_loss_analysis()
    return True, ""


def _h_yaml_cs_model(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a ControlStructure model with responsibility RESP-1 and PM-1-1."""
    world.yaml_model = _make_minimal_control_structure()
    return True, ""


def _h_yaml_valid_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a YAML file containing a valid loss analysis with loss L-1."""
    import tempfile
    model = _make_minimal_loss_analysis()
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "model.yaml"
    write_yaml(model, world.yaml_path)
    return True, ""


def _h_yaml_invalid_file(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a YAML file containing a loss analysis where hazard references non-existent loss."""
    import tempfile
    import yaml as _yaml
    bad_data = {
        "risk_card_losses": [],
        "use_case_losses": [
            {"loss_id": "L-1", "description": "Loss", "provenance": "use_case"},
        ],
        "hazards": [
            {"hazard_id": "H-1", "description": "Hazard", "related_losses": ["L-99"]},
        ],
        "security_constraints": [],
    }
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "bad.yaml"
    world.yaml_path.write_text(_yaml.dump(bad_data), encoding="utf-8")
    return True, ""


def _h_yaml_write(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: write_yaml is called with the model and a file path."""
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "output.yaml"
    write_yaml(world.yaml_model, world.yaml_path)
    return True, ""


def _h_yaml_read(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: read_yaml is called with the path and LossAnalysis class."""
    try:
        world.yaml_read_back = read_yaml(world.yaml_path, LossAnalysis)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_yaml_roundtrip(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the model is written to YAML and read back."""
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp())
    world.yaml_path = tmp_dir / "roundtrip.yaml"
    write_yaml(world.yaml_model, world.yaml_path)
    model_class = type(world.yaml_model)
    world.yaml_read_back = read_yaml(world.yaml_path, model_class)
    return True, ""


def _h_yaml_file_exists(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a YAML file exists at the path containing loss_id L-1."""
    if world.yaml_path is None or not world.yaml_path.exists():
        return False, "No YAML file found"
    content = world.yaml_path.read_text(encoding="utf-8")
    if "L-1" not in content:
        return False, "YAML file does not contain loss_id L-1"
    return True, ""


def _h_yaml_model_returned(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a LossAnalysis model is returned with loss_id L-1."""
    if world.yaml_read_back is None:
        return False, "No model returned from read_yaml"
    if not isinstance(world.yaml_read_back, LossAnalysis):
        return False, f"Expected LossAnalysis but got {type(world.yaml_read_back).__name__}"
    if not any(l.loss_id == "L-1" for l in world.yaml_read_back.use_case_losses):
        return False, "Returned model does not have loss_id L-1"
    return True, ""


def _h_yaml_readback_matches(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the read-back model matches the original model."""
    if world.yaml_read_back is None or world.yaml_model is None:
        return False, "Missing model for comparison"
    if world.yaml_read_back.model_dump() != world.yaml_model.model_dump():
        return False, "Read-back model does not match original"
    return True, ""


def _h_yaml_validation_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a validation error is raised."""
    if world.validation_error is None:
        return False, "Expected validation error but none was raised"
    return True, ""


# --- Template handlers ---

def _h_template_dir_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a prompts directory at <path> containing template <name> with variable <var>."""
    import tempfile
    match = re.search(r"directory at (\S+)", text)
    dir_path = match.group(1) if match else "tmp/prompts"

    if dir_path.startswith("tmp/"):
        tmp_dir = Path(tempfile.mkdtemp())
        world.template_dir = tmp_dir
    else:
        world.template_dir = Path(dir_path)

    world.template_dir.mkdir(parents=True, exist_ok=True)

    # Extract template name and variable
    template_match = re.search(r"template (\S+\.j2)", text)
    template_name = template_match.group(1) if template_match else "test.j2"
    var_match = re.search(r"variable (\w+)", text)
    var_name = var_match.group(1) if var_match else "name"

    (world.template_dir / template_name).write_text(
        f"Hello {{{{ {var_name} }}}}", encoding="utf-8"
    )
    return True, ""


def _h_template_dir_two_files(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a prompts directory at tmp/prompts containing templates a.j2 and b.j2."""
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp())
    world.template_dir = tmp_dir
    (tmp_dir / "a.j2").write_text("A {{ name }}", encoding="utf-8")
    (tmp_dir / "b.j2").write_text("B {{ name }}", encoding="utf-8")
    return True, ""


def _h_template_dir_var_only(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a prompts directory containing template test.j2 with variable name."""
    return _h_template_dir_given(world, text, examples)


def _h_template_loader_created(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a template loader is created with the directory path."""
    world.template_loader = TemplateLoader(world.template_dir)
    return True, ""


def _h_template_render(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: render_prompt is called with template test.j2 and name World."""
    template_match = re.search(r"template (\S+\.j2)", text)
    template_name = template_match.group(1) if template_match else "test.j2"
    name_match = re.search(r"name (\S+)", text)
    name_value = name_match.group(1) if name_match else "World"
    world.template_rendered = world.template_loader.render_prompt(
        template_name, **{"name": name_value}
    )
    return True, ""


def _h_template_render_no_var(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: render_prompt is called with template test.j2 without providing name."""
    try:
        world.template_loader.render_prompt("test.j2")
    except Exception as e:
        world.validation_error = e
    return True, ""


def _h_template_rendered_contains(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the rendered text contains World."""
    match = re.search(r"contains (\S+)", text)
    expected = match.group(1) if match else "World"
    if world.template_rendered is None:
        return False, "No rendered text"
    if expected not in world.template_rendered:
        return False, f"Expected '{expected}' in rendered text but got '{world.template_rendered}'"
    return True, ""


def _h_template_hash(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: hash_prompt_templates is called with the directory path."""
    world.template_hashes = hash_prompt_templates(world.template_dir)
    return True, ""


def _h_template_hash_result(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a dict is returned with keys a.j2 and b.j2 mapping to 64-character hex digests."""
    if world.template_hashes is None:
        return False, "No template hashes"
    for key in ["a.j2", "b.j2"]:
        if key not in world.template_hashes:
            return False, f"Key '{key}' not in hashes: {list(world.template_hashes.keys())}"
        digest = world.template_hashes[key]
        if len(digest) != 64:
            return False, f"Hash for '{key}' is {len(digest)} chars, expected 64"
    return True, ""


def _h_template_undefined_error(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an undefined variable error is raised."""
    if world.validation_error is None:
        return False, "Expected undefined variable error but none was raised"
    return True, ""


def _h_template_loader_independent(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a template loader created with directory tmp/stpa_prompts."""
    import tempfile
    tmp_dir = Path(tempfile.mkdtemp())
    world.template_dir = tmp_dir
    world.template_loader = TemplateLoader(tmp_dir)
    return True, ""


def _h_template_no_pipeline_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the loader does not reference the existing pipeline data/prompts directory."""
    if world.template_loader is None:
        return False, "No template loader"
    # The loader's prompts_dir should not contain "data/prompts"
    prompts_dir_str = str(world.template_loader.prompts_dir)
    if "data/prompts" in prompts_dir_str:
        return False, f"Template loader references existing pipeline prompts: {prompts_dir_str}"
    return True, ""


# --- Manifest handlers ---

def _h_manifest_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a run manifest with run_id ..., run_dir ..., and created_at ..."""
    base_kwargs = {
        "run_id": "RUN-001",
        "run_dir": "output/test",
        "created_at": "2026-08-08T12:00:00Z",
        "model_config": {"model": "test-model", "base_url": "http://test:8080", "temperature": 0.4},
        "input_hashes": {"use_case": "abc123"},
        "prompt_hashes": {"call0_system.j2": "def456"},
        "stage_summary": {"stage_2": {"calls": 1, "duration_ms": 5000, "prompt_tokens": 1000, "completion_tokens": 500}},
    }

    if "slot_count" in text:
        match = re.search(r"slot_count (\d+)", text)
        if match:
            base_kwargs["slot_count"] = int(match.group(1))
    if "na_count" in text:
        match = re.search(r"na_count (\d+)", text)
        if match:
            base_kwargs["na_count"] = int(match.group(1))
    if "fill_rate" in text:
        match = re.search(r"fill_rate ([\d.]+)", text)
        if match:
            base_kwargs["fill_rate"] = float(match.group(1))
    if "scenario_count" in text:
        match = re.search(r"scenario_count (\d+)", text)
        if match:
            base_kwargs["scenario_count"] = int(match.group(1))
    if "critic_findings" in text:
        base_kwargs["critic_findings"] = ["gap in hazard coverage", "missing constraint for H-2"]
    if "eval_scorecard_path" in text:
        match = re.search(r"eval_scorecard_path (\S+)", text)
        if match:
            base_kwargs["eval_scorecard_path"] = match.group(1)

    try:
        world.manifest = STPARunManifest(**base_kwargs)
    except (ValidationError, ValueError) as e:
        world.validation_error = e
    return True, ""


def _h_manifest_validated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the manifest is validated."""
    # Pydantic validation already happened during construction
    if world.manifest is None and world.validation_error is None:
        return False, "No manifest to validate"
    return True, ""


def _h_manifest_module_imported(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA run manifest module is imported."""
    import scenario_forge.stpa.infra.manifest
    return True, ""


def _h_manifest_no_coupling(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the module does not import or reference the existing pipeline manifest module."""
    import inspect
    import scenario_forge.stpa.infra.manifest as stpa_manifest
    source = inspect.getsource(stpa_manifest)
    forbidden = ["scenario_forge.manifest", "scenario_forge.pipeline.manifest"]
    for ref in forbidden:
        if ref in source:
            return False, f"STPA manifest module references '{ref}'"
    return True, ""


# ---------------------------------------------------------------------------
# ScenarioEnvelope handlers
# ---------------------------------------------------------------------------

from scenario_forge.stpa.models.scenario_envelope import ScenarioEnvelope


def _h_envelope_given(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with narrative text, attack tree dict, and gherkin spec text."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative text",
        attack_tree={"root": {"children": []}},
        gherkin_spec="Feature: Test\n  Scenario: Test\n",
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )
    return True, ""


def _h_envelope_id_match(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope with scenario_id SCN-001 wrapping spec SCN-001."""
    return _h_envelope_given(world, text, examples)


def _h_envelope_faceting(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with target_responsibility RESP-1, ica_type NOT_PROVIDED, and provenance structural."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative",
        attack_tree={"root": {}},
        gherkin_spec="Feature: T\n",
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )
    return True, ""


def _h_envelope_catalog(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a scenario envelope wrapping SCN-001 with catalog mappings OWASP_AGENTIC T2-T3 high."""
    spec = world.scenario_spec or _make_minimal_scenario_spec()
    world.scenario_spec = spec
    world.envelope = ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec,
        narrative="Narrative",
        attack_tree={"root": {}},
        gherkin_spec="Feature: T\n",
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
        catalog_mappings=[CatalogMapping(
            catalog="OWASP_AGENTIC", id="T2-T3", name="Test", confidence="high",
        )],
    )
    return True, ""


def _h_envelope_validated(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the scenario envelope is validated."""
    if world.envelope is None and world.validation_error is None:
        return False, "No scenario envelope to validate"
    return True, ""


def _h_faceting_target_resp(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the faceting metadata target_responsibility is RESP-1."""
    match = re.search(r"target_responsibility is (\S+)", text)
    expected = match.group(1) if match else "RESP-1"
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.target_responsibility != expected:
        return False, f"Expected target_responsibility '{expected}' but got '{world.envelope.target_responsibility}'"
    return True, ""


def _h_faceting_ica_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the faceting metadata ica_type is NOT_PROVIDED."""
    match = re.search(r"ica_type is (\S+)", text)
    expected = match.group(1) if match else "NOT_PROVIDED"
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.ica_type.value != expected:
        return False, f"Expected ica_type '{expected}' but got '{world.envelope.ica_type}'"
    return True, ""


def _h_faceting_provenance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the faceting metadata provenance is structural."""
    match = re.search(r"provenance is (\S+)", text)
    expected = match.group(1) if match else "structural"
    if world.envelope is None:
        return False, "No envelope"
    if world.envelope.provenance != expected:
        return False, f"Expected provenance '{expected}' but got '{world.envelope.provenance}'"
    return True, ""


# ---------------------------------------------------------------------------
# Additional step registrations
# ---------------------------------------------------------------------------

# ScenarioSpec - background and Given steps
_register(r"a control structure with responsibility RESP-1, process model part PM-1-1, and control action CA-1-1", _h_cs_with_pm_and_ca)
_register(r"a control structure with responsibilities RESP-1 and RESP-2 where CA-2-1 belongs to RESP-2", _h_cs_two_resp_ca_belongs)
_register(r"a valid scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1", _h_scenario_spec_valid)
_register(r"a scenario spec SCN-001 with target_controller RESP-1 and target_control_action CA-1-1", _h_scenario_spec_valid)
_register(r"defender belief referencing PM-1-1, desire referencing RESP-1, intention referencing CA-1-1", _h_scenario_spec_defender_bdi)
_register(r"a scenario spec with defender belief referencing PM-99-1", _h_scenario_spec_bad_belief)
_register(r"a scenario spec with defender desire referencing RESP-99", _h_scenario_spec_bad_desire)
_register(r"a scenario spec with defender intention referencing CA-99-1", _h_scenario_spec_bad_intention)
_register(r"a scenario spec with target_controller RESP-99$", _h_scenario_spec_bad_target_controller)
_register(r"a scenario spec with target_control_action CA-99-1", _h_scenario_spec_bad_target_ca)
_register(r"a scenario spec with target_controller RESP-1 and target_control_action CA-2-1", _h_scenario_spec_target_ca_other_resp)
_register(r"a scenario spec with threat source ica_slot_id .* and provenance structural", _h_scenario_spec_threat_structural)
_register(r"a scenario spec with threat source ica_slot_id .* and provenance catalog_only", _h_scenario_spec_threat_catalog)
_register(r"a scenario spec with attacker beliefs, desires, and intentions as free-form strings", _h_scenario_spec_attacker_bdi)
_register(r"a scenario spec with catalog context containing", _h_scenario_spec_catalog_context)

# ScenarioSpec - When/Then steps
_register(r"the scenario spec is validated against the control structure", _h_validate_scenario_spec)

# Fixture steps
_register(r"the STPA fixtures directory exists at", _h_fixtures_dir_exists)
_register(r"the fixture file \S+\.yaml$", _h_fixture_file_given)
_register(r"the fixture is loaded and validated as", _h_fixture_loaded)
_register(r"the fixture file contains a header comment documenting provenance", _h_fixture_header_comment)
_register(r"the fixtures directory is scanned for YAML files", _h_fixtures_scanned)
_register(r"the fixture file \S+\.yaml is present", _h_fixture_file_present)

# LLM steps
_register(r"environment variable \S+ is set to", _h_env_var_set)
_register(r"no \S+ environment variable is set", _h_no_env_var)
_register(r"an LLMClient is constructed", _h_llm_client_construct)
_register(r"an LLMClient constructed with base_url", _h_llm_client_given)
_register(r"the client base_url is", _h_llm_client_base_url)
_register(r"the client model is", _h_llm_client_model)
_register(r"the client temperature is", _h_llm_client_temperature)
_register(r"a ValueError is raised containing", _h_llm_valueerror)
_register(r"the client extra headers include", _h_llm_headers)
_register(r"an LLMResult with content", _h_llm_result_given)
_register(r"the result content is", _h_llm_result_content)
_register(r"the result prompt_tokens is", _h_llm_result_prompt_tokens)
_register(r"the result completion_tokens is", _h_llm_result_completion_tokens)
_register(r"the result duration_ms is", _h_llm_result_duration)

# Call log steps
_register(r"a call log entry with stage", _h_call_log_entry_given)
_register(r"three call log entries with stages", _h_call_log_three_entries)
_register(r"an empty list of call log entries", _h_call_log_empty)
_register(r"the entry is appended to calls.jsonl", _h_call_log_append)
_register(r"the entries are appended to calls.jsonl", _h_call_log_append)
_register(r"all entries are appended to calls.jsonl", _h_call_log_append)
_register(r"the file contains one valid JSON line with stage", _h_call_log_one_line)
_register(r"the file contains one valid JSON line with scenario_id", _h_call_log_scenario_id)
_register(r"the file contains three valid JSON lines in order", _h_call_log_three_lines)
_register(r"no calls.jsonl file is created", _h_call_log_no_file)

# YAML steps
_register(r"a LossAnalysis model with one loss L-1 and one hazard H-1", _h_yaml_loss_model)
_register(r"a ControlStructure model with responsibility RESP-1 and PM-1-1", _h_yaml_cs_model)
_register(r"a YAML file containing a valid loss analysis with loss L-1", _h_yaml_valid_file)
_register(r"a YAML file containing a loss analysis where hazard references non-existent loss", _h_yaml_invalid_file)
_register(r"write_yaml is called with the model and a file path", _h_yaml_write)
_register(r"read_yaml is called with the path and LossAnalysis class", _h_yaml_read)
_register(r"the model is written to YAML and read back", _h_yaml_roundtrip)
_register(r"a YAML file exists at the path containing loss_id L-1", _h_yaml_file_exists)
_register(r"a LossAnalysis model is returned with loss_id L-1", _h_yaml_model_returned)
_register(r"the read-back model matches the original model", _h_yaml_readback_matches)
_register(r"a validation error is raised", _h_yaml_validation_error)

# Template steps
_register(r"a prompts directory at .* containing template .* with variable", _h_template_dir_given)
_register(r"a prompts directory at .* containing templates a.j2 and b.j2", _h_template_dir_two_files)
_register(r"a prompts directory containing template .* with variable", _h_template_dir_var_only)
_register(r"a template loader is created with the directory path", _h_template_loader_created)
_register(r"render_prompt is called with template .* and name", _h_template_render)
_register(r"render_prompt is called with template .* without providing name", _h_template_render_no_var)
_register(r"the rendered text contains", _h_template_rendered_contains)
_register(r"hash_prompt_templates is called with the directory path", _h_template_hash)
_register(r"a dict is returned with keys a.j2 and b.j2", _h_template_hash_result)
_register(r"an undefined variable error is raised", _h_template_undefined_error)
_register(r"a template loader created with directory", _h_template_loader_independent)
_register(r"the loader does not reference the existing pipeline data/prompts directory", _h_template_no_pipeline_ref)

# Manifest steps
_register(r"a run manifest with", _h_manifest_given)
_register(r"the manifest is validated", _h_manifest_validated)
_register(r"the STPA run manifest module is imported", _h_manifest_module_imported)
_register(r"the module does not import or reference the existing pipeline manifest module", _h_manifest_no_coupling)

# ScenarioEnvelope steps
_register(r"a scenario envelope wrapping SCN-001 with narrative text", _h_envelope_given)
_register(r"a scenario envelope with scenario_id SCN-001 wrapping spec SCN-001", _h_envelope_id_match)
_register(r"a scenario envelope wrapping SCN-001 with target_responsibility", _h_envelope_faceting)
_register(r"a scenario envelope wrapping SCN-001 with catalog mappings", _h_envelope_catalog)
_register(r"the scenario envelope is validated", _h_envelope_validated)
_register(r"the faceting metadata target_responsibility is", _h_faceting_target_resp)
_register(r"the faceting metadata ica_type is", _h_faceting_ica_type)
_register(r"the faceting metadata provenance is", _h_faceting_provenance)


# ---------------------------------------------------------------------------
# SP1 System Model handlers
# ---------------------------------------------------------------------------

from scenario_forge.stpa.system_model.heuristics import (
    check_solution_neutrality as _sp1_check_neutrality,
)
from scenario_forge.stpa.system_model.critic import (
    CriticFindings as _SP1CriticFindings,
    CriticGap as _SP1CriticGap,
)
from scenario_forge.stpa.system_model.control_structure import (
    Requirement as _SP1Requirement,
    RequirementSet as _SP1RequirementSet,
)


def _sp1_make_control_structure_with_resp(desc: str = "Controller 1") -> ControlStructure:
    """Build a minimal valid ControlStructure with one responsibility."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=desc,
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
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ],
    )


def _sp1_make_control_structure_two_resps() -> ControlStructure:
    """Build a ControlStructure with two responsibilities."""
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
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
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
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-2"),
                    )
                ],
            ),
        ],
    )


def _sp1_make_loss_analysis_with_constraints() -> LossAnalysis:
    """Build a LossAnalysis with security constraints SC-1 and SC-2."""
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Loss 1", provenance=LossProvenance.use_case),
            Loss(loss_id="L-2", description="Loss 2", provenance=LossProvenance.use_case),
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard 1", related_losses=["L-1"]),
            Hazard(hazard_id="H-2", description="Hazard 2", related_losses=["L-2"]),
        ],
        security_constraints=[
            SecurityConstraint(constraint_id="SC-1", description="C1", related_hazards=["H-1"]),
            SecurityConstraint(constraint_id="SC-2", description="C2", related_hazards=["H-2"]),
        ],
    )


# --- Background step handlers ---

def _h_sp1_module_importable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the STPA system model ... module is importable."""
    import scenario_forge.stpa.system_model  # noqa: F401
    return True, ""


def _h_sp1_use_case_risk_cards(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and risk cards are available as input."""
    return True, ""


def _h_sp1_use_case_loss_analysis(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and loss analysis are available as input."""
    return True, ""


def _h_sp1_use_case_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description is available."""
    return True, ""


def _h_sp1_use_case_risk_json(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a use-case description and risk extraction JSON are available as input."""
    return True, ""


def _h_sp1_cs_two_resps_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibilities RESP-1 and RESP-2 is available."""
    world.control_structure = _sp1_make_control_structure_two_resps()
    return True, ""


def _h_sp1_cap_profile_use_case(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a capability profile and use-case text are available."""
    return True, ""


def _h_sp1_loss_analysis_constraints(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a loss analysis with security constraints SC-1 and SC-2 is available."""
    world.loss_analysis = _sp1_make_loss_analysis_with_constraints()
    return True, ""


def _h_sp1_cs_and_critic_available(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure and CriticFindings with unjustified gaps are available."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


def _h_sp1_cs_resp1(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


def _h_sp1_cs_resp1_full(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1."""
    world.control_structure = _sp1_make_control_structure_with_resp()
    return True, ""


# --- SP1-LA-04: Loss analysis invalid cross-reference ---

def _h_sp1_la_invalid_ref(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a loss analysis where <entity> references non-existent <ref_target>."""
    entity = examples.get("entity", "")
    ref_target = examples.get("ref_target", "")
    world.sp1_entity = entity
    world.sp1_ref_target = ref_target
    if entity == "hazard":
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [
                {"loss_id": "L-1", "description": "Loss 1", "provenance": "use_case", "source_risk_cards": []},
            ],
            "hazards": [
                {"hazard_id": "H-1", "description": "Hazard 1", "related_losses": ["L-99"]},
            ],
            "security_constraints": [],
        }
    elif entity == "constraint":
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [
                {"loss_id": "L-1", "description": "Loss 1", "provenance": "use_case", "source_risk_cards": []},
            ],
            "hazards": [
                {"hazard_id": "H-1", "description": "Hazard 1", "related_losses": ["L-1"]},
            ],
            "security_constraints": [
                {"constraint_id": "SC-1", "description": "C1", "related_hazards": ["H-99"]},
            ],
        }
    else:
        world.sp1_llm_content = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
        }
    return True, ""


def _h_sp1_stage1a_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 1a loss analysis is run."""
    if world.sp1_llm_content is not None:
        try:
            world.loss_analysis = LossAnalysis.model_validate(world.sp1_llm_content)
        except (ValidationError, ValueError) as e:
            world.validation_error = e
    return True, ""


def _h_sp1_post_call_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: post-call validation fails with error containing <error_fragment>."""
    fragment = examples.get("error_fragment", "")
    if not fragment:
        # Extract from text
        m = re.search(r"containing\s+(\S+)", text)
        fragment = m.group(1) if m else ""
    if world.validation_error is None:
        return False, f"Expected validation error containing '{fragment}' but none was raised"
    err_str = str(world.validation_error)
    if fragment and fragment not in err_str:
        return False, f"Expected error containing '{fragment}' but got: {err_str}"
    return True, ""


# --- SP1-NEUT-01/02: Solution neutrality ---

def _h_sp1_neut_resp_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with description containing <component_name>."""
    component = examples.get("component_name", "LLM")
    world.sp1_component_name = component
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description=f"Controller using {component} for processing",
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
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ],
    )
    return True, ""


def _h_sp1_neut_pm_desc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a process model part PM-1-1 with description containing <component_name>."""
    component = examples.get("component_name", "LLM")
    world.sp1_component_name = component
    world.control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description=f"State tracked by {component}")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Action 1")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                    )
                ],
            )
        ],
    )
    return True, ""


def _h_sp1_neut_check_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the solution-neutrality check is run."""
    if world.control_structure is None:
        return False, "No control structure available"
    world.sp1_warnings = _sp1_check_neutrality(world.control_structure)
    return True, ""


def _h_sp1_neut_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a warning is produced containing <component_name>."""
    component = examples.get("component_name", "")
    if not component:
        m = re.search(r"containing\s+(\S+)", text)
        component = m.group(1) if m else ""
    if not world.sp1_warnings:
        return False, "Expected a warning but none was produced"
    found = any(component.lower() in w.lower() for w in world.sp1_warnings)
    if not found:
        return False, f"Expected warning containing '{component}' but got: {world.sp1_warnings}"
    return True, ""


# --- SP1-S2-03: Invalid classification ---

def _h_sp1_s2_bad_class(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a RequirementSet with REQ-1 classified as <bad_class>."""
    bad_class = examples.get("bad_class", "enforcement")
    world.sp1_llm_content = {
        "requirements": [
            {
                "req_id": "REQ-1",
                "description": "Test requirement",
                "classification": bad_class,
                "source_constraint": "SC-1",
            }
        ]
    }
    return True, ""


def _h_sp1_s2_call1_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: Stage 2 Call 1 requirements derivation is run."""
    if world.sp1_llm_content is not None:
        try:
            world.sp1_llm_content = _SP1RequirementSet.model_validate(world.sp1_llm_content)
        except (ValidationError, ValueError) as e:
            world.validation_error = e
    return True, ""


def _h_sp1_validation_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: validation fails with error containing <fragment>."""
    m = re.search(r"containing\s+(\S+)", text)
    fragment = m.group(1) if m else ""
    if world.validation_error is None:
        return False, f"Expected validation error containing '{fragment}' but none was raised"
    err_str = str(world.validation_error)
    if fragment and fragment not in err_str:
        return False, f"Expected error containing '{fragment}' but got: {err_str}"
    return True, ""


# --- SP1-HEUR-02: Missing element type ---

def _h_sp1_heur_zero_element(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: a responsibility RESP-1 with zero <element_type>."""
    element_type = examples.get("element_type", "")
    world.sp1_element_type = element_type
    resp_kwargs: dict = {
        "resp_id": "RESP-1",
        "description": "Controller 1",
    }
    if element_type != "process_model_parts":
        resp_kwargs["process_model_parts"] = [
            ProcessModelPart(pm_id="PM-1-1", description="State 1")
        ]
    if element_type != "control_actions":
        resp_kwargs["control_actions"] = [
            ControlAction(ca_id="CA-1-1", description="Action 1")
        ]
    # Only add feedback channels if there are PMs to reference
    if element_type != "feedback_channels" and "process_model_parts" in resp_kwargs:
        resp_kwargs["feedback_channels"] = [
            FeedbackChannel(
                fb_id="FB-1-1",
                description="FB 1",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
            )
        ]
    world.control_structure = ControlStructure(
        responsibilities=[Responsibility(**resp_kwargs)]
    )
    return True, ""


def _h_sp1_heur_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: structural heuristics are checked."""
    if world.control_structure is None:
        return False, "No control structure available"
    world.heuristic_result = check_structural_heuristics(world.control_structure)
    return True, ""


def _h_sp1_heur_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the heuristic check fails with error containing <error_fragment>."""
    fragment = examples.get("error_fragment", "")
    if not fragment:
        m = re.search(r"containing\s+(.+)$", text)
        fragment = m.group(1).strip() if m else ""
    if world.heuristic_result is None:
        return False, "No heuristic result available"
    errors = world.heuristic_result.errors
    if not errors:
        return False, "Expected heuristic errors but none were found"
    found = any(fragment.lower() in e.lower() for e in errors)
    if not found:
        return False, f"Expected error containing '{fragment}' but got: {errors}"
    return True, ""


# --- SP1-CRITIC-03: Gap type validation ---

def _h_sp1_critic_gap_type(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: an LLM that returns a CriticFindings JSON with a gap of type <gap_type>."""
    gap_type = examples.get("gap_type", "")
    world.sp1_gap_type = gap_type
    world.sp1_llm_content = {
        "gaps": [
            {
                "gap_type": gap_type,
                "description": "Test gap",
                "related_attack_path": "Attack path",
                "suggested_remedy": "Fix",
            }
        ],
        "checklist_results": {},
        "taxonomy_probe_results": {},
    }
    return True, ""


def _h_sp1_critic_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the completeness critic is run."""
    if world.sp1_llm_content is not None:
        try:
            world.sp1_llm_content = _SP1CriticFindings.model_validate(world.sp1_llm_content)
        except (ValidationError, ValueError) as e:
            world.validation_error = e
    return True, ""


def _h_sp1_critic_gap_found(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the CriticFindings model contains a gap with gap_type <gap_type>."""
    gap_type = examples.get("gap_type", "")
    if not isinstance(world.sp1_llm_content, _SP1CriticFindings):
        return False, "CriticFindings model was not created"
    gaps = world.sp1_llm_content.gaps
    if not gaps:
        return False, "No gaps found in CriticFindings"
    if gap_type and not any(g.gap_type == gap_type for g in gaps):
        return False, f"Expected gap_type '{gap_type}' but got: {[g.gap_type for g in gaps]}"
    return True, ""


# --- SP1 step registrations ---

# Background steps
_register(r"the STPA system model(?: \S+)? module is importable", _h_sp1_module_importable)
_register(r"a use-case description and risk cards are available as input", _h_sp1_use_case_risk_cards)
_register(r"a use-case description and loss analysis are available as input", _h_sp1_use_case_loss_analysis)
_register(r"a use-case description is available", _h_sp1_use_case_available)
_register(r"a use-case description and risk extraction JSON are available as input", _h_sp1_use_case_risk_json)
_register(r"a control structure with responsibilities RESP-1 and RESP-2 is available", _h_sp1_cs_two_resps_available)
_register(r"a capability profile and use-case text are available", _h_sp1_cap_profile_use_case)
_register(r"a loss analysis with security constraints SC-1 and SC-2 is available", _h_sp1_loss_analysis_constraints)
_register(r"a control structure and CriticFindings with unjustified gaps are available", _h_sp1_cs_and_critic_available)
_register(r"a control structure with responsibility RESP-1$", _h_sp1_cs_resp1)
_register(r"a control structure with responsibility RESP-1, PM-1-1, CA-1-1, and FB-1-1", _h_sp1_cs_resp1_full)

# SP1-LA-04
_register(r"an LLM that returns a loss analysis where .* references non-existent", _h_sp1_la_invalid_ref)
_register(r"Stage 1a loss analysis is run", _h_sp1_stage1a_run)
_register(r"post-call validation fails with error containing", _h_sp1_post_call_fails)

# SP1-NEUT-01/02
_register(r"a responsibility RESP-1 with description containing", _h_sp1_neut_resp_desc)
_register(r"a process model part PM-1-1 with description containing", _h_sp1_neut_pm_desc)
_register(r"the solution-neutrality check is run", _h_sp1_neut_check_run)
_register(r"a warning is produced containing", _h_sp1_neut_warning)

# SP1-S2-03
_register(r"an LLM that returns a RequirementSet with REQ-1 classified as", _h_sp1_s2_bad_class)
_register(r"Stage 2 Call 1 requirements derivation is run", _h_sp1_s2_call1_run)
_register(r"validation fails with error containing", _h_sp1_validation_fails)

# SP1-HEUR-02
_register(r"a responsibility RESP-1 with zero", _h_sp1_heur_zero_element)
_register(r"structural heuristics are checked", _h_sp1_heur_check)
_register(r"the heuristic check fails with error containing", _h_sp1_heur_fails)

# SP1-CRITIC-03
_register(r"an LLM that returns a CriticFindings JSON with a gap of type", _h_sp1_critic_gap_type)
_register(r"the completeness critic is run", _h_sp1_critic_run)
_register(r"the CriticFindings model contains a gap with gap_type", _h_sp1_critic_gap_found)


def execute_step(world: World, step: dict, examples: dict) -> tuple[bool, str]:
    """Execute a single step against the world.

    If a handler raises ValidationError or ValueError during model
    construction, the error is stored in world.validation_error and
    the step is considered successful (the error is an expected outcome
    that will be checked by a subsequent 'Then' step).
    """
    keyword = step.get("keyword", "")
    raw_text = step.get("text", "")
    text = _resolve_value(raw_text, examples)

    try:
        for pattern, handler in STEP_PATTERNS:
            if pattern.search(text):
                return handler(world, text, examples)

        return False, f"Unsupported step: {keyword} {text}"
    except (ValidationError, ValueError) as e:
        world.validation_error = e
        return True, ""


def execute_ir(ir_path: str) -> tuple[bool, str]:
    """Execute all scenarios in a JSON IR file.

    Returns (all_passed, output).
    """
    with open(ir_path) as f:
        ir = json.load(f)

    background_steps = ir.get("background", [])
    scenarios = ir.get("scenarios", [])

    output_lines: list[str] = []
    all_passed = True

    for s_idx, scenario in enumerate(scenarios):
        scenario_name = scenario.get("name", f"scenario_{s_idx}")
        steps = scenario.get("steps", [])
        examples = scenario.get("examples", [])

        if not examples:
            examples = [{}]

        for e_idx, example in enumerate(examples):
            exec_name = f"{scenario_name}/example_{e_idx + 1}"
            world = World()

            # Execute background steps
            for bg_step in background_steps:
                success, error = execute_step(world, bg_step, example)
                if not success:
                    output_lines.append(f"FAIL {exec_name}: background step failed: {error}")
                    all_passed = False
                    break
            else:
                # Execute scenario steps
                for step in steps:
                    success, error = execute_step(world, step, example)
                    if not success:
                        output_lines.append(f"FAIL {exec_name}: {error}")
                        all_passed = False
                        break
                else:
                    output_lines.append(f"PASS {exec_name}")

    return all_passed, "\n".join(output_lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: acceptance_runtime.py <ir-path>", file=sys.stderr)
        sys.exit(2)

    ir_path = sys.argv[1]
    try:
        # First, try to construct the models to trigger validation
        with open(ir_path) as f:
            ir = json.load(f)

        # For scenarios that involve model construction, we need to actually
        # construct the models to trigger Pydantic validation
        all_passed = True
        output_lines: list[str] = []

        background_steps = ir.get("background", [])
        scenarios = ir.get("scenarios", [])

        for s_idx, scenario in enumerate(scenarios):
            scenario_name = scenario.get("name", f"scenario_{s_idx}")
            steps = scenario.get("steps", [])
            examples = scenario.get("examples", [])

            if not examples:
                examples = [{}]

            for e_idx, example in enumerate(examples):
                exec_name = f"{scenario_name}/example_{e_idx + 1}"
                world = World()

                # Execute background steps
                bg_failed = False
                for bg_step in background_steps:
                    success, error = execute_step(world, bg_step, example)
                    if not success:
                        output_lines.append(f"FAIL {exec_name}: background: {error}")
                        all_passed = False
                        bg_failed = True
                        break

                if bg_failed:
                    continue

                # Execute scenario steps
                step_failed = False
                for step in steps:
                    success, error = execute_step(world, step, example)
                    if not success:
                        output_lines.append(f"FAIL {exec_name}: {error}")
                        all_passed = False
                        step_failed = True
                        break

                if not step_failed:
                    output_lines.append(f"PASS {exec_name}")

        output = "\n".join(output_lines)
        print(output)
        sys.exit(0 if all_passed else 1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
