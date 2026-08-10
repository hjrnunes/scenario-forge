"""Unit tests for SP2 Stage 3 Phase 2 — LLM slot-filling."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from scenario_forge.stpa.infra.templates import TemplateLoader
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
    ControlledProcess,
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
from scenario_forge.stpa.threat_enum._constants import PROMPTS_DIR
from scenario_forge.stpa.threat_enum.slot_creation import create_slots
from scenario_forge.stpa.threat_enum.slot_filling import (
    ICASlotFillResult,
    build_slot_filling_prompts,
    fill_all_slots,
)

from tests.stpa.sp1_helpers import MockLLMClient


def _make_test_control_structure() -> ControlStructure:
    """Build a control structure with 2 responsibilities, 2 CAs each, 1 coordination link."""
    cps = [
        ControlledProcess(cp_id="CP-1", description="P1"),
        ControlledProcess(cp_id="CP-2", description="P2"),
    ]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        responsibility_constraints=[
            {"rc_id": "RC-1-1", "description": "Must validate"}
        ],
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-1-{j+1}",
                description=f"Action {j+1}",
                target=ElementRef(type=ReferenceType.controlled_process, id=f"CP-{j+1}"),
            )
            for j in range(2)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="F",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    resp2 = Responsibility(
        resp_id="RESP-2",
        description="R2",
        process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="State")],
        control_actions=[
            ControlAction(
                ca_id=f"CA-2-{j+1}",
                description=f"Action {j+1}",
                target=ElementRef(type=ReferenceType.controlled_process, id=f"CP-{j+1}"),
            )
            for j in range(2)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-2-1",
                description="F",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-2"),
            )
        ],
    )
    link = CoordinationLink(
        link_id="CL-1",
        source="RESP-1",
        target="RESP-2",
        shared_pm="PM-1-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Mechanism", payload="data"
        ),
        description="Link",
    )
    return ControlStructure(
        responsibilities=[resp1, resp2],
        controlled_processes=cps,
        coordination_links=[link],
    )


def _make_test_loss_analysis() -> LossAnalysis:
    """Build a loss analysis with hazard H-1 and constraint SC-1."""
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="Constraint", related_hazards=["H-1"]
            ),
        ],
    )


def _make_test_capability_profile() -> CapabilityProfile:
    """Build a capability profile with input zone failure modes."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(name="chat", direction="input", controllability="direct"),
        ],
        confidence="medium",
        kc_subcodes=["KC1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test-tool", description="A test tool"),
        ],
    )


def _make_valid_slot_fill_result(resp_id: str, ca_ids: list[str]) -> dict:
    """Build a valid ICASlotFillResult dict for a responsibility."""
    filled_slots = []
    for ca_id in ca_ids:
        for uca_type in UCAType:
            slot_id = f"{resp_id}:{ca_id}:{uca_type.value}"
            if uca_type == UCAType.wrong_duration:
                # N/A slot with structural keyword
                filled_slots.append({
                    "slot_id": slot_id,
                    "responsibility": resp_id,
                    "coordination_link": None,
                    "control_action": ca_id,
                    "uca_type": uca_type.value,
                    "is_na": True,
                    "icas": [],
                    "na_justification": "Action is atomic with no duration component",
                })
            else:
                # Non-N/A slot with a concrete ICA
                filled_slots.append({
                    "slot_id": slot_id,
                    "responsibility": resp_id,
                    "coordination_link": None,
                    "control_action": ca_id,
                    "uca_type": uca_type.value,
                    "is_na": False,
                    "icas": [
                        {
                            "ica_id": f"{slot_id}:1",
                            "ica_text": f"Concrete failure for {ca_id} {uca_type.value}",
                            "hazardous_context": "Attacker context",
                            "loss_scenario": "Attack chain leading to harm",
                            "related_hazards": ["H-1"],
                            "related_constraints": ["SC-1"],
                        }
                    ],
                    "na_justification": None,
                })
    return {"filled_slots": filled_slots}


# ---------------------------------------------------------------------------
# One LLM call per responsibility (SP2-FILL-01)
# ---------------------------------------------------------------------------


class TestOneCallPerResponsibility:
    """One LLM call per responsibility, labeled stage_3."""

    def test_call_count_and_stage(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        slots = create_slots(cs)

        client = MockLLMClient()
        client.set_response_for(
            ICASlotFillResult,
            _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"]),
        )
        # We need different responses per call. Since MockLLMClient uses a queue
        # based on response_format, we need to use the queue approach
        client2 = MockLLMClient()
        client2.set_response_queue([
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ])

        with TemporaryDirectory() as tmpdir:
            fill_all_slots(
                llm_client=client2,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir),
                max_workers=1,
            )

        assert client2.call_count == 2
        # Check stage label in calls.jsonl
        with TemporaryDirectory() as tmpdir2:
            client3 = MockLLMClient()
            client3.set_response_queue([
                ICASlotFillResult.model_validate(
                    _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
                ),
                ICASlotFillResult.model_validate(
                    _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
                ),
            ])
            fill_all_slots(
                llm_client=client3,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir2),
                max_workers=1,
            )
            calls_file = Path(tmpdir2) / "calls.jsonl"
            assert calls_file.exists()
            entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
            for entry in entries:
                assert entry["stage"] == "stage_3"


# ---------------------------------------------------------------------------
# System prompt defines four ICA types (SP2-FILL-02)
# ---------------------------------------------------------------------------


class TestSystemPromptContent:
    """System prompt defines four ICA types."""

    def test_four_ica_types_in_system_prompt(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        loader = TemplateLoader(PROMPTS_DIR)
        resp_slots = [s for s in create_slots(cs) if s.responsibility == "RESP-1"]
        system_prompt, _ = build_slot_filling_prompts(
            cs, la, "tech context", resp_slots, "RESP-1", loader
        )
        assert "NOT_PROVIDED" in system_prompt
        assert "INCORRECT" in system_prompt
        assert "WRONG_TIMING" in system_prompt
        assert "WRONG_DURATION" in system_prompt


# ---------------------------------------------------------------------------
# User prompt includes control structure, tech context, slots (SP2-FILL-03)
# ---------------------------------------------------------------------------


class TestUserPromptContent:
    """User prompt includes control structure, tech context, and slots."""

    def test_user_prompt_contains_required_content(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        loader = TemplateLoader(PROMPTS_DIR)
        resp_slots = [s for s in create_slots(cs) if s.responsibility == "RESP-1"]
        _, user_prompt = build_slot_filling_prompts(
            cs, la, "input zone failure modes", resp_slots, "RESP-1", loader
        )
        assert "RESP-1" in user_prompt  # control structure
        assert "H-1" in user_prompt  # hazards
        assert "SC-1" in user_prompt  # security constraints
        assert "input zone failure modes" in user_prompt  # technology context
        assert "RESP-1:CA-1-1:NOT_PROVIDED" in user_prompt  # slot IDs


# ---------------------------------------------------------------------------
# Filled non-N/A slot has concrete ICA text (SP2-FILL-04)
# ---------------------------------------------------------------------------


class TestFilledNonNASlot:
    """Filled non-N/A slot has concrete ICA text."""

    def test_non_na_slot_has_ica_text(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        slots = create_slots(cs)

        client = MockLLMClient()
        client.set_response_queue([
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ])

        with TemporaryDirectory() as tmpdir:
            filled = fill_all_slots(
                llm_client=client,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir),
                max_workers=1,
            )

        non_na = [s for s in filled if not s.is_na and s.responsibility == "RESP-1"]
        assert len(non_na) > 0
        ica = non_na[0].icas[0]
        assert ica.ica_text
        assert len(ica.ica_text) > 0


# ---------------------------------------------------------------------------
# Filled N/A slot has na_justification (SP2-FILL-05)
# ---------------------------------------------------------------------------


class TestFilledNASlot:
    """Filled N/A slot has na_justification."""

    def test_na_slot_has_justification(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        slots = create_slots(cs)

        client = MockLLMClient()
        client.set_response_queue([
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ])

        with TemporaryDirectory() as tmpdir:
            filled = fill_all_slots(
                llm_client=client,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir),
                max_workers=1,
            )

        na_slots = [s for s in filled if s.is_na and s.responsibility == "RESP-1"]
        assert len(na_slots) > 0
        for slot in na_slots:
            assert slot.na_justification is not None
            assert slot.icas == []


# ---------------------------------------------------------------------------
# ICA loss_scenario present (SP2-FILL-12)
# ---------------------------------------------------------------------------


class TestLossScenario:
    """ICA loss_scenario is present for non-N/A slots."""

    def test_loss_scenario_present(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        slots = create_slots(cs)

        client = MockLLMClient()
        client.set_response_queue([
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ])

        with TemporaryDirectory() as tmpdir:
            filled = fill_all_slots(
                llm_client=client,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir),
                max_workers=1,
            )

        non_na = [s for s in filled if not s.is_na and s.icas]
        assert len(non_na) > 0
        for slot in non_na:
            for ica in slot.icas:
                assert ica.loss_scenario
                assert len(ica.loss_scenario) > 0


# ---------------------------------------------------------------------------
# Calls are stateless (SP2-FILL-08)
# ---------------------------------------------------------------------------


class TestStatelessCalls:
    """Calls are stateless with no conversation history."""

    def test_each_call_receives_full_control_structure(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        loader = TemplateLoader(PROMPTS_DIR)

        resp1_slots = [s for s in create_slots(cs) if s.responsibility == "RESP-1"]
        sys1, user1 = build_slot_filling_prompts(
            cs, la, "tech", resp1_slots, "RESP-1", loader
        )

        resp2_slots = [s for s in create_slots(cs) if s.responsibility == "RESP-2"]
        sys2, user2 = build_slot_filling_prompts(
            cs, la, "tech", resp2_slots, "RESP-2", loader
        )

        # Both calls receive the full control structure
        assert "RESP-1" in user1 and "RESP-2" in user1
        assert "RESP-1" in user2 and "RESP-2" in user2
        # No conversation history — system prompts are identical
        assert sys1 == sys2


# ---------------------------------------------------------------------------
# Parallelizable (SP2-FILL-09)
# ---------------------------------------------------------------------------


class TestParallelizable:
    """Slot-filling calls are parallelizable across responsibilities."""

    def test_parallel_results_same_order(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        slots = create_slots(cs)

        client = MockLLMClient()
        client.set_response_queue([
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ])

        with TemporaryDirectory() as tmpdir:
            filled = fill_all_slots(
                llm_client=client,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir),
                max_workers=2,
            )

        assert client.call_count == 2
        # Verify RESP-1 and RESP-2 slots are filled
        resp1_filled = [s for s in filled if s.responsibility == "RESP-1" and (s.is_na or s.icas)]
        resp2_filled = [s for s in filled if s.responsibility == "RESP-2" and (s.is_na or s.icas)]
        assert len(resp1_filled) > 0
        assert len(resp2_filled) > 0


# ---------------------------------------------------------------------------
# Calls logged to calls.jsonl (SP2-FILL-11)
# ---------------------------------------------------------------------------


class TestCallLogging:
    """All LLM calls are logged to calls.jsonl."""

    def test_calls_jsonl_exists_with_stage_3(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        cp = _make_test_capability_profile()
        slots = create_slots(cs)

        client = MockLLMClient()
        client.set_response_queue([
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-1", ["CA-1-1", "CA-1-2"])
            ),
            ICASlotFillResult.model_validate(
                _make_valid_slot_fill_result("RESP-2", ["CA-2-1", "CA-2-2"])
            ),
        ])

        with TemporaryDirectory() as tmpdir:
            fill_all_slots(
                llm_client=client,
                control_structure=cs,
                loss_analysis=la,
                capability_profile=cp,
                slots=slots,
                run_dir=Path(tmpdir),
                max_workers=1,
            )
            calls_file = Path(tmpdir) / "calls.jsonl"
            assert calls_file.exists()
            entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
            assert len(entries) == 2
            for entry in entries:
                assert entry["stage"] == "stage_3"


# ---------------------------------------------------------------------------
# ICAs reference valid hazard IDs (SP2-FILL-06, SP2-FILL-07)
# ---------------------------------------------------------------------------


class TestHazardIDValidation:
    """ICAs reference valid hazard IDs from the loss analysis."""

    def test_valid_hazard_ids_validate(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        ica_enum = ICAEnumeration(
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
            ]
        )
        # Should not raise
        ica_enum.validate_against(la, cs)

    def test_invalid_hazard_ids_rejected(self):
        cs = _make_test_control_structure()
        la = _make_test_loss_analysis()
        ica_enum = ICAEnumeration(
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
                            related_hazards=["H-99"],
                            related_constraints=["SC-1"],
                        )
                    ],
                ),
            ]
        )
        try:
            ica_enum.validate_against(la, cs)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "related_hazards" in str(e) or "H-99" in str(e)
