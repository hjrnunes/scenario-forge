"""Property-based tests for STPA-Sec boundary schemas using Hypothesis.

These tests verify invariants that should hold across broad input ranges:

- **YAML round-trip**: Any valid model instance, when serialized to YAML
  and reloaded, produces an equal instance.
- **Duplicate-ID rejection**: Duplicate IDs in any ID-bearing list always
  raise ValidationError.
- **Invalid-reference rejection**: References to non-existent IDs always
  raise ValidationError.
- **validate_against correctness**: Valid references pass, invalid ones
  are rejected.
- **Structural heuristic completeness**: A well-formed control structure
  passes all structural heuristics; removing required children produces
  errors.

Property tests complement the example-based unit tests by exploring a
broader input space than hand-written cases can cover.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel, ValidationError

from scenario_forge.stpa.infra.yaml_io import read_yaml, write_yaml
from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    check_structural_heuristics,
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
from tests.stpa.helpers import (
    make_ica,
    make_ica_slot,
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Unique-ID strategies: generate N unique IDs with a given prefix pattern.
st_loss_ids = st.lists(
    st.from_regex(r"L-[1-9][0-9]*", fullmatch=True),
    min_size=1,
    max_size=5,
    unique=True,
)
st_hazard_ids = st.lists(
    st.from_regex(r"H-[1-9][0-9]*", fullmatch=True),
    min_size=1,
    max_size=5,
    unique=True,
)
st_constraint_ids = st.lists(
    st.from_regex(r"SC-[1-9][0-9]*", fullmatch=True),
    min_size=1,
    max_size=5,
    unique=True,
)

# Exclude YAML 1.1 line-break characters (\x85 NEL, \u2028 LS, \u2029 PS)
# and control characters that PyYAML does not round-trip correctly.
st_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters=("\x85", "\u2028", "\u2029"),
    ),
    min_size=1,
    max_size=50,
)


# ---------------------------------------------------------------------------
# YAML round-trip property tests
# ---------------------------------------------------------------------------


def _yaml_round_trip(model: BaseModel, tmp_path: Path) -> BaseModel:
    """Serialize model to YAML, reload, and return the new instance."""
    path = tmp_path / "round_trip.yaml"
    write_yaml(model, path)
    return read_yaml(path, type(model))


class TestYamlRoundTrip:
    """Any valid model round-trips through YAML without loss."""

    @given(
        loss_ids=st_loss_ids,
        hazard_ids=st_hazard_ids,
        constraint_ids=st_constraint_ids,
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_loss_analysis_yaml_round_trip(
        self, tmp_path, loss_ids, hazard_ids, constraint_ids
    ):
        """LossAnalysis round-trips through YAML."""
        losses = [
            Loss(
                loss_id=lid,
                description=f"Loss {lid}",
                provenance=LossProvenance.use_case,
            )
            for lid in loss_ids
        ]
        hazards = [
            Hazard(
                hazard_id=hid,
                description=f"Hazard {hid}",
                related_losses=loss_ids[:1],
            )
            for hid in hazard_ids
        ]
        constraints = [
            SecurityConstraint(
                constraint_id=cid,
                description=f"Constraint {cid}",
                related_hazards=hazard_ids[:1],
            )
            for cid in constraint_ids
        ]
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=losses,
            hazards=hazards,
            security_constraints=constraints,
        )
        result = _yaml_round_trip(la, tmp_path)
        assert result == la

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
        n_pms=st.integers(min_value=1, max_value=3),
        n_cas=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_control_structure_yaml_round_trip(
        self, tmp_path, n_resps, n_pms, n_cas
    ):
        """ControlStructure round-trips through YAML."""
        responsibilities = []
        for i in range(1, n_resps + 1):
            resp_id = f"RESP-{i}"
            pms = [
                ProcessModelPart(pm_id=f"PM-{i}-{j}", description=f"PM {i}-{j}")
                for j in range(1, n_pms + 1)
            ]
            cas = [
                ControlAction(ca_id=f"CA-{i}-{j}", description=f"CA {i}-{j}")
                for j in range(1, n_cas + 1)
            ]
            fbs = [
                FeedbackChannel(
                    fb_id=f"FB-{i}-{j}",
                    description=f"FB {i}-{j}",
                    updates=f"PM-{i}-{j}",
                    source=ElementRef(type=ReferenceType.responsibility, id=resp_id),
                )
                for j in range(1, min(n_pms, n_cas) + 1)
            ]
            responsibilities.append(
                Responsibility(
                    resp_id=resp_id,
                    description=f"Controller {i}",
                    process_model_parts=pms,
                    control_actions=cas,
                    feedback_channels=fbs,
                )
            )
        cs = ControlStructure(responsibilities=responsibilities)
        result = _yaml_round_trip(cs, tmp_path)
        assert result == cs

    @given(
        slot_id=st.from_regex(r"RESP-1:CA-1-1:[A-Z_]+", fullmatch=True),
        ica_text=st_text,
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_ica_enumeration_yaml_round_trip(self, tmp_path, slot_id, ica_text):
        """ICAEnumeration round-trips through YAML."""
        slot = ICASlot(
            slot_id=slot_id,
            responsibility="RESP-1",
            control_action="CA-1-1",
            uca_type=UCAType.not_provided,
            is_na=False,
            icas=[
                ICA(
                    ica_id=f"{slot_id}:1",
                    ica_text=ica_text,
                    hazardous_context="Context",
                    loss_scenario="Scenario",
                    related_hazards=["H-1"],
                    related_constraints=["SC-1"],
                )
            ],
        )
        enum = ICAEnumeration(slots=[slot])
        result = _yaml_round_trip(enum, tmp_path)
        assert result == enum


# ---------------------------------------------------------------------------
# Duplicate-ID rejection property tests
# ---------------------------------------------------------------------------


class TestDuplicateIdRejection:
    """Duplicate IDs in any ID-bearing list must always be rejected."""

    @given(dup_id=st.from_regex(r"L-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_loss_id_rejected(self, dup_id):
        """Duplicate loss_id in use_case_losses is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id=dup_id,
                        description="A",
                        provenance=LossProvenance.use_case,
                    ),
                    Loss(
                        loss_id=dup_id,
                        description="B",
                        provenance=LossProvenance.use_case,
                    ),
                ],
                hazards=[],
                security_constraints=[],
            )

    @given(dup_id=st.from_regex(r"H-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_hazard_id_rejected(self, dup_id):
        """Duplicate hazard_id is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id=dup_id, description="A", related_losses=["L-1"]),
                    Hazard(hazard_id=dup_id, description="B", related_losses=["L-1"]),
                ],
                security_constraints=[],
            )

    @given(dup_id=st.from_regex(r"SC-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_constraint_id_rejected(self, dup_id):
        """Duplicate constraint_id is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id="H-1", description="A", related_losses=["L-1"]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id=dup_id, description="A", related_hazards=["H-1"]
                    ),
                    SecurityConstraint(
                        constraint_id=dup_id, description="B", related_hazards=["H-1"]
                    ),
                ],
            )

    @given(dup_id=st.from_regex(r"RESP-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_resp_id_rejected(self, dup_id):
        """Duplicate resp_id in ControlStructure is always rejected."""
        with pytest.raises(ValidationError):
            ControlStructure(
                responsibilities=[
                    Responsibility(
                        resp_id=dup_id,
                        description="A",
                        process_model_parts=[
                            ProcessModelPart(pm_id="PM-1-1", description="PM"),
                        ],
                        control_actions=[
                            ControlAction(ca_id="CA-1-1", description="CA"),
                        ],
                        feedback_channels=[
                            FeedbackChannel(
                                fb_id="FB-1-1",
                                description="FB",
                                updates="PM-1-1",
                                source=ElementRef(
                                    type=ReferenceType.responsibility,
                                    id=dup_id,
                                ),
                            ),
                        ],
                    ),
                    Responsibility(
                        resp_id=dup_id,
                        description="B",
                        process_model_parts=[
                            ProcessModelPart(pm_id="PM-2-1", description="PM"),
                        ],
                        control_actions=[
                            ControlAction(ca_id="CA-2-1", description="CA"),
                        ],
                        feedback_channels=[
                            FeedbackChannel(
                                fb_id="FB-2-1",
                                description="FB",
                                updates="PM-2-1",
                                source=ElementRef(
                                    type=ReferenceType.responsibility,
                                    id=dup_id,
                                ),
                            ),
                        ],
                    ),
                ]
            )

    @given(dup_slot=st.from_regex(r"RESP-1:CA-1-1:[A-Z_]+", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_slot_id_rejected(self, dup_slot):
        """Duplicate slot_id in ICAEnumeration is always rejected."""
        with pytest.raises(ValidationError):
            ICAEnumeration(
                slots=[
                    ICASlot(
                        slot_id=dup_slot,
                        responsibility="RESP-1",
                        control_action="CA-1-1",
                        uca_type=UCAType.not_provided,
                        is_na=False,
                        icas=[make_ica()],
                    ),
                    ICASlot(
                        slot_id=dup_slot,
                        responsibility="RESP-1",
                        control_action="CA-1-1",
                        uca_type=UCAType.incorrect,
                        is_na=False,
                        icas=[make_ica()],
                    ),
                ]
            )


# ---------------------------------------------------------------------------
# Invalid-reference rejection property tests
# ---------------------------------------------------------------------------


class TestInvalidReferenceRejection:
    """References to non-existent IDs must always be rejected."""

    @given(bad_ref=st.from_regex(r"L-[9][0-9]+", fullmatch=True))
    @settings(max_examples=15, deadline=None)
    def test_hazard_invalid_loss_ref_rejected(self, bad_ref):
        """Hazard referencing a non-existent loss is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(
                        hazard_id="H-1", description="H", related_losses=[bad_ref]
                    ),
                ],
                security_constraints=[],
            )

    @given(bad_ref=st.from_regex(r"H-[9][0-9]+", fullmatch=True))
    @settings(max_examples=15, deadline=None)
    def test_constraint_invalid_hazard_ref_rejected(self, bad_ref):
        """Constraint referencing a non-existent hazard is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id="H-1", description="H", related_losses=["L-1"]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-1",
                        description="C",
                        related_hazards=[bad_ref],
                    ),
                ],
            )


# ---------------------------------------------------------------------------
# validate_against property tests
# ---------------------------------------------------------------------------


class TestValidateAgainst:
    """Cross-artifact validation: valid references pass, invalid rejected."""

    @given(
        bad_pm_id=st.from_regex(r"PM-[9][0-9]-[0-9]+", fullmatch=True),
    )
    @settings(max_examples=15, deadline=None)
    def test_scenario_spec_invalid_belief_pm_rejected(self, bad_pm_id):
        """ScenarioSpec with invalid DefenderBelief.pm_id is rejected."""
        cs = make_minimal_control_structure()
        spec = ScenarioSpec(
            scenario_id="SCN-001",
            threat_source=ThreatSource(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                provenance="structural",
            ),
            target_controller="RESP-1",
            target_control_action="CA-1-1",
            ica_type=UCAType.not_provided,
            defender_bdi=DefenderBDI(
                beliefs=[
                    DefenderBelief(
                        pm_id=bad_pm_id,
                        content="Belief",
                        vulnerability="Vuln",
                    )
                ],
                desires=[
                    DefenderDesire(resp_id="RESP-1", content="Desire"),
                ],
                intentions=[
                    DefenderIntention(ca_id="CA-1-1", content="Intention"),
                ],
            ),
            attacker_bdi=AttackerBDI(
                beliefs=["b"], desires=["d"], intentions=["i"]
            ),
            loss_scenario="Scenario",
        )
        with pytest.raises(ValueError, match="pm_id"):
            spec.validate_against(cs)

    @given(
        bad_hazard_id=st.from_regex(r"H-[9][0-9]+", fullmatch=True),
    )
    @settings(max_examples=15, deadline=None)
    def test_ica_invalid_hazard_ref_rejected(self, bad_hazard_id):
        """ICA with invalid hazard reference is rejected by validate_against."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        slot = make_ica_slot(
            icas=[
                ICA(
                    ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                    ica_text="UCA",
                    hazardous_context="Ctx",
                    loss_scenario="Scenario",
                    related_hazards=[bad_hazard_id],
                    related_constraints=["SC-1"],
                )
            ],
        )
        enum = ICAEnumeration(slots=[slot])
        with pytest.raises(ValueError, match="hazard"):
            enum.validate_against(la, cs)


# ---------------------------------------------------------------------------
# Structural heuristic property tests
# ---------------------------------------------------------------------------


class TestStructuralHeuristics:
    """Structural heuristics: well-formed CS passes, malformed CS fails."""

    def test_minimal_cs_passes_heuristics(self):
        """A minimal valid control structure passes structural heuristics (no LA)."""
        cs = make_minimal_control_structure()
        result = check_structural_heuristics(cs)
        assert result.passed, f"Expected pass, got errors: {result.errors}"

    @given(
        remove_pms=st.booleans(),
        remove_cas=st.booleans(),
        remove_fbs=st.booleans(),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_missing_children_produce_errors(
        self, remove_pms, remove_cas, remove_fbs
    ):
        """Removing any required child from a responsibility produces errors."""
        cs = make_minimal_control_structure()
        resp = cs.responsibilities[0]
        if remove_pms:
            resp.process_model_parts = []
        if remove_cas:
            resp.control_actions = []
        if remove_fbs:
            resp.feedback_channels = []
        result = check_structural_heuristics(cs)
        # At least one error should be present if any children were removed.
        if remove_pms or remove_cas or remove_fbs:
            assert result.errors, (
                f"Expected errors when removing children, got none. "
                f"remove_pms={remove_pms}, remove_cas={remove_cas}, "
                f"remove_fbs={remove_fbs}"
            )
        else:
            assert result.passed
