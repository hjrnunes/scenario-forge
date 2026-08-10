"""Unit tests for Stage 6 output quality (jpkw, gddi, v689).

Covers:
  - jpkw: GherkinSpec structured model, assembly, .feature writing, validation
  - gddi: Loss/Hazard ID hallucination prevention and validation
  - v689: Attack tree root label exact ICA type enforcement
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from scenario_forge.stpa.infra.templates import TemplateLoader
from scenario_forge.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from scenario_forge.stpa.models.ica_enumeration import UCAType
from scenario_forge.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from scenario_forge.stpa.models.scenario_envelope import GherkinSpec, ScenarioEnvelope
from scenario_forge.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from scenario_forge.stpa.scenario_prod.assembly import assemble_envelope
from scenario_forge.stpa.scenario_prod.attack_tree import build_attack_tree_prompts
from scenario_forge.stpa.scenario_prod.gherkin import (
    build_gherkin_prompts,
    find_security_constraint,
    generate_gherkin,
    parse_gherkin_spec,
)
from scenario_forge.stpa.scenario_prod.validators import (
    validate_attack_tree_root_label,
    validate_gherkin_structure,
    validate_loss_hazard_id_references,
)
from scenario_forge.stpa.scenario_prod._constants import PROMPTS_DIR

from tests.stpa.sp1_helpers import MockLLMClient


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_cs() -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Action",
                        target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Feedback",
                        updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                    ),
                ],
            ),
        ],
        controlled_processes=cps,
    )


def _make_scenario_spec(
    ica_type: UCAType = UCAType.not_provided,
    ca_id: str = "CA-1-1",
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=f"RESP-1:{ca_id}:{ica_type.value}",
            provenance="structural",
            ica_id=f"RESP-1:{ca_id}:{ica_type.value}:1",
        ),
        target_controller="RESP-1",
        target_control_action=ca_id,
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="exploitable"),
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="R1")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["Knows PM-1-1 is weak"],
            desires=["Induce NOT_PROVIDED"],
            intentions=["Poison PM-1-1 via FB-1-1"],
        ),
        loss_scenario="Loss scenario text",
    )


def _make_loss_analysis(
    loss_ids: list[str] | None = None,
    hazard_ids: list[str] | None = None,
) -> LossAnalysis:
    loss_ids = loss_ids or ["L-1", "L-2"]
    hazard_ids = hazard_ids or ["H-1", "H-2"]
    risk_card_losses = [
        Loss(
            loss_id=lid,
            description=f"Loss {lid}",
            provenance=LossProvenance.risk_card,
            source_risk_cards=[f"r{i}"],
        )
        for i, lid in enumerate(loss_ids)
    ]
    hazards = [
        Hazard(
            hazard_id=hid,
            description=f"Hazard {hid}",
            related_losses=[loss_ids[0]],
        )
        for hid in hazard_ids
    ]
    return LossAnalysis(
        risk_card_losses=risk_card_losses,
        use_case_losses=[],
        hazards=hazards,
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="The system must validate before action",
                related_hazards=[hazard_ids[0]],
            ),
        ],
    )


def _make_gherkin_spec(
    feature: str = "Safe orchestration",
    scenario: str = "SCN-001",
    given: list[str] | None = None,
    when: list[str] | None = None,
    then_expected: list[str] | None = None,
    then_actual: list[str] | None = None,
) -> GherkinSpec:
    return GherkinSpec(
        feature=feature,
        scenario=scenario,
        given=given if given is not None else ["Given PM-1-1 is active"],
        when=when if when is not None else ["When a revoked user requests access"],
        then_expected=then_expected if then_expected is not None else ["Then the system should reject the request"],
        then_actual=then_actual if then_actual is not None else [
            "But the system approves the request",
            "And loss L-1 is realized",
        ],
    )


def _make_envelope(
    gherkin_spec: GherkinSpec | None = None,
    gherkin_raw: str = "",
    spec: ScenarioSpec | None = None,
) -> ScenarioEnvelope:
    return ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec or _make_scenario_spec(),
        narrative="Narrative text",
        attack_tree={
            "root": "Induce ICA NOT_PROVIDED on CA-1-1",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        },
        gherkin_spec=gherkin_spec or _make_gherkin_spec(),
        gherkin_raw=gherkin_raw,
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )


_VALID_GHERKIN_YAML = (
    "feature: Safe orchestration\n"
    "scenario: SCN-001\n"
    "given:\n"
    "  - Given PM-1-1 is active\n"
    "  - And the system is online\n"
    "when:\n"
    "  - When a revoked user requests access\n"
    "then_expected:\n"
    "  - Then the system should reject the request\n"
    "then_actual:\n"
    "  - But the system approves the request\n"
    "  - And loss L-1 is realized\n"
)


# ===========================================================================
# JPKW — GherkinSpec structured output
# ===========================================================================


class TestGherkinSpecModel:
    """JPKW-01: GherkinSpec model has structured fields."""

    def test_jpkw_01_fields_and_types(self):
        spec = _make_gherkin_spec()
        assert isinstance(spec.feature, str)
        assert isinstance(spec.scenario, str)
        assert isinstance(spec.given, list)
        assert all(isinstance(s, str) for s in spec.given)
        assert isinstance(spec.when, list)
        assert all(isinstance(s, str) for s in spec.when)
        assert isinstance(spec.then_expected, list)
        assert all(isinstance(s, str) for s in spec.then_expected)
        assert isinstance(spec.then_actual, list)
        assert all(isinstance(s, str) for s in spec.then_actual)


class TestScenarioEnvelopeGherkinFields:
    """JPKW-02: ScenarioEnvelope has gherkin_spec of type GherkinSpec and gherkin_raw of type str."""

    def test_jpkw_02_gherkin_spec_is_gherkin_spec_type(self):
        envelope = _make_envelope()
        assert isinstance(envelope.gherkin_spec, GherkinSpec)

    def test_jpkw_02_gherkin_raw_is_str_type(self):
        envelope = _make_envelope(gherkin_raw="Feature: Test\n")
        assert isinstance(envelope.gherkin_raw, str)


class TestGherkinSystemPrompt:
    """JPKW-03: Stage 6c system prompt requests structured YAML output."""

    def test_jpkw_03_system_prompt_requests_yaml(self):
        loader = TemplateLoader(PROMPTS_DIR)
        prompt = loader.render_prompt("stage6c_gherkin_system.j2")
        assert "yaml" in prompt.lower()
        assert "feature" in prompt
        assert "scenario" in prompt
        assert "given" in prompt
        assert "when" in prompt
        assert "then_expected" in prompt
        assert "then_actual" in prompt


class TestGenerateGherkinReturns:
    """JPKW-04: generate_gherkin returns a GherkinSpec and raw text."""

    def test_jpkw_04_returns_gherkin_spec_and_raw(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, _VALID_GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            result, raw, error = generate_gherkin(client, spec, la, Path(tmpdir))
            assert error is None
            assert isinstance(result, GherkinSpec)
            assert isinstance(raw, str)
            assert len(raw) > 0


class TestGenerateGherkinParsesYaml:
    """JPKW-05: generate_gherkin parses YAML response into structured fields."""

    def test_jpkw_05_given_list_contains_steps(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, _VALID_GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            result, _, _ = generate_gherkin(client, spec, la, Path(tmpdir))
            assert result is not None
            assert "Given PM-1-1 is active" in result.given
            assert "And the system is online" in result.given


class TestAssembleEnvelopeGherkinSpec:
    """JPKW-06: assemble_envelope accepts a GherkinSpec and gherkin_raw."""

    def test_jpkw_06_assemble_with_gherkin_spec_and_raw(self):
        spec = _make_scenario_spec()
        ghk = _make_gherkin_spec(feature="Safe orchestration", scenario="SCN-001")
        raw = "Feature: Safe orchestration\nScenario: SCN-001\n"

        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=ghk,
            gherkin_raw=raw,
        )
        assert envelope.gherkin_spec == ghk
        assert envelope.gherkin_raw == raw


class TestFeatureFileFromGherkinRaw:
    """JPKW-07: .feature file is written from gherkin_raw."""

    def test_jpkw_07_feature_file_contains_gherkin_raw(self):
        from scenario_forge.stpa.scenario_prod.run import _write_scenario_artifacts

        raw = "Feature: Safe orchestration\nScenario: SCN-001\n"
        envelope = _make_envelope(gherkin_raw=raw)

        with TemporaryDirectory() as tmpdir:
            scenarios_dir = Path(tmpdir)
            _write_scenario_artifacts(envelope, scenarios_dir)
            feature_path = scenarios_dir / "SCN-001.feature"
            assert feature_path.exists()
            content = feature_path.read_text(encoding="utf-8")
            assert raw in content


class TestGherkinSpecValidationFailures:
    """JPKW-08: structured validation catches missing required GherkinSpec content."""

    def test_jpkw_08_empty_then_expected(self):
        spec = _make_gherkin_spec(then_expected=[])
        result = validate_gherkin_structure(spec)
        assert not result.passed
        assert any("should" in e.lower() for e in result.errors)

    def test_jpkw_08_empty_then_actual(self):
        spec = _make_gherkin_spec(then_actual=[])
        result = validate_gherkin_structure(spec)
        assert not result.passed
        assert any("but" in e.lower() for e in result.errors)

    def test_jpkw_08_given_no_pm_reference(self):
        spec = _make_gherkin_spec(given=["Given the system is running"])
        result = validate_gherkin_structure(spec)
        assert not result.passed
        assert any("process model" in e.lower() for e in result.errors)


class TestGherkinSpecValidationPass:
    """JPKW-09: valid structured GherkinSpec passes validation."""

    def test_jpkw_09_valid_spec_passes(self):
        spec = _make_gherkin_spec(
            then_expected=["Then the system should reject"],
            then_actual=["But approves"],
            given=["Given PM-1-1 is active"],
        )
        result = validate_gherkin_structure(spec)
        assert result.passed


class TestGherkinSpecToFeatureText:
    """JPKW-10: raw Gherkin text is reconstructable from structured fields."""

    def test_jpkw_10_to_feature_text(self):
        spec = GherkinSpec(
            feature="Safe orchestration",
            scenario="SCN-001",
            given=["Given PM-1-1 is active"],
            when=["When a revoked user requests access"],
            then_expected=["Then the system should reject the request"],
            then_actual=["But the system approves"],
        )
        text = spec.to_feature_text()
        assert "Feature: Safe orchestration" in text
        assert "Scenario: SCN-001" in text
        assert "Given PM-1-1 is active" in text
        assert "When a revoked user requests access" in text
        assert "Then the system should reject the request" in text


class TestStage7EnvelopeGherkinValidation:
    """JPKW-11: Stage 7 envelope validation uses GherkinSpec fields."""

    def test_jpkw_11_empty_then_expected_fails(self):
        from scenario_forge.stpa.scenario_prod.run import _validate_envelope_stage7

        la = _make_loss_analysis()
        envelope = _make_envelope(
            gherkin_spec=_make_gherkin_spec(then_expected=[]),
        )
        errors: list[str] = []
        _validate_envelope_stage7(envelope, la, errors)
        assert any("should" in e.lower() for e in errors)


class TestGherkinRawPreservesFeatureText:
    """JPKW-12: backward compatibility gherkin_raw preserves full Feature text."""

    def test_jpkw_12_raw_contains_feature_and_scenario(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, _VALID_GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            _, raw, _ = generate_gherkin(client, spec, la, Path(tmpdir))
            assert "Safe orchestration" in raw
            assert "SCN-001" in raw


class TestParseGherkinSpec:
    """Tests for parse_gherkin_spec utility."""

    def test_parse_valid_yaml(self):
        spec = parse_gherkin_spec(_VALID_GHERKIN_YAML)
        assert spec is not None
        assert spec.feature == "Safe orchestration"
        assert spec.scenario == "SCN-001"
        assert len(spec.given) == 2

    def test_parse_yaml_in_code_fence(self):
        fenced = f"```yaml\n{_VALID_GHERKIN_YAML}\n```"
        spec = parse_gherkin_spec(fenced)
        assert spec is not None
        assert spec.feature == "Safe orchestration"

    def test_parse_invalid_yaml_returns_none(self):
        assert parse_gherkin_spec("not valid yaml: : :") is None

    def test_parse_non_string_returns_none(self):
        assert parse_gherkin_spec(42) is None  # type: ignore[arg-type]


# ===========================================================================
# GDDI — Loss/Hazard ID validation
# ===========================================================================


class TestGherkinUserPromptValidIds:
    """GDDI-01: user prompt includes valid Loss and Hazard IDs."""

    def test_gddi_01_user_prompt_contains_loss_ids(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis(loss_ids=["L-1", "L-2", "L-3"], hazard_ids=["H-1", "H-2"])
        loader = TemplateLoader(PROMPTS_DIR)
        sc = find_security_constraint(spec, la)
        _, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
        assert "L-1" in user_prompt
        assert "L-2" in user_prompt
        assert "L-3" in user_prompt

    def test_gddi_01_user_prompt_contains_hazard_ids(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis(loss_ids=["L-1", "L-2", "L-3"], hazard_ids=["H-1", "H-2"])
        loader = TemplateLoader(PROMPTS_DIR)
        sc = find_security_constraint(spec, la)
        _, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
        assert "H-1" in user_prompt
        assert "H-2" in user_prompt


class TestGherkinUserPromptInstructions:
    """GDDI-02: user prompt instructs LLM to reference only valid IDs."""

    def test_gddi_02_instructs_reference_only_provided(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        loader = TemplateLoader(PROMPTS_DIR)
        sc = find_security_constraint(spec, la)
        _, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
        assert "only" in user_prompt.lower()
        assert "provided" in user_prompt.lower()

    def test_gddi_02_instructs_not_to_invent(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        loader = TemplateLoader(PROMPTS_DIR)
        sc = find_security_constraint(spec, la)
        _, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
        assert "invent" in user_prompt.lower()


class TestGherkinSystemPromptIdConstraint:
    """GDDI-03: system prompt instructs LLM to reference only valid Loss and Hazard IDs."""

    def test_gddi_03_system_prompt_references_only_provided_ids(self):
        loader = TemplateLoader(PROMPTS_DIR)
        prompt = loader.render_prompt("stage6c_gherkin_system.j2")
        assert "only" in prompt.lower()
        assert "L-*" in prompt or "L-" in prompt
        assert "H-*" in prompt or "H-" in prompt
        assert "invent" in prompt.lower()


class TestBuildGherkinPromptsAcceptsLossAnalysis:
    """GDDI-04: build_gherkin_prompts accepts loss analysis."""

    def test_gddi_04_user_prompt_contains_valid_ids(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis(loss_ids=["L-1", "L-2"], hazard_ids=["H-1", "H-2"])
        loader = TemplateLoader(PROMPTS_DIR)
        sc = find_security_constraint(spec, la)
        _, user_prompt = build_gherkin_prompts(spec, sc, la, loader)
        assert "L-1" in user_prompt
        assert "H-1" in user_prompt


class TestLossHazardIdValidator:
    """GDDI-05 through GDDI-08: validator catches hallucinated IDs."""

    def _la_with_ids(self, loss_ids=None, hazard_ids=None):
        return _make_loss_analysis(
            loss_ids=loss_ids or ["L-1", "L-2"],
            hazard_ids=hazard_ids or ["H-1", "H-2"],
        )

    def test_gddi_05_catches_hallucinated_loss_l99(self):
        text = "Scenario: Test\n  But loss L-99 is realized\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("L-99" in e for e in result.errors)

    def test_gddi_05_catches_hallucinated_loss_l100(self):
        text = "Scenario: Test\n  But loss L-100 is realized\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("L-100" in e for e in result.errors)

    def test_gddi_05_catches_hallucinated_hazard_h99(self):
        text = "Scenario: Test\n  And hazard H-99 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("H-99" in e for e in result.errors)

    def test_gddi_05_catches_hallucinated_hazard_h100(self):
        text = "Scenario: Test\n  And hazard H-100 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("H-100" in e for e in result.errors)

    def test_gddi_06_catches_multiple_hallucinated_ids(self):
        text = "Scenario: Test\n  But loss L-99 is realized\n  And hazard H-88 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("L-99" in e for e in result.errors)
        assert any("H-88" in e for e in result.errors)

    def test_gddi_07_passes_with_valid_ids(self):
        text = "Scenario: Test\n  But loss L-1 is realized\n  And hazard H-1 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert result.passed

    def test_gddi_08_passes_with_no_id_references(self):
        text = "Scenario: Test\n  Given PM-1-1 is active\n  When x\n  Then should reject\n  But approves\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert result.passed

    def test_gddi_validator_accepts_gherkin_spec(self):
        """Validator also works with GherkinSpec objects."""
        spec = _make_gherkin_spec(
            then_actual=["But the system approves", "And loss L-99 is realized"],
        )
        result = validate_loss_hazard_id_references(spec, self._la_with_ids())
        assert not result.passed
        assert any("L-99" in e for e in result.errors)


class TestLossHazardIdValidationInStage6:
    """GDDI-09: Loss/Hazard ID validation runs during Stage 6 artifact validation."""

    def test_gddi_09_stage6_validation_catches_hallucinated_id(self):
        from scenario_forge.stpa.scenario_prod.run import _validate_stage6_artifacts

        spec = _make_scenario_spec()
        cs = _make_cs()
        la = _make_loss_analysis(loss_ids=["L-1"], hazard_ids=["H-1"])
        gherkin_raw = "Scenario: Test\n  But loss L-99 is realized\n"
        errors: list[str] = []
        _validate_stage6_artifacts(
            {"root": "Induce ICA NOT_PROVIDED on CA-1-1", "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ], "leaves": []},
            None, gherkin_raw, cs, la, spec, errors,
        )
        assert any("L-99" in e for e in errors)


class TestLossHazardIdValidationInStage7:
    """GDDI-10: Loss/Hazard ID validation runs during Stage 7 envelope validation."""

    def test_gddi_10_stage7_validation_catches_hallucinated_id(self):
        from scenario_forge.stpa.scenario_prod.run import _validate_envelope_stage7

        la = _make_loss_analysis(loss_ids=["L-1"], hazard_ids=["H-1"])
        envelope = _make_envelope(
            gherkin_spec=_make_gherkin_spec(
                then_actual=["But the system approves", "And hazard H-99 occurs"],
            ),
            gherkin_raw="Scenario: Test\n  But hazard H-99 occurs\n",
        )
        errors: list[str] = []
        _validate_envelope_stage7(envelope, la, errors)
        assert any("H-99" in e for e in errors)


# ===========================================================================
# V689 — Attack tree root label
# ===========================================================================


class TestAttackTreeSystemPromptRootLabel:
    """V689-01: system prompt instructs exact ICA type usage."""

    def test_v689_01_system_prompt_instructs_exact_ica_type(self):
        loader = TemplateLoader(PROMPTS_DIR)
        prompt = loader.render_prompt("stage6b_tree_system.j2")
        assert "exact ICA type" in prompt.lower() or "exact ica type" in prompt.lower()
        assert "Induce ICA" in prompt
        assert "substitute" in prompt.lower() or "paraphrase" in prompt.lower()


class TestAttackTreeRootLabelValidatorPass:
    """V689-02: validator passes when root label matches exact ICA type."""

    def test_v689_02_not_provided(self):
        tree = {"root": "Induce ICA NOT_PROVIDED on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "NOT_PROVIDED", "CA-1-1")
        assert result.passed

    def test_v689_02_incorrect(self):
        tree = {"root": "Induce ICA INCORRECT on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "INCORRECT", "CA-1-1")
        assert result.passed

    def test_v689_02_wrong_timing(self):
        tree = {"root": "Induce ICA WRONG_TIMING on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "WRONG_TIMING", "CA-1-1")
        assert result.passed

    def test_v689_02_wrong_duration(self):
        tree = {"root": "Induce ICA WRONG_DURATION on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "WRONG_DURATION", "CA-1-1")
        assert result.passed


class TestAttackTreeRootLabelValidatorDrift:
    """V689-03: validator catches ICA type drift."""

    def test_v689_03_not_provided_to_not_triggered(self):
        tree = {"root": "Induce ICA NOT_TRIGGERED on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "NOT_PROVIDED", "CA-1-1")
        assert not result.passed
        assert any("NOT_PROVIDED" in e for e in result.errors)

    def test_v689_03_incorrect_to_wrong_value(self):
        tree = {"root": "Induce ICA WRONG_VALUE on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "INCORRECT", "CA-1-1")
        assert not result.passed
        assert any("INCORRECT" in e for e in result.errors)

    def test_v689_03_wrong_timing_to_late(self):
        tree = {"root": "Induce ICA LATE on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "WRONG_TIMING", "CA-1-1")
        assert not result.passed
        assert any("WRONG_TIMING" in e for e in result.errors)

    def test_v689_03_wrong_duration_to_too_long(self):
        tree = {"root": "Induce ICA TOO_LONG on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "WRONG_DURATION", "CA-1-1")
        assert not result.passed
        assert any("WRONG_DURATION" in e for e in result.errors)


class TestAttackTreeRootLabelMalformed:
    """V689-04: validator catches malformed root labels."""

    def test_v689_04_missing_ica_type(self):
        tree = {"root": "Induce ICA on CA-1-1"}
        result = validate_attack_tree_root_label(tree, "NOT_PROVIDED", "CA-1-1")
        assert not result.passed
        assert any("NOT_PROVIDED" in e for e in result.errors)

    def test_v689_04_wrong_ca_id(self):
        tree = {"root": "Induce ICA NOT_PROVIDED on CA-9-9"}
        result = validate_attack_tree_root_label(tree, "NOT_PROVIDED", "CA-1-1")
        assert not result.passed
        assert any("CA-1-1" in e for e in result.errors)

    def test_v689_04_empty_root(self):
        tree = {"root": ""}
        result = validate_attack_tree_root_label(tree, "NOT_PROVIDED", "CA-1-1")
        assert not result.passed
        assert any("root" in e.lower() for e in result.errors)


class TestAttackTreeRootLabelInStage6:
    """V689-05: root label validation runs during Stage 6 artifact validation."""

    def test_v689_05_stage6_validation_catches_drift(self):
        from scenario_forge.stpa.scenario_prod.run import _validate_stage6_artifacts

        spec = _make_scenario_spec(ica_type=UCAType.not_provided)
        cs = _make_cs()
        la = _make_loss_analysis()
        errors: list[str] = []
        _validate_stage6_artifacts(
            {"root": "Induce ICA NOT_TRIGGERED on CA-1-1", "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ], "leaves": []},
            None, "", cs, la, spec, errors,
        )
        assert any("NOT_PROVIDED" in e for e in errors)


class TestAttackTreeRootLabelInStage7:
    """V689-06: root label validation runs during Stage 7 envelope validation."""

    def test_v689_06_stage7_validation_catches_drift(self):
        from scenario_forge.stpa.scenario_prod.run import _validate_envelope_stage7

        la = _make_loss_analysis()
        envelope = ScenarioEnvelope(
            scenario_id="SCN-001",
            scenario_spec=_make_scenario_spec(ica_type=UCAType.not_provided),
            narrative="Narrative",
            attack_tree={"root": "Induce ICA NOT_TRIGGERED on CA-1-1", "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ], "leaves": []},
            gherkin_spec=_make_gherkin_spec(),
            gherkin_raw="",
            target_responsibility="RESP-1",
            ica_type=UCAType.not_provided,
            provenance="structural",
        )
        errors: list[str] = []
        _validate_envelope_stage7(envelope, la, errors)
        assert any("NOT_PROVIDED" in e for e in errors)


class TestAttackTreeUserPromptIcaType:
    """V689-07: user prompt passes ICA type to the LLM."""

    def test_v689_07_user_prompt_contains_ica_type(self):
        spec = _make_scenario_spec(ica_type=UCAType.not_provided)
        cs = _make_cs()
        loader = TemplateLoader(PROMPTS_DIR)
        _, user_prompt = build_attack_tree_prompts(spec, cs, loader)
        assert "NOT_PROVIDED" in user_prompt
        assert "CA-1-1" in user_prompt
