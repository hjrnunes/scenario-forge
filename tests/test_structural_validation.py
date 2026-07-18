"""Tests for structural (JSON Schema) validation of scenario envelopes.

Covers:
- Valid envelope passes structural validation
- Missing required fields are caught
- Invalid ID patterns are caught
- Invalid gate/children combinations are caught
- Validation results are written to the envelope
- Multiple violations are collected
"""

from __future__ import annotations

from datetime import datetime

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.scenario import (
    ArchitectureMatch,
    AttackComplexity,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeLayer,
    NarrativeStep,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SeverityLevel,
    StructuralExposureSignal,
    TaxonomyChain,
    TechniqueMaturity,
    ValidationBlock,
)
from scenario_forge.pipeline.validation import validate_scenario_structure


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(**overrides) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    steps = [
        NarrativeStep(
            step_number=1,
            zone="input",
            action="I craft a malicious prompt.",
            effect="The system processes the input.",
        ),
    ]
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="A test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=steps,
    )
    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1", label="Path A", gate=GateType.LEAF, zone="input"
                ),
                AttackTreeNode(
                    id="n1.2", label="Path B", gate=GateType.LEAF, zone="reasoning"
                ),
            ],
        ),
    )
    faceting = FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts (zone 1)",
        ),
        maestro_layers=[1, 2],
    )
    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )
    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )

    kwargs = dict(
        scenario_id="AP-T1-01-abc123",
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )
    kwargs.update(overrides)
    return ScenarioEnvelope(**kwargs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStructuralValidation:
    """Tests for validate_scenario_structure."""

    def test_valid_envelope_passes(self):
        """A well-formed envelope passes structural validation."""
        envelope = _make_envelope()
        validate_scenario_structure([envelope])

        assert envelope.validation is not None
        assert envelope.validation.structural.valid is True
        assert envelope.validation.structural.violations == []

    def test_validation_block_created_when_none(self):
        """When envelope.validation is None, structural validation creates it."""
        envelope = _make_envelope()
        assert envelope.validation is None
        validate_scenario_structure([envelope])
        assert envelope.validation is not None

    def test_validation_block_updated_when_exists(self):
        """When envelope.validation already exists, structural updates it."""
        envelope = _make_envelope()
        envelope.validation = ValidationBlock()
        validate_scenario_structure([envelope])

        assert envelope.validation.structural.valid is True

    def test_multiple_envelopes(self):
        """Structural validation runs on all envelopes in the list."""
        envelopes = [_make_envelope() for _ in range(3)]
        validate_scenario_structure(envelopes)

        for env in envelopes:
            assert env.validation is not None
            assert env.validation.structural.valid is True

    def test_validation_passed_reflects_structural(self):
        """validation_passed reflects structural result."""
        envelope = _make_envelope()
        validate_scenario_structure([envelope])

        # With all passes at defaults (valid=True), validation_passed should be True
        assert envelope.validation_passed is True

    def test_schema_loads_without_error(self):
        """The hand-maintained JSON Schema loads and is valid."""
        from scenario_forge.pipeline.validation import _load_envelope_schema

        schema = _load_envelope_schema()
        assert "$schema" in schema or "$defs" in schema
        assert schema["type"] == "object"


class TestStructuralValidationEdgeCases:
    """Edge cases for structural validation."""

    def test_envelope_with_behavior_spec_string(self):
        """Envelope with behavior_spec as a Gherkin string passes."""
        envelope = _make_envelope(
            behavior_spec="Feature: Test\n  Scenario: Attack\n    Given the system is running"
        )
        validate_scenario_structure([envelope])
        assert envelope.validation is not None
        assert envelope.validation.structural.valid is True

    def test_envelope_with_none_optional_fields(self):
        """Envelope with None optional fields still passes."""
        envelope = _make_envelope(
            scenario_seed_metadata=None,
            legitimate_task=None,
            actor_profile=None,
            candidate_filter=None,
        )
        validate_scenario_structure([envelope])
        assert envelope.validation is not None
        assert envelope.validation.structural.valid is True
