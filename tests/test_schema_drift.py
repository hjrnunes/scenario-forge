"""Drift detection test for the hand-maintained JSON Schema.

Compares key structural elements from ScenarioEnvelope.model_json_schema()
against the hand-maintained schema at
src/scenario_forge/data/schemas/scenario-envelope.schema.json
to flag divergences when the Pydantic model changes.

This test does NOT require exact equality -- the hand-maintained schema
may add constraints that Pydantic cannot express (e.g. conditional
gate/children rules). Instead, it checks that:

1. All required fields in the Pydantic schema are required in the JSON Schema.
2. All top-level property names in the Pydantic schema appear in the JSON Schema.
3. All $defs (model names) in the Pydantic schema appear in the JSON Schema.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scenario_forge.models.scenario import ScenarioEnvelope


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "scenario_forge"
    / "data"
    / "schemas"
    / "scenario-envelope.schema.json"
)


@pytest.fixture
def pydantic_schema() -> dict:
    """Generate the JSON Schema from the Pydantic model."""
    return ScenarioEnvelope.model_json_schema()


@pytest.fixture
def hand_schema() -> dict:
    """Load the hand-maintained JSON Schema."""
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


class TestSchemaDrift:
    """Drift detection between Pydantic model and hand-maintained schema."""

    def test_required_fields_present(self, pydantic_schema, hand_schema):
        """All fields that Pydantic marks as required appear in the hand schema's required list."""
        pydantic_required = set(pydantic_schema.get("required", []))
        hand_required = set(hand_schema.get("required", []))

        missing = pydantic_required - hand_required
        assert not missing, (
            f"Fields required in Pydantic model but missing from hand schema's required list: {missing}. "
            f"Update scenario-envelope.schema.json to include them."
        )

    def test_top_level_properties_present(self, pydantic_schema, hand_schema):
        """All top-level properties in the Pydantic schema appear in the hand schema."""
        pydantic_props = set(pydantic_schema.get("properties", {}).keys())
        hand_props = set(hand_schema.get("properties", {}).keys())

        missing = pydantic_props - hand_props
        assert not missing, (
            f"Properties in Pydantic model but missing from hand schema: {missing}. "
            f"Update scenario-envelope.schema.json to include them."
        )

    def test_defs_present(self, pydantic_schema, hand_schema):
        """All object-type $defs in the Pydantic schema appear in the hand schema.

        Note: Pydantic generates enum types as separate $defs, but the hand
        schema deliberately inlines them as ``enum`` arrays on their parent
        properties.  We only check object-type defs (actual sub-models),
        not enum defs.
        """
        pydantic_all_defs = pydantic_schema.get("$defs", {})
        hand_defs = set(hand_schema.get("$defs", {}).keys())

        # Filter to only object-type defs (models with properties).
        pydantic_object_defs = {
            name
            for name, defn in pydantic_all_defs.items()
            if defn.get("type") == "object" or "properties" in defn
        }

        missing = pydantic_object_defs - hand_defs
        assert not missing, (
            f"Sub-models in Pydantic schema but missing from hand schema $defs: {missing}. "
            f"Update scenario-envelope.schema.json to include them."
        )

    def test_hand_schema_is_valid_json_schema(self, hand_schema):
        """The hand-maintained schema is a syntactically valid JSON Schema."""
        import jsonschema

        # Validate the meta-schema of the hand schema itself.
        # Draft 2020-12 is used by the hand schema.
        validator_cls = jsonschema.Draft202012Validator
        validator_cls.check_schema(hand_schema)

    def test_pydantic_model_validates_against_hand_schema(self, hand_schema):
        """A Pydantic-serialized envelope validates against the hand schema."""
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
            SeverityLevel,
            StructuralExposureSignal,
            TaxonomyChain,
            TechniqueMaturity,
        )

        envelope = ScenarioEnvelope(
            scenario_id="AP-T1-01-abc123",
            generated_at=datetime.now(),
            generator_version="0.1.0",
            narrative=NarrativeLayer(
                title="Test",
                summary="Summary",
                entry_point="user prompts",
                zone_sequence=["input"],
                steps=[
                    NarrativeStep(
                        step_number=1,
                        zone="input",
                        action="Test action",
                        effect="Test effect",
                    )
                ],
            ),
            attack_tree=AttackTree(
                id="tree-AP-T1-01",
                seed_id="AP-T1-01",
                goal="Test goal",
                root=AttackTreeNode(
                    id="n1",
                    label="Root",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1",
                            label="A",
                            gate=GateType.LEAF,
                            zone="input",
                        ),
                        AttackTreeNode(
                            id="n1.2",
                            label="B",
                            gate=GateType.LEAF,
                            zone="input",
                        ),
                    ],
                ),
            ),
            behavior_spec="Feature: Test",
            faceting=FacetingMetadata(
                risk_card=RiskCardRef(
                    risk_id="r1",
                    risk_name="Risk",
                    risk_description="Desc",
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
                    zones_traversed=["input"],
                    architecture_match=ArchitectureMatch.explicit,
                    entry_point="user prompts",
                ),
                maestro_layers=[1],
            ),
            priority=Priority(
                composite=0.5,
                signals=PrioritySignals(
                    technique_maturity=TechniqueMaturity.feasible,
                    risk_impact=SeverityLevel.medium,
                    risk_likelihood=LikelihoodLevel.medium,
                    attack_complexity=AttackComplexity.medium,
                    architecture_match=ArchitectureMatch.explicit,
                    structural_exposure=StructuralExposureSignal.none,
                ),
            ),
            generation=GenerationMetadata(
                model="test-model",
                call_metadata=[
                    CallMetadata(
                        call=CallName.narrative,
                        prompt_tokens=100,
                        completion_tokens=200,
                        duration_ms=1000,
                    )
                ],
            ),
        )

        import jsonschema

        envelope_dict = envelope.model_dump(mode="json")
        jsonschema.validate(envelope_dict, hand_schema)
