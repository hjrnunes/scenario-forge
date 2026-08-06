"""Tests for cmps.6 structured-evidence-based insider access validation.

Covers direct insider ingress with and without a material insider advantage,
indirect insider ingress, non-insider actors, and mixed batch validation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scenario_forge.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
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
)
from scenario_forge.pipeline.validation import validate_insider_access_floor
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block

ENTRY_POINT_ID = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
DEFAULT_INSIDER_ACCESS = ActorAccessProvenance(
    initial_entry_point_id=ENTRY_POINT_ID,
    ingress_mode="direct",
    access_class="public",
    material_insider_advantage="Authorized access to internal customer records.",
)


def _make_envelope(
    actor_type: str = "malicious-insider",
    step_actions: list[str] | None = None,
    step_effects: list[str] | None = None,
    summary: str = "An insider attacks the system.",
    resources: list[str] | None = None,
    scenario_id: str = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
    access: ActorAccessProvenance | None = DEFAULT_INSIDER_ACCESS,
) -> ScenarioEnvelope:
    """Build a minimal ScenarioEnvelope with an actor profile for testing."""
    if step_actions is None:
        step_actions = ["The attacker sends a prompt to the system."]
    if step_effects is None:
        step_effects = ["The system processes the input."] * len(step_actions)

    while len(step_effects) < len(step_actions):
        step_effects.append("The system processes the input.")

    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone="input",
            action=action,
            effect=step_effects[i],
        )
        for i, action in enumerate(step_actions)
    ]
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary=summary,
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=steps,
    )
    actor_profile = ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["The system has vulnerabilities."],
        desires=["Extract sensitive data."],
        intentions=["Exploit internal access to steal data."],
        resources=resources or ["Standard tools"],
        access=access,
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
                    id="n1.1",
                    label="Path A",
                    gate=GateType.LEAF,
                    zone="input",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Path B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
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
    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id=scenario_id,
        candidate_id="cand:v1:7e57c0de000000000000000000000000",
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        initial_entry_point_id=ENTRY_POINT_ID,
        narrative=narrative,
        actor_profile=actor_profile,
        attack_tree=attack_tree,
        behavior_spec=make_behavior_spec(),
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


class TestInsiderStructuredAccess:
    def test_direct_access_with_material_insider_advantage_passes(self):
        result = validate_insider_access_floor([_make_envelope()])
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_indirect_access_passes(self):
        access = ActorAccessProvenance(
            initial_entry_point_id=ENTRY_POINT_ID,
            ingress_mode="indirect",
            access_class="supply_chain",
            influence_source="ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            influence_mechanism="Poisoned content",
            trust_boundary_id="tb:v1:cccccccccccccccccccccccccccccccc",
        )
        result = validate_insider_access_floor([_make_envelope(access=access)])
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_direct_privileged_access_without_material_advantage_flagged(self):
        access = ActorAccessProvenance(
            initial_entry_point_id=ENTRY_POINT_ID,
            ingress_mode="direct",
            access_class="privileged",
        )
        result = validate_insider_access_floor([_make_envelope(access=access)])
        assert result.flagged_count == 1
        assert result.clean_count == 0


class TestInsiderMissingStructuredEvidence:
    def test_direct_access_without_material_insider_advantage_flagged(self):
        access = ActorAccessProvenance(
            initial_entry_point_id=ENTRY_POINT_ID,
            ingress_mode="direct",
            access_class="public",
        )
        result = validate_insider_access_floor([_make_envelope(access=access)])
        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_direct_access_with_blank_material_insider_advantage_flagged(self):
        access = ActorAccessProvenance(
            initial_entry_point_id=ENTRY_POINT_ID,
            ingress_mode="direct",
            access_class="authenticated",
            material_insider_advantage="   ",
        )
        result = validate_insider_access_floor([_make_envelope(access=access)])
        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_no_access_provenance_flagged(self):
        result = validate_insider_access_floor([_make_envelope(access=None)])
        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_violation_identifies_actor_and_missing_evidence(self):
        result = validate_insider_access_floor([_make_envelope(access=None)])
        _scenario, violation = result.flagged_scenarios[0]
        assert violation.actor_type == "malicious-insider"
        reason = violation.reason.lower()
        assert "material_insider_advantage" in reason or "access provenance" in reason


class TestNonInsiderActorsSkipped:
    def test_adversarial_user_passes_without_access(self):
        result = validate_insider_access_floor(
            [_make_envelope(actor_type="adversarial-user", access=None)]
        )
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_cybercriminal_passes_without_material_advantage(self):
        access = ActorAccessProvenance(
            initial_entry_point_id=ENTRY_POINT_ID,
            ingress_mode="direct",
            access_class="public",
        )
        result = validate_insider_access_floor(
            [_make_envelope(actor_type="cybercriminal", access=access)]
        )
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_supply_chain_actor_passes_regardless_of_access(self):
        result = validate_insider_access_floor(
            [_make_envelope(actor_type="supply-chain-actor", access=None)]
        )
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_scenario_without_actor_profile_passes(self):
        envelope = _make_envelope()
        envelope.actor_profile = None
        result = validate_insider_access_floor([envelope])
        assert result.flagged_count == 0
        assert result.clean_count == 1


class TestBatchValidation:
    def test_mixed_batch_correct_counts(self):
        missing_advantage = ActorAccessProvenance(
            initial_entry_point_id=ENTRY_POINT_ID,
            ingress_mode="direct",
            access_class="public",
        )
        flagged_id = "scenario:v2:cc2675b912bd0ffb62b4b2b77b59c46712c32ac167201286e694bdd306ed11d0"
        scenarios = [
            _make_envelope(
                scenario_id="scenario:v2:cff7f3f347f1cb94c1a3120f82e8564d63ef811b41784cc50d2d7b2ec05da64b",
            ),
            _make_envelope(scenario_id=flagged_id, access=missing_advantage),
            _make_envelope(
                scenario_id="scenario:v2:3c4623849a49a53911c4a3e48d8cead8a1858960bccdea7a1b978d73ec2f06d7",
                actor_type="adversarial-user",
                access=None,
            ),
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.clean_count == 2
        assert result.flagged_count == 1
        assert result.flagged_scenarios[0][0].scenario_id == flagged_id

    def test_empty_batch(self):
        result = validate_insider_access_floor([])
        assert result.clean_count == 0
        assert result.flagged_count == 0
