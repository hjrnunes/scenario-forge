"""Tests for cmps.6 typed access provenance validation (Rule 12)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scenario_forge.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    InitialIngressAction,
)
from scenario_forge.models.capability_profile import (
    BoundaryConfidence,
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
    TrustBoundary,
    compute_trust_boundary_id,
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
from scenario_forge.pipeline.validation import validate_scenario_semantics
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block


def _make_profile(
    entry_points: list[EntryPoint] | None = None,
    zones_active: list[str] | None = None,
    trust_boundaries: list[TrustBoundary] | None = None,
) -> CapabilityProfile:
    if zones_active is None:
        zones_active = ["input", "reasoning", "tool_execution"]
    if entry_points is None:
        entry_points = [
            EntryPoint(
                name="user prompts (zone 1)",
                direction="input",
                controllability="direct",
            ),
        ]
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=entry_points,
        trust_boundaries=trust_boundaries,
        confidence="high",
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
    )


def _make_indirect_profile() -> CapabilityProfile:
    """Build a profile with two input EPs and a trust boundary for indirect access."""
    target = EntryPoint(
        name="knowledge base",
        direction="input",
        controllability="indirect",
    )
    source = EntryPoint(
        name="memory store feed",
        direction="input",
        controllability="indirect",
        ingress_zone="memory",
    )
    boundary = TrustBoundary(
        name="memory-to-input",
        from_zone="memory",
        to_zone="input",
        confidence=BoundaryConfidence.explicit,
    )
    return _make_profile(
        entry_points=[target, source],
        zones_active=["memory", "input", "reasoning", "tool_execution"],
        trust_boundaries=[boundary],
    )


def _make_envelope(
    actor_type: str = "cybercriminal",
    narrative_entry_point: str = "user prompts (zone 1)",
    zone_sequence: list[str] | None = None,
    seed_metadata: dict | None = None,
    entry_point_id: str | None = None,
    access: ActorAccessProvenance | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid scenario with an optional cmps.6 access record."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="A test summary.",
        entry_point=narrative_entry_point,
        zone_sequence=zone_sequence,
        steps=[
            NarrativeStep(
                step_number=1,
                zone=zone_sequence[0],
                action="Crafting a malicious prompt.",
                effect="System processes input.",
                projected_step_ids=("step.1",),
                canonical_action_kind="prepare",
                canonical_executor_role="attacker",
                canonical_boundary_position="crossing",
            ),
        ],
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
                    label="Step 1",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051.000",
                    action=(
                        InitialIngressAction(entry_point_id=entry_point_id)
                        if entry_point_id is not None
                        else AiSystemAction()
                    ),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step 2",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
                ),
            ],
        ),
    )
    actor_profile = ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["System accepts user input."],
        desires=["Exfiltrate data."],
        intentions=["Inject crafted payload."],
        resources=["Open-source tools."],
        access=access,
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
            zones_traversed=zone_sequence,
            architecture_match=ArchitectureMatch.explicit,
            entry_point=narrative_entry_point,
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
    if seed_metadata is None:
        seed_metadata = {
            "seed_id": "AP-T1-01",
            "threat_id": "T1",
            "threat_name": "Test Threat",
        }

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id="scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
        candidate_id="cand:v2:7e57c0de000000000000000000000000",
        initial_entry_point_id=(
            actor_profile.access.initial_entry_point_id
            if actor_profile.access is not None
            else "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=make_behavior_spec(),
        faceting=faceting,
        priority=priority,
        generation=generation,
        scenario_seed_metadata=seed_metadata,
        actor_profile=actor_profile,
    )


def _find_violations(envelope: ScenarioEnvelope, rule: str) -> list:
    """Extract semantic violations matching a rule from the envelope."""
    if envelope.validation is None or envelope.validation.semantic is None:
        return []
    return [v for v in envelope.validation.semantic.violations if v.rule == rule]


def _access(
    entry_point_id: str,
    ingress_mode: str = "direct",
    access_class: str = "public",
    **evidence: str,
):
    return ActorAccessProvenance(
        initial_entry_point_id=entry_point_id,
        ingress_mode=ingress_mode,
        access_class=access_class,
        **evidence,
    )


def _validate(
    profile: CapabilityProfile,
    actor_type: str,
    access: ActorAccessProvenance | None,
    entry_point_id: str | None = None,
) -> ScenarioEnvelope:
    if entry_point_id is None:
        entry_point_id = profile.entry_points[0].entry_point_id
    envelope = _make_envelope(
        actor_type=actor_type,
        narrative_entry_point=profile.entry_points[0].name,
        entry_point_id=entry_point_id,
        access=access,
    )
    validate_scenario_semantics([envelope], profile)
    return envelope


class TestMissingAccessProvenance:
    def test_insider_with_ingress_and_no_access_flags(self) -> None:
        profile = _make_profile()
        envelope = _validate(profile, "malicious-insider", None)

        violations = _find_violations(envelope, "missing_access_provenance")
        assert len(violations) == 1
        assert violations[0].severity == "moderate"


class TestAccessClassIngressModeIncompatible:
    @pytest.mark.parametrize(
        "actor_type", ["adversarial-user", "cybercriminal", "hacktivist"]
    )
    def test_indirect_public_access_flags(self, actor_type: str) -> None:
        """Public access_class with indirect ingress is incompatible for any actor."""
        profile = _make_indirect_profile()
        ep_id = profile.entry_points[0].entry_point_id
        source_id = profile.entry_points[1].entry_point_id
        boundary_id = compute_trust_boundary_id("memory", "input", "memory-to-input")
        access = _access(
            ep_id,
            ingress_mode="indirect",
            access_class="public",
            influence_source=source_id,
            influence_mechanism="Poisoned content",
            trust_boundary_id=boundary_id,
        )
        envelope = _validate(profile, actor_type, access)

        violations = _find_violations(
            envelope, "access_class_ingress_mode_incompatible"
        )
        assert len(violations) == 1
        assert violations[0].severity == "major"


class TestIncompleteIndirectEvidence:
    @pytest.mark.parametrize(
        "missing_field",
        ["influence_source", "influence_mechanism", "trust_boundary_id"],
    )
    def test_missing_indirect_evidence_flags(self, missing_field: str) -> None:
        profile = _make_indirect_profile()
        ep_id = profile.entry_points[0].entry_point_id
        source_id = profile.entry_points[1].entry_point_id
        boundary_id = compute_trust_boundary_id("memory", "input", "memory-to-input")
        evidence = {
            "influence_source": source_id,
            "influence_mechanism": "Poisoned content",
            "trust_boundary_id": boundary_id,
        }
        evidence.pop(missing_field)
        envelope = _validate(
            profile,
            "supply-chain-actor",
            _access(
                ep_id,
                ingress_mode="indirect",
                access_class="supply_chain",
                **evidence,
            ),
        )

        violations = _find_violations(envelope, "incomplete_indirect_evidence")
        assert len(violations) == 1
        assert violations[0].severity == "major"

    def test_complete_indirect_evidence_passes(self) -> None:
        profile = _make_indirect_profile()
        ep_id = profile.entry_points[0].entry_point_id
        source_id = profile.entry_points[1].entry_point_id
        boundary_id = compute_trust_boundary_id("memory", "input", "memory-to-input")
        access = _access(
            ep_id,
            ingress_mode="indirect",
            access_class="supply_chain",
            influence_source=source_id,
            influence_mechanism="Poisoned content",
            trust_boundary_id=boundary_id,
        )
        envelope = _validate(profile, "supply-chain-actor", access)
        assert not _find_violations(envelope, "incomplete_indirect_evidence")


class TestMissingInsiderAdvantage:
    @pytest.mark.parametrize("actor_type", ["malicious-insider", "negligent-insider"])
    def test_direct_insider_without_advantage_flags(self, actor_type: str) -> None:
        profile = _make_profile()
        ep_id = profile.entry_points[0].entry_point_id
        envelope = _validate(
            profile,
            actor_type,
            _access(ep_id, ingress_mode="direct", access_class="authenticated"),
        )

        violations = _find_violations(envelope, "missing_insider_advantage")
        assert len(violations) == 1
        assert violations[0].severity == "major"

    def test_direct_insider_with_advantage_passes(self) -> None:
        profile = _make_profile()
        ep_id = profile.entry_points[0].entry_point_id
        access = _access(
            ep_id,
            ingress_mode="direct",
            access_class="authenticated",
            material_insider_advantage="Privileged internal credentials",
        )
        envelope = _validate(profile, "malicious-insider", access)
        assert not _find_violations(envelope, "missing_insider_advantage")


class TestValidActorAccessCombinations:
    @pytest.mark.parametrize(
        ("actor_type", "ingress_mode", "access_class", "evidence"),
        [
            ("cybercriminal", "direct", "public", {}),
            (
                "supply-chain-actor",
                "indirect",
                "supply_chain",
                {
                    "influence_mechanism": "Compromised release",
                    "trust_boundary_id": compute_trust_boundary_id(
                        "memory", "input", "memory-to-input"
                    ),
                },
            ),
            (
                "malicious-insider",
                "direct",
                "authenticated",
                {"material_insider_advantage": "Privileged internal credentials"},
            ),
            (
                "nation-state",
                "indirect",
                "supply_chain",
                {
                    "influence_mechanism": "Coordinated poisoning",
                    "trust_boundary_id": compute_trust_boundary_id(
                        "memory", "input", "memory-to-input"
                    ),
                },
            ),
        ],
    )
    def test_valid_combination_has_no_access_violation(
        self,
        actor_type: str,
        ingress_mode: str,
        access_class: str,
        evidence: dict[str, str],
    ) -> None:
        profile = (
            _make_indirect_profile()
            if ingress_mode == "indirect"
            else _make_profile(
                [
                    EntryPoint(
                        name="ingress", direction="input", controllability=ingress_mode
                    )
                ]
            )
        )
        ep_id = profile.entry_points[0].entry_point_id
        if ingress_mode == "indirect":
            evidence = {
                "influence_source": profile.entry_points[1].entry_point_id,
                **evidence,
            }
        envelope = _validate(
            profile,
            actor_type,
            _access(
                ep_id,
                ingress_mode=ingress_mode,
                access_class=access_class,
                **evidence,
            ),
        )

        access_rules = {
            "missing_access_provenance",
            "access_class_ingress_mode_incompatible",
            "incomplete_indirect_evidence",
            "missing_insider_advantage",
            "initial_entry_point_id_mismatch",
            "ineligible_ingress_entry_point",
            "unresolved_entry_point_id",
            "unresolved_influence_source",
            "unresolved_trust_boundary",
            "trust_boundary_target_zone_mismatch",
            "trust_boundary_source_zone_mismatch",
            "self_relation_influence_source",
            "output_influence_source",
            "system_influence_source",
            "system_entry_point_as_ingress",
            "ingress_mode_controllability_mismatch",
            "external_boundary_source_not_indirect",
        }
        assert not [
            violation
            for rule in access_rules
            for violation in _find_violations(envelope, rule)
        ]


class TestInitialEntryPointIdMismatch:
    def test_divergent_access_and_ingress_ids_both_flag(self) -> None:
        profile = _make_profile(
            [
                EntryPoint(
                    name="canonical ingress",
                    direction="input",
                    controllability="direct",
                ),
                EntryPoint(
                    name="actor ingress",
                    direction="input",
                    controllability="direct",
                ),
                EntryPoint(
                    name="tree ingress",
                    direction="input",
                    controllability="direct",
                ),
            ]
        )
        canonical_id, actor_id, tree_id = (
            entry_point.entry_point_id for entry_point in profile.entry_points
        )
        envelope = _make_envelope(
            actor_type="cybercriminal",
            narrative_entry_point=profile.entry_points[0].name,
            entry_point_id=tree_id,
            access=_access(actor_id),
        )
        envelope.initial_entry_point_id = canonical_id
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "initial_entry_point_id_mismatch")
        assert len(violations) == 2
        assert all(violation.severity == "major" for violation in violations)
        assert any("Actor access" in violation.message for violation in violations)
        assert any("Attack tree" in violation.message for violation in violations)

    def test_access_id_different_from_envelope_id_flags(self) -> None:
        profile = _make_profile(
            [
                EntryPoint(
                    name="primary ingress", direction="input", controllability="direct"
                ),
                EntryPoint(
                    name="other ingress", direction="input", controllability="direct"
                ),
            ]
        )
        envelope_ep_id = profile.entry_points[0].entry_point_id
        access_ep_id = profile.entry_points[1].entry_point_id
        access = _access(envelope_ep_id, ingress_mode="direct", access_class="public")
        envelope = _make_envelope(
            actor_type="cybercriminal",
            narrative_entry_point=profile.entry_points[0].name,
            entry_point_id=envelope_ep_id,
            access=access,
        )
        # Diverge actor provenance after construction so the tree remains
        # aligned with the canonical envelope ID.
        access.initial_entry_point_id = access_ep_id
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "initial_entry_point_id_mismatch")
        assert len(violations) == 1
        assert violations[0].severity == "major"

    def test_matching_access_and_tree_id_passes(self) -> None:
        profile = _make_profile()
        ep_id = profile.entry_points[0].entry_point_id
        envelope = _validate(
            profile,
            "cybercriminal",
            _access(ep_id, ingress_mode="direct", access_class="public"),
        )
        assert not _find_violations(envelope, "initial_entry_point_id_mismatch")


class TestIneligibleIngressEntryPoint:
    def test_output_only_entry_point_flags(self) -> None:
        profile = _make_profile(
            [
                EntryPoint(
                    name="response stream", direction="output", controllability="direct"
                )
            ]
        )
        ep_id = profile.entry_points[0].entry_point_id
        envelope = _validate(
            profile,
            "cybercriminal",
            _access(ep_id, ingress_mode="direct", access_class="public"),
        )

        violations = _find_violations(envelope, "ineligible_ingress_entry_point")
        assert len(violations) == 1
        assert violations[0].severity == "major"

    def test_system_controlled_entry_point_flags(self) -> None:
        profile = _make_profile(
            [
                EntryPoint(
                    name="internal scheduler",
                    direction="input",
                    controllability="system",
                )
            ]
        )
        ep_id = profile.entry_points[0].entry_point_id
        envelope = _validate(
            profile,
            "cybercriminal",
            _access(ep_id, ingress_mode="direct", access_class="public"),
        )

        violations = _find_violations(envelope, "ineligible_ingress_entry_point")
        assert len(violations) == 1
        assert violations[0].severity == "major"
