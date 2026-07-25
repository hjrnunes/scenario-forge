"""Tests for actor-type vs entry-point controllability validation (Rule 12).

Covers:
- Insider actor + direct controllability EP -> violation
- External actor + system controllability EP -> violation
- Valid combinations produce no violations
- No matching entry point in profile -> graceful skip
"""

from __future__ import annotations

from datetime import datetime

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
)
from scenario_forge.models.scenario import (
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    entry_points: list[EntryPoint] | None = None,
    zones_active: list[str] | None = None,
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
        confidence="high",
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool"),
        ],
    )


def _make_envelope(
    actor_type: str = "cybercriminal",
    narrative_entry_point: str = "user prompts (zone 1)",
    zone_sequence: list[str] | None = None,
    seed_metadata: dict | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for actor/entry-point tests."""
    if zone_sequence is None:
        zone_sequence = ["input", "reasoning"]

    steps = [
        NarrativeStep(
            step_number=1,
            zone=zone_sequence[0],
            action="Crafting a malicious prompt.",
            effect="System processes input.",
        ),
    ]

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="A test summary.",
        entry_point=narrative_entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
    )

    children = [
        AttackTreeNode(
            id="n1.1",
            label="Step 1",
            gate=GateType.LEAF,
            zone="input",
            technique_id="AML.T0051.000",
        ),
        AttackTreeNode(
            id="n1.2",
            label="Step 2",
            gate=GateType.LEAF,
            zone="reasoning",
        ),
    ]

    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=children,
        ),
    )

    actor_profile = ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["System accepts user input."],
        desires=["Exfiltrate data."],
        intentions=["Inject crafted payload."],
        resources=["Open-source tools."],
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
        scenario_id="AP-T1-01-abc123",
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
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
    return [
        v
        for v in envelope.validation.semantic.violations
        if v.rule == rule
    ]


# ---------------------------------------------------------------------------
# Tests: Insider actor + direct controllability -> violation
# ---------------------------------------------------------------------------


class TestInsiderDirectControllabilityMismatch:
    """Insider actors using direct-controllability entry points are flagged."""

    def test_malicious_insider_direct_ep_flags(self) -> None:
        """malicious-insider + direct controllability EP -> violation."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="chat interface",
                    direction="input",
                    controllability="direct",
                ),
            ],
        )
        envelope = _make_envelope(
            actor_type="malicious-insider",
            narrative_entry_point="chat interface",
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "actor_entry_point_mismatch")
        assert len(violations) == 1
        assert "malicious-insider" in violations[0].message
        assert "direct-controllability" in violations[0].message
        assert violations[0].severity == "moderate"

    def test_negligent_insider_direct_ep_flags(self) -> None:
        """negligent-insider + direct controllability EP -> violation."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="user prompts (zone 1)",
                    direction="input",
                    controllability="direct",
                ),
            ],
        )
        envelope = _make_envelope(
            actor_type="negligent-insider",
            narrative_entry_point="user prompts (zone 1)",
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "actor_entry_point_mismatch")
        assert len(violations) == 1
        assert "negligent-insider" in violations[0].message
        assert violations[0].severity == "moderate"


# ---------------------------------------------------------------------------
# Tests: External actor + system controllability -> violation
# ---------------------------------------------------------------------------


class TestExternalSystemControllabilityMismatch:
    """External actors using system-controllability entry points are flagged."""

    def test_adversarial_user_system_ep_flags(self) -> None:
        """adversarial-user + system controllability EP -> violation."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="internal scheduler",
                    direction="input",
                    controllability="system",
                ),
            ],
        )
        envelope = _make_envelope(
            actor_type="adversarial-user",
            narrative_entry_point="internal scheduler",
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "actor_entry_point_mismatch")
        assert len(violations) == 1
        assert "adversarial-user" in violations[0].message
        assert "system-controllability" in violations[0].message
        assert violations[0].severity == "moderate"


# ---------------------------------------------------------------------------
# Tests: Valid combinations -> no violation
# ---------------------------------------------------------------------------


class TestValidActorEntryPointCombinations:
    """Valid actor/entry-point combinations produce no violations."""

    def test_cybercriminal_direct_ep_passes(self) -> None:
        """cybercriminal + direct controllability EP -> no violation."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="chat interface",
                    direction="input",
                    controllability="direct",
                ),
            ],
        )
        envelope = _make_envelope(
            actor_type="cybercriminal",
            narrative_entry_point="chat interface",
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "actor_entry_point_mismatch")
        assert len(violations) == 0

    def test_insider_indirect_ep_passes(self) -> None:
        """malicious-insider + indirect controllability EP -> no violation."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="RAG knowledge base",
                    direction="input",
                    controllability="indirect",
                ),
            ],
        )
        envelope = _make_envelope(
            actor_type="malicious-insider",
            narrative_entry_point="RAG knowledge base",
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "actor_entry_point_mismatch")
        assert len(violations) == 0

    def test_no_matching_ep_skips_gracefully(self) -> None:
        """Narrative EP not matching any profile EP -> no violation (skip)."""
        profile = _make_profile(
            entry_points=[
                EntryPoint(
                    name="admin console",
                    direction="input",
                    controllability="system",
                ),
            ],
        )
        envelope = _make_envelope(
            actor_type="malicious-insider",
            narrative_entry_point="completely unrelated entry point",
        )
        validate_scenario_semantics([envelope], profile)

        violations = _find_violations(envelope, "actor_entry_point_mismatch")
        assert len(violations) == 0
