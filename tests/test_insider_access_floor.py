"""Tests for insider access floor validation (6xe7 bead, Fix C).

Covers:
- Malicious-insider scenarios with insider-specific actions pass
- Malicious-insider scenarios with only public actions are flagged
- Non-insider actor types are not checked (always pass)
- Keyword matching on narrative steps (action + effect)
- Keyword matching on narrative summary
- Keyword matching on actor profile resources
- Multiple scenarios batch validation
"""

from __future__ import annotations

from datetime import datetime

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
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
from scenario_forge.pipeline.validation import (
    _has_insider_access_markers,
    validate_insider_access_floor,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    actor_type: str = "malicious-insider",
    step_actions: list[str] | None = None,
    step_effects: list[str] | None = None,
    summary: str = "An insider attacks the system.",
    resources: list[str] | None = None,
    scenario_id: str = "AP-T1-01-abc123",
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

    return ScenarioEnvelope(
        scenario_id=scenario_id,
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        actor_profile=actor_profile,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ---------------------------------------------------------------------------
# Tests: insider access keyword helper
# ---------------------------------------------------------------------------


class TestInsiderAccessMarkers:
    """Unit tests for the keyword matching helper."""

    def test_internal_system_matches(self):
        assert _has_insider_access_markers("Access the internal system to extract data")

    def test_admin_panel_matches(self):
        assert _has_insider_access_markers("Navigate to the admin panel")

    def test_admin_console_matches(self):
        assert _has_insider_access_markers("Log into the admin console")

    def test_backend_access_matches(self):
        assert _has_insider_access_markers("Leverage backend access to the database")

    def test_employee_portal_matches(self):
        assert _has_insider_access_markers("Use the employee portal credentials")

    def test_privileged_access_matches(self):
        assert _has_insider_access_markers("Exploit privileged access to internal resources")

    def test_corporate_vpn_matches(self):
        assert _has_insider_access_markers("Connect via corporate VPN to reach internal servers")

    def test_intranet_matches(self):
        assert _has_insider_access_markers("Access the intranet documentation")

    def test_deployment_pipeline_matches(self):
        assert _has_insider_access_markers("Modify the deployment pipeline configuration")

    def test_service_account_matches(self):
        assert _has_insider_access_markers("Use the service account to authenticate")

    def test_production_access_matches(self):
        assert _has_insider_access_markers("Gain production access to the database")

    def test_insider_keyword_matches(self):
        assert _has_insider_access_markers("Leveraging insider knowledge of the system")

    def test_hr_system_matches(self):
        assert _has_insider_access_markers("Query the HR system for employee records")

    def test_public_interface_no_match(self):
        assert not _has_insider_access_markers(
            "Send a carefully crafted prompt to the chatbot"
        )

    def test_generic_attack_no_match(self):
        assert not _has_insider_access_markers(
            "Submit malicious input through the customer-facing form"
        )

    def test_empty_string_no_match(self):
        assert not _has_insider_access_markers("")


# ---------------------------------------------------------------------------
# Tests: insider scenarios with insider-specific actions pass
# ---------------------------------------------------------------------------


class TestInsiderWithInsiderActions:
    """Malicious-insider scenarios exercising insider-specific actions pass."""

    def test_insider_with_internal_system_passes(self):
        scenarios = [
            _make_envelope(
                step_actions=["Access the internal system to extract customer data"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_insider_with_admin_panel_passes(self):
        scenarios = [
            _make_envelope(
                step_actions=["Log into the admin panel and modify access controls"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_insider_with_backend_access_passes(self):
        scenarios = [
            _make_envelope(
                step_actions=["Use backend access to modify transaction records"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_insider_with_insider_effect_passes(self):
        """Insider marker in step effect (not action) should still count."""
        scenarios = [
            _make_envelope(
                step_actions=["Execute the data exfiltration plan"],
                step_effects=["The internal system returns sensitive records"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_insider_with_insider_summary_passes(self):
        """Insider marker in narrative summary should count."""
        scenarios = [
            _make_envelope(
                summary="An insider leverages admin console access to steal data",
                step_actions=["Proceed with the attack plan"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_insider_with_insider_resources_passes(self):
        """Insider marker in actor resources should count."""
        scenarios = [
            _make_envelope(
                step_actions=["Execute the data theft plan"],
                resources=["Employee portal credentials", "Knowledge of workflows"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1


# ---------------------------------------------------------------------------
# Tests: insider scenarios with only public actions are flagged
# ---------------------------------------------------------------------------


class TestInsiderWithOnlyPublicActions:
    """Malicious-insider scenarios using only public interface are flagged."""

    def test_insider_with_public_prompt_flagged(self):
        scenarios = [
            _make_envelope(
                summary="A threat actor attacks the chatbot.",
                step_actions=["Send a jailbreak prompt to the chatbot"],
                step_effects=["The chatbot processes the input and responds"],
                resources=["Open-source tools", "Public documentation"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_insider_with_only_customer_interface_flagged(self):
        scenarios = [
            _make_envelope(
                summary="The attacker submits crafted queries.",
                step_actions=[
                    "Submit malicious input through the customer-facing form",
                    "Wait for the system to generate a response",
                ],
                step_effects=[
                    "The system processes the query",
                    "The system returns manipulated output",
                ],
                resources=["Standard attack tools"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 1
        assert result.clean_count == 0

    def test_flagged_violation_has_correct_actor_type(self):
        scenarios = [
            _make_envelope(
                summary="An attack via public interface.",
                step_actions=["Send crafted input through the API"],
                resources=["Public documentation"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 1
        _scenario, violation = result.flagged_scenarios[0]
        assert violation.actor_type == "malicious-insider"

    def test_flagged_violation_has_reason(self):
        scenarios = [
            _make_envelope(
                summary="An attack.",
                step_actions=["Send a prompt"],
                resources=["Tools"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 1
        _scenario, violation = result.flagged_scenarios[0]
        assert "insider-specific" in violation.reason.lower() or "insider" in violation.reason.lower()


# ---------------------------------------------------------------------------
# Tests: non-insider actor types are not checked
# ---------------------------------------------------------------------------


class TestNonInsiderActorsSkipped:
    """Non-insider actor types always pass -- no insider access floor check."""

    def test_adversarial_user_always_passes(self):
        scenarios = [
            _make_envelope(
                actor_type="adversarial-user",
                step_actions=["Send a jailbreak prompt"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_cybercriminal_always_passes(self):
        scenarios = [
            _make_envelope(
                actor_type="cybercriminal",
                step_actions=["Send a phishing payload"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_supply_chain_actor_always_passes(self):
        scenarios = [
            _make_envelope(
                actor_type="supply-chain-actor",
                step_actions=["Inject malicious code into the dependency"],
            )
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.flagged_count == 0
        assert result.clean_count == 1

    def test_scenario_without_actor_profile_passes(self):
        """Scenario with no actor_profile should pass (not applicable)."""
        envelope = _make_envelope(
            actor_type="adversarial-user",
            step_actions=["Do something"],
        )
        # Remove actor profile
        envelope.actor_profile = None
        result = validate_insider_access_floor([envelope])
        assert result.flagged_count == 0
        assert result.clean_count == 1


# ---------------------------------------------------------------------------
# Tests: batch validation
# ---------------------------------------------------------------------------


class TestBatchValidation:
    """Validate correct handling of mixed scenario batches."""

    def test_mixed_batch_correct_counts(self):
        """A batch with both passing and failing insider scenarios."""
        scenarios = [
            # Passes: insider with internal system
            _make_envelope(
                scenario_id="insider-good",
                step_actions=["Access the internal system"],
            ),
            # Fails: insider with only public actions
            _make_envelope(
                scenario_id="insider-bad",
                summary="An attack.",
                step_actions=["Send a prompt to the chatbot"],
                resources=["Tools"],
            ),
            # Passes: not an insider
            _make_envelope(
                scenario_id="external",
                actor_type="adversarial-user",
                step_actions=["Send a prompt"],
            ),
        ]
        result = validate_insider_access_floor(scenarios)
        assert result.clean_count == 2
        assert result.flagged_count == 1
        assert result.flagged_scenarios[0][0].scenario_id == "insider-bad"

    def test_empty_batch(self):
        result = validate_insider_access_floor([])
        assert result.clean_count == 0
        assert result.flagged_count == 0
