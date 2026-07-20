"""Tests for phantom system prompt retrieval detection (i00d).

Covers:
- Configuration/settings/admin API used for system prompt retrieval
- Diagnostic/introspection API/endpoint references
- Direct system prompt retrieval/dump/extraction phrasing
- Internal/system instructions accessed via API
- Identity management / auth token manipulation endpoints
- False positive guards for benign configuration text
"""

from __future__ import annotations

from datetime import datetime

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import CapabilityProfile
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
)
from scenario_forge.pipeline.validation import (
    _check_system_prompt_retrieval,
    validate_phantom_capabilities,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_envelope(
    step_actions: list[str] | None = None,
    step_effects: list[str] | None = None,
    scenario_id: str = "AP-T3-02-abc123",
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if step_actions is None:
        step_actions = ["I craft a malicious prompt to inject commands."]
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
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=steps,
    )

    attack_tree = AttackTree(
        id="tree-AP-T3-02",
        seed_id="AP-T3-02",
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
            agentic_threat_ids=["T3"],
            scenario_seed="AP-T3-02",
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
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


def _make_profile(
    kc_subcodes: list[str] | None = None,
    entry_points: list[str] | None = None,
) -> CapabilityProfile:
    """Build a minimal CapabilityProfile for testing."""
    if entry_points is None:
        entry_points = ["user prompts (zone 1)"]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=entry_points,
        confidence="high",
        kc_subcodes=kc_subcodes or [],
    )


# ---------------------------------------------------------------------------
# Unit tests: _check_system_prompt_retrieval directly
# ---------------------------------------------------------------------------


class TestCheckSystemPromptRetrievalDirect:
    """Direct tests for the _check_system_prompt_retrieval checker."""

    def test_configuration_api_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent uses the configuration API to retrieve the system prompt "
            "and expose internal instructions.",
            profile,
        )
        assert result is not None

    def test_config_api_system_instruction_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker queries the config API to access the system instruction "
            "governing agent behavior.",
            profile,
        )
        assert result is not None

    def test_settings_api_internal_instruction_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The compromised agent calls the settings API and returns the "
            "internal instruction set to the attacker.",
            profile,
        )
        assert result is not None

    def test_admin_api_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker leverages the admin API to dump the system prompt "
            "contents.",
            profile,
        )
        assert result is not None

    def test_diagnostic_api_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent accesses the diagnostic API to extract internal "
            "system configuration.",
            profile,
        )
        assert result is not None

    def test_diagnostic_endpoint_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker calls the diagnostic endpoint to inspect the "
            "agent's configuration.",
            profile,
        )
        assert result is not None

    def test_introspection_api_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker uses the introspection API to read internal "
            "prompt templates.",
            profile,
        )
        assert result is not None

    def test_introspection_endpoint_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent queries the introspection endpoint for system "
            "metadata.",
            profile,
        )
        assert result is not None

    def test_retrieve_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker retrieves the system prompt through a "
            "crafted tool call.",
            profile,
        )
        assert result is not None

    def test_dump_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent dumps the system prompt to the conversation output.",
            profile,
        )
        assert result is not None

    def test_extract_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker extracts the system prompt through a series "
            "of API calls.",
            profile,
        )
        assert result is not None

    def test_system_prompt_retrieval_noun_phrase_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The scenario involves system prompt retrieval via "
            "backend services.",
            profile,
        )
        assert result is not None

    def test_access_internal_instructions_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker accesses internal instructions governing "
            "the agent's behavior.",
            profile,
        )
        assert result is not None

    def test_obtain_system_instructions_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The compromised tool call obtains system instructions "
            "from the platform.",
            profile,
        )
        assert result is not None

    def test_internal_instructions_via_api_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent leaks its internal instructions via API to "
            "the attacker.",
            profile,
        )
        assert result is not None

    def test_system_instructions_via_endpoint_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker exposes the system instructions via endpoint "
            "response manipulation.",
            profile,
        )
        assert result is not None

    def test_configuration_endpoint_for_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker calls the configuration endpoint to read "
            "the prompt governing the agent.",
            profile,
        )
        assert result is not None

    def test_settings_endpoint_for_instruction_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The compromised agent queries the settings endpoint to "
            "extract the instruction template.",
            profile,
        )
        assert result is not None

    def test_diagnostic_retrieval_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker uses diagnostic retrieval to access system "
            "internals.",
            profile,
        )
        assert result is not None

    def test_configuration_retrieval_api_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent calls the configuration retrieval API to "
            "obtain its operating parameters.",
            profile,
        )
        assert result is not None

    def test_identity_management_api_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker abuses the identity management API to "
            "manipulate agent identity.",
            profile,
        )
        assert result is not None

    def test_auth_token_manipulation_endpoint_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent calls the auth token manipulation endpoint to "
            "forge credentials.",
            profile,
        )
        assert result is not None

    def test_fetch_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker fetches the system prompt from the backend "
            "configuration store.",
            profile,
        )
        assert result is not None

    def test_query_system_prompt_flagged(self) -> None:
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent queries the system prompt to determine its "
            "operational constraints.",
            profile,
        )
        assert result is not None


# ---------------------------------------------------------------------------
# False positive guards
# ---------------------------------------------------------------------------


class TestSystemPromptRetrievalFalsePositives:
    """Benign text should NOT trigger the system prompt retrieval checker."""

    def test_configure_chatbot_settings_not_flagged(self) -> None:
        """Normal reference to configuring settings."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The administrator uses the dashboard to configure the chatbot "
            "settings for the support channel.",
            profile,
        )
        assert result is None

    def test_api_returns_normal_data_not_flagged(self) -> None:
        """Normal API response without system prompt context."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The API returns account balance data for the authenticated user.",
            profile,
        )
        assert result is None

    def test_configuration_file_mention_not_flagged(self) -> None:
        """Mentioning configuration without API/retrieval context."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The system reads the configuration file to set up the "
            "database connection parameters.",
            profile,
        )
        assert result is None

    def test_diagnostic_log_not_flagged(self) -> None:
        """Diagnostic in a logging context, not API context."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The system writes a diagnostic log entry for the failed "
            "transaction.",
            profile,
        )
        assert result is None

    def test_system_prompt_injection_not_flagged(self) -> None:
        """Prompt injection (attacker injecting INTO the prompt) is not retrieval."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The attacker crafts a prompt injection payload to override "
            "the system prompt behavior.",
            profile,
        )
        assert result is None

    def test_internal_api_reference_not_flagged(self) -> None:
        """Generic internal API reference without system prompt context."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent makes a call to the internal API to fetch "
            "customer records.",
            profile,
        )
        assert result is None

    def test_settings_page_not_flagged(self) -> None:
        """User-facing settings page is not a system prompt retrieval."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The user navigates to the settings page and updates "
            "their notification preferences.",
            profile,
        )
        assert result is None

    def test_admin_api_without_prompt_context_not_flagged(self) -> None:
        """Admin API reference that does not involve system prompt retrieval."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The admin API is used to manage user accounts and roles.",
            profile,
        )
        assert result is None

    def test_legitimate_endpoint_call_not_flagged(self) -> None:
        """Normal endpoint for data retrieval."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The agent calls the payment endpoint to initiate a "
            "funds transfer.",
            profile,
        )
        assert result is None

    def test_configuration_management_not_flagged(self) -> None:
        """Configuration management for infrastructure, not prompt retrieval."""
        profile = _make_profile()
        result = _check_system_prompt_retrieval(
            "The infrastructure team uses configuration management "
            "tools to deploy updates.",
            profile,
        )
        assert result is None


# ---------------------------------------------------------------------------
# Integration tests: full validation pipeline
# ---------------------------------------------------------------------------


class TestSystemPromptRetrievalIntegration:
    """Integration tests using validate_phantom_capabilities."""

    def test_config_api_system_prompt_in_action_flagged(self) -> None:
        """Reference scenario AP-T3-02-29c701 pattern."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent uses the configuration API to retrieve the "
                    "system prompt and extract internal operating instructions."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "system_prompt_retrieval" for v in violations)

    def test_diagnostic_endpoint_in_effect_flagged(self) -> None:
        """Reference scenario AP-T9-01-216f4e pattern."""
        scenarios = [
            _make_envelope(
                step_actions=["The attacker probes the system."],
                step_effects=[
                    "The agent calls the diagnostic endpoint to retrieve "
                    "internal configuration details."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "system_prompt_retrieval" for v in violations)

    def test_retrieve_system_prompt_in_action_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker retrieves the system prompt by exploiting "
                    "a backend configuration lookup tool."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "system_prompt_retrieval" for v in violations)

    def test_introspection_api_in_tree_label_flagged(self) -> None:
        """Phantom pattern in attack tree node label."""
        scenario = _make_envelope(
            step_actions=["The attacker probes the system."],
        )
        scenario.attack_tree.root.children[0].label = (
            "Call introspection API to read system configuration"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "system_prompt_retrieval" and v.field == "attack_tree"
            for v in violations
        )

    def test_system_prompt_dump_in_gherkin_flagged(self) -> None:
        """Phantom pattern in behavior_spec."""
        scenario = _make_envelope(
            step_actions=["The attacker sends a benign prompt."],
        )
        scenario.behavior_spec = (
            "Feature: System prompt extraction\n"
            "  Scenario: Agent dumps system prompt\n"
            "    Given a compromised agent context\n"
            "    When the attacker dumps the system prompt via tool call\n"
            "    Then the system prompt contents are exposed\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "system_prompt_retrieval" and v.field == "behavior_spec"
            for v in violations
        )

    def test_benign_scenario_not_flagged(self) -> None:
        """Normal scenario passes without system_prompt_retrieval violations."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker crafts a prompt injection to manipulate "
                    "the agent's reasoning."
                ],
                step_effects=[
                    "The system follows the injected instructions and "
                    "reveals sensitive customer data."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "system_prompt_retrieval"

    def test_always_fires_regardless_of_profile(self) -> None:
        """System prompt retrieval is always phantom, even with rich profile."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent uses the diagnostic API to retrieve "
                    "system configuration."
                ],
            ),
        ]
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution", "memory"],
            has_persistent_memory=True,
            multi_agent=True,
            hitl=True,
            entry_points=[
                "user prompts (zone 1)",
                "admin console (zone 2)",
                "API gateway (zone 1)",
            ],
            confidence="high",
            kc_subcodes=["KC6.1.2", "KC6.2.2", "KC6.4", "KC6.5"],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "system_prompt_retrieval" for v in violations)

    def test_configure_chatbot_integration_not_flagged(self) -> None:
        """Full pipeline: benign configuration text passes."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The administrator configures the chatbot settings "
                    "through the management dashboard."
                ],
                step_effects=[
                    "The chatbot updates its greeting message according "
                    "to the new configuration."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "system_prompt_retrieval"

    def test_mixed_batch_with_system_prompt_retrieval(self) -> None:
        """Batch with clean and flagged scenarios separates correctly."""
        clean = _make_envelope(
            step_actions=["I craft a carefully designed prompt."],
            scenario_id="clean-1",
        )
        flagged = _make_envelope(
            step_actions=[
                "The attacker extracts the system prompt via "
                "a diagnostic endpoint call."
            ],
            scenario_id="flagged-1",
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([clean, flagged], profile)

        # The flagged scenario should have system_prompt_retrieval
        flagged_violations = [
            v
            for scenario, violations in result.flagged_scenarios
            for v in violations
            if scenario.scenario_id == "flagged-1"
        ]
        assert any(v.category == "system_prompt_retrieval" for v in flagged_violations)
