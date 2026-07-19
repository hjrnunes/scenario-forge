"""Tests for phantom capability validation pass.

Covers:
- Clean scenarios pass validation
- Privilege escalation detection (flagged when profile lacks admin KC)
- Code execution detection (flagged when KC6.2.2/KC6.5 absent)
- Credential exposure detection (flagged when KC6.1.2 absent)
- No false positives when profile declares relevant capabilities
- Integration point in runner.py
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
    validate_phantom_capabilities,
)


# ---------------------------------------------------------------------------
# Fixtures: helpers to build minimal valid objects
# ---------------------------------------------------------------------------


def _make_envelope(
    step_actions: list[str] | None = None,
    step_effects: list[str] | None = None,
    scenario_id: str = "AP-T1-01-abc123",
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if step_actions is None:
        step_actions = ["I craft a malicious prompt to inject commands."]
    if step_effects is None:
        step_effects = ["The system processes the input."] * len(step_actions)

    # Ensure actions and effects are the same length
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
# Tests: clean scenarios pass validation
# ---------------------------------------------------------------------------


class TestCleanScenariosPass:
    """Scenarios with benign narrative steps should pass validation."""

    def test_benign_steps_pass(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["I send a carefully crafted prompt."],
                step_effects=["The system responds with sensitive data."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0
        assert result.valid_scenarios == scenarios

    def test_multiple_clean_scenarios(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["I probe the system with edge-case inputs."],
                scenario_id="s1",
            ),
            _make_envelope(
                step_actions=["I manipulate the conversation context."],
                scenario_id="s2",
            ),
            _make_envelope(
                step_actions=["I exploit a reasoning flaw."],
                scenario_id="s3",
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 3
        assert result.flagged_count == 0

    def test_empty_scenarios_list(self) -> None:
        result = validate_phantom_capabilities([], _make_profile())
        assert result.valid_count == 0
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: privilege escalation detection
# ---------------------------------------------------------------------------


class TestPrivilegeEscalation:
    """Scenarios referencing privilege escalation should be flagged
    when the profile lacks admin/role-management capabilities."""

    def test_elevated_privileges_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I escalate privileges to gain admin access to the system."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        assert result.valid_count == 0
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "privilege_escalation" for v in violations)

    def test_tiered_privilege_levels_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["I leverage tiered privilege tokens to move laterally."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "privilege_escalation" for v in violations)

    def test_role_escalation_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["I perform role escalation to obtain elevated access."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_admin_token_in_effect_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["I probe the system."],
                step_effects=[
                    "The system issues an elevated token granting admin access."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.field == "effect" for v in violations)

    def test_privilege_escalation_passes_with_admin_entry_point(self) -> None:
        """No false positive when profile has admin entry points."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I escalate privileges to gain admin access to the system."
                ],
            ),
        ]
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "admin console (zone 2)"],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0

    def test_privilege_escalation_passes_with_kc64(self) -> None:
        """No false positive when profile has KC6.4 (identity/auth management)."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I escalate privileges to gain admin access to the system."
                ],
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.4"])
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: code execution detection
# ---------------------------------------------------------------------------


class TestCodeExecution:
    """Scenarios referencing code execution should be flagged
    when KC6.2.2/KC6.5 are absent from the profile."""

    def test_python_script_execution_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I trick the assistant into generating a Python script "
                    "that exfiltrates data."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_shell_command_execution_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["The agent executes shell commands on the host system."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_arbitrary_code_execution_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system executes arbitrary code provided in the prompt."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_code_execution_passes_with_kc622(self) -> None:
        """No false positive when profile has KC6.2.2 (code execution)."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I trick the assistant into generating a Python script "
                    "that exfiltrates data."
                ],
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.2.2"])
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0

    def test_code_execution_passes_with_kc65(self) -> None:
        """No false positive when profile has KC6.5 (filesystem operations)."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I trick the assistant into generating a Python script "
                    "that exfiltrates data."
                ],
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.5"])
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0

    def test_runs_python_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=["The assistant runs the python payload on the server."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1


# ---------------------------------------------------------------------------
# Tests: credential exposure detection
# ---------------------------------------------------------------------------


class TestCredentialExposure:
    """Scenarios referencing credential exposure should be flagged
    when the profile lacks API/HTTP capabilities."""

    def test_auth_header_exposure_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The LLM outputs the authorization header containing "
                    "the bearer token in its response."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "credential_exposure" for v in violations)

    def test_api_key_leak_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=["The system exposes the API key in the chat output."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_infrastructure_credential_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I extract infrastructure credentials from the model output."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_credential_exposure_passes_with_kc612(self) -> None:
        """No credential_exposure false positive when profile has KC6.1.2.

        Note: session_introspection still fires on 'bearer token' (always
        phantom — el87), but credential_exposure specifically is suppressed.
        """
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The LLM outputs the authorization header containing "
                    "the bearer token in its response."
                ],
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.1.2"])
        result = validate_phantom_capabilities(scenarios, profile)

        # credential_exposure should NOT fire with KC6.1.2
        all_violations = [
            v
            for _, violations in result.flagged_scenarios
            for v in violations
        ]
        assert not any(
            v.category == "credential_exposure" for v in all_violations
        )
        # session_introspection fires on 'bearer token' (always phantom)
        assert any(
            v.category == "session_introspection" for v in all_violations
        )

    def test_credential_exposure_passes_with_api_entry_point(self) -> None:
        """No credential_exposure false positive when profile has API entry
        points.

        Note: session_introspection still fires on 'bearer token' (always
        phantom — el87), but credential_exposure specifically is suppressed.
        """
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The LLM outputs the authorization header containing "
                    "the bearer token in its response."
                ],
            ),
        ]
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "API gateway (zone 1)"],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        # credential_exposure should NOT fire with API entry point
        all_violations = [
            v
            for _, violations in result.flagged_scenarios
            for v in violations
        ]
        assert not any(
            v.category == "credential_exposure" for v in all_violations
        )
        # session_introspection fires on 'bearer token' (always phantom)
        assert any(
            v.category == "session_introspection" for v in all_violations
        )


# ---------------------------------------------------------------------------
# Tests: mass broadcasting detection
# ---------------------------------------------------------------------------


class TestMassBroadcasting:
    """Scenarios referencing mass broadcasting should be flagged
    when the profile is reactive (no persistent memory, no multi-agent)."""

    def test_broadcast_keyword_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent uses the broadcast channel to notify all users."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "mass_broadcasting" for v in violations)

    def test_proactively_reach_out_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The compromised assistant begins to proactively reach out "
                    "to customers with phishing links."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "mass_broadcasting" for v in violations)

    def test_push_to_all_users_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system push to all users a fraudulent notification."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_mass_notification_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker triggers a mass notification containing "
                    "the malicious payload."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_bulk_messaging_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent starts bulk messaging customers with "
                    "fraudulent payment links."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_send_to_thousands_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system send to thousands of customers the "
                    "manipulated response."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_notify_all_customers_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker instructs the agent to notify all customers "
                    "about a fake security update."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_broadcasting_passes_with_persistent_memory(self) -> None:
        """No false positive when profile has persistent memory."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent uses the broadcast channel to notify all users."
                ],
            ),
        ]
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=True,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=[],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0

    def test_broadcasting_passes_with_multi_agent(self) -> None:
        """No false positive when profile has multi-agent."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent uses the broadcast channel to notify all users."
                ],
            ),
        ]
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "inter_agent"],
            has_persistent_memory=False,
            multi_agent=True,
            hitl=False,
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=[],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: cross-session access detection
# ---------------------------------------------------------------------------


class TestCrossSessionAccess:
    """Scenarios referencing cross-session/cross-user access should be flagged
    when the profile lacks persistent memory."""

    def test_other_user_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker accesses data belonging to other user accounts."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "cross_session_access" for v in violations)

    def test_different_account_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent retrieves records from a different account."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_cross_user_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system enables cross-user data access through "
                    "the compromised context."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_another_customer_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker pivots to access another customer's "
                    "financial data."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_target_victim_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker identifies a target victim and extracts "
                    "their session data."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_access_other_session_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent can now access the other active session's "
                    "data store."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_process_unauthorized_user_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system begins to process requests for an "
                    "unauthorized user."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_cross_session_passes_with_persistent_memory(self) -> None:
        """No false positive when profile has persistent memory."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker accesses data belonging to other user accounts."
                ],
            ),
        ]
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "memory"],
            has_persistent_memory=True,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=[],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: audit/monitoring write access detection
# ---------------------------------------------------------------------------


class TestAuditMonitoringWrite:
    """Scenarios referencing audit/monitoring write access should always be
    flagged since no KC subcode grants this capability."""

    def test_modify_audit_trail_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker instructs the agent to modify audit trail "
                    "entries to cover tracks."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)

    def test_alter_logs_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The compromised agent can now alter logs to remove "
                    "evidence of the intrusion."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_tamper_logging_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker uses the agent to tamper with the logging "
                    "infrastructure."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_suppress_alerts_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent is able to suppress security alerts to "
                    "avoid detection."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_disable_monitoring_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker convinces the agent to disable monitoring "
                    "for the compromised service."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_manipulate_log_entries_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent manipulates log entries to hide the "
                    "unauthorized access."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_write_to_monitoring_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The attacker can write to monitoring dashboards "
                    "to create false alerts."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_audit_write_flagged_even_with_rich_profile(self) -> None:
        """Audit write is always phantom — even profiles with many
        capabilities should be flagged."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker instructs the agent to modify audit trail "
                    "entries to cover tracks."
                ],
            ),
        ]
        # Rich profile with many capabilities
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "memory", "inter_agent"],
            has_persistent_memory=True,
            multi_agent=True,
            hitl=True,
            entry_points=[
                "user prompts (zone 1)",
                "admin console (zone 2)",
                "API gateway (zone 1)",
            ],
            confidence="high",
            kc_subcodes=[],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)


# ---------------------------------------------------------------------------
# Tests: mixed scenarios
# ---------------------------------------------------------------------------


class TestMixedScenarios:
    """Test batches with a mix of valid and invalid scenarios."""

    def test_mixed_batch_separates_valid_from_flagged(self) -> None:
        clean = _make_envelope(
            step_actions=["I craft a carefully designed prompt."],
            scenario_id="clean-1",
        )
        phantom = _make_envelope(
            step_actions=[
                "I escalate privileges to gain elevated access to the admin role."
            ],
            scenario_id="phantom-1",
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([clean, phantom], profile)

        assert result.valid_count == 1
        assert result.flagged_count == 1
        assert result.valid_scenarios[0].scenario_id == "clean-1"
        assert result.flagged_scenarios[0][0].scenario_id == "phantom-1"

    def test_multiple_violations_in_single_scenario(self) -> None:
        """A scenario with multiple phantom categories gets all violations."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I escalate privileges to gain admin access.",
                    "I trick the system into generating a Python script.",
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        categories = {v.category for v in violations}
        assert "privilege_escalation" in categories
        assert "code_execution" in categories

    def test_violation_categories_property(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=["I escalate privileges to gain admin access."],
                scenario_id="s1",
            ),
            _make_envelope(
                step_effects=["The system exposes the API key in plain text."],
                scenario_id="s2",
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 2
        cats = result.violation_categories
        assert "credential_exposure" in cats
        assert "privilege_escalation" in cats

    def test_all_seven_categories_detected(self) -> None:
        """Integration: all 7 sub-patterns fire on a reactive profile."""
        scenarios = [
            _make_envelope(
                step_actions=["I escalate privileges to gain admin access."],
                scenario_id="s1",
            ),
            _make_envelope(
                step_effects=[
                    "The LLM outputs the authorization header containing "
                    "the bearer token."
                ],
                scenario_id="s2",
            ),
            _make_envelope(
                step_actions=[
                    "I trick the system into generating a Python script."
                ],
                scenario_id="s3",
            ),
            _make_envelope(
                step_actions=[
                    "The agent starts bulk messaging customers with scam links."
                ],
                scenario_id="s4",
            ),
            _make_envelope(
                step_actions=[
                    "The attacker pivots to access another customer's data."
                ],
                scenario_id="s5",
            ),
            _make_envelope(
                step_effects=[
                    "The agent can now alter logs to remove evidence."
                ],
                scenario_id="s6",
            ),
            _make_envelope(
                step_actions=[
                    "The attacker triggers a Policy Audit tool invocation "
                    "to extract internal compliance data."
                ],
                scenario_id="s7",
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 7
        cats = result.violation_categories
        assert "privilege_escalation" in cats
        assert "credential_exposure" in cats
        assert "code_execution" in cats
        assert "mass_broadcasting" in cats
        assert "cross_session_access" in cats
        assert "audit_monitoring_write" in cats
        assert "phantom_tool_invocation" in cats


# ---------------------------------------------------------------------------
# Tests: v17 escapee patterns — new phrasing variants
# ---------------------------------------------------------------------------


class TestV17EscapeePrivilegeEscalation:
    """v16 escapee phrasing that v17 patterns must now catch."""

    def test_emergency_administrative_debugging_mode(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker activates the Emergency Administrative "
                    "Debugging Mode to access restricted functions."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "privilege_escalation" for v in violations)

    def test_self_permission_elevation(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The compromised agent performs self-permission elevation "
                    "to bypass access controls."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "privilege_escalation" for v in violations)

    def test_dynamic_privilege_request(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system processes a dynamic privilege request "
                    "granting elevated access."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "privilege_escalation" for v in violations)


class TestV17EscapeeCredentialExposure:
    """v16 escapee phrasing for credential exposure."""

    def test_error_messages_containing_tokens(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "API error messages containing active session tokens "
                    "and API credentials are exposed to the attacker."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "credential_exposure" for v in violations)

    def test_diagnostic_messages_leaking_secrets(self) -> None:
        """Non-escapee variant to test pattern breadth."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "Debug messages reveal the session token used for "
                    "backend authentication."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "credential_exposure" for v in violations)


class TestV17EscapeeCodeExecution:
    """v16 escapee phrasing for code execution."""

    def test_execute_distribute_malicious_payloads(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker tricks the agent to execute and distribute "
                    "malicious financial payloads to downstream systems."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_deploy_malicious_payload(self) -> None:
        """Variant: deploy instead of execute."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system deploys a malicious update payload "
                    "across the infrastructure."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)


class TestV17EscapeeMassBroadcasting:
    """v16 escapee phrasing for mass broadcasting."""

    def test_mass_phishing_message_distribution(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The attacker initiates mass phishing message "
                    "distribution to all account holders."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "mass_broadcasting" for v in violations)

    def test_mass_distribution_variant(self) -> None:
        """Test the mass + distribution pattern specifically."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent begins mass distribution of fraudulent "
                    "account alerts to customers."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "mass_broadcasting" for v in violations)


class TestV17EscapeeCrossSessionAccess:
    """v16 escapee phrasing for cross-session access."""

    def test_feedback_loop_across_sessions(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The attacker establishes a feedback loop across "
                    "thousands of sessions to amplify the attack."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "cross_session_access" for v in violations)

    def test_across_sessions_variant(self) -> None:
        """Simple 'across sessions' reference."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent propagates corrupted data across sessions."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "cross_session_access" for v in violations)


class TestV17EscapeeAuditMonitoringWrite:
    """v16 escapee phrasing for audit/monitoring write access."""

    def test_session_history_reset(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent performs a session history reset to "
                    "eliminate evidence of the manipulation."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)

    def test_generate_deceptive_success_reports(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker instructs the agent to generate deceptive "
                    "success reports to conceal the failed transactions."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)

    def test_transaction_description_modification(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The compromised agent carries out transaction "
                    "description modification to disguise the fraud."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)

    def test_overwrite_audit_logs(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker uses the agent to overwrite audit "
                    "log entries covering the intrusion."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)

    def test_clear_session_history(self) -> None:
        """Verb-before-noun order for session history."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent clears the session history to remove "
                    "traces of the interaction."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)

    def test_modify_transaction_records(self) -> None:
        """Verb-before-noun order for transaction records."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The compromised agent modifies transaction records "
                    "to conceal unauthorized transfers."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "audit_monitoring_write" for v in violations)


# ---------------------------------------------------------------------------
# Tests: phantom tool invocation detection (new v17 checker)
# ---------------------------------------------------------------------------


class TestPhantomToolInvocation:
    """Scenarios referencing tools/APIs/endpoints not in the profile's
    entry_points should be flagged."""

    def test_named_tool_not_in_profile_flagged(self) -> None:
        """'Policy Audit tool' is not in entry_points."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker triggers a Policy Audit tool invocation "
                    "to extract internal compliance data."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "phantom_tool_invocation" for v in violations)

    def test_named_api_not_in_profile_flagged(self) -> None:
        """'Transaction Override API' is not in entry_points."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system connects to the Transaction Override API "
                    "to reverse completed payments."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "phantom_tool_invocation" for v in violations)

    def test_named_endpoint_not_in_profile_flagged(self) -> None:
        """'Admin Configuration endpoint' is not in entry_points."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker accesses the Admin Configuration endpoint "
                    "to modify system parameters."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "phantom_tool_invocation" for v in violations)

    def test_api_calls_to_phantom_action_flagged(self) -> None:
        """'API calls to overwrite audit logs' references a phantom API."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The attacker uses API calls to overwrite audit logs "
                    "and session history."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        cats = {v.category for v in violations}
        # Should be caught by phantom_tool_invocation and/or audit_monitoring_write
        assert "phantom_tool_invocation" in cats or "audit_monitoring_write" in cats

    def test_named_tool_in_profile_not_flagged(self) -> None:
        """Tool name matches an entry_point name -- no false positive."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker triggers a Policy Audit tool invocation "
                    "to extract internal compliance data."
                ],
            ),
        ]
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "Policy Audit dashboard (zone 2)",
            ],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        # phantom_tool_invocation should NOT fire (name matches entry point)
        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "phantom_tool_invocation"

    def test_named_api_in_profile_not_flagged(self) -> None:
        """API name matches an entry_point name -- no false positive."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system connects to the Transaction Override API "
                    "to reverse completed payments."
                ],
            ),
        ]
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "Transaction Override API (zone 2)",
            ],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "phantom_tool_invocation"

    def test_api_calls_word_overlap_suppresses(self) -> None:
        """'API calls to fetch account data' should not fire if profile
        has an entry point mentioning 'account'."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker makes API calls to fetch account data "
                    "for unauthorized purposes."
                ],
            ),
        ]
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "Account Management Portal (zone 2)",
            ],
        )
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "phantom_tool_invocation"

    def test_generic_tool_reference_not_flagged(self) -> None:
        """Generic 'a tool' reference should not trigger the checker."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker uses a tool to probe the system for "
                    "vulnerabilities."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "phantom_tool_invocation"

    def test_generic_api_reference_not_flagged(self) -> None:
        """Generic 'the API' reference should not trigger the checker."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The API returns sensitive information in the "
                    "response body."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "phantom_tool_invocation"

    def test_benign_text_no_false_positive(self) -> None:
        """Ordinary scenario text should not trigger phantom_tool."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I craft a carefully designed prompt to extract "
                    "sensitive information from the system."
                ],
                step_effects=[
                    "The system returns confidential data in the "
                    "response without proper filtering."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "phantom_tool_invocation"


# ---------------------------------------------------------------------------
# Tests: false positive guards for v17 patterns
# ---------------------------------------------------------------------------


class TestV17FalsePositiveGuards:
    """Ensure new v17 patterns do not fire on benign text."""

    def test_admin_discussion_no_false_positive(self) -> None:
        """Mentioning 'admin' in a non-escalation context."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker sends a message mentioning admin "
                    "policies as a social engineering lure."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "privilege_escalation"

    def test_session_mention_no_false_positive(self) -> None:
        """Mentioning 'session' without write/reset context."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The session continues with the attacker's injected "
                    "context still active."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "audit_monitoring_write"

    def test_transaction_mention_no_false_positive(self) -> None:
        """Mentioning 'transaction' without modification context."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker initiates a fraudulent transaction "
                    "through the compromised assistant."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "audit_monitoring_write"

    def test_payload_mention_no_false_positive(self) -> None:
        """Mentioning 'payload' without execution context."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker crafts a prompt injection payload "
                    "designed to confuse the reasoning engine."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_mass_mention_no_false_positive(self) -> None:
        """Mentioning 'mass' in a non-broadcasting context."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The attack achieves a massive impact on the "
                    "system's response quality."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "mass_broadcasting"


# ---------------------------------------------------------------------------
# Tests: runner.py integration
# ---------------------------------------------------------------------------


class TestRunnerIntegration:
    """Verify that validate_phantom_capabilities is wired into runner.py."""

    def test_validation_import_exists(self) -> None:
        """The runner imports validate_phantom_capabilities."""
        from scenario_forge.pipeline import runner

        assert hasattr(runner, "validate_phantom_capabilities")

    def test_validation_called_in_pipeline(self) -> None:
        """validate_phantom_capabilities is called after generation
        and before coverage remediation in run_pipeline()."""
        import inspect

        from scenario_forge.pipeline import runner

        source = inspect.getsource(runner.run_pipeline)
        # Validation call should appear in the source
        assert "validate_phantom_capabilities" in source
        # Validation should appear before coverage remediation
        val_pos = source.index("validate_phantom_capabilities")
        cov_pos = source.index("Coverage Remediation Pass")
        assert val_pos < cov_pos, (
            "Validation pass should run before coverage remediation"
        )


# ---------------------------------------------------------------------------
# Tests: v18 expanded code generation patterns
# ---------------------------------------------------------------------------


class TestV18CodeGenPatterns:
    """v18 expanded patterns catch code-generation phrasing that
    bypassed the v17 checker."""

    # -- The three v17 escapee scenarios that must now be caught --

    def test_exploit_code_assembly_flagged(self) -> None:
        """v17 AP-T8-02-427677: 'exploit code assembly'."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker leverages the agent for exploit code assembly "
                    "targeting downstream services."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_python_script_generation_flagged(self) -> None:
        """v17 AP-T8-03-cc1aa3: 'Python script generation for API exploitation'."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system performs Python script generation for "
                    "API exploitation against external endpoints."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_obfuscated_script_synthesis_flagged(self) -> None:
        """v17 AP-T7-05-f6e7b4: 'obfuscated script synthesis'."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker instructs the agent to perform obfuscated "
                    "script synthesis to evade detection."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    # -- Noun-phrase generation patterns --

    def test_script_generation_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent performs script generation to create "
                    "exploitation tools."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_script_synthesis_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker triggers script synthesis through "
                    "a carefully crafted prompt."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_script_assembly_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system carries out script assembly for the "
                    "attacker's payload."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_code_generation_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent engages in code generation to produce "
                    "attack utilities."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_code_synthesis_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker uses the system for code synthesis of "
                    "data exfiltration routines."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_code_assembly_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system completes code assembly for the "
                    "malicious workflow."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    # -- Broader creation verbs --

    def test_craft_script_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker tricks the agent into crafting a script "
                    "that exfiltrates credentials."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_produce_exploit_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system produces an exploit that targets "
                    "the backend API."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_assemble_payload_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker instructs the agent to assemble "
                    "a payload for data exfiltration."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_synthesize_code_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent synthesizes code to bypass "
                    "the authentication layer."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    # -- Qualified noun phrases --

    def test_malicious_code_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system outputs malicious code that targets "
                    "the payment processing system."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)

    def test_exploit_code_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker uses the system to prepare exploit code "
                    "for the authentication bypass."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_obfuscated_script_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent produces an obfuscated script to avoid "
                    "detection by security tools."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_python_script_standalone_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system outputs a Python script that automates "
                    "credential harvesting."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_automated_script_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker triggers the creation of an automated "
                    "script for data exfiltration."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    def test_weaponized_code_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The agent delivers weaponized code to the target "
                    "infrastructure."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    # -- generate.*code pattern (broadened from "code snippet" to "code") --

    def test_generate_code_flagged(self) -> None:
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system generates code to automate the "
                    "attack workflow."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1

    # -- Gherkin behavior_spec scanning --

    def test_code_gen_in_gherkin_flagged(self) -> None:
        """Phantom code-gen phrasing in behavior_spec is caught."""
        scenario = _make_envelope(
            step_actions=["I send a benign prompt."],
        )
        scenario.behavior_spec = (
            "Feature: Exploit code assembly\n"
            "  Scenario: Agent assembles exploit code\n"
            "    Given a compromised agent context\n"
            "    When the attacker requests exploit code assembly\n"
            "    Then the system produces weaponized code\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "code_execution" and v.field == "behavior_spec"
            for v in violations
        )

    def test_gherkin_not_checked_when_none(self) -> None:
        """No error when behavior_spec is None."""
        scenario = _make_envelope(
            step_actions=["I send a benign prompt."],
        )
        scenario.behavior_spec = None
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0

    def test_gherkin_not_checked_when_dict(self) -> None:
        """behavior_spec as dict is not string-scanned (opaque)."""
        scenario = _make_envelope(
            step_actions=["I send a benign prompt."],
        )
        scenario.behavior_spec = {"steps": ["exploit code assembly"]}
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0

    # -- Profile suppression: patterns do NOT fire with KC6.2.2/KC6.5 --

    def test_expanded_patterns_pass_with_kc622(self) -> None:
        """All v18 patterns are suppressed when profile has KC6.2.2."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent performs exploit code assembly for the attacker."
                ],
                scenario_id="s1",
            ),
            _make_envelope(
                step_effects=[
                    "The system does Python script generation for "
                    "API exploitation."
                ],
                scenario_id="s2",
            ),
            _make_envelope(
                step_actions=[
                    "The agent carries out obfuscated script synthesis."
                ],
                scenario_id="s3",
            ),
            _make_envelope(
                step_effects=[
                    "The system outputs malicious code targeting the backend."
                ],
                scenario_id="s4",
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.2.2"])
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 4
        assert result.flagged_count == 0

    def test_expanded_patterns_pass_with_kc65(self) -> None:
        """All v18 patterns are suppressed when profile has KC6.5."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent crafts a script for data exfiltration."
                ],
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.5"])
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.valid_count == 1
        assert result.flagged_count == 0


# ---------------------------------------------------------------------------
# Tests: v18 false positive guards
# ---------------------------------------------------------------------------


class TestV18FalsePositiveGuards:
    """Expanded v18 patterns must not fire on benign phrases."""

    def test_error_code_no_false_positive(self) -> None:
        """'error code' is not about code execution."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system returns an error code indicating the "
                    "request was malformed."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_status_code_no_false_positive(self) -> None:
        """'status code' is not about code execution."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The API responds with a 403 status code denying "
                    "the request."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_code_of_conduct_no_false_positive(self) -> None:
        """'code of conduct' is not about code execution."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker references the code of conduct policy "
                    "to social-engineer the agent."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_manipulate_existing_script_no_false_positive(self) -> None:
        """Manipulating an existing script (not generating one) should
        not trigger the code_execution checker."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker modifies the existing configuration "
                    "to alter system behavior."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_prompt_injection_payload_no_false_positive(self) -> None:
        """'payload' in prompt injection context is not code execution."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker embeds a prompt injection payload "
                    "in the user query."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_qr_code_no_false_positive(self) -> None:
        """'QR code' is not about code execution."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system displays a QR code for the "
                    "payment confirmation."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_response_code_no_false_positive(self) -> None:
        """'response code' is not about code execution."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The server returns a response code 200 confirming "
                    "the transaction."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_benign_code_mention_no_false_positive(self) -> None:
        """Generic 'code' without generation/execution context
        should not be flagged."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker includes deceptive instructions in the "
                    "code section of the prompt."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"
