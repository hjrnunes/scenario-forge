"""Tests for phantom capability hardening (el87 bead).

Covers three root-cause fixes:
  A. AB-8 capability-based exclusion in compute_compatible_goal_ids
  B. Session introspection always-fire (KC6.1.2 / API suppression removed)
  C. API response fabrication phantom detection pattern
"""

from __future__ import annotations

from datetime import datetime

import pytest

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
from scenario_forge.pipeline.generate import (
    _THREAT_GOAL_EXCLUSIONS,
    compute_compatible_goal_ids,
)
from scenario_forge.pipeline.validation import (
    _check_api_response_fabrication,
    _check_session_introspection,
    validate_phantom_capabilities,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sub_goal(goal_id: str, name: str = "Test Goal") -> dict:
    """Create a minimal sub-goal dict for testing."""
    return {
        "id": goal_id,
        "name": name,
        "description": f"Description for {goal_id}",
        "sources": ["test"],
        "category_id": goal_id.split("-")[0].upper() if "-" in goal_id else "unknown",
        "category_name": "Test Category",
        "category_description": "Test category description",
    }


def _make_sub_goals_with_ids(*ids: str) -> list[dict]:
    """Create a list of sub-goals with the given IDs."""
    return [_make_sub_goal(gid) for gid in ids]


def _make_profile(
    kc_subcodes: list[str] | None = None,
    entry_points: list[str] | None = None,
    has_persistent_memory: bool = False,
) -> CapabilityProfile:
    """Build a minimal CapabilityProfile for testing."""
    if entry_points is None:
        entry_points = ["user prompts (zone 1)"]
    codes = list(kc_subcodes) if kc_subcodes else ["KC1.1"]
    if has_persistent_memory and "KC4.3" not in codes:
        codes.append("KC4.3")
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points,
        confidence="high",
        kc_subcodes=codes,
    )


def _make_envelope(
    step_actions: list[str] | None = None,
    step_effects: list[str] | None = None,
    scenario_id: str = "AP-T1-01-abc123",
    behavior_spec: str | dict | None = None,
    tree_labels: list[str] | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing.

    When *tree_labels* is provided, they are used as leaf node labels
    in the attack tree (for testing tree-node scanning).
    """
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

    # Build tree with custom labels if provided
    if tree_labels:
        children = [
            AttackTreeNode(
                id=f"n1.{i + 1}",
                label=label,
                gate=GateType.LEAF,
                zone="input",
            )
            for i, label in enumerate(tree_labels)
        ]
    else:
        children = [
            AttackTreeNode(
                id="n1.1", label="Path A", gate=GateType.LEAF, zone="input"
            ),
            AttackTreeNode(
                id="n1.2", label="Path B", gate=GateType.LEAF, zone="reasoning"
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
        behavior_spec=behavior_spec if behavior_spec is not None else {},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


# ===========================================================================
# Part A: AB-8 exclusion when profile lacks KCX-AUDIT
# ===========================================================================


class TestAB8ExclusionWithoutAudit:
    """AB-8 (Evidence Destruction) should be excluded when the profile
    lacks KCX-AUDIT (audit-write capability)."""

    def test_ab8_excluded_without_kcx_audit(self):
        """AB-8 removed when no KCX-AUDIT in kc_subcodes."""
        goals = _make_sub_goals_with_ids("AB-8", "AB-5", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T2",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=[],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" not in result_ids
        assert "AB-5" in result_ids
        assert "PR-1" in result_ids

    def test_ab8_kept_with_kcx_audit(self):
        """AB-8 retained when KCX-AUDIT is present."""
        goals = _make_sub_goals_with_ids("AB-8", "AB-5", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T2",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=["KCX-AUDIT"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" in result_ids

    def test_ab8_excluded_without_kc_subcodes_param(self):
        """AB-8 excluded when kc_subcodes is omitted (defaults to None)."""
        goals = _make_sub_goals_with_ids("AB-8", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T2",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" not in result_ids
        assert "PR-1" in result_ids

    def test_ab8_excluded_with_other_kcx_codes(self):
        """AB-8 excluded when KCX codes present but not KCX-AUDIT."""
        goals = _make_sub_goals_with_ids("AB-8", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id=None,
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=["KCX-MAGENT", "KCX-PMEM", "KC6.1.2"],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" not in result_ids


class TestAB8InteractionWithThreatExclusions:
    """AB-8 capability exclusion stacks with threat-specific exclusions."""

    def test_ab8_excluded_by_t15_even_with_audit(self):
        """T15 excludes AB-8 regardless of KCX-AUDIT (both mechanisms)."""
        goals = _make_sub_goals_with_ids("AB-8", "AB-5", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=["KCX-AUDIT"],
        )
        result_ids = {g["id"] for g in result}
        # T15 exclusion takes precedence even with audit capability
        assert "AB-8" not in result_ids

    def test_ab8_doubly_excluded_t15_no_audit(self):
        """T15 without audit: AB-8 excluded by both mechanisms."""
        goals = _make_sub_goals_with_ids("AB-8", "AB-9", "AB-5")
        result = compute_compatible_goal_ids(
            threat_id="T15",
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=[],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" not in result_ids
        assert "AB-9" not in result_ids  # T15 exclusion
        assert "AB-5" in result_ids

    def test_fallback_when_only_ab8_left(self):
        """If AB-8 is the only goal and would be excluded, fallback fires."""
        goals = _make_sub_goals_with_ids("AB-8")
        result = compute_compatible_goal_ids(
            threat_id=None,
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=[],
        )
        # Safety fallback: never return empty when input is non-empty
        assert len(result) == 1
        assert result[0]["id"] == "AB-8"

    def test_ab8_excluded_threat_goal_exclusion_constant_unchanged(self):
        """Verify AB-8 is still in T15 _THREAT_GOAL_EXCLUSIONS."""
        assert "AB-8" in _THREAT_GOAL_EXCLUSIONS["T15"]


# ===========================================================================
# Part B: Session introspection always fires
# ===========================================================================


class TestSessionIntrospectionAlwaysFires:
    """Session introspection should fire regardless of KC6.1.2 or API
    entry points -- the suppression was a bug (el87)."""

    def test_session_token_flagged_without_api_kc(self):
        """Baseline: session token flagged without API capability."""
        profile = _make_profile()
        result = _check_session_introspection(
            "extract the session tokens from the active context", profile
        )
        assert result is not None

    def test_session_token_flagged_with_kc612(self):
        """Session token still flagged WITH KC6.1.2 (was previously suppressed)."""
        profile = _make_profile(kc_subcodes=["KC6.1.2"])
        result = _check_session_introspection(
            "extract the session tokens from the active context", profile
        )
        assert result is not None

    def test_session_token_flagged_with_extensive_api_codes(self):
        """Session token still flagged WITH KC6.1.2 + KC6.2.2."""
        profile = _make_profile(kc_subcodes=["KC6.1.2", "KC6.2.2"])
        result = _check_session_introspection(
            "dump the authentication tokens used by the agent", profile
        )
        assert result is not None

    def test_bearer_token_flagged_with_api_entry_point(self):
        """Bearer token flagged even WITH API entry point."""
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "REST API (zone 1)"]
        )
        result = _check_session_introspection(
            "expose the bearer tokens for downstream services", profile
        )
        assert result is not None

    def test_api_auth_headers_flagged_with_http_entry_point(self):
        """API authorization headers flagged with HTTP entry point."""
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "HTTP gateway (zone 1)"]
        )
        result = _check_session_introspection(
            "requesting a dump of the active API authorization headers", profile
        )
        assert result is not None

    def test_session_credentials_flagged_with_both_kc_and_api_ep(self):
        """Session credentials flagged with KC6.1.2 + API entry point."""
        profile = _make_profile(
            kc_subcodes=["KC6.1.2"],
            entry_points=["user prompts (zone 1)", "API gateway (zone 1)"],
        )
        result = _check_session_introspection(
            "leak the session credentials to the attacker", profile
        )
        assert result is not None

    def test_integration_session_introspection_fires_with_kc612(self):
        """Full pipeline flags session introspection with KC6.1.2."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I trick the agent into dumping the session tokens."
                ],
            ),
        ]
        profile = _make_profile(kc_subcodes=["KC6.1.2"])
        result = validate_phantom_capabilities(scenarios, profile)
        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "session_introspection" for v in violations)

    def test_negative_normal_session_mention(self):
        """Ordinary 'session' reference should not trigger."""
        profile = _make_profile(kc_subcodes=["KC6.1.2"])
        result = _check_session_introspection(
            "The session continues with normal processing.", profile
        )
        assert result is None

    def test_negative_api_call_mention(self):
        """Generic API call mention should not trigger."""
        profile = _make_profile(kc_subcodes=["KC6.1.2"])
        result = _check_session_introspection(
            "The agent calls the payment API to process refunds.", profile
        )
        assert result is None


# ===========================================================================
# Part C: API response fabrication detection
# ===========================================================================


class TestAPIResponseFabricationDetection:
    """Scenarios that assume APIs return system metadata, prompt fragments,
    or other internal data should be flagged."""

    def test_system_metadata_flagged(self):
        """'system metadata' in narrative should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The API returns system metadata about the deployment.", profile
        )
        assert result is not None
        assert "system metadata" in result.lower()

    def test_system_level_metadata_flagged(self):
        """'system-level metadata' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "extract system-level metadata from the response payload", profile
        )
        assert result is not None

    def test_prompt_fragments_flagged(self):
        """'prompt fragments' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The response leaks prompt fragments from the system prompt.", profile
        )
        assert result is not None

    def test_model_configuration_flagged(self):
        """'model configuration' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The API reveals model configuration details.", profile
        )
        assert result is not None

    def test_model_weights_flagged(self):
        """'model weights' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The attacker downloads the model weights from an API.", profile
        )
        assert result is not None

    def test_training_data_flagged(self):
        """'training data' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The response includes training data samples.", profile
        )
        assert result is not None

    def test_internal_system_information_flagged(self):
        """'internal system information' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "Leak internal system information via error messages.", profile
        )
        assert result is not None

    def test_infrastructure_metadata_flagged(self):
        """'infrastructure metadata' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The endpoint exposes infrastructure metadata.", profile
        )
        assert result is not None

    def test_retrieve_system_internals_flagged(self):
        """'retrieve system internals' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The attacker retrieves system internals through the API.", profile
        )
        assert result is not None

    def test_extract_prompt_template_flagged(self):
        """'extract ... prompt template' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The adversary extracts the full prompt template.", profile
        )
        assert result is not None

    def test_raw_system_data_flagged(self):
        """'raw system data' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "Access raw system data from the monitoring endpoint.", profile
        )
        assert result is not None

    def test_model_parameters_exposure_flagged(self):
        """'model parameters ... exposed' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The API response exposes model parameters to the user.", profile
        )
        assert result is not None

    def test_system_prompt_content_flagged(self):
        """'system prompt content' should be flagged."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The error message reveals system prompt content.", profile
        )
        assert result is not None


class TestAPIResponseFabricationNegatives:
    """Normal API-related text should not trigger false positives."""

    def test_normal_api_response_passes(self):
        """Regular API response description should not trigger."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The API returns the user's account balance.", profile
        )
        assert result is None

    def test_system_call_passes(self):
        """'system call' without metadata should not trigger."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The system calls the payment processor.", profile
        )
        assert result is None

    def test_model_output_passes(self):
        """'model output' without configuration/weights should not trigger."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The model generates a helpful response.", profile
        )
        assert result is None

    def test_prompt_injection_passes(self):
        """'prompt injection' should not trigger (no 'fragment')."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The attacker performs a prompt injection attack.", profile
        )
        assert result is None

    def test_training_process_passes(self):
        """'training process' without 'data' should not trigger."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The model was fine-tuned during the training process.", profile
        )
        assert result is None

    def test_internal_api_passes(self):
        """'internal API' (common usage) should not trigger."""
        profile = _make_profile()
        result = _check_api_response_fabrication(
            "The agent accesses the internal API for processing.", profile
        )
        assert result is None


class TestAPIResponseFabricationIntegration:
    """Full-pipeline integration tests for API response fabrication."""

    def test_narrative_action_flagged(self):
        """System metadata in narrative action is flagged."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I probe the API to extract system metadata "
                    "about the deployment architecture."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)
        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "api_response_fabrication" for v in violations
        )

    def test_narrative_effect_flagged(self):
        """Prompt fragments in narrative effect is flagged."""
        scenarios = [
            _make_envelope(
                step_actions=["I send a crafted query."],
                step_effects=[
                    "The response leaks prompt fragments from the "
                    "system configuration."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)
        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "api_response_fabrication" and v.field == "effect"
            for v in violations
        )

    def test_behavior_spec_flagged(self):
        """Model configuration in behavior_spec is flagged."""
        scenario = _make_envelope(step_actions=["I send a benign prompt."])
        scenario.behavior_spec = (
            "Feature: Data Exfiltration\n"
            "  Scenario: Config leak\n"
            "    Then the API response reveals model configuration\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)
        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "api_response_fabrication"
            and v.field == "behavior_spec"
            for v in violations
        )

    def test_attack_tree_node_label_flagged(self):
        """System metadata in attack tree node label is flagged."""
        scenarios = [
            _make_envelope(
                step_actions=["I send a benign prompt."],
                tree_labels=[
                    "Extract system metadata via API probe",
                    "Benign path",
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)
        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "api_response_fabrication"
            and v.field == "attack_tree"
            for v in violations
        )

    def test_clean_scenario_passes(self):
        """Scenario with normal API references passes."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I query the API to retrieve account details."
                ],
                step_effects=[
                    "The API returns the user's financial summary."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)
        # Check no api_response_fabrication violations
        all_violations = [
            v
            for _, violations in result.flagged_scenarios
            for v in violations
        ]
        assert not any(
            v.category == "api_response_fabrication" for v in all_violations
        )

    def test_fabrication_always_fires_regardless_of_profile(self):
        """API response fabrication fires even with extensive API access."""
        profile = _make_profile(
            kc_subcodes=["KC6.1.2"],
            entry_points=["user prompts (zone 1)", "REST API (zone 1)"],
        )
        result = _check_api_response_fabrication(
            "The API returns system metadata about the infrastructure.", profile
        )
        assert result is not None


# ===========================================================================
# Adversarial / edge cases
# ===========================================================================


class TestAdversarialCases:
    """Adversarial and edge cases across all three fixes."""

    def test_ab8_only_goal_fallback(self):
        """When AB-8 is the only goal, fallback prevents empty pool."""
        goals = _make_sub_goals_with_ids("AB-8")
        result = compute_compatible_goal_ids(
            threat_id=None,
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=[],
        )
        assert len(result) == 1

    def test_session_introspection_with_all_api_indicators(self):
        """Session introspection fires even with maximum API presence."""
        profile = _make_profile(
            kc_subcodes=["KC6.1.2", "KC6.2.2"],
            entry_points=[
                "user prompts (zone 1)",
                "REST API (zone 1)",
                "HTTP webhook (zone 2)",
            ],
        )
        result = _check_session_introspection(
            "extract the bearer tokens from the session", profile
        )
        assert result is not None

    def test_fabrication_pattern_in_tree_not_narrative(self):
        """Fabrication only in tree node label, not narrative, is caught."""
        scenarios = [
            _make_envelope(
                step_actions=["I send a benign query."],
                step_effects=["The system responds normally."],
                tree_labels=[
                    "Obtain raw system configuration from endpoint",
                    "Normal processing path",
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)
        all_violations = [
            v
            for _, violations in result.flagged_scenarios
            for v in violations
        ]
        assert any(
            v.category == "api_response_fabrication"
            and v.field == "attack_tree"
            for v in all_violations
        )

    def test_multiple_phantom_categories_coexist(self):
        """A single scenario can trigger multiple phantom categories."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I extract the session tokens to access system metadata."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)
        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        categories = {v.category for v in violations}
        assert "session_introspection" in categories
        assert "api_response_fabrication" in categories

    def test_empty_kc_subcodes_excludes_ab8(self):
        """Explicitly passing empty list still excludes AB-8."""
        goals = _make_sub_goals_with_ids("AB-8", "PR-1")
        result = compute_compatible_goal_ids(
            threat_id=None,
            sub_goals=goals,
            zones_active=["input", "reasoning", "output", "tool_execution"],
            kc_subcodes=[],
        )
        result_ids = {g["id"] for g in result}
        assert "AB-8" not in result_ids
