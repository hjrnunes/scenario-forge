"""Tests for field-aware code_execution phantom checker (dv72).

Covers:
- Action fields are skipped by _check_code_execution (attacker-side behavior)
- Effect fields are still caught (system-side phantom capability)
- Tree labels and Gherkin with attacker-context words are skipped
- Tree labels and Gherkin without attacker context are still caught
- Integration: validate_phantom_capabilities passes field_name through
- Other checkers are NOT affected by field_name (only code_execution skips)
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
    ToolInventoryEntry,
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
)
from scenario_forge.pipeline.validation import (
    _check_code_execution,
    validate_phantom_capabilities,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    kc_subcodes: list[str] | None = None,
    entry_points: list[str] | None = None,
) -> CapabilityProfile:
    """Build a minimal CapabilityProfile for testing."""
    if entry_points is None:
        entry_points = ["user prompts (zone 1)"]
    codes = list(kc_subcodes) if kc_subcodes else ["KC1.1"]
    kw = {}
    if any(c.startswith("KC5.") or c.startswith("KC6.") for c in codes):
        kw["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points,
        confidence="high",
        kc_subcodes=codes,
        **kw,
    )


def _make_envelope(
    step_actions: list[str] | None = None,
    step_effects: list[str] | None = None,
    scenario_id: str = "AP-T1-01-abc123",
    tree_labels: list[str] | None = None,
    behavior_spec: str | dict | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing.

    If tree_labels is provided, uses those as tree node labels.
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


# ---------------------------------------------------------------------------
# Unit tests: _check_code_execution field_name parameter
# ---------------------------------------------------------------------------


class TestCodeExecutionActionFieldSkip:
    """Action fields describe attacker behavior — code_execution
    should NOT fire on action fields (dv72)."""

    def test_action_field_skipped_python_script(self) -> None:
        """'generates a Python script' in an action field is skipped."""
        text = "I trick the assistant into generating a Python script."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="action")
        assert result is None

    def test_action_field_skipped_shell_command(self) -> None:
        """'executes shell commands' in an action field is skipped."""
        text = "The agent executes shell commands on the host system."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="action")
        assert result is None

    def test_action_field_skipped_crafts_payload(self) -> None:
        """'crafts a payload' in an action field is skipped."""
        text = "The attacker crafts a script to exfiltrate credentials."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="action")
        assert result is None

    def test_action_field_skipped_automated_script(self) -> None:
        """'automated script' in an action field is skipped."""
        text = "The attacker triggers an automated script for data theft."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="action")
        assert result is None

    def test_action_field_skipped_exploit_code(self) -> None:
        """'exploit code' in an action field is skipped."""
        text = "The attacker prepares exploit code for the bypass."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="action")
        assert result is None

    def test_action_field_skipped_automation_scripts(self) -> None:
        """'automation scripts' in an action field is skipped."""
        text = (
            "The attacker wraps requests for complex automation "
            "scripts within fragmented customer inquiries."
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="action")
        assert result is None


class TestCodeExecutionEffectFieldStillCaught:
    """Effect fields describe system behavior — code_execution
    SHOULD fire on effect fields (dv72)."""

    def test_effect_field_catches_python_script(self) -> None:
        text = "The system generates a Python script that exfiltrates data."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="effect")
        assert result is not None

    def test_effect_field_catches_shell_command(self) -> None:
        text = "The agent executes shell commands on the host system."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="effect")
        assert result is not None

    def test_effect_field_catches_arbitrary_code(self) -> None:
        text = "The system executes arbitrary code provided in the prompt."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="effect")
        assert result is not None

    def test_effect_field_catches_malicious_code(self) -> None:
        text = "The system outputs malicious code targeting the backend."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="effect")
        assert result is not None

    def test_effect_field_catches_automation_scripts(self) -> None:
        text = "The system produces automation scripts in response."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="effect")
        assert result is not None


class TestCodeExecutionEmptyFieldName:
    """When field_name is empty (default), code_execution fires normally
    for backward compatibility."""

    def test_empty_field_name_fires(self) -> None:
        text = "The system generates a Python script."
        profile = _make_profile()
        result = _check_code_execution(text, profile)
        assert result is not None

    def test_empty_field_name_fires_explicit(self) -> None:
        text = "The system generates a Python script."
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="")
        assert result is not None


# ---------------------------------------------------------------------------
# Unit tests: tree_label / gherkin attacker-context heuristic
# ---------------------------------------------------------------------------


class TestCodeExecutionTreeLabelAttackerContext:
    """Tree labels preceded by attacker-referencing words should be
    skipped by _check_code_execution (dv72)."""

    def test_tree_label_attacker_prefix_skipped(self) -> None:
        """'attacker crafts a script' in tree label is skipped."""
        text = "attacker crafts a script for data theft"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is None

    def test_tree_label_actor_prefix_skipped(self) -> None:
        """'actor writes a Python script' in tree label is skipped."""
        text = "actor writes a Python script to exploit the API"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is None

    def test_tree_label_adversary_prefix_skipped(self) -> None:
        """'adversary generates code' in tree label is skipped."""
        text = "adversary generates code for the payload"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is None

    def test_tree_label_threat_agent_prefix_skipped(self) -> None:
        """'threat agent produces a script' in tree label is skipped."""
        text = "threat agent produces a script to bypass auth"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is None

    def test_tree_label_red_team_prefix_skipped(self) -> None:
        """'red team crafts exploit code' in tree label is skipped."""
        text = "red team crafts exploit code for testing"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is None

    def test_tree_label_no_attacker_context_caught(self) -> None:
        """Code execution in tree label WITHOUT attacker context IS caught."""
        text = "Generate Python script for data exfiltration"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is not None

    def test_tree_label_system_side_caught(self) -> None:
        """System-side code execution in tree label IS caught."""
        text = "System executes arbitrary code from prompt"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        assert result is not None

    def test_tree_label_attacker_too_far_caught(self) -> None:
        """Attacker reference more than 20 chars before match is NOT skipped."""
        # "attacker" ends at char 8. The code execution match starts much later.
        text = (
            "attacker sends a carefully designed elaborate long "
            "prompt that generates a Python script"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label")
        # The attacker word is > 20 chars before the match — should be caught
        assert result is not None


class TestCodeExecutionGherkinAttackerContext:
    """Gherkin text preceded by attacker-referencing words should be
    skipped by _check_code_execution (dv72)."""

    def test_gherkin_attacker_prefix_skipped(self) -> None:
        """'attacker crafts a script' in Gherkin is skipped."""
        text = "When the attacker crafts a script for exfiltration"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is None

    def test_gherkin_actor_prefix_skipped(self) -> None:
        """'actor generates code' in Gherkin is skipped."""
        text = "Given the actor generates code for exploitation"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is None

    def test_gherkin_no_attacker_context_caught(self) -> None:
        """Code execution in Gherkin WITHOUT attacker context IS caught."""
        text = "Then the system generates a Python script for data theft"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is not None

    def test_gherkin_system_produces_caught(self) -> None:
        """System producing scripts in Gherkin IS caught."""
        text = "Then the system produces an exploit for the bypass"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is not None


# ---------------------------------------------------------------------------
# Integration tests: validate_phantom_capabilities field threading
# ---------------------------------------------------------------------------


class TestFieldAwarenessIntegration:
    """validate_phantom_capabilities passes field_name correctly."""

    def test_action_field_code_exec_not_flagged(self) -> None:
        """Code execution in action field does NOT produce a violation."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The attacker crafts a Python script to exfiltrate data."
                ],
                step_effects=["The system processes the input normally."],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        # No code_execution violation from the action field
        for _scenario, violations in result.flagged_scenarios:
            for v in violations:
                assert v.category != "code_execution"

    def test_effect_field_code_exec_still_flagged(self) -> None:
        """Code execution in effect field DOES produce a violation."""
        scenarios = [
            _make_envelope(
                step_effects=[
                    "The system generates a Python script for exploitation."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "code_execution" for v in violations)
        # Verify it's from the effect field
        code_exec_violations = [
            v for v in violations if v.category == "code_execution"
        ]
        assert all(v.field == "effect" for v in code_exec_violations)

    def test_same_text_action_vs_effect(self) -> None:
        """Identical text in action vs effect: action skipped, effect caught."""
        text = "The system generates a Python script for data theft."
        scenarios = [
            _make_envelope(
                step_actions=[text],
                step_effects=[text],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        code_violations = [
            v for v in violations if v.category == "code_execution"
        ]
        # Should only have violation from the effect field
        assert len(code_violations) == 1
        assert code_violations[0].field == "effect"

    def test_tree_label_with_attacker_context_not_flagged(self) -> None:
        """Tree labels with attacker context are not flagged for code_execution."""
        scenario = _make_envelope(
            tree_labels=[
                "attacker crafts exploit code",
                "System responds with data",
            ],
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        for _s, violations in result.flagged_scenarios:
            for v in violations:
                if v.field == "attack_tree":
                    assert v.category != "code_execution"

    def test_tree_label_without_attacker_context_flagged(self) -> None:
        """Tree labels WITHOUT attacker context ARE flagged for code_execution."""
        scenario = _make_envelope(
            tree_labels=[
                "Execute Python script for exfiltration",
                "Normal path B",
            ],
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "code_execution" and v.field == "attack_tree"
            for v in violations
        )

    def test_gherkin_with_attacker_context_not_flagged(self) -> None:
        """Gherkin text with attacker context skips code_execution."""
        scenario = _make_envelope()
        scenario.behavior_spec = (
            "Feature: Attack scenario\n"
            "  Scenario: Script creation\n"
            "    When the attacker crafts a script for exploitation\n"
            "    Then the system is compromised\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        for _s, violations in result.flagged_scenarios:
            for v in violations:
                if v.field == "behavior_spec":
                    assert v.category != "code_execution"

    def test_gherkin_without_attacker_context_flagged(self) -> None:
        """Gherkin text WITHOUT attacker context IS flagged for code_execution."""
        scenario = _make_envelope()
        scenario.behavior_spec = (
            "Feature: Code generation\n"
            "  Scenario: Script synthesis\n"
            "    When the system generates a Python script\n"
            "    Then the exploit is delivered\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "code_execution" and v.field == "behavior_spec"
            for v in violations
        )


class TestOtherCheckersNotAffected:
    """Other phantom checkers should NOT skip action fields — only
    code_execution has field-awareness (dv72)."""

    def test_privilege_escalation_still_fires_on_action(self) -> None:
        """Privilege escalation in action field IS still flagged."""
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
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "privilege_escalation" for v in violations)

    def test_credential_exposure_still_fires_on_action(self) -> None:
        """Credential exposure in action field IS still flagged."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "I cause the system to leak the API key in plain text."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "credential_exposure" for v in violations)

    def test_mass_broadcasting_still_fires_on_action(self) -> None:
        """Mass broadcasting in action field IS still flagged."""
        scenarios = [
            _make_envelope(
                step_actions=[
                    "The agent starts bulk messaging customers with scam links."
                ],
            ),
        ]
        profile = _make_profile()
        result = validate_phantom_capabilities(scenarios, profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(v.category == "mass_broadcasting" for v in violations)
