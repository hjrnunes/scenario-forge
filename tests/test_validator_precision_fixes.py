"""Tests for validator precision fixes (9jfi, enwb, ryxu, lgws, 3mal).

Covers:
- 9jfi: cross-newline matching prevention in audit_monitoring_write
- enwb: Gherkin step keywords added to _TOOL_NAME_NOISE
- ryxu: title-case filter on 'API calls to' phantom tool extractor
- lgws: input-zone skip for tree label code_execution
- 3mal: Gherkin step-type awareness for code_execution
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
    _check_audit_monitoring_write,
    _check_code_execution,
    _check_phantom_tool_invocation,
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
    tree_zones: list[str] | None = None,
    behavior_spec: str | dict | None = None,
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

    if tree_labels:
        if tree_zones is None:
            tree_zones = ["input"] * len(tree_labels)
        children = [
            AttackTreeNode(
                id=f"n1.{i + 1}",
                label=label,
                gate=GateType.LEAF,
                zone=tree_zones[i],
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
# 9jfi: cross-newline matching prevention in audit_monitoring_write
# ===========================================================================


class TestAuditMonitoringCrossNewline:
    """Verify [^.\\n] prevents cross-newline regex matches."""

    def test_multiline_gherkin_no_false_match(self) -> None:
        """Pattern should NOT span across Gherkin list items.

        Reproduces the FP from AP-T15-01-bcdd6d where 'generated summary'
        on one line matched with 'fraudulent transaction is record...'
        on the next line.
        """
        text = (
            "    * the generated summary\n"
            "    * the fraudulent transaction is recorded in the audit log"
        )
        profile = _make_profile()
        result = _check_audit_monitoring_write(text, profile)
        assert result is None

    def test_single_line_still_matches(self) -> None:
        """Pattern should still match within a single line."""
        text = (
            "The agent fabricates a fraudulent report to cover the attack."
        )
        profile = _make_profile()
        result = _check_audit_monitoring_write(text, profile)
        assert result is not None

    def test_single_line_deceptive_record(self) -> None:
        """'creates a deceptive transaction record' on one line is caught."""
        text = "The system creates a deceptive transaction record."
        profile = _make_profile()
        result = _check_audit_monitoring_write(text, profile)
        assert result is not None


# ===========================================================================
# enwb: Gherkin step keywords in _TOOL_NAME_NOISE
# ===========================================================================


class TestGherkinStepKeywordsInToolNameNoise:
    """Gherkin step keywords should be stripped from tool name candidates."""

    def test_and_generate_tool_not_flagged(self) -> None:
        """'And Generate tool call...' should NOT produce a phantom tool violation.

        After stripping 'And', only 'Generate' remains (1 word < 2 minimum).
        """
        text = "And Generate tool call with unauthorized, excessively high refund value."
        profile = _make_profile(entry_points=["refund processing api"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_when_process_tool_not_flagged(self) -> None:
        """'When Process tool confirmation...' should NOT flag."""
        text = "When Process tool confirmation to finalize hijacked workflow."
        profile = _make_profile(entry_points=["workflow api"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_then_submit_tool_not_flagged(self) -> None:
        """'Then Submit tool...' should NOT flag (single word after strip)."""
        text = "Then Submit tool is invoked."
        profile = _make_profile(entry_points=["some api"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_real_tool_name_still_flagged(self) -> None:
        """A genuine multi-word tool name like 'Policy Audit tool' is still caught."""
        text = "The agent calls the Policy Audit tool to verify permissions."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is not None


# ===========================================================================
# ryxu: tighten 'API calls to' phantom tool extractor
# ===========================================================================


class TestApiCallsToTitleCaseFilter:
    """'API calls to <action>' should only flag when the action contains
    at least one title-cased word (proper-noun indicator)."""

    def test_all_lowercase_action_not_flagged(self) -> None:
        """'API calls to clear the queue' is a generic action, not a tool name."""
        text = "The reviewer makes API calls to clear the queue."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_lowercase_fulfill_mission_not_flagged(self) -> None:
        """'API calls to fulfill its perceived absolute mission' is generic."""
        text = "The agent makes API calls to fulfill its perceived absolute mission."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_lowercase_satisfy_requirements_not_flagged(self) -> None:
        """'API calls to satisfy recursive state requirements' is generic."""
        text = "The system makes API calls to satisfy recursive state requirements."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_lowercase_prevent_exhaustion_not_flagged(self) -> None:
        """'API calls to prevent resource exhaustion' is generic."""
        text = "The agent limits API calls to prevent resource exhaustion."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is None

    def test_title_case_tool_name_still_flagged(self) -> None:
        """'API calls to Refund Processing API' is a proper-noun tool reference."""
        text = "The agent makes API calls to Refund Processing service."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is not None

    def test_title_case_admin_config_still_flagged(self) -> None:
        """'API calls to Admin Configuration endpoint' is a proper-noun tool reference."""
        text = "The system uses API calls to Admin Configuration endpoint."
        profile = _make_profile(entry_points=["user prompts (zone 1)"])
        result = _check_phantom_tool_invocation(text, profile)
        assert result is not None


# ===========================================================================
# lgws: input-zone skip for tree label code_execution
# ===========================================================================


class TestInputZoneTreeLabelSkip:
    """Input-zone tree labels describe attacker injection and should
    skip code_execution checks."""

    def test_input_zone_automated_script_not_flagged(self) -> None:
        """'Submit queries via automated script' in input zone is skipped."""
        text = "Submit massive volume of repetitive queries via automated script"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label", zone="input")
        assert result is None

    def test_input_zone_craft_payload_not_flagged(self) -> None:
        """'Craft payload with high-priority commands' in input zone is skipped."""
        text = "Craft payload with high-priority commands to disregard medical data"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label", zone="input")
        assert result is None

    def test_input_zone_obfuscated_script_not_flagged(self) -> None:
        """'Craft responses containing obfuscated script' in input zone is skipped."""
        text = "Craft malformed questionnaire responses containing obfuscated script payloads"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label", zone="input")
        assert result is None

    def test_tool_execution_zone_same_text_flagged(self) -> None:
        """Same text in tool_execution zone IS flagged."""
        text = "Submit massive volume of repetitive queries via automated script"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label", zone="tool_execution")
        assert result is not None

    def test_reasoning_zone_same_text_flagged(self) -> None:
        """Same text in reasoning zone IS flagged (without attacker context)."""
        text = "Generate Python script for data exfiltration"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label", zone="reasoning")
        assert result is not None

    def test_output_zone_same_text_flagged(self) -> None:
        """Same text in output zone IS flagged."""
        text = "System produces an automated script for exfiltration"
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="tree_label", zone="output")
        assert result is not None


class TestInputZoneTreeLabelIntegration:
    """Integration test: validate_phantom_capabilities respects input-zone skip."""

    def test_input_zone_tree_label_no_code_exec_violation(self) -> None:
        """Code execution in input-zone tree label does NOT produce a violation."""
        scenario = _make_envelope(
            tree_labels=[
                "Submit queries via automated script",
                "Normal path B",
            ],
            tree_zones=["input", "reasoning"],
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        for _s, violations in result.flagged_scenarios:
            for v in violations:
                if v.field == "attack_tree":
                    assert v.category != "code_execution"

    def test_tool_execution_zone_tree_label_code_exec_flagged(self) -> None:
        """Code execution in tool_execution-zone tree label IS flagged."""
        scenario = _make_envelope(
            tree_labels=[
                "Execute Python script for exfiltration",
                "Normal path B",
            ],
            tree_zones=["tool_execution", "reasoning"],
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "code_execution" and v.field == "attack_tree"
            for v in violations
        )


# ===========================================================================
# 3mal: Gherkin step-type awareness for code_execution
# ===========================================================================


class TestGherkinStepTypeAwareness:
    """code_execution should only check Then/But/* lines in Gherkin,
    skipping Given/When/And lines (attacker actions)."""

    def test_when_line_automated_script_not_flagged(self) -> None:
        """'When I use an automated script...' is an attacker action, NOT flagged."""
        text = (
            "Feature: Denial of service\n"
            "  Scenario: Flood attack\n"
            "    When I use an automated script to flood the chat interface\n"
            "    Then the system becomes unresponsive\n"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is None

    def test_given_line_crafts_payload_not_flagged(self) -> None:
        """'Given the attacker crafts a payload...' is setup, NOT flagged."""
        text = (
            "Feature: Prompt injection\n"
            "  Scenario: Payload delivery\n"
            "    Given I use a crafted script to prepare the payload\n"
            "    When I submit the malicious input\n"
            "    Then the system processes the request\n"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is None

    def test_and_line_automated_script_not_flagged(self) -> None:
        """'And I run an automated script...' is an attacker action, NOT flagged."""
        text = (
            "Feature: Data theft\n"
            "  Scenario: Automated extraction\n"
            "    When I submit a prompt\n"
            "    And I use an automated script to submit many requests\n"
            "    Then the system rate-limits requests\n"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is None

    def test_then_line_generates_script_flagged(self) -> None:
        """'Then the system generates a Python script' IS flagged (system outcome)."""
        text = (
            "Feature: Code execution\n"
            "  Scenario: Script generation\n"
            "    When I send a prompt\n"
            "    Then the system generates a Python script for data theft\n"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is not None

    def test_but_line_executes_code_flagged(self) -> None:
        """'But the system executes arbitrary code' IS flagged (system outcome)."""
        text = (
            "Feature: Code execution\n"
            "  Scenario: Unexpected execution\n"
            "    When I submit input\n"
            "    Then the system processes the request\n"
            "    But the system executes arbitrary code from the prompt\n"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is not None

    def test_star_line_script_flagged(self) -> None:
        """'* the system produces exploit code' IS flagged (outcome line)."""
        text = (
            "Feature: Code execution\n"
            "  Scenario: Exploit delivery\n"
            "    When I submit input\n"
            "    * the system produces exploit code for the bypass\n"
        )
        profile = _make_profile()
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is not None

    def test_mixed_lines_only_then_checked(self) -> None:
        """When and Then lines: only Then triggers code_execution."""
        text = (
            "Feature: Test\n"
            "  Scenario: Mixed\n"
            "    When I use an automated script to inject commands\n"
            "    Then the system responds normally\n"
        )
        profile = _make_profile()
        # 'automated script' is on When line (skipped), Then line is clean
        result = _check_code_execution(text, profile, field_name="gherkin")
        assert result is None

    def test_non_gherkin_field_not_affected(self) -> None:
        """Non-gherkin fields are not affected by step-type filtering."""
        text = "The system generates a Python script for data theft."
        profile = _make_profile()
        # Effect field should still fire
        result = _check_code_execution(text, profile, field_name="effect")
        assert result is not None


class TestGherkinStepTypeIntegration:
    """Integration test: validate_phantom_capabilities applies step-type filter."""

    def test_when_line_code_exec_not_flagged_in_behavior_spec(self) -> None:
        """Code execution in Gherkin When line does NOT produce a violation."""
        scenario = _make_envelope()
        scenario.behavior_spec = (
            "Feature: Attack scenario\n"
            "  Scenario: Automated injection\n"
            "    When I use an automated script to inject queries\n"
            "    Then the system processes the requests\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        for _s, violations in result.flagged_scenarios:
            for v in violations:
                if v.field == "behavior_spec":
                    assert v.category != "code_execution"

    def test_then_line_code_exec_flagged_in_behavior_spec(self) -> None:
        """Code execution in Gherkin Then line DOES produce a violation."""
        scenario = _make_envelope()
        scenario.behavior_spec = (
            "Feature: Code generation\n"
            "  Scenario: Script output\n"
            "    When I send a prompt\n"
            "    Then the system generates a Python script for exploitation\n"
        )
        profile = _make_profile()
        result = validate_phantom_capabilities([scenario], profile)

        assert result.flagged_count == 1
        violations = result.flagged_scenarios[0][1]
        assert any(
            v.category == "code_execution" and v.field == "behavior_spec"
            for v in violations
        )
