"""Tests for the tool_inventory feature on CapabilityProfile (4w56).

Tests:
  - Model validation: tool_execution requires non-empty tool_inventory
  - Model validation: no tool_execution + no tool_inventory is OK
  - Stage1Profile threading: tool_inventory propagates through to_capability_profile
  - Phantom tool detection in semantic validation
  - Prompt template rendering with and without tool_inventory
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    Stage1Profile,
    ToolInventoryEntry,
)
from scenario_forge.prompts import render_prompt


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_TOOL_INVENTORY = [
    ToolInventoryEntry(name="test_tool", description="A test tool"),
]


def _make_profile_with_tools(
    kc_subcodes: list[str] | None = None,
    tool_inventory: list[ToolInventoryEntry] | None = None,
) -> CapabilityProfile:
    """Build a CapabilityProfile with tool_execution active."""
    codes = kc_subcodes or ["KC1.1", "KC6.1.1"]
    inv = tool_inventory if tool_inventory is not None else _MINIMAL_TOOL_INVENTORY
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=["user prompts (zone 1)"],
        confidence="high",
        kc_subcodes=codes,
        tool_inventory=inv,
    )


def _make_profile_no_tools() -> CapabilityProfile:
    """Build a CapabilityProfile without tool_execution."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user prompts (zone 1)"],
        confidence="high",
        kc_subcodes=["KC1.1"],
    )


# ---------------------------------------------------------------------------
# Model validation tests
# ---------------------------------------------------------------------------


class TestToolInventoryModelValidation:
    """Validate CapabilityProfile tool_inventory enforcement."""

    def test_tool_execution_without_tool_inventory_raises(self) -> None:
        """CapabilityProfile with tool_execution but no tool_inventory raises ValueError."""
        with pytest.raises(ValidationError, match="tool_inventory"):
            CapabilityProfile(
                zones_active=["input", "reasoning", "tool_execution"],
                entry_points=["user prompts (zone 1)"],
                confidence="high",
                kc_subcodes=["KC1.1", "KC6.1.1"],
            )

    def test_tool_execution_with_empty_tool_inventory_raises(self) -> None:
        """CapabilityProfile with tool_execution but empty tool_inventory raises."""
        with pytest.raises(ValidationError, match="tool_inventory"):
            CapabilityProfile(
                zones_active=["input", "reasoning", "tool_execution"],
                entry_points=["user prompts (zone 1)"],
                confidence="high",
                kc_subcodes=["KC1.1", "KC6.1.1"],
                tool_inventory=[],
            )

    def test_tool_execution_with_tool_inventory_ok(self) -> None:
        """CapabilityProfile with tool_execution and tool_inventory validates."""
        profile = _make_profile_with_tools()
        assert "tool_execution" in profile.zones_active
        assert profile.tool_inventory is not None
        assert len(profile.tool_inventory) == 1

    def test_no_tool_execution_no_inventory_ok(self) -> None:
        """CapabilityProfile without tool_execution and no tool_inventory is valid."""
        profile = _make_profile_no_tools()
        assert "tool_execution" not in profile.zones_active
        assert profile.tool_inventory is None

    def test_no_tool_execution_with_inventory_ok(self) -> None:
        """CapabilityProfile without tool_execution but with tool_inventory is valid (benign)."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=["KC1.1"],
            tool_inventory=_MINIMAL_TOOL_INVENTORY,
        )
        assert "tool_execution" not in profile.zones_active
        assert profile.tool_inventory is not None

    def test_multiple_tools_in_inventory(self) -> None:
        """CapabilityProfile accepts multiple tool_inventory entries."""
        tools = [
            ToolInventoryEntry(name="query_db", description="Query the database"),
            ToolInventoryEntry(name="send_email", description="Send email notifications"),
            ToolInventoryEntry(name="process_refund", description="Process customer refund"),
        ]
        profile = _make_profile_with_tools(tool_inventory=tools)
        assert len(profile.tool_inventory) == 3

    def test_kc5_derives_tool_execution_requires_inventory(self) -> None:
        """KC5.* subcodes derive tool_execution, requiring tool_inventory."""
        with pytest.raises(ValidationError, match="tool_inventory"):
            CapabilityProfile(
                zones_active=["input", "reasoning"],
                entry_points=["user prompts (zone 1)"],
                confidence="high",
                kc_subcodes=["KC1.1", "KC5.1"],
            )

    def test_kc6_derives_tool_execution_requires_inventory(self) -> None:
        """KC6.* subcodes derive tool_execution, requiring tool_inventory."""
        with pytest.raises(ValidationError, match="tool_inventory"):
            CapabilityProfile(
                zones_active=["input", "reasoning"],
                entry_points=["user prompts (zone 1)"],
                confidence="high",
                kc_subcodes=["KC1.1", "KC6.3.2"],
            )


# ---------------------------------------------------------------------------
# Stage1Profile threading tests
# ---------------------------------------------------------------------------


class TestStage1ProfileToolInventory:
    """Test that tool_inventory flows from Stage1Profile to CapabilityProfile."""

    def test_stage1_with_tool_inventory_propagates(self) -> None:
        """Stage1Profile.to_capability_profile() passes tool_inventory through."""
        stage1 = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=[
                ToolInventoryEntry(name="search_api", description="Search for information"),
            ],
        )
        profile = stage1.to_capability_profile()
        assert "tool_execution" in profile.zones_active
        assert profile.tool_inventory is not None
        assert len(profile.tool_inventory) == 1
        assert profile.tool_inventory[0].name == "search_api"

    def test_stage1_without_tool_inventory_no_tool_execution(self) -> None:
        """Stage1Profile without KC5/KC6 codes produces profile without tool_execution."""
        stage1 = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        profile = stage1.to_capability_profile()
        assert "tool_execution" not in profile.zones_active
        assert profile.tool_inventory is None or profile.tool_inventory == []

    def test_stage1_with_tool_execution_no_inventory_fails(self) -> None:
        """Stage1Profile with KC6 codes but empty tool_inventory fails on promote."""
        stage1 = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (zone 1)"],
            confidence="high",
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=[],
        )
        with pytest.raises(ValidationError, match="tool_inventory"):
            stage1.to_capability_profile()


# ---------------------------------------------------------------------------
# Prompt template rendering tests
# ---------------------------------------------------------------------------


class TestToolInventoryPromptRendering:
    """Test that prompt templates render tool_inventory correctly."""

    def test_call1_system_with_tool_inventory(self) -> None:
        """call1_system.j2 includes tool inventory section when provided."""
        tools = [
            ToolInventoryEntry(name="query_db", description="Query the database"),
            ToolInventoryEntry(name="send_email", description="Send email"),
        ]
        rendered = render_prompt(
            "call1_system.j2",
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            zones_active=["input", "reasoning", "tool_execution"],
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=tools,
        )
        assert "Tool Inventory (MANDATORY)" in rendered
        assert "query_db: Query the database" in rendered
        assert "send_email: Send email" in rendered
        assert "Do NOT reference any tool, API, or capability not in this list" in rendered

    def test_call1_system_without_tool_inventory(self) -> None:
        """call1_system.j2 omits tool inventory section when list is empty."""
        rendered = render_prompt(
            "call1_system.j2",
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            zones_active=["input", "reasoning"],
            kc_subcodes=["KC1.1"],
            tool_inventory=[],
        )
        assert "Tool Inventory (MANDATORY)" not in rendered

    def test_call2_system_with_tool_inventory(self) -> None:
        """call2_system.j2 includes tool inventory section when provided."""
        tools = [
            ToolInventoryEntry(name="process_refund", description="Process refunds"),
        ]
        rendered = render_prompt(
            "call2_system.j2",
            zones_active=["input", "reasoning", "tool_execution"],
            tool_inventory=tools,
        )
        assert "Tool Inventory (MANDATORY)" in rendered
        assert "process_refund: Process refunds" in rendered

    def test_call2_system_without_tool_inventory(self) -> None:
        """call2_system.j2 omits tool inventory section when list is empty."""
        rendered = render_prompt(
            "call2_system.j2",
            zones_active=["input", "reasoning"],
            tool_inventory=[],
        )
        assert "Tool Inventory (MANDATORY)" not in rendered


# ---------------------------------------------------------------------------
# Phantom tool validation tests
# ---------------------------------------------------------------------------


class TestPhantomToolValidation:
    """Test phantom_tool semantic validation rule."""

    def _make_scenario_with_tree(
        self,
        leaf_labels_and_zones: list[tuple[str, str]],
    ):
        """Build a scenario with an attack tree containing specified leaves."""
        from datetime import datetime

        from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
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
            PhantomValidation,
            Priority,
            PrioritySignals,
            RiskCardRef,
            ScenarioEnvelope,
            SemanticValidation,
            SeverityLevel,
            StructuralExposureSignal,
            StructuralValidation,
            TaxonomyChain,
            TechniqueMaturity,
            ValidationBlock,
        )

        # Build tree with leaves
        children = []
        for i, (label, zone) in enumerate(leaf_labels_and_zones, start=1):
            children.append(
                AttackTreeNode(
                    id=f"n1.{i}",
                    label=label,
                    gate=GateType.LEAF,
                    zone=zone,
                    technique_id="AML.T0054" if i == 1 else None,
                )
            )

        root = AttackTreeNode(
            id="n1",
            label="Root attack goal",
            gate=GateType.AND if len(children) > 1 else GateType.LEAF,
            zone="input",
            children=children if len(children) > 1 else None,
        )
        if len(children) == 1:
            root = children[0]

        tree = AttackTree(
            id="tree-AP-T2-01",
            seed_id="AP-T2-01",
            goal="Test goal",
            root=root,
        )

        zone_sequence = ["input", "reasoning", "tool_execution"]
        narrative = NarrativeLayer(
            title="Test narrative",
            summary="Test summary",
            entry_point="user prompts",
            zone_sequence=zone_sequence,
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Inject prompt",
                    effect="Prompt accepted",
                ),
                NarrativeStep(
                    step_number=2,
                    zone="tool_execution",
                    action="Invoke tool",
                    effect="Tool executes",
                ),
            ],
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
                agentic_threat_ids=["T2"],
                scenario_seed="AP-T2-01",
            ),
            capability_profile=CapabilityProfileRef(
                zones_traversed=zone_sequence,
                architecture_match=ArchitectureMatch.explicit,
                entry_point="user prompts",
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
            scenario_id="AP-T2-01-abc123",
            seed_id="AP-T2-01",
            generated_at=datetime.now(),
            generator_version="0.1.0",
            narrative=narrative,
            attack_tree=tree,
            behavior_spec="Feature: Test",
            faceting=faceting,
            priority=priority,
            generation=generation,
            validation=ValidationBlock(
                phantom=PhantomValidation(valid=True, violations=[]),
                structural=StructuralValidation(valid=True, violations=[]),
                semantic=SemanticValidation(valid=True, violations=[]),
            ),
            validation_passed=True,
            scenario_seed_metadata={
                "threat_id": "T2",
                "atlas_provenance_ids": ["AML.T0054"],
            },
        )

    def test_phantom_tool_detected_when_not_in_inventory(self) -> None:
        """Leaf in tool_execution zone referencing unknown tool is flagged."""
        from scenario_forge.pipeline.validation import validate_scenario_semantics

        profile = _make_profile_with_tools(
            tool_inventory=[
                ToolInventoryEntry(name="query_database", description="Query DB"),
                ToolInventoryEntry(name="send_email", description="Send emails"),
            ],
        )

        scenario = self._make_scenario_with_tree([
            ("Inject prompt via chat [AML.T0054]", "input"),
            ("Invoke billing_api to process fraudulent refund", "tool_execution"),
        ])

        validate_scenario_semantics([scenario], profile)

        # Check for phantom_tool violations
        phantom_violations = [
            v for v in scenario.validation.semantic.violations
            if v.rule == "phantom_tool"
        ]
        assert len(phantom_violations) >= 1
        assert "billing_api" in phantom_violations[0].message.lower() or "billing" in phantom_violations[0].message.lower()

    def test_known_tool_not_flagged(self) -> None:
        """Leaf in tool_execution zone referencing known tool is NOT flagged."""
        from scenario_forge.pipeline.validation import validate_scenario_semantics

        profile = _make_profile_with_tools(
            tool_inventory=[
                ToolInventoryEntry(name="query_database", description="Query DB"),
                ToolInventoryEntry(name="send_email", description="Send emails"),
            ],
        )

        scenario = self._make_scenario_with_tree([
            ("Inject prompt via chat [AML.T0054]", "input"),
            ("Invoke query_database to extract patient records", "tool_execution"),
        ])

        validate_scenario_semantics([scenario], profile)

        phantom_violations = [
            v for v in scenario.validation.semantic.violations
            if v.rule == "phantom_tool"
        ]
        assert len(phantom_violations) == 0

    def test_no_inventory_skips_check(self) -> None:
        """When tool_inventory is None, phantom_tool check is skipped."""
        from scenario_forge.pipeline.validation import validate_scenario_semantics

        profile = _make_profile_no_tools()

        scenario = self._make_scenario_with_tree([
            ("Inject prompt [AML.T0054]", "input"),
            ("Invoke mystery_api to do something", "tool_execution"),
        ])

        validate_scenario_semantics([scenario], profile)

        phantom_violations = [
            v for v in scenario.validation.semantic.violations
            if v.rule == "phantom_tool"
        ]
        assert len(phantom_violations) == 0

    def test_non_tool_execution_zone_not_checked(self) -> None:
        """Leaves in non-tool_execution zones are not checked for phantom tools."""
        from scenario_forge.pipeline.validation import validate_scenario_semantics

        profile = _make_profile_with_tools(
            tool_inventory=[
                ToolInventoryEntry(name="query_database", description="Query DB"),
            ],
        )

        scenario = self._make_scenario_with_tree([
            ("Craft adversarial prompt mentioning unknown_api [AML.T0054]", "input"),
            ("Invoke query_database to extract data", "tool_execution"),
        ])

        validate_scenario_semantics([scenario], profile)

        phantom_violations = [
            v for v in scenario.validation.semantic.violations
            if v.rule == "phantom_tool"
        ]
        assert len(phantom_violations) == 0

    def test_phantom_tool_severity_is_major(self) -> None:
        """Phantom tool violations have severity 'major'."""
        from scenario_forge.pipeline.validation import validate_scenario_semantics

        profile = _make_profile_with_tools(
            tool_inventory=[
                ToolInventoryEntry(name="query_database", description="Query DB"),
            ],
        )

        scenario = self._make_scenario_with_tree([
            ("Inject prompt [AML.T0054]", "input"),
            ("Invoke malware_compiler to build exploit", "tool_execution"),
        ])

        validate_scenario_semantics([scenario], profile)

        phantom_violations = [
            v for v in scenario.validation.semantic.violations
            if v.rule == "phantom_tool"
        ]
        assert len(phantom_violations) >= 1
        assert phantom_violations[0].severity == "major"


# ---------------------------------------------------------------------------
# ToolInventoryEntry model tests
# ---------------------------------------------------------------------------


class TestToolInventoryEntry:
    """Test ToolInventoryEntry model."""

    def test_basic_creation(self) -> None:
        """ToolInventoryEntry can be created with name and description."""
        entry = ToolInventoryEntry(name="test_tool", description="A test tool")
        assert entry.name == "test_tool"
        assert entry.description == "A test tool"

    def test_serialization_roundtrip(self) -> None:
        """ToolInventoryEntry serializes and deserializes correctly."""
        entry = ToolInventoryEntry(name="query_db", description="Query the database")
        data = entry.model_dump()
        restored = ToolInventoryEntry.model_validate(data)
        assert restored.name == entry.name
        assert restored.description == entry.description
