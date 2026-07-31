"""Acceptance tests for the cmps.9 typed-action contract."""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from scenario_forge.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from scenario_forge.models.capability_profile import (
    AuthMethod,
    CapabilityProfile,
    DataSensitivity,
    EntryPoint,
    ExternalIntegration,
    IntegrationType,
    InventoryCompleteness,
    Stage1Profile,
    ToolInventoryEntry,
    compute_integration_id,
    compute_tool_id,
    deduplicate_external_integrations,
    deduplicate_tool_inventory,
)
from scenario_forge.pipeline.generate.gherkin import (
    _STEP_KIND_GIVEN,
    _STEP_KIND_THEN,
    _STEP_KIND_WHEN,
    _leaf_step_kind,
)
from scenario_forge.pipeline.generate.tree import resolve_action_ids
from scenario_forge.report.template import _build_attack_tree_node

TOOL_ID = compute_tool_id("test_tool", "A test tool")
UNKNOWN_TOOL_ID = "tool:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
UNKNOWN_ENTRY_POINT_ID = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
UNKNOWN_INTEGRATION_ID = "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def leaf(action, zone, *, label="Step", node_id="n1"):
    return AttackTreeNode(
        id=node_id, label=label, gate=GateType.LEAF, zone=zone, action=action
    )


def tree(node):
    return AttackTree(id="tree-AP-T1-01", seed_id="AP-T1-01", goal="Test", root=node)


def integration(name="Test CRM"):
    return ExternalIntegration(
        name=name,
        integration_type=IntegrationType.api,
        auth_method=AuthMethod.oauth,
        data_sensitivity=DataSensitivity.high,
    )


def profile():
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[EntryPoint(name="User chat", direction="input")],
        confidence="high",
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
        external_integrations=[integration()],
    )


def stage1(**extra):
    return Stage1Profile(
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=[EntryPoint(name="User chat", direction="input")],
        confidence="high",
        kc_subcodes=["KC1.1"],
        **extra,
    )


class TestActionConditionalValidation:
    @pytest.mark.parametrize(
        ("action", "zone"),
        [
            (ExternalPreconditionAction(), None),
            (AiSystemAction(), "input"),
            (ToolInvocationAction(tool_id=TOOL_ID), "tool_execution"),
            (ImpactAction(boundary="internal", target="Data"), "input"),
            (ImpactAction(boundary="external", target="Reputation"), None),
            (InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), "input"),
            (
                IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
                "tool_execution",
            ),
        ],
    )
    def test_valid_action_zone_combinations(self, action, zone):
        assert leaf(action, zone).zone == zone

    @pytest.mark.parametrize(
        ("action", "zone"),
        [
            (ExternalPreconditionAction(), "input"),
            (AiSystemAction(), None),
            (ToolInvocationAction(tool_id=TOOL_ID), "input"),
            (ImpactAction(boundary="internal", target="Data"), None),
            (ImpactAction(boundary="external", target="Reputation"), "input"),
            (InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), None),
            (
                IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
                None,
            ),
        ],
    )
    def test_invalid_action_zone_combinations(self, action, zone):
        with pytest.raises(ValidationError):
            leaf(action, zone)

    def test_leaf_requires_action(self):
        with pytest.raises(ValidationError):
            AttackTreeNode(id="n1", label="No action", gate=GateType.LEAF)

    @pytest.mark.parametrize("gate", [GateType.AND, GateType.OR])
    def test_internal_node_forbids_action(self, gate):
        children = [
            leaf(AiSystemAction(), "input", node_id="n1.1"),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        with pytest.raises(ValidationError):
            AttackTreeNode(
                id="n1",
                label="Internal",
                gate=gate,
                action=AiSystemAction(),
                children=children,
            )


class TestTypedLeafSemantics:
    def test_external_precondition_has_no_zone_and_provenance(self):
        node = leaf(ExternalPreconditionAction(access_provenance="phishing"), None)
        assert node.zone is None
        assert node.action.access_provenance == "phishing"

    def test_initial_ingress_accepts_canonical_pattern(self):
        node = leaf(
            InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), "input"
        )
        assert node.action.entry_point_id == UNKNOWN_ENTRY_POINT_ID

    def test_tool_invocation_with_optional_integration(self):
        node = leaf(
            ToolInvocationAction(
                tool_id=TOOL_ID, integration_id=UNKNOWN_INTEGRATION_ID
            ),
            "tool_execution",
        )
        assert node.action.tool_id.startswith("tool:v1:")
        assert node.action.integration_id == UNKNOWN_INTEGRATION_ID

    def test_direct_integration_interaction(self):
        node = leaf(
            IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
            "tool_execution",
        )
        assert node.action.integration_id.startswith("int:v1:")

    def test_internal_and_external_impacts(self):
        internal = leaf(ImpactAction(boundary="internal", target="Model"), "reasoning")
        external = leaf(ImpactAction(boundary="external", target="Customer"), None)
        assert internal.zone == "reasoning"
        assert external.zone is None


class TestActionIdResolution:
    def test_unknown_tool_id_is_violation(self):
        violations = resolve_action_ids(
            tree(leaf(ToolInvocationAction(tool_id=UNKNOWN_TOOL_ID), "tool_execution")),
            profile(),
        )
        assert any("unresolved-tool-id" in violation for violation in violations)

    def test_unknown_entry_point_id_is_violation(self):
        violations = resolve_action_ids(
            tree(
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), "input"
                )
            ),
            profile(),
        )
        assert any("unresolved-entry-point-id" in violation for violation in violations)

    def test_unknown_integration_id_is_violation(self):
        violations = resolve_action_ids(
            tree(
                leaf(
                    IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
                    "tool_execution",
                )
            ),
            profile(),
        )
        assert any("unresolved-integration-id" in violation for violation in violations)

    def test_all_ids_resolve(self):
        prof = profile()
        children = [
            leaf(
                InitialIngressAction(
                    entry_point_id=prof.entry_points[0].entry_point_id
                ),
                "input",
                node_id="n1.1",
            ),
            leaf(
                ToolInvocationAction(
                    tool_id=prof.tool_inventory[0].tool_id,
                    integration_id=prof.external_integrations[0].integration_id,
                ),
                "tool_execution",
                node_id="n1.2",
            ),
            leaf(
                IntegrationInteractionAction(
                    integration_id=prof.external_integrations[0].integration_id
                ),
                "tool_execution",
                node_id="n1.3",
            ),
        ]
        root = AttackTreeNode(
            id="n1", label="Path", gate=GateType.AND, children=children
        )
        assert resolve_action_ids(tree(root), prof) == []


class TestCanonicalIdentity:
    def test_tools_and_integrations_are_distinct_concepts(self):
        tool = ToolInventoryEntry(name="CRM", description="Customer records")
        integ = integration("CRM")
        assert isinstance(tool, ToolInventoryEntry)
        assert isinstance(integ, ExternalIntegration)
        assert tool.tool_id.startswith("tool:v1:")
        assert integ.integration_id.startswith("int:v1:")

    def test_tool_id_is_stable(self):
        assert compute_tool_id("test_tool", "A test tool") == TOOL_ID

    def test_tool_ids_are_order_independent(self):
        tools = [
            ToolInventoryEntry(name="A", description="first"),
            ToolInventoryEntry(name="B", description="second"),
        ]
        assert {item.tool_id for item in tools} == {
            item.tool_id for item in reversed(tools)
        }

    def test_tool_deduplication(self):
        tools = [
            ToolInventoryEntry(name="Test Tool", description="Does work"),
            ToolInventoryEntry(name="test tool", description="does work"),
        ]
        assert len(deduplicate_tool_inventory(tools)) == 1

    def test_tool_collision_guard(self):
        with patch(
            "scenario_forge.models.capability_profile.compute_tool_id",
            return_value=UNKNOWN_TOOL_ID,
        ):
            tools = [
                ToolInventoryEntry(name="A", description="first"),
                ToolInventoryEntry(name="B", description="second"),
            ]
            with pytest.raises(ValueError, match="Ambiguous tool identity"):
                deduplicate_tool_inventory(tools)

    def test_integration_id_is_stable_and_order_independent(self):
        args = ("CRM", "api", "oauth", "high")
        assert compute_integration_id(*args) == compute_integration_id(*args)
        integrations = [integration("A"), integration("B")]
        assert {item.integration_id for item in integrations} == {
            item.integration_id for item in reversed(integrations)
        }

    def test_integration_deduplication(self):
        assert (
            len(deduplicate_external_integrations([integration(), integration()])) == 1
        )

    def test_integration_collision_guard(self):
        with patch(
            "scenario_forge.models.capability_profile.compute_integration_id",
            return_value=UNKNOWN_INTEGRATION_ID,
        ):
            integrations = [integration("A"), integration("B")]
            with pytest.raises(ValueError, match="Ambiguous integration identity"):
                deduplicate_external_integrations(integrations)


class TestInventoryCompleteness:
    def test_default_is_inferred_partial(self):
        assert (
            profile().inventory_completeness == InventoryCompleteness.inferred_partial
        )

    def test_stage1_conversion_forces_inferred_partial(self):
        assert (
            stage1().to_capability_profile().inventory_completeness
            == InventoryCompleteness.inferred_partial
        )

    def test_operator_confirmed_complete_requires_evidence(self):
        data = profile().model_dump(
            exclude={"inventory_completeness", "evidence_sources"}
        )
        confirmed = CapabilityProfile(
            **data,
            inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            evidence_sources=["manual architecture review"],
        )
        assert confirmed.is_inventory_complete
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
                evidence_sources=[],
            )

    def test_stage1_cannot_self_promote(self):
        inferred = stage1(
            inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            evidence_sources=["LLM claim"],
        ).to_capability_profile()
        assert inferred.inventory_completeness == InventoryCompleteness.inferred_partial
        assert inferred.evidence_sources == []


class TestGherkinProjection:
    @pytest.mark.parametrize(
        ("action", "zone", "label", "expected"),
        [
            (ExternalPreconditionAction(), None, "Execute tool", _STEP_KIND_GIVEN),
            (
                ImpactAction(boundary="internal", target="Data"),
                "input",
                "Inject prompt",
                _STEP_KIND_THEN,
            ),
            (AiSystemAction(), "input", "Given precondition", _STEP_KIND_WHEN),
            (
                ToolInvocationAction(tool_id=TOOL_ID),
                "tool_execution",
                "Then system",
                _STEP_KIND_WHEN,
            ),
        ],
    )
    def test_step_kind_ignores_misleading_label(self, action, zone, label, expected):
        assert _leaf_step_kind(leaf(action, zone, label=label)) == expected

    def test_adversarial_tool_label_does_not_change_semantics(self):
        node = leaf(
            ToolInvocationAction(tool_id=TOOL_ID),
            "tool_execution",
            label="Given the system processes input",
        )
        assert node.zone == "tool_execution"
        assert node.action.kind == "tool_invocation"

    def test_adversarial_external_label_does_not_change_semantics(self):
        node = leaf(
            ExternalPreconditionAction(), None, label="Execute query_database tool"
        )
        assert node.zone is None
        assert node.action.kind == "external_precondition"


class TestReportResolution:
    def test_report_resolves_tool_id_to_name(self):
        prof = profile()
        node = leaf(
            ToolInvocationAction(tool_id=prof.tool_inventory[0].tool_id),
            "tool_execution",
        )
        html = _build_attack_tree_node(node.model_dump(), prof.model_dump())
        assert "Tool: test_tool" in html

    @pytest.mark.parametrize(
        "node",
        [
            leaf(ExternalPreconditionAction(), None),
            leaf(ImpactAction(boundary="external", target="Reputation"), None),
        ],
    )
    def test_report_shows_external_boundary(self, node):
        assert ">External<" in _build_attack_tree_node(node.model_dump())
