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
    ConfidenceLevel,
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
    _build_gherkin_template,
    _leaf_step_kind,
)
from scenario_forge.pipeline.generate.tree import (
    _enumerate_root_to_leaf_paths,
    _validate_pinned_ingress,
    resolve_action_ids,
)
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

    def test_tool_id_is_stable_under_description_edits(self):
        assert compute_tool_id("test_tool", "Original") == compute_tool_id(
            "test_tool", "Updated"
        )

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

    def test_tool_duplicate_with_conflicting_description_is_rejected(self):
        tools = [
            ToolInventoryEntry(name="Test Tool", description="Reads records"),
            ToolInventoryEntry(name="test tool", description="Deletes records"),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate tool"):
            deduplicate_tool_inventory(tools)

    def test_tool_duplicate_empty_nonempty_description_rejected(self):
        """Empty/non-empty description mismatch must be rejected, not silently deduplicated."""
        tools = [
            ToolInventoryEntry(name="Test Tool", description=""),
            ToolInventoryEntry(name="test tool", description="Reads records"),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_tool_inventory(tools)

    def test_tool_dedup_reversed_order_identical_outcome(self):
        """Reversed order of exact duplicates produces identical result (no information loss)."""
        tools_a = [
            ToolInventoryEntry(name="Search", description="Search tool"),
            ToolInventoryEntry(name="search", description="Search tool"),
        ]
        tools_b = list(reversed(tools_a))
        result_a = deduplicate_tool_inventory(tools_a)
        result_b = deduplicate_tool_inventory(tools_b)
        assert len(result_a) == 1
        assert len(result_b) == 1
        # Both produce exactly one entry with the same canonical identity
        assert result_a[0].tool_id == result_b[0].tool_id

    def test_tool_dedup_empty_nonempty_reversed_order_rejected(self):
        """Reversed order of empty/non-empty mismatch still rejects."""
        tools = [
            ToolInventoryEntry(name="Test Tool", description="Reads records"),
            ToolInventoryEntry(name="test tool", description=""),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_tool_inventory(tools)

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

    def test_integration_id_is_stable_under_metadata_edits(self):
        assert compute_integration_id(
            "CRM", "api", "oauth", "high"
        ) == compute_integration_id("CRM", "api", "api_key", "low")

    def test_integration_deduplication(self):
        assert (
            len(deduplicate_external_integrations([integration(), integration()])) == 1
        )

    def test_integration_duplicate_with_conflicting_metadata_is_rejected(self):
        integrations = [
            integration("CRM"),
            ExternalIntegration(
                name="crm",
                integration_type=IntegrationType.api,
                auth_method=AuthMethod.api_key,
                data_sensitivity=DataSensitivity.low,
            ),
        ]
        with pytest.raises(
            ValueError, match="Ambiguous semantic duplicate integration"
        ):
            deduplicate_external_integrations(integrations)

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
        p = profile()
        assert p.entry_point_completeness == InventoryCompleteness.inferred_partial
        assert p.tool_inventory_completeness == InventoryCompleteness.inferred_partial

    def test_stage1_conversion_forces_inferred_partial(self):
        p = stage1().to_capability_profile()
        assert p.entry_point_completeness == InventoryCompleteness.inferred_partial
        assert p.tool_inventory_completeness == InventoryCompleteness.inferred_partial

    def test_operator_confirmed_complete_requires_evidence(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        confirmed = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["manual architecture review"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API documentation audit"],
        )
        assert confirmed.is_inventory_complete
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
                entry_point_evidence=[],
                tool_inventory_completeness=InventoryCompleteness.inferred_partial,
            )
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.inferred_partial,
                tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
                tool_inventory_evidence=[],
            )

    def test_stage1_cannot_self_promote(self):
        inferred = stage1(
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["LLM claim"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["LLM claim"],
        ).to_capability_profile()
        assert (
            inferred.entry_point_completeness == InventoryCompleteness.inferred_partial
        )
        assert inferred.entry_point_evidence == []
        assert (
            inferred.tool_inventory_completeness
            == InventoryCompleteness.inferred_partial
        )
        assert inferred.tool_inventory_evidence == []


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


# ---------------------------------------------------------------------------
# Raw Draft 2020-12 JSON Schema adversarial tests (Mayor correction 1)
# ---------------------------------------------------------------------------


class TestRawJsonSchemaAdversarial:
    """Raw Draft 2020-12 validation of the hand-authored schema."""

    @staticmethod
    def _node_validator():
        """Build a Draft 2020-12 validator for the AttackTreeNode sub-schema."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        # Build a standalone schema that includes $defs so $ref resolves.
        node_schema = {
            **full_schema["$defs"]["AttackTreeNode"],
            "$defs": full_schema["$defs"],
        }
        return jsonschema.Draft202012Validator(node_schema)

    _SENTINEL = object()

    def _make_leaf_node(self, action=_SENTINEL, **overrides):
        node = {
            "id": "n1",
            "label": "Test",
            "gate": "LEAF",
            "zone": "input",
        }
        if action is not self._SENTINEL:
            node["action"] = action
        elif "action" not in overrides:
            node["action"] = {"kind": "ai_system_action"}
        # Map node_id= to id= for convenience
        if "node_id" in overrides:
            overrides["id"] = overrides.pop("node_id")
        node.update(overrides)
        return node

    def _make_tree(self, root_node):
        return {
            "id": "tree-AP-T1-01",
            "seed_id": "AP-T1-01",
            "goal": "Test",
            "root": root_node,
        }

    def test_leaf_with_null_action_rejected(self):
        """LEAF node with action:null must be rejected."""
        node = self._make_leaf_node(action=None)
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "action" in str(e.path) or "action" in str(e.message) for e in errors
        )

    def test_leaf_with_omitted_action_rejected(self):
        """LEAF node without action field must be rejected."""
        node = {"id": "n1", "label": "Test", "gate": "LEAF", "zone": "input"}
        errors = list(self._node_validator().iter_errors(node))
        assert any("action" in str(e.message) for e in errors)

    def test_leaf_with_omitted_kind_rejected(self):
        """Action object without kind field must be rejected."""
        node = self._make_leaf_node(action={"tool_id": "tool:v1:abc"})
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "kind" in str(e.message)
            or any("kind" in str(ctx.message) for ctx in (e.context or []))
            for e in errors
        )

    def test_foreign_resource_field_rejected(self):
        """Action with a foreign field (e.g. tool_id on ai_system_action) must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "ai_system_action", "tool_id": "tool:v1:abc"}
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "additional" in str(e.message).lower()
            or any(
                "additional" in str(ctx.message).lower() for ctx in (e.context or [])
            )
            for e in errors
        )

    def test_internal_node_with_action_payload_rejected(self):
        """AND/OR node with a non-null action must be rejected."""
        node = {
            "id": "n1",
            "label": "Internal",
            "gate": "AND",
            "children": [
                self._make_leaf_node(node_id="n1.1"),
                self._make_leaf_node(node_id="n1.2"),
            ],
            "action": {"kind": "ai_system_action"},
        }
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "action" in str(e.path)
            or "action" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_internal_node_with_insufficient_children_rejected(self):
        """AND/OR node with fewer than 2 children must be rejected."""
        node = {
            "id": "n1",
            "label": "Internal",
            "gate": "OR",
            "action": None,
            "children": [self._make_leaf_node(node_id="n1.1")],
        }
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "children" in str(e.path)
            or "children" in str(e.message)
            or "minItems" in str(e.message)
            for e in errors
        )

    def test_external_precondition_with_zone_rejected(self):
        """external_precondition with a non-null zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "external_precondition"},
            zone="input",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_tool_invocation_with_wrong_zone_rejected(self):
        """tool_invocation with zone other than tool_execution must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "tool_invocation", "tool_id": "tool:v1:abc"},
            zone="input",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_integration_interaction_in_tool_execution_accepted(self):
        """integration_interaction in tool_execution must be accepted (Mayor correction 6)."""
        node = self._make_leaf_node(
            action={
                "kind": "integration_interaction",
                "integration_id": "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            zone="tool_execution",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert not errors, f"Expected no errors but got: {[str(e) for e in errors]}"

    def test_integration_interaction_without_zone_rejected(self):
        """integration_interaction with zone:null must be rejected."""
        node = self._make_leaf_node(
            action={
                "kind": "integration_interaction",
                "integration_id": "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            zone=None,
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_internal_impact_without_zone_rejected(self):
        """internal impact without zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "impact", "boundary": "internal", "target": "Data"},
            zone=None,
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_external_impact_with_zone_rejected(self):
        """external impact with a zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "impact", "boundary": "external", "target": "Reputation"},
            zone="input",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_initial_ingress_without_zone_rejected(self):
        """initial_ingress without zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "initial_ingress", "entry_point_id": "ep:v1:abc"},
            zone=None,
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )


# ---------------------------------------------------------------------------
# Per-path pinned ingress validation (Mayor correction 3)
# ---------------------------------------------------------------------------


class TestPerPathIngressValidation:
    """Every root-to-leaf path must contain an initial_ingress leaf."""

    def test_and_tree_single_path_has_ingress(self):
        """AND tree with ingress in one leaf — single merged path has it."""
        children = [
            leaf(
                InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                "input",
                node_id="n1.1",
            ),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.AND, children=children
        )
        t = tree(root)
        assert _validate_pinned_ingress(t, None) == []

    def test_or_tree_one_path_missing_ingress(self):
        """OR tree where one branch lacks ingress — must be a violation."""
        branch_a = AttackTreeNode(
            id="n1.1",
            label="A",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                    "input",
                    node_id="n1.1.1",
                ),
                leaf(AiSystemAction(), "reasoning", node_id="n1.1.2"),
            ],
        )
        branch_b = AttackTreeNode(
            id="n1.2",
            label="B",
            gate=GateType.AND,
            children=[
                leaf(AiSystemAction(), "reasoning", node_id="n1.2.1"),
                leaf(AiSystemAction(), "input", node_id="n1.2.2"),
            ],
        )
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=[branch_a, branch_b]
        )
        t = tree(root)
        violations = _validate_pinned_ingress(t, None)
        assert any("missing-initial-ingress" in v for v in violations)

    def test_pinned_mismatch_rejected(self):
        """Ingress with a different entry_point_id than pinned must be rejected."""
        ep_id = "ep:v1:cccccccccccccccccccccccccccccccc"
        children = [
            leaf(
                InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                "input",
                node_id="n1.1",
            ),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.AND, children=children
        )
        t = tree(root)
        violations = _validate_pinned_ingress(t, ep_id)
        assert any("pinned-entry-point-mismatch" in v for v in violations)

    def test_all_paths_have_ingress_passes(self):
        """OR tree where both branches have ingress — no violations."""
        branch_a = AttackTreeNode(
            id="n1.1",
            label="A",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                    "input",
                    node_id="n1.1.1",
                ),
                leaf(AiSystemAction(), "reasoning", node_id="n1.1.2"),
            ],
        )
        branch_b = AttackTreeNode(
            id="n1.2",
            label="B",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                    "input",
                    node_id="n1.2.1",
                ),
                leaf(AiSystemAction(), "reasoning", node_id="n1.2.2"),
            ],
        )
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=[branch_a, branch_b]
        )
        t = tree(root)
        assert _validate_pinned_ingress(t, None) == []

    def test_path_enumeration_and_merges(self):
        """AND gate merges children into one path."""
        children = [
            leaf(AiSystemAction(), "input", node_id="n1.1"),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.AND, children=children
        )
        paths = _enumerate_root_to_leaf_paths(root)
        assert len(paths) == 1
        assert len(paths[0]) == 2

    def test_path_enumeration_or_branches(self):
        """OR gate creates separate branches."""
        children = [
            leaf(AiSystemAction(), "input", node_id="n1.1"),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=children
        )
        paths = _enumerate_root_to_leaf_paths(root)
        assert len(paths) == 2


# ---------------------------------------------------------------------------
# Evidence nonblank check (Mayor correction 2)
# ---------------------------------------------------------------------------


class TestEvidenceNonblank:
    """Operator-confirmed complete requires nonblank evidence."""

    def test_whitespace_only_evidence_rejected(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
                entry_point_evidence=["   "],
                tool_inventory_completeness=InventoryCompleteness.inferred_partial,
            )

    def test_whitespace_only_tool_evidence_rejected(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.inferred_partial,
                tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
                tool_inventory_evidence=["\t", "  "],
            )

    def test_nonblank_evidence_accepted(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        confirmed = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["  manual review  "],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API audit"],
        )
        assert confirmed.is_inventory_complete


# ---------------------------------------------------------------------------
# Closed-world corpus claim applicability (Mayor correction 2)
# ---------------------------------------------------------------------------


class TestCorpusClaimApplicability:
    """Closed-world claims must be typed and category-specific (cmps.9 review 2)."""

    def test_partial_inventory_marks_not_applicable(self):
        from scenario_forge.models.scenario import (
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from scenario_forge.pipeline.validation import check_corpus_claims_applicability

        prof = profile()
        result = check_corpus_claims_applicability(None, prof)
        # Must produce two typed records, one per category
        assert len(result) == 2
        cats = {r.category for r in result}
        assert cats == {
            CorpusClaimCategory.entry_points,
            CorpusClaimCategory.tool_inventory,
        }
        # Both must be not_applicable under inferred_partial
        for r in result:
            assert r.status == CorpusClaimStatus.not_applicable
            assert r.reason is not None and r.reason.strip()

    def test_complete_inventory_marks_applicable(self):
        from scenario_forge.models.scenario import (
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from scenario_forge.pipeline.validation import check_corpus_claims_applicability

        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        prof = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["manual review"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API audit"],
        )
        result = check_corpus_claims_applicability(None, prof)
        assert len(result) == 2
        cats = {r.category for r in result}
        assert cats == {
            CorpusClaimCategory.entry_points,
            CorpusClaimCategory.tool_inventory,
        }
        # Both must be applicable under operator_confirmed_complete
        for r in result:
            assert r.status == CorpusClaimStatus.applicable
        # Evidence is carried for applicable records
        ep_rec = next(
            r for r in result if r.category == CorpusClaimCategory.entry_points
        )
        assert "manual review" in ep_rec.evidence
        tool_rec = next(
            r for r in result if r.category == CorpusClaimCategory.tool_inventory
        )
        assert "API audit" in tool_rec.evidence

    def test_corpus_claim_extra_fields_forbidden(self):
        """CorpusClaimApplicability must forbid extra fields."""
        from scenario_forge.models.scenario import CorpusClaimApplicability

        with pytest.raises(ValidationError):
            CorpusClaimApplicability(
                category="entry_points",
                status="not_applicable",
                foreign_field="bad",
            )

    def test_corpus_claim_serialization_roundtrip(self):
        """Typed records serialize and round-trip correctly."""
        from scenario_forge.models.scenario import CorpusClaimApplicability

        rec = CorpusClaimApplicability(
            category="entry_points",
            status="not_applicable",
            reason="Partial inventory",
        )
        dumped = rec.model_dump(mode="json")
        restored = CorpusClaimApplicability(**dumped)
        assert restored.category.value == "entry_points"
        assert restored.status.value == "not_applicable"
        assert restored.reason == "Partial inventory"

    def test_partial_means_structurally_not_applicable(self):
        """Partial inventory record validates against JSON Schema def."""
        import json
        from pathlib import Path

        import jsonschema

        from scenario_forge.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        schema_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        rec = CorpusClaimApplicability(
            category=CorpusClaimCategory.entry_points,
            status=CorpusClaimStatus.not_applicable,
            reason="inferred_partial",
        )
        dumped = rec.model_dump(mode="json")
        jsonschema.validate(dumped, schema["$defs"]["CorpusClaimApplicability"])

    def test_complete_means_applicable_in_schema(self):
        """Complete inventory record validates against JSON Schema def."""
        import json
        from pathlib import Path

        import jsonschema

        from scenario_forge.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        schema_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        rec = CorpusClaimApplicability(
            category=CorpusClaimCategory.tool_inventory,
            status=CorpusClaimStatus.applicable,
            evidence=["API audit"],
        )
        dumped = rec.model_dump(mode="json")
        jsonschema.validate(dumped, schema["$defs"]["CorpusClaimApplicability"])

    def test_corpus_claim_independent_of_phantom(self):
        """Corpus claim applicability does not conflate with phantom.valid."""
        from scenario_forge.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        # A not_applicable corpus claim record can coexist with any
        # phantom validation state — they are independent.
        rec = CorpusClaimApplicability(
            category=CorpusClaimCategory.tool_inventory,
            status=CorpusClaimStatus.not_applicable,
        )
        assert rec.status == CorpusClaimStatus.not_applicable
        # The record has no phantom-related field
        assert not hasattr(rec, "valid")


# ---------------------------------------------------------------------------
# Gherkin OR-branch precondition projection (Mayor correction 5)
# ---------------------------------------------------------------------------


class TestGherkinOrBranchPreconditions:
    """Branch-only preconditions stay in Scenario, not Background."""

    def _make_narrative(self):
        from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep

        return NarrativeLayer(
            title="Test Scenario",
            summary="Test summary",
            entry_point="user chat",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Test action",
                    effect="Test effect",
                )
            ],
        )

    def _make_seed(self):
        from scenario_forge.models.scenario import (
            RiskCardRef,
        )
        from scenario_forge.pipeline.seeds import ScenarioSeed

        return ScenarioSeed(
            seed_id="AP-T1-01",
            threat_id="T1",
            threat_name="Test Threat",
            attack_pattern_name="Test Pattern",
            attack_pattern_description="Test description",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="Risk",
                risk_description="Desc",
                taxonomy="ibm-risk-atlas",
                confidence=0.9,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
        )

    def test_branch_only_precondition_not_global_background(self):
        """A precondition on only one OR branch must not appear in Background."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        branch_a = AttackTreeNode(
            id="n1.1",
            label="Branch A",
            gate=GateType.AND,
            children=[
                leaf(
                    ExternalPreconditionAction(access_provenance="phishing"),
                    None,
                    label="Phishing setup",
                    node_id="n1.1.1",
                ),
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Ingress",
                    node_id="n1.1.2",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.1.3"),
            ],
        )
        branch_b = AttackTreeNode(
            id="n1.2",
            label="Branch B",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Ingress",
                    node_id="n1.2.1",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.2.2"),
            ],
        )
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=[branch_a, branch_b]
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        # Background should not contain the branch-only precondition
        bg_section = gherkin.split("Scenario:")[0]
        assert "Phishing setup" not in bg_section
        # But it should appear in the branch Scenario
        assert "Phishing setup" in gherkin

    def test_intersection_precondition_becomes_background(self):
        """A precondition in an AND parent of an OR appears in Background."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        or_branch = AttackTreeNode(
            id="n1.2",
            label="OR Branches",
            gate=GateType.OR,
            children=[
                AttackTreeNode(
                    id="n1.2.1",
                    label="A",
                    gate=GateType.AND,
                    children=[
                        leaf(
                            InitialIngressAction(entry_point_id=ep_id),
                            "input",
                            label="Ingress",
                            node_id="n1.2.1.1",
                        ),
                        leaf(
                            AiSystemAction(),
                            "reasoning",
                            label="Reason",
                            node_id="n1.2.1.2",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2.2",
                    label="B",
                    gate=GateType.AND,
                    children=[
                        leaf(
                            InitialIngressAction(entry_point_id=ep_id),
                            "input",
                            label="Ingress",
                            node_id="n1.2.2.1",
                        ),
                        leaf(
                            AiSystemAction(),
                            "reasoning",
                            label="Reason",
                            node_id="n1.2.2.2",
                        ),
                    ],
                ),
            ],
        )
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            children=[
                leaf(
                    ExternalPreconditionAction(access_provenance="recon"),
                    None,
                    label="Recon setup",
                    node_id="n1.1",
                ),
                or_branch,
            ],
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        bg_section = gherkin.split("Scenario:")[0]
        assert "Recon setup" in bg_section

    def test_ingress_step_from_typed_id_not_label(self):
        """Ingress step display name must come from typed entry_point_id, not label."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Misleading label about tools",
                    node_id="n1.1",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.2"),
            ],
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        # The entry point name is "User chat" — must appear, not the misleading label
        assert "User chat" in gherkin
        assert "Misleading label" not in gherkin

    def test_given_when_then_ordering_per_path(self):
        """Given/When/And/Then/But ordering must be action-derived per path."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            children=[
                leaf(
                    ExternalPreconditionAction(),
                    None,
                    label="External setup",
                    node_id="n1.1",
                ),
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Ingress",
                    node_id="n1.2",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.3"),
                leaf(
                    ImpactAction(boundary="internal", target="Model"),
                    "reasoning",
                    label="Impact",
                    node_id="n1.4",
                ),
            ],
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        # Extract the scenario section (after Background)
        scenario_section = (
            gherkin.split("Scenario:")[1] if "Scenario:" in gherkin else gherkin
        )
        # Given must come before When, When before Then
        given_pos = scenario_section.find("Given the system")
        when_pos = scenario_section.find("When ")
        then_pos = scenario_section.find("Then ")
        assert 0 <= given_pos < when_pos < then_pos


# ---------------------------------------------------------------------------
# Integration interaction in tool_execution with adversarial labels (Mayor correction 6)
# ---------------------------------------------------------------------------


class TestIntegrationInteractionToolExecution:
    """integration_interaction in tool_execution must not be rejected (Mayor 6)."""

    def test_integration_in_tool_execution_model_valid(self):
        """Model-level: integration_interaction with tool_execution zone is valid."""
        node = leaf(
            IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
            "tool_execution",
            label="Execute query_database tool via API",
        )
        assert node.zone == "tool_execution"
        assert node.action.kind == "integration_interaction"

    def test_adversarial_label_does_not_change_action_kind(self):
        """A label containing tool keywords must not change the action semantics."""
        node = leaf(
            IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
            "tool_execution",
            label="Given the system processes input and exfiltrates data",
        )
        assert _leaf_step_kind(node) == _STEP_KIND_WHEN
        assert node.action.kind == "integration_interaction"

    def test_financial_tool_label_does_not_affect_consequence(self):
        """A tool_invocation with financial label must not be treated as consequence."""
        node = leaf(
            ToolInvocationAction(tool_id=TOOL_ID),
            "tool_execution",
            label="refund payment billing transaction",
        )
        from scenario_forge.pipeline.validation import _is_consequence_leaf

        assert not _is_consequence_leaf(node)
        assert _leaf_step_kind(node) == _STEP_KIND_WHEN


# ---------------------------------------------------------------------------
# Report corpus applicability display (Mayor correction 2/6)
# ---------------------------------------------------------------------------


class TestReportCorpusApplicability:
    """Report must display separate category status and corpus applicability."""

    def test_report_shows_category_completeness(self):
        prof = profile()
        from scenario_forge.report.template import build_capability_profile_section

        html = build_capability_profile_section(prof.model_dump())
        assert "Entry-Point Inventory Completeness" in html
        assert "Tool Inventory Completeness" in html
        assert "Inferred Partial" in html

    def test_report_shows_corpus_applicability(self):
        from scenario_forge.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from scenario_forge.report.template import build_capability_profile_section

        prof = profile()
        claims = [
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
                reason="inferred_partial",
            ),
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.not_applicable,
                reason="inferred_partial",
            ),
        ]
        html = build_capability_profile_section(
            prof.model_dump(),
            corpus_claims=[c.model_dump(mode="json") for c in claims],
        )
        assert "Corpus Claim Applicability" in html
        assert "not_applicable" in html

    def test_report_shows_applicable_when_complete(self):
        from scenario_forge.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from scenario_forge.report.template import build_capability_profile_section

        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        prof = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["manual review"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API audit"],
        )
        claims = [
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                evidence=["manual review"],
            ),
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.applicable,
                evidence=["API audit"],
            ),
        ]
        html = build_capability_profile_section(
            prof.model_dump(),
            corpus_claims=[c.model_dump(mode="json") for c in claims],
        )
        assert "Corpus Claim Applicability" in html
        assert "applicable" in html
        assert "not_applicable" not in html


# ---------------------------------------------------------------------------
# ID stability under metadata edits and ambiguous duplicate rejection (Mayor correction 7)
# ---------------------------------------------------------------------------


class TestIdStabilityAndDuplicateSemantics:
    """IDs must be stable under non-identity edits and reject ambiguous duplicates."""

    def test_tool_id_ignores_description(self):
        """Tool ID is computed from name only — description changes don't affect ID."""
        id1 = compute_tool_id("my_tool", "Original description")
        id2 = compute_tool_id("my_tool", "Completely different description")
        assert id1 == id2

    def test_tool_id_ignores_evidence(self):
        """Tool ID is computed from name only — evidence/provenance doesn't affect ID."""
        id1 = compute_tool_id("my_tool", "desc")
        id2 = compute_tool_id("my_tool", "")
        assert id1 == id2

    def test_integration_id_ignores_auth_and_sensitivity(self):
        """Integration ID is computed from name + type only."""
        id1 = compute_integration_id("CRM", "api", "oauth", "high")
        id2 = compute_integration_id("CRM", "api", "api_key", "low")
        assert id1 == id2

    def test_integration_id_changes_with_type(self):
        """Integration ID changes when type differs (part of identity)."""
        id1 = compute_integration_id("CRM", "api", "oauth", "high")
        id2 = compute_integration_id("CRM", "database", "oauth", "high")
        assert id1 != id2

    def test_tool_id_is_128_bit(self):
        """Tool ID must be at least 128 bits (32 hex chars)."""
        tid = compute_tool_id("test", "desc")
        hex_part = tid.split(":")[-1]
        assert len(hex_part) >= 32

    def test_integration_id_is_128_bit(self):
        """Integration ID must be at least 128 bits (32 hex chars)."""
        iid = compute_integration_id("CRM", "api", "oauth", "high")
        hex_part = iid.split(":")[-1]
        assert len(hex_part) >= 32

    def test_ambiguous_same_name_conflicting_description_rejected(self):
        """Same canonical name with conflicting descriptions must be rejected."""
        tools = [
            ToolInventoryEntry(name="Payment API", description="Reads transactions"),
            ToolInventoryEntry(name="payment api", description="Deletes transactions"),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_tool_inventory(tools)

    def test_ambiguous_integration_conflicting_auth_rejected(self):
        """Same identity integration with conflicting auth must be rejected."""
        integrations = [
            ExternalIntegration(
                name="CRM",
                integration_type=IntegrationType.api,
                auth_method=AuthMethod.oauth,
                data_sensitivity=DataSensitivity.high,
            ),
            ExternalIntegration(
                name="crm",
                integration_type=IntegrationType.api,
                auth_method=AuthMethod.api_key,
                data_sensitivity=DataSensitivity.high,
            ),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_external_integrations(integrations)

    def test_exact_duplicate_deduplication_preserves_provenance(self):
        """Exact semantic duplicates deduplicate, preserving the first entry."""
        tools = [
            ToolInventoryEntry(name="Search", description="Search tool"),
            ToolInventoryEntry(name="search", description="Search tool"),
        ]
        result = deduplicate_tool_inventory(tools)
        assert len(result) == 1
        assert result[0].name == "Search"


# ---------------------------------------------------------------------------
# Ingress zone validation — Mayor correction 3
# ---------------------------------------------------------------------------


class TestIngressZoneValidation:
    """Initial ingress zone must match the entry point's canonical ingress zone."""

    def test_ingress_zone_mismatch_is_violation(self):
        """An initial_ingress leaf with a zone that doesn't match the entry
        point's canonical ingress_zone must produce a violation, not be
        silently repaired."""
        from scenario_forge.models.capability_profile import EntryPoint
        from scenario_forge.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        # Create a tree with an initial_ingress leaf that has the wrong zone
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="reasoning",  # WRONG — should be "input"
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate="LEAF",
                        action=ImpactAction(boundary="internal", target="system"),
                        zone="reasoning",
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert any("ingress-zone-mismatch" in v for v in violations)

    def test_ingress_zone_match_no_violation(self):
        """An initial_ingress leaf with the correct zone produces no violation."""
        from scenario_forge.models.capability_profile import EntryPoint
        from scenario_forge.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="input",  # CORRECT — matches canonical
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate="LEAF",
                        action=ImpactAction(boundary="internal", target="system"),
                        zone="reasoning",
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert not any("ingress-zone-mismatch" in v for v in violations)

    def test_adversarial_label_does_not_affect_ingress_zone(self):
        """A label containing 'reasoning' does not change the canonical ingress zone."""
        from scenario_forge.models.capability_profile import EntryPoint
        from scenario_forge.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Reasoning manipulation via reasoning zone",  # adversarial label
                        gate="LEAF",
                        zone="input",  # CORRECT — label doesn't change zone
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate="LEAF",
                        action=ImpactAction(boundary="internal", target="system"),
                        zone="reasoning",
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert not any("ingress-zone-mismatch" in v for v in violations)


# ---------------------------------------------------------------------------
# Zone enforcement rejection — Mayor correction 4
# ---------------------------------------------------------------------------


class TestZoneEnforcementRejection:
    """Zone enforcement must reject invalid zones, not prune/collapse."""

    def test_disallowed_zone_raises_not_prunes(self):
        """A tree with a disallowed zone must raise ValueError, not silently prune."""
        from scenario_forge.pipeline.generate.zones import _enforce_zones_attack_tree

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="ok",
                    gate="LEAF",
                    zone="input",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="bad",
                    gate="LEAF",
                    zone="memory",
                    action=AiSystemAction(),
                ),
            ],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=root,
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])

    def test_no_collapse_on_disallowed_zone(self):
        """The tree must not be collapsed when a zone is disallowed — it must reject."""
        from scenario_forge.pipeline.generate.zones import _enforce_zones_attack_tree

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="keep",
                    gate="LEAF",
                    zone="input",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="drop",
                    gate="LEAF",
                    zone="memory",
                    action=AiSystemAction(),
                ),
            ],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=root,
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input"])

    def test_external_precondition_zone_none_not_rejected(self):
        """Zone=None (external precondition) must never be rejected by zone enforcement."""
        from scenario_forge.pipeline.generate.zones import _enforce_zones_attack_tree

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="AND",
            zone=None,
            action=None,
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="external",
                    gate="LEAF",
                    zone=None,
                    action=ExternalPreconditionAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="internal",
                    gate="LEAF",
                    zone="input",
                    action=AiSystemAction(),
                ),
            ],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=root,
        )
        # Should pass — zone=None is always allowed
        result = _enforce_zones_attack_tree(tree, zones_active=["input"])
        assert result is tree


# ---------------------------------------------------------------------------
# Authored YAML schema alignment — Mayor correction 1
# ---------------------------------------------------------------------------


class TestAuthoredYamlSchemaZones:
    """Authored YAML schemas must use string zones, not integer zones."""

    def test_attack_tree_yaml_uses_string_zones(self):
        """The attack-tree.yaml schema must define zone as string with named values."""
        import yaml

        with open("data/schemas/attack-tree.yaml") as f:
            doc = yaml.safe_load(f)
        zone_def = doc["schema"]["node"]["properties"]["zone"]
        assert zone_def["type"] == "string", (
            f"attack-tree.yaml zone type should be 'string', got '{zone_def['type']}'"
        )
        assert set(zone_def["enum"]) == {
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        }

    def test_capability_profile_yaml_uses_string_zones(self):
        """The capability-profile.yaml schema must define zones_active as string list."""
        import yaml

        with open("data/schemas/capability-profile.yaml") as f:
            doc = yaml.safe_load(f)
        zones_def = doc["stage_1"]["zones_active"]
        assert "string" in zones_def["type"], (
            f"capability-profile.yaml zones_active type should contain 'string', "
            f"got '{zones_def['type']}'"
        )
        assert set(zones_def["valid_values"]) == {
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        }

    def test_scenario_envelope_yaml_uses_string_zones(self):
        """The scenario-envelope.yaml schema must define zone_sequence as string list."""
        import yaml

        with open("data/schemas/scenario-envelope.yaml") as f:
            doc = yaml.safe_load(f)
        zs_def = doc["fields"]["narrative"]["fields"]["zone_sequence"]
        assert "string" in zs_def["type"], (
            f"scenario-envelope.yaml zone_sequence type should contain 'string', "
            f"got '{zs_def['type']}'"
        )
        step_def = doc["fields"]["NarrativeStep"]
        assert step_def["fields"]["zone"]["type"] == "string"
        assert set(step_def["fields"]["zone"]["enum"]) == {
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        }

    def test_attack_tree_yaml_example_uses_string_zones(self):
        """The attack-tree.yaml example must use string zone values, not integers."""
        import yaml

        with open("data/schemas/attack-tree.yaml") as f:
            doc = yaml.safe_load(f)
        example = doc.get("example", {}).get("attack_tree", {})
        root = example.get("root", {})
        # Check the root zone
        assert root.get("zone") in (
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        ), f"Example root zone should be a string, got '{root.get('zone')}'"


# ---------------------------------------------------------------------------
# Tests: canonical ingress tightening (cmps.9 second review correction 5)
# ---------------------------------------------------------------------------


class TestIngressZoneDeclarations:
    """EntryPoint.ingress_zone must be a valid Schneider zone Literal,
    and output-only entries cannot have an ingress zone (cmps.9 review 5)."""

    def test_invalid_ingress_zone_rejected(self):
        """A non-Schneider ingress_zone value is rejected by Pydantic."""
        from scenario_forge.models.capability_profile import EntryPoint

        with pytest.raises(ValidationError):
            EntryPoint(
                name="test entry",
                direction="input",
                ingress_zone="invalid_zone",
            )

    def test_output_only_with_ingress_zone_rejected(self):
        """An output-only entry point with an ingress zone is rejected."""
        from scenario_forge.models.capability_profile import EntryPoint

        with pytest.raises(ValidationError, match="output.*ingress_zone"):
            EntryPoint(
                name="dashboard alerts",
                direction="output",
                ingress_zone="input",
            )

    def test_output_only_without_ingress_zone_accepted(self):
        """An output-only entry point without an ingress zone is accepted."""
        from scenario_forge.models.capability_profile import EntryPoint

        ep = EntryPoint(
            name="dashboard alerts",
            direction="output",
            ingress_zone=None,
        )
        assert ep.ingress_zone is None

    def test_valid_ingress_zone_accepted(self):
        """A valid Schneider zone for ingress_zone is accepted."""
        from scenario_forge.models.capability_profile import EntryPoint

        for zone in ("input", "reasoning", "tool_execution", "memory", "inter_agent"):
            ep = EntryPoint(
                name=f"entry_{zone}",
                direction="input",
                ingress_zone=zone,
            )
            assert ep.ingress_zone == zone


class TestIngressZoneActiveAdmission:
    """An ingress-capable entry point whose effective canonical ingress zone
    is not active in the profile must be rejected at admission (cmps.9 review 5).
    """

    def test_inactive_ingress_zone_rejected_at_admission(self):
        """An initial_ingress leaf whose canonical ingress zone is not active
        in the profile produces a violation."""
        from scenario_forge.models.capability_profile import EntryPoint
        from scenario_forge.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="tool API gateway",
            direction="input",
            ingress_zone="tool_execution",
        )
        # Profile has tool_execution NOT active
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T2-01",
            seed_id="AP-T2-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress via tool API",
                        gate="LEAF",
                        zone="tool_execution",
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert any("ingress-zone-not-active" in v for v in violations)

    def test_active_ingress_zone_accepted_at_admission(self):
        """An initial_ingress leaf whose canonical ingress zone is active
        in the profile produces no violation."""
        from scenario_forge.models.capability_profile import EntryPoint
        from scenario_forge.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="input",
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert not any("ingress-zone-not-active" in v for v in violations)
        assert not any("ingress-zone-mismatch" in v for v in violations)


class TestSystemControllabilityCandidateExclusion:
    """System-controlled entry points must not enter candidate expansion
    (cmps.9 second review correction 5).

    Explicit controllability='system' from a reviewed profile is preserved
    and excluded from the candidate cross-product.  Heuristics only apply
    when controllability is None.
    """

    def test_explicit_system_excluded_from_candidates(self):
        """An explicit system-controlled entry point does not appear in
        expanded candidates."""
        from scenario_forge.models.capability_profile import (
            CapabilityProfile,
            EntryPoint,
        )
        from scenario_forge.models.scenario import RiskCardRef
        from scenario_forge.pipeline.candidates import (
            ScenarioSeed,
            expand_candidates,
        )

        system_ep = EntryPoint(
            name="internal backend scheduler API",
            direction="input",
            controllability="system",
        )
        direct_ep = EntryPoint(
            name="user chat interface",
            direction="input",
            controllability="direct",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[system_ep, direct_ep],
            confidence="medium",
            kc_subcodes=["KC1.1"],
        )
        seed = ScenarioSeed(
            seed_id="AP-T2-01",
            threat_id="T2",
            threat_name="Test",
            attack_pattern_name="Test pattern",
            attack_pattern_description="A test",
            atlas_technique_ids=["AML.T0051"],
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T2"],
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="Risk",
                risk_description="Desc",
                taxonomy="ibm-risk-atlas",
                confidence=0.9,
                grounding_confidence="high",
            ),
        )
        candidates = expand_candidates([seed], profile)
        # system_ep must NOT appear in any candidate
        ep_names = {c.entry_point for c in candidates}
        assert "internal backend scheduler API" not in ep_names
        # direct_ep should appear
        assert "user chat interface" in ep_names

    def test_explicit_system_preserved_not_downgraded(self):
        """Explicit 'system' controllability is preserved, not downgraded
        to 'indirect' or 'direct' by heuristics."""
        from scenario_forge.models.capability_profile import (
            EntryPoint,
            classify_entry_point,
        )

        # bidirectional + system → system (preserved)
        assert (
            classify_entry_point("backend API", "bidirectional", "system") == "system"
        )
        # input + system → system (preserved)
        assert classify_entry_point("data feed", "input", "system") == "system"
        # output + system → system (preserved)
        assert classify_entry_point("alerts", "output", "system") == "system"

    def test_none_controllability_uses_heuristic(self):
        """When controllability is None, the keyword heuristic applies."""
        from scenario_forge.models.capability_profile import (
            classify_entry_point,
        )

        # system keyword + input + None → system (heuristic)
        assert classify_entry_point("internal backend API", "input", None) == "system"
        # no keyword + input + None → direct (heuristic)
        assert classify_entry_point("user chat", "input", None) == "direct"
