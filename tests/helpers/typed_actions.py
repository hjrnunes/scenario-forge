"""Test helpers for creating AttackTreeNode objects with typed actions (cmps.9).

Provides factory functions that create leaf nodes with the correct discriminated
action based on zone and context.  Use these instead of manually constructing
AttackTreeNode(gate=GateType.LEAF, ...) without an action.
"""

from __future__ import annotations

from scenario_forge.models.attack_tree import (
    AiSystemAction,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from scenario_forge.models.capability_profile import compute_tool_id

# A stable test tool_id for use in fixtures.
_TEST_TOOL_ID = compute_tool_id("test_tool", "A test tool")
_TEST_ENTRY_POINT_ID = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_TEST_INTEGRATION_ID = "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def make_leaf(
    node_id: str,
    label: str,
    zone: str | None = "input",
    technique_id: str | None = None,
    *,
    action=None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF AttackTreeNode with an appropriate typed action.

    If *action* is provided, it is used directly.  Otherwise, an action
    is chosen based on *zone*:

    - ``None`` → ExternalPreconditionAction
    - ``"tool_execution"`` → ToolInvocationAction(tool_id=test_tool_id)
    - any other zone → AiSystemAction

    Extra kwargs are forwarded to AttackTreeNode (e.g. threat_id, description).
    """
    if action is None:
        if zone is None:
            action = ExternalPreconditionAction()
        elif zone == "tool_execution":
            action = ToolInvocationAction(tool_id=_TEST_TOOL_ID)
        else:
            action = AiSystemAction()
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=action,
        technique_id=technique_id,
        **kwargs,
    )


def make_ai_leaf(
    node_id: str,
    label: str,
    zone: str = "input",
    technique_id: str | None = None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF with an ai_system_action."""
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=AiSystemAction(),
        technique_id=technique_id,
        **kwargs,
    )


def make_tool_leaf(
    node_id: str,
    label: str,
    tool_id: str | None = None,
    technique_id: str | None = None,
    integration_id: str | None = None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF with a tool_invocation action (zone=tool_execution)."""
    action = ToolInvocationAction(
        tool_id=tool_id or _TEST_TOOL_ID,
        integration_id=integration_id,
    )
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone="tool_execution",
        action=action,
        technique_id=technique_id,
        **kwargs,
    )


def make_external_precondition_leaf(
    node_id: str,
    label: str,
    technique_id: str | None = None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF with an external_precondition action (zone=None)."""
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=None,
        action=ExternalPreconditionAction(),
        technique_id=technique_id,
        **kwargs,
    )


def make_ingress_leaf(
    node_id: str,
    label: str,
    entry_point_id: str | None = None,
    zone: str = "input",
    technique_id: str | None = None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF with an initial_ingress action."""
    action = InitialIngressAction(
        entry_point_id=entry_point_id or _TEST_ENTRY_POINT_ID,
    )
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=action,
        technique_id=technique_id,
        **kwargs,
    )


def make_impact_leaf(
    node_id: str,
    label: str,
    boundary: str = "internal",
    target: str = "system integrity",
    zone: str | None = None,
    technique_id: str | None = None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF with an impact action.

    Zone is auto-set: 'input' for internal, None for external.
    """
    if zone is None:
        zone = "input" if boundary == "internal" else None
    action = ImpactAction(boundary=boundary, target=target)
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=action,
        technique_id=technique_id,
        **kwargs,
    )


def make_integration_leaf(
    node_id: str,
    label: str,
    integration_id: str | None = None,
    zone: str = "tool_execution",
    technique_id: str | None = None,
    **kwargs,
) -> AttackTreeNode:
    """Create a LEAF with an integration_interaction action."""
    action = IntegrationInteractionAction(
        integration_id=integration_id or _TEST_INTEGRATION_ID,
    )
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=action,
        technique_id=technique_id,
        **kwargs,
    )
