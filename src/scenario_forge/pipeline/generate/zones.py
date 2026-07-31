"""Zone enforcement logic for narratives and attack trees.

Action-aware enforcement (cmps.9):
- External preconditions (zone=None) are never repaired into active AI zones.
- Internal action zone requirements remain profile-active.
- Tool invocation zone must be exactly 'tool_execution'.
"""

from __future__ import annotations

import logging

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode
from scenario_forge.models.scenario import NarrativeLayer, NarrativeStep

logger = logging.getLogger(__name__)


def _enforce_zones_narrative(
    narrative: NarrativeLayer,
    zones_active: list[str] | None = None,
) -> NarrativeLayer:
    """Strip zones/steps not in *zones_active* from a narrative.

    When *zones_active* is ``None`` the narrative is returned unchanged.
    If any zones or steps are removed a warning is logged.  If the
    ``zone_sequence`` would become empty after filtering, a warning is
    logged but the (now-empty) result is still returned so the caller
    can decide how to handle it.
    """
    if zones_active is None:
        return narrative

    allowed = set(zones_active)

    # --- zone_sequence ---
    filtered_zs = [z for z in narrative.zone_sequence if z in allowed]
    removed_zs = set(narrative.zone_sequence) - allowed

    # --- steps ---
    filtered_steps = [s for s in narrative.steps if s.zone in allowed]
    removed_step_zones = {s.zone for s in narrative.steps if s.zone not in allowed}

    removed_all = removed_zs | removed_step_zones
    if removed_all:
        logger.warning(
            "Stripped disallowed zones from narrative: %s (zones_active=%s)",
            sorted(removed_all),
            zones_active,
        )

    if not removed_all:
        return narrative

    if not filtered_zs or not filtered_steps:
        logger.warning(
            "Zone enforcement would leave narrative with empty %s; "
            "keeping original narrative unchanged (zones_active=%s)",
            "zone_sequence and steps"
            if (not filtered_zs and not filtered_steps)
            else ("zone_sequence" if not filtered_zs else "steps"),
            zones_active,
        )
        return narrative

    # Re-number surviving steps sequentially
    renumbered_steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=s.zone,
            action=s.action,
            effect=s.effect,
            control_point=s.control_point,
        )
        for i, s in enumerate(filtered_steps)
    ]

    return NarrativeLayer(
        title=narrative.title,
        summary=narrative.summary,
        entry_point=narrative.entry_point,
        zone_sequence=filtered_zs,
        steps=renumbered_steps,
    )


def _node_zone_allowed(node: AttackTreeNode, allowed: set[str]) -> bool:
    """Check whether a node's zone is allowed, action-aware.

    - External preconditions (zone=None) are always allowed — they are
      outside the AI boundary and must not be repaired into fake zones.
    - External impacts (zone=None) are always allowed.
    - Nodes with a zone value: zone must be in *allowed*.
    """
    if node.zone is None:
        # zone=None is valid for external_precondition and external impact.
        # These must never be filtered out by zone enforcement.
        return True
    return node.zone in allowed


def _enforce_zones_tree_node(
    node: AttackTreeNode,
    allowed: set[str],
) -> AttackTreeNode | None:
    """Recursively filter an attack-tree node, removing nodes with disallowed zones.

    Returns ``None`` when the node itself (or the entire subtree) should be
    removed.  For AND/OR nodes whose children shrink below the minimum of 2,
    the node is collapsed to its single remaining child (preserving the
    parent's ``id``), or removed entirely if no children survive.

    Action-aware (cmps.9): nodes with zone=None (external preconditions,
    external impacts) are always kept — they are outside the AI boundary.
    """
    if not _node_zone_allowed(node, allowed):
        return None

    if node.children is None:
        # LEAF node with an allowed zone (or zone=None for external) — keep it
        return node

    # Recurse into children
    surviving: list[AttackTreeNode] = []
    for child in node.children:
        kept = _enforce_zones_tree_node(child, allowed)
        if kept is not None:
            surviving.append(kept)

    if len(surviving) == 0:
        # All children removed — convert to LEAF preserving action if any
        return AttackTreeNode(
            id=node.id,
            label=node.label,
            description=node.description,
            gate="LEAF",
            zone=node.zone,
            action=node.action,
            threat_id=node.threat_id,
            technique_id=node.technique_id,
            maestro_layer=node.maestro_layer,
            control_point=node.control_point,
            structural_exposure=node.structural_exposure,
            evidence_level=node.evidence_level,
            children=None,
        )

    if len(surviving) == 1:
        # Collapse: keep child's content but preserve parent's id
        child = surviving[0]
        return AttackTreeNode(
            id=node.id,
            label=child.label,
            description=child.description,
            gate=child.gate,
            zone=child.zone,
            action=child.action,
            threat_id=child.threat_id,
            technique_id=child.technique_id,
            maestro_layer=child.maestro_layer,
            control_point=child.control_point,
            structural_exposure=child.structural_exposure,
            evidence_level=child.evidence_level,
            children=child.children,
        )

    # >= 2 children survived — rebuild the node with surviving children
    return AttackTreeNode(
        id=node.id,
        label=node.label,
        description=node.description,
        gate=node.gate,
        zone=node.zone,
        action=node.action,
        threat_id=node.threat_id,
        technique_id=node.technique_id,
        maestro_layer=node.maestro_layer,
        control_point=node.control_point,
        structural_exposure=node.structural_exposure,
        evidence_level=node.evidence_level,
        children=surviving,
    )


def _collect_zones_from_tree(node: AttackTreeNode) -> set[str]:
    """Collect all non-None zones referenced in a tree."""
    zones: set[str] = set()
    if node.zone is not None:
        zones.add(node.zone)
    if node.children:
        for child in node.children:
            zones.update(_collect_zones_from_tree(child))
    return zones


def _enforce_zones_attack_tree(
    tree: AttackTree,
    zones_active: list[str] | None = None,
) -> AttackTree:
    """Strip attack-tree nodes whose zone is not in *zones_active*.

    Returns the tree unchanged when *zones_active* is ``None``.
    Logs a warning when nodes are removed.

    Action-aware (cmps.9): nodes with zone=None (external preconditions,
    external impacts) are never removed — they are outside the AI boundary.
    """
    if zones_active is None:
        return tree

    allowed = set(zones_active)
    all_zones = _collect_zones_from_tree(tree.root)
    disallowed = all_zones - allowed

    if not disallowed:
        return tree

    logger.warning(
        "Stripping disallowed zones from attack tree: %s (zones_active=%s)",
        sorted(disallowed),
        zones_active,
    )

    new_root = _enforce_zones_tree_node(tree.root, allowed)
    if new_root is None:
        logger.warning(
            "Entire attack tree removed after zone enforcement "
            "(root zone '%s' not in zones_active=%s)",
            tree.root.zone,
            zones_active,
        )
        # Return tree with root converted to a minimal LEAF to avoid
        # downstream crashes — this scenario is likely unusable.
        from scenario_forge.models.attack_tree import AiSystemAction

        new_root = AttackTreeNode(
            id="n1",
            label=tree.root.label,
            description="[all nodes removed by zone enforcement]",
            gate="LEAF",
            zone=zones_active[0],
            action=AiSystemAction(),
            children=None,
        )

    return AttackTree(
        id=tree.id,
        seed_id=tree.seed_id,
        goal=tree.goal,
        root=new_root,
    )
