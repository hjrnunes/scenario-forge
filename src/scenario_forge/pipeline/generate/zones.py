"""Zone enforcement logic for narratives and attack trees.

Action-aware enforcement (cmps.9):
- External preconditions (zone=None) are never repaired into active AI zones.
- Internal action zone requirements remain profile-active.
- Tool invocation zone must be exactly 'tool_execution'.
- Invalid zones are rejected (violation list), not silently pruned (cmps.9 review correction 4).
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


def _collect_zones_from_tree(node: AttackTreeNode) -> set[str]:
    """Collect all non-None zones referenced in a tree."""
    zones: set[str] = set()
    if node.zone is not None:
        zones.add(node.zone)
    if node.children:
        for child in node.children:
            zones.update(_collect_zones_from_tree(child))
    return zones


def _validate_tree_zones_node(
    node: AttackTreeNode,
    allowed: set[str],
    violations: list[str],
) -> None:
    """Recursively validate that all zoned nodes use allowed zones.

    Nodes with zone=None (external preconditions, external impacts) are
    always valid — they are outside the AI boundary.

    Returns violations for nodes with zones not in *allowed*.  Does NOT
    prune or collapse — the caller retries or rejects the tree.
    """
    if node.zone is not None and node.zone not in allowed:
        violations.append(
            f"disallowed-zone: node '{node.id}' has zone '{node.zone}' "
            f"which is not in zones_active={sorted(allowed)}. "
            f"The tree must be retried or rejected — no silent pruning."
        )

    if node.children:
        for child in node.children:
            _validate_tree_zones_node(child, allowed, violations)


def validate_attack_tree_zones(
    tree: AttackTree,
    zones_active: list[str] | None = None,
) -> list[str]:
    """Validate that all zoned nodes in the attack tree use allowed zones.

    Returns a list of violation descriptions (empty if all zones are valid).
    Nodes with zone=None (external preconditions, external impacts) are
    always valid.

    This is a **validation**, not a transform — it never prunes, collapses,
    or fabricates nodes.  The caller must retry or reject when violations
    exist (cmps.9 review correction 4).
    """
    if zones_active is None:
        return []

    allowed = set(zones_active)
    violations: list[str] = []
    _validate_tree_zones_node(tree.root, allowed, violations)
    return violations


def _enforce_zones_attack_tree(
    tree: AttackTree,
    zones_active: list[str] | None = None,
) -> AttackTree:
    """Validate attack-tree zones against *zones_active*.

    Returns the tree unchanged when all zones are valid or when
    *zones_active* is ``None``.  Raises ``ValueError`` when any node
    has a disallowed zone — the caller must retry or reject.

    This is a **validation gate**, not a pruning transform (cmps.9 review
    correction 4).  It never prunes, collapses, or fabricates nodes.
    """
    if zones_active is None:
        return tree

    violations = validate_attack_tree_zones(tree, zones_active)
    if violations:
        raise ValueError("Attack tree has disallowed zones: " + "; ".join(violations))

    return tree
