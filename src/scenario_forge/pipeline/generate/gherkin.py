"""Call 3: Behavior Spec (Gherkin) generation logic.

Action-aware Gherkin projection (cmps.9):
- ``external_precondition`` → Given / Background
- ``initial_ingress`` and attack actions (ai_system_action, tool_invocation,
  integration_interaction) → When / And
- ``impact`` → Then (projected before the LLM assertion block)
- Human labels remain display text only; the action discriminator
  determines step kind, not label text.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from scenario_forge.data.atlas import ATLAS_TECHNIQUE_NAMES
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import NarrativeLayer
from scenario_forge.pipeline.generate.constants import (
    _ASSERTIONS_MARKER,
    THREAT_VIOLATION_CATEGORY,
)
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

logger = logging.getLogger(__name__)

# Maximum number of Scenario blocks generated from OR-gate cross-products.
# Beyond this, paths are truncated to avoid Gherkin explosion.
MAX_OR_PATHS = 6


# ---------------------------------------------------------------------------
# Leaf-action step classification (cmps.9)
# ---------------------------------------------------------------------------

# Step kinds derived from action discriminator, not labels.
_STEP_KIND_GIVEN = "given"  # external_precondition
_STEP_KIND_WHEN = "when"  # initial_ingress, ai_system_action, tool_invocation, integration_interaction
_STEP_KIND_THEN = "then"  # impact


def _leaf_step_kind(leaf: AttackTreeNode) -> str:
    """Classify a leaf node's Gherkin step kind from its typed action.

    Returns one of ``_STEP_KIND_GIVEN``, ``_STEP_KIND_WHEN``, ``_STEP_KIND_THEN``.
    The classification is based solely on the action discriminator — never
    on label/description text.
    """
    action = leaf.action
    if action is None:
        # Should not happen — LEAF nodes require actions.  Defensive default.
        return _STEP_KIND_WHEN
    kind = action.kind
    if kind == "external_precondition":
        return _STEP_KIND_GIVEN
    if kind == "impact":
        return _STEP_KIND_THEN
    # initial_ingress, ai_system_action, tool_invocation, integration_interaction
    return _STEP_KIND_WHEN


def _collect_leaf_nodes_dfs(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect leaf nodes from an attack tree in depth-first order.

    Leaf nodes are nodes with ``gate == GateType.LEAF`` (no children).
    The ordering matches the narrative's attack-phase sequence.
    """
    leaves: list[AttackTreeNode] = []
    if node.gate == GateType.LEAF:
        leaves.append(node)
    elif node.children:
        for child in node.children:
            leaves.extend(_collect_leaf_nodes_dfs(child))
    return leaves


def _enumerate_paths(node: AttackTreeNode) -> list[list[AttackTreeNode]]:
    """Enumerate all distinct attack paths through an AND/OR tree.

    At AND gates, all children are required — their paths are combined via
    cross-product (each resulting path contains leaves from every child).
    At OR gates, each child is an alternative — their paths are appended
    as separate alternatives.

    Returns a list of paths, where each path is a list of leaf nodes
    in depth-first order.
    """
    if node.gate == GateType.LEAF:
        return [[node]]

    if not node.children:
        return [[]]

    if node.gate == GateType.AND:
        # All children required — cross-product of each child's paths.
        result: list[list[AttackTreeNode]] = [[]]
        for child in node.children:
            child_paths = _enumerate_paths(child)
            new_result: list[list[AttackTreeNode]] = []
            for existing in result:
                for cp in child_paths:
                    new_result.append(existing + cp)
            result = new_result
        return result

    # node.gate == GateType.OR
    # Each child is an alternative — collect all children's paths.
    result = []
    for child in node.children:
        result.extend(_enumerate_paths(child))
    return result


def _format_leaf_step_text(leaf: AttackTreeNode) -> str:
    """Build the display text for a leaf node's Gherkin step.

    Labels are display prose only.  The technique ID is appended if present.
    The zone is appended if the leaf has one (non-None).
    """
    step_text = leaf.label

    # When the label is just a raw technique ID, replace with the name.
    _TECHNIQUE_ID_PATTERN = re.compile(r"^AML\.T\d+(\.\d+)?$")
    if _TECHNIQUE_ID_PATTERN.match(step_text):
        step_text = ATLAS_TECHNIQUE_NAMES.get(step_text, step_text)
    else:
        # When the label is a verbatim ATLAS technique name, replace with
        # description or generic action label.
        _known_technique_names: dict[str, str] = {
            name.lower(): tid for tid, name in ATLAS_TECHNIQUE_NAMES.items()
        }
        if step_text.lower() in _known_technique_names:
            if leaf.description:
                step_text = leaf.description
            else:
                step_text = f"Execute attack step via {step_text}"

    if leaf.technique_id:
        step_text = re.sub(r"\s*\[AML\.T\d+(?:\.\d+)?\]", "", step_text)
        step_text += f" [{leaf.technique_id}]"
    if leaf.zone is not None:
        step_text += f" ({leaf.zone})"
    return step_text


def _build_gherkin_template(
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    seed: ScenarioSeed,
    scenario_tag: str,
) -> str:
    """Build a deterministic Gherkin skeleton from the tree and narrative.

    Action-aware projection (cmps.9):
    - ``external_precondition`` leaves → Background Given steps
    - ``initial_ingress`` and attack actions → Scenario When/And steps
    - ``impact`` leaves → Scenario Then steps (before {ASSERTIONS})
    - Labels are display text only; action discriminator determines step kind.

    When the tree contains OR gates, alternative paths are rendered as
    separate ``Scenario:`` blocks (one per OR-branch combination).  If
    the cross-product of OR branches exceeds :data:`MAX_OR_PATHS`, only
    the first ``MAX_OR_PATHS`` paths are rendered.
    """
    # --- Violation category tag ---
    violation_tag = THREAT_VIOLATION_CATEGORY.get(
        seed.threat_id, "misaligned-and-deceptive-behavior"
    )

    # --- Feature header ---
    lines: list[str] = [
        f"@id:{scenario_tag}",
        f"@{violation_tag}",
        f"Feature: {narrative.title}",
        f"  {narrative.summary}",
        "",
    ]

    # --- Collect leaf nodes for zone scoping and Background ---
    leaf_nodes = _collect_leaf_nodes_dfs(attack_tree.root)
    tree_zones = {leaf.zone for leaf in leaf_nodes if leaf.zone is not None}

    # --- Separate external preconditions for Background ---
    precondition_leaves = [
        leaf for leaf in leaf_nodes if _leaf_step_kind(leaf) == _STEP_KIND_GIVEN
    ]

    # --- Background: preconditions ---
    first_zone = narrative.zone_sequence[0] if narrative.zone_sequence else "input"
    lines.append("  Background: Preconditions")

    # Bug fix: strip any trailing zone suffix already present in entry_point
    entry_point = re.sub(
        r"\s*\((input|reasoning|tool_execution|memory|inter_agent)\)\s*$",
        "",
        narrative.entry_point,
    )
    lines.append(f"    Given {entry_point} ({first_zone})")

    # External precondition leaves go to Background as Given/And steps
    for prec_leaf in precondition_leaves:
        prec_text = _format_leaf_step_text(prec_leaf)
        lines.append(f"    And {prec_text}")

    # Additional zone/capability preconditions — scoped to zones
    # actually present in the tree's leaf nodes, not the full profile
    from scenario_forge.models.capability_profile import ZONE_DISPLAY_NAMES

    for zone in profile.zones_active:
        if zone == first_zone:
            continue  # already covered by the entry point
        if zone not in tree_zones:
            continue  # zone not used in this scenario's tree

        display_name = ZONE_DISPLAY_NAMES.get(zone, zone)
        lines.append(f"    And the system has {display_name} capabilities ({zone})")
    lines.append("")

    # --- Enumerate attack paths (OR-gate aware) ---
    paths = _enumerate_paths(attack_tree.root)

    if len(paths) > MAX_OR_PATHS:
        logger.warning(
            "Attack tree produces %d paths (OR-gate cross-product), capping at %d",
            len(paths),
            MAX_OR_PATHS,
        )
        paths = paths[:MAX_OR_PATHS]

    multi_path = len(paths) > 1

    for path_idx, path_leaves in enumerate(paths, 1):
        # --- Separate leaves by step kind ---
        when_leaves: list[AttackTreeNode] = []
        then_leaves: list[AttackTreeNode] = []
        for leaf in path_leaves:
            kind = _leaf_step_kind(leaf)
            if kind == _STEP_KIND_GIVEN:
                continue  # already in Background
            elif kind == _STEP_KIND_THEN:
                then_leaves.append(leaf)
            else:
                when_leaves.append(leaf)

        # --- Scenario header ---
        if multi_path:
            lines.append(f"  Scenario: {narrative.title} (Path {path_idx})")
        else:
            lines.append(f"  Scenario: {narrative.title}")
        lines.append("    Given the system is in its normal operating state")
        lines.append("")

        # --- Attack steps (When/And) from action leaves ---
        for i, leaf in enumerate(when_leaves):
            step_text = _format_leaf_step_text(leaf)
            keyword = "When" if i == 0 else "And"
            lines.append(f"    {keyword} {step_text}")

        # --- Impact steps (Then) from impact leaves ---
        for leaf in then_leaves:
            step_text = _format_leaf_step_text(leaf)
            lines.append(f"    Then {step_text}")

        lines.append("")
        lines.append(f"    {_ASSERTIONS_MARKER}")

        # Blank line between scenarios (not after the last one)
        if path_idx < len(paths):
            lines.append("")

    return "\n".join(lines) + "\n"


def _collect_control_points(node: AttackTreeNode) -> list[str]:
    """Collect unique non-None control_point values from tree nodes."""
    points: set[str] = set()
    if node.control_point:
        points.add(node.control_point)
    if node.children:
        for child in node.children:
            points.update(_collect_control_points(child))
    return sorted(points)


def build_call3_context(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    scenario_tag: str,
) -> dict[str, Any]:
    """Build prompt template variables for Call 3 (Behavior Spec).

    Pure data-preparation function that constructs all template variables
    needed by ``call3_user.j2``.  No LLM calls.

    Returns:
        Dict mapping template variable names to their values.
    """
    # Build deterministic Gherkin skeleton from tree + narrative
    gherkin_template = _build_gherkin_template(
        narrative=narrative,
        attack_tree=attack_tree,
        profile=profile,
        seed=seed,
        scenario_tag=scenario_tag,
    )

    # Collect defensive control points from attack tree nodes
    control_points = _collect_control_points(attack_tree.root)

    return {
        "gherkin_skeleton": gherkin_template,
        "narrative": narrative,
        "seed": seed,
        "control_points": control_points,
    }


def _call_behavior_spec(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    scenario_tag: str,
    pinned_technique_ids: list[str] | None = None,
) -> tuple[str, LLMResult]:
    """Generate a behavior spec for a scenario seed (Call 3).

    Delegates context building to :func:`build_call3_context`, then renders
    templates, calls the LLM, and splices assertions into the Gherkin skeleton.

    Returns:
        Tuple of (complete_gherkin_spec, LLMResult).
    """
    ctx = build_call3_context(
        seed=seed,
        narrative=narrative,
        attack_tree=attack_tree,
        profile=profile,
        scenario_tag=scenario_tag,
    )

    result = client.complete(
        system_prompt=render_prompt("call3_system.j2"),
        user_prompt=render_prompt("call3_user.j2", **ctx),
        response_format=None,
    )

    content = result.content
    if not isinstance(content, str) or not content.strip():
        raise ValueError(
            f"Behavior spec generation returned empty content for {seed.seed_id}"
        )

    # Clean markdown fences from LLM output
    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines)

    # Splice the assertion block into the template, ensuring every
    # Then/But/* line is indented with 4 spaces to sit inside the
    # Scenario block (the template marker already sits at col 4).
    indented_lines = []
    for line in cleaned.strip().splitlines():
        stripped = line.strip()
        if stripped:
            indented_lines.append(f"    {stripped}")
        else:
            indented_lines.append("")
    indented_assertions = "\n".join(indented_lines)
    complete_gherkin = ctx["gherkin_skeleton"].replace(
        f"    {_ASSERTIONS_MARKER}", indented_assertions
    )

    return complete_gherkin, result
