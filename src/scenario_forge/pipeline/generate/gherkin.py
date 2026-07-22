"""Call 3: Behavior Spec (Gherkin) generation logic."""

from __future__ import annotations

import logging
import re
from typing import Any

from scenario_forge.data.atlas import ATLAS_TECHNIQUE_NAMES
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import NarrativeLayer
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

from scenario_forge.pipeline.generate.constants import (
    THREAT_VIOLATION_CATEGORY,
    _ASSERTIONS_MARKER,
)

logger = logging.getLogger(__name__)

# Maximum number of Scenario blocks generated from OR-gate cross-products.
# Beyond this, paths are truncated to avoid Gherkin explosion.
MAX_OR_PATHS = 6


def _collect_leaf_nodes_dfs(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect leaf nodes from an attack tree in depth-first order.

    Leaf nodes are nodes with ``gate == GateType.LEAF`` (no children).
    The ordering matches the narrative's attack-phase sequence.
    """
    from scenario_forge.models.attack_tree import GateType

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
    from scenario_forge.models.attack_tree import GateType

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


def _build_gherkin_template(
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    seed: ScenarioSeed,
    scenario_tag: str,
) -> str:
    """Build a deterministic Gherkin skeleton from the tree and narrative.

    The mechanical parts (tags, Feature, Background, When/And steps) are
    projected directly from the attack tree and narrative.

    When the tree contains OR gates, alternative paths are rendered as
    separate ``Scenario:`` blocks (one per OR-branch combination).  If
    the cross-product of OR branches exceeds :data:`MAX_OR_PATHS`, only
    the first ``MAX_OR_PATHS`` paths are rendered.

    Each ``Scenario:`` block contains a ``{ASSERTIONS}`` marker where
    the LLM-generated Then/But/* block will be spliced in.

    Returns:
        A Gherkin template string containing ``{ASSERTIONS}`` once per
        ``Scenario:`` block.
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

    # --- Collect leaf nodes early so we can scope Background zones ---
    leaf_nodes = _collect_leaf_nodes_dfs(attack_tree.root)
    tree_zones = {leaf.zone for leaf in leaf_nodes}

    # --- Background: preconditions ---
    # First Given: narrative entry point with the first zone
    first_zone = narrative.zone_sequence[0] if narrative.zone_sequence else "input"
    lines.append("  Background: Preconditions")

    # Bug fix: strip any trailing zone suffix already present in entry_point
    # to avoid doubled labels like "(input) (input)"
    entry_point = re.sub(
        r"\s*\((input|reasoning|tool_execution|memory|inter_agent)\)\s*$",
        "",
        narrative.entry_point,
    )
    lines.append(f"    Given {entry_point} ({first_zone})")

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
            "Attack tree produces %d paths (OR-gate cross-product), "
            "capping at %d",
            len(paths),
            MAX_OR_PATHS,
        )
        paths = paths[:MAX_OR_PATHS]

    multi_path = len(paths) > 1

    _TECHNIQUE_ID_PATTERN = re.compile(r"^AML\.T\d+(\.\d+)?$")

    # Build a case-insensitive lookup of known ATLAS technique names so
    # we can detect when a leaf label is a verbatim technique name.
    _known_technique_names: dict[str, str] = {
        name.lower(): tid
        for tid, name in ATLAS_TECHNIQUE_NAMES.items()
    }

    for path_idx, path_leaves in enumerate(paths, 1):
        # --- Scenario header ---
        if multi_path:
            lines.append(f"  Scenario: {narrative.title} (Path {path_idx})")
        else:
            lines.append(f"  Scenario: {narrative.title}")
        lines.append("    Given the system is in its normal operating state")
        lines.append("")

        # --- Attack steps from path leaves ---
        for i, leaf in enumerate(path_leaves):
            # Build step text: label [technique_id] (zone)
            step_text = leaf.label

            # Bug fix: when the label is just a raw technique ID (e.g. "AML.T0052"),
            # replace it with the human-readable technique name
            if _TECHNIQUE_ID_PATTERN.match(step_text):
                step_text = ATLAS_TECHNIQUE_NAMES.get(step_text, step_text)

            # Bug fix: when the label is a verbatim ATLAS technique name
            # (e.g. "AI Agent Tool Invocation"), replace with the node's
            # description or a generic action label — the technique name
            # alone is not a meaningful Gherkin step.
            elif step_text.lower() in _known_technique_names:
                if leaf.description:
                    step_text = leaf.description
                else:
                    step_text = f"Execute attack step via {step_text}"

            if leaf.technique_id:
                step_text += f" [{leaf.technique_id}]"
            step_text += f" ({leaf.zone})"

            keyword = "When" if i == 0 else "And"
            lines.append(f"    {keyword} {step_text}")

        lines.append("")
        lines.append(f"    {_ASSERTIONS_MARKER}")

        # Blank line between scenarios (not after the last one)
        if path_idx < len(paths):
            lines.append("")

    return "\n".join(lines) + "\n"


def build_call3_context(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    scenario_hash: str,
) -> dict[str, Any]:
    """Build prompt template variables for Call 3 (Behavior Spec).

    Pure data-preparation function that constructs all template variables
    needed by ``call3_user.j2``.  No LLM calls.

    Returns:
        Dict mapping template variable names to their values.
    """
    scenario_tag = f"{seed.seed_id}-{scenario_hash}"

    # Build deterministic Gherkin skeleton from tree + narrative
    gherkin_template = _build_gherkin_template(
        narrative=narrative,
        attack_tree=attack_tree,
        profile=profile,
        seed=seed,
        scenario_tag=scenario_tag,
    )

    return {
        "gherkin_skeleton": gherkin_template,
        "narrative": narrative,
        "seed": seed,
    }


def _call_behavior_spec(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    attack_tree: AttackTree,
    profile: CapabilityProfile,
    client: LLMClient,
    use_case: str,
    scenario_hash: str,
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
        scenario_hash=scenario_hash,
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
