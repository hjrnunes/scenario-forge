"""Call 2: Attack Tree generation logic."""

from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Any

import yaml

from scenario_forge.data.atlas import TECHNIQUE_ZONE_CONSTRAINTS
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
    repair_attack_tree_dict,
)
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.scenario import ActorProfile, NarrativeLayer
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.prompts import render_prompt

from scenario_forge.pipeline.generate.constants import (
    _STEP_NODE_CORRESPONDENCE_FLOOR,
)
from scenario_forge.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
)
from scenario_forge.pipeline.generate.zones import (
    _collect_zones_from_tree,
    _enforce_zones_attack_tree,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Post-generation threat_id cross-reference validation
# ---------------------------------------------------------------------------


def _collect_threat_ids_from_tree(node: AttackTreeNode) -> list[str | None]:
    """Collect all threat_id values from an attack tree (depth-first)."""
    ids: list[str | None] = [node.threat_id]
    if node.children:
        for child in node.children:
            ids.extend(_collect_threat_ids_from_tree(child))
    return ids


def _warn_dominant_threat_id_crossref(
    tree: AttackTree,
    parent_threat_id: str,
    scenario_id: str,
) -> None:
    """Log a warning if a dominant cross-ref threat_id differs from the parent.

    Flags trees where >50% of nodes share the same threat_id AND that
    threat_id differs from the scenario's parent threat. This catches the
    "everything is T1" pattern where the LLM defaults to tagging most
    nodes with T1 regardless of the actual threat context.

    This is warning-level only -- it does NOT reject or modify the tree.
    """
    all_ids = _collect_threat_ids_from_tree(tree.root)
    # Only consider nodes that actually have a threat_id set
    non_null_ids = [tid for tid in all_ids if tid is not None]

    if not non_null_ids:
        return

    counts = Counter(non_null_ids)
    dominant_id, dominant_count = counts.most_common(1)[0]

    total_with_id = len(non_null_ids)
    ratio = dominant_count / total_with_id

    if ratio > 0.5 and dominant_id != parent_threat_id:
        logger.warning(
            "threat_id cross-ref anomaly in %s: %.0f%% of nodes (%d/%d) "
            "tagged as %s but parent threat is %s",
            scenario_id,
            ratio * 100,
            dominant_count,
            total_with_id,
            dominant_id,
            parent_threat_id,
        )


# ---------------------------------------------------------------------------
# YAML sanitization
# ---------------------------------------------------------------------------


def _sanitize_yaml_colons(raw_yaml: str) -> str:
    """Quote YAML values that contain unquoted colons.

    LLM-generated YAML often contains values like:
        description: Human-in-the-loop: Investigator/Supervisor approval
    which fails parsing because the second colon starts a new mapping.

    This function finds lines matching ``<indent><key>: <value>`` where
    ``<value>`` itself contains a ``:`` and is not already quoted, then wraps
    the value in double quotes (escaping any internal double quotes).

    Lines that are pure mapping keys (value is empty or only whitespace, i.e.
    the value starts on the next indented line) are left untouched.
    """
    # Pattern: optional leading whitespace, a YAML key (``- `` list prefix
    # allowed), then ``: ``, then a value that contains another ``:``.
    # We only act when the value is *not* already wrapped in quotes.
    _KEY_VALUE_RE = re.compile(
        r"^(?P<prefix>\s*(?:-\s+)?)(?P<key>[A-Za-z_][\w.]*):\s+(?P<value>.+)$"
    )

    sanitized_lines: list[str] = []
    for line in raw_yaml.split("\n"):
        m = _KEY_VALUE_RE.match(line)
        if m:
            value = m.group("value")
            # Only act if the value contains another colon AND is not already
            # quoted (single or double).
            if (
                ":" in value
                and not (value.startswith('"') and value.endswith('"'))
                and not (value.startswith("'") and value.endswith("'"))
            ):
                # Escape existing double quotes inside the value, then wrap.
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                line = f'{m.group("prefix")}{m.group("key")}: "{escaped}"'
        sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


def _parse_attack_tree_yaml(raw: str, seed: ScenarioSeed) -> AttackTree:
    """Parse YAML text into an AttackTree model.

    Strips markdown code fences if present, then validates through Pydantic.
    If the initial parse fails due to YAML syntax errors (commonly from
    unquoted colons in LLM-generated values), the raw text is sanitized
    and parsing is retried once.
    """
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]  # drop opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines)

    try:
        data = yaml.safe_load(cleaned)
    except yaml.YAMLError:
        logger.warning(
            "YAML parse failed for seed %s; attempting colon sanitization",
            seed.seed_id,
        )
        sanitized = _sanitize_yaml_colons(cleaned)
        try:
            data = yaml.safe_load(sanitized)
        except yaml.YAMLError as exc:
            raise yaml.YAMLError(
                f"Failed to parse attack tree YAML for seed {seed.seed_id} "
                f"even after colon sanitization: {exc}"
            ) from exc

    if isinstance(data, dict) and "root" not in data and "id" in data:
        pass  # top-level is the tree itself
    if isinstance(data, dict) and "attack_tree" in data:
        data = data["attack_tree"]

    # Repair single-child AND/OR nodes before Pydantic validation.
    if isinstance(data, dict):
        data = repair_attack_tree_dict(data)

    return AttackTree.model_validate(data)


# ---------------------------------------------------------------------------
# Tree skeleton builder
# ---------------------------------------------------------------------------


def _build_tree_skeleton(
    narrative: NarrativeLayer,
    pinned_technique_ids: list[str],
    pinned_technique_names: list[str],
) -> list[dict[str, str]]:
    """Build mandatory leaf-node specs from pinned techniques and narrative.

    Each pinned technique is matched against the narrative steps by checking
    whether the technique ID or name appears in the step's ``action`` or
    ``effect`` text (case-insensitive).  The zone of the first matching step
    is assigned to the leaf.  If no step matches, the narrative's first zone
    is used as a fallback.

    Returns a list of dicts, each with keys:
      ``id``, ``technique_id``, ``technique_name``, ``zone``
    """
    if not pinned_technique_ids:
        return []

    fallback_zone = narrative.zone_sequence[0] if narrative.zone_sequence else "input"

    leaves: list[dict[str, str]] = []
    for idx, (tid, tname) in enumerate(
        zip(pinned_technique_ids, pinned_technique_names), start=1
    ):
        # Match technique against narrative steps by ID or name
        matched_zone: str | None = None
        tid_lower = tid.lower()
        tname_lower = tname.lower()
        for step in narrative.steps:
            haystack = f"{step.action} {step.effect}".lower()
            if tid_lower in haystack or tname_lower in haystack:
                matched_zone = step.zone
                break

        zone = matched_zone if matched_zone is not None else fallback_zone

        # Validate zone against technique-zone semantic constraints.
        # If the narrative-derived zone is invalid for this technique,
        # pick the first valid zone from the constraint set.
        valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(tid)
        if valid_zones is not None and zone not in valid_zones:
            zone = sorted(valid_zones)[0]

        leaves.append(
            {
                "id": f"n0.{idx}",
                "technique_id": tid,
                "technique_name": tname,
                "zone": zone,
            }
        )

    return leaves


def _format_skeleton_yaml(skeleton: list[dict[str, str]]) -> str:
    """Format mandatory leaf specs as a YAML block for prompt injection."""
    if not skeleton:
        return ""
    lines = ["## Mandatory Leaf Nodes"]
    lines.append(
        "Your tree MUST include ALL of the leaf nodes listed below with their "
        "exact technique_id and zone. Each mandatory leaf MUST have gate: LEAF "
        "and use a valid node id (e.g. n1.1, n1.2.1). Reassign the placeholder "
        "ids below to match your tree's numbering scheme. You may add up to "
        f"{len(skeleton) + 2} additional connector/setup leaves "
        "beyond these mandatory ones. Organize them into a coherent AND/OR "
        "tree with meaningful labels and gate structure."
    )
    lines.append("")
    lines.append("```yaml")
    lines.append("mandatory_leaves:")
    for leaf in skeleton:
        lines.append(f"  - id: {leaf['id']}")
        lines.append(f"    technique_id: {leaf['technique_id']}")
        lines.append(f"    technique_name: {leaf['technique_name']}")
        lines.append(f"    zone: {leaf['zone']}")
    lines.append("```")
    lines.append("")
    return "\n".join(lines) + "\n"


def _validate_mandatory_leaves(
    tree: AttackTree,
    skeleton: list[dict[str, str]],
    seed_id: str,
) -> None:
    """Warn if any mandatory leaf techniques are missing from the parsed tree.

    This is a post-generation check: it logs warnings but does not reject
    the tree, since this is a first-pass implementation.
    """
    if not skeleton:
        return

    tree_technique_ids = set(tree.collect_technique_ids())
    for leaf in skeleton:
        if leaf["technique_id"] not in tree_technique_ids:
            logger.warning(
                "Mandatory leaf technique %s (%s) missing from attack tree "
                "for seed %s — tree has: %s",
                leaf["technique_id"],
                leaf["technique_name"],
                seed_id,
                sorted(tree_technique_ids),
            )


# ---------------------------------------------------------------------------
# Context builder and LLM call
# ---------------------------------------------------------------------------


def build_call2_context(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    use_case: str,
    profile: CapabilityProfile | None = None,
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 2 (Attack Tree).

    Pure data-preparation function that constructs all template variables
    needed by ``call2_user.j2``.  No LLM calls.

    Returns:
        Dict mapping template variable names to their values.  Also
        includes ``skeleton`` (the raw leaf-node spec list) for use in
        post-generation validation.
    """
    # Build shared technique context + Call 2-specific constraint rules
    # Pin to specific techniques if set
    tech_ids_for_tree = (
        pinned_technique_ids if pinned_technique_ids else seed.atlas_technique_ids
    )
    technique_context = _build_technique_context_block(tech_ids_for_tree)
    if tech_ids_for_tree:
        allowed_ids = ", ".join(tech_ids_for_tree)
        if pinned_technique_ids:
            technique_constraint = (
                "\n## ATLAS Technique Constraint\n"
                f"You MUST use this ATLAS technique: {allowed_ids}\n\n"
                "Only assign a technique_id to a node if the technique's "
                "description semantically matches the attack action described "
                "in the node's label.\n"
                "Use ONLY this technique ID on leaf nodes. "
                "Do NOT invent or hallucinate new technique IDs. "
                "If the ID does not fit a particular node, omit technique_id "
                "from that node rather than inventing one.\n"
            )
        else:
            technique_constraint = (
                "\n## ATLAS Technique Constraint\n"
                f"Allowed technique_id values: {allowed_ids}\n\n"
                "Only assign a technique_id to a node if the technique's "
                "description semantically matches the attack action described "
                "in the node's label. For example, 'AI Agent Tool Invocation' "
                "should only be used for nodes that involve invoking or "
                "manipulating tools, not for prompt injection or hallucination "
                "steps.\n"
                "Use ONLY these technique IDs on leaf nodes. "
                "Do NOT invent or hallucinate new technique IDs. "
                "If none of these IDs fit a particular node, omit technique_id "
                "from that node rather than inventing one.\n"
            )
    else:
        technique_constraint = (
            "\n## ATLAS Technique Constraint\n"
            "No ATLAS technique IDs are available for this seed. "
            "Do NOT add technique_id to any node.\n"
        )

    # Build optional architecture and actor profile sections for Call 2
    arch_section = ""
    if profile is not None:
        entry_point_names = [ep.name for ep in profile.entry_points]
        arch_section = (
            "\n## Target System Architecture\n"
            "Every node's zone must be drawn from these active zones.\n"
            f"- Active zones: {profile.zones_active}\n"
            f"- Entry points: {entry_point_names}\n"
        )

    actor_section = ""
    if actor_profile is not None:
        actor_section = (
            "\n## Actor Profile\n"
            "The tree's depth and complexity must be commensurate with "
            "the actor's capability level.\n"
            f"- Actor type: {actor_profile.actor_type}\n"
            f"- Capability level: {actor_profile.capability_level}\n"
        )

    # Compute concrete leaf budget so the LLM sees the exact number
    technique_count = len(tech_ids_for_tree) if tech_ids_for_tree else 0
    leaf_budget = 2 * technique_count + 2 if technique_count > 0 else 5

    # Build tree skeleton from pinned techniques (tree-anchored flow)
    skeleton: list[dict[str, str]] = []
    if pinned_technique_ids and pinned_technique_names:
        skeleton = _build_tree_skeleton(
            narrative, pinned_technique_ids, pinned_technique_names
        )
    skeleton_section = _format_skeleton_yaml(skeleton)

    # Build focused ontology context block for this seed
    # Use narrative.entry_point for the entry point (it was pinned upstream)
    _tree_ep_direction = _lookup_entry_point_direction(
        profile, narrative.entry_point
    ) if profile else None
    _tree_ep_controllability = _lookup_entry_point_controllability(
        profile, narrative.entry_point
    ) if profile else None
    ontology_context = _build_ontology_context(
        entry_point_name=narrative.entry_point or "",
        entry_point_direction=_tree_ep_direction,
        zones=profile.zones_active if profile else [],
        technique_ids=list(tech_ids_for_tree) if tech_ids_for_tree else [],
        entry_point_controllability=_tree_ep_controllability,
    )

    return {
        "seed": seed,
        "use_case": use_case,
        "arch_section": arch_section,
        "actor_section": actor_section,
        "technique_context": technique_context,
        "technique_constraint": technique_constraint,
        "narrative": narrative,
        "technique_count": technique_count,
        "leaf_budget": leaf_budget,
        "skeleton_section": skeleton_section,
        "ontology_context": ontology_context,
        "tool_inventory": (profile.tool_inventory if profile else None) or [],
        "kill_chain": seed.kill_chain,
        # Non-template data for post-generation validation
        "skeleton": skeleton,
    }


def _call_attack_tree(
    seed: ScenarioSeed,
    narrative: NarrativeLayer,
    client: LLMClient,
    use_case: str,
    profile: CapabilityProfile | None = None,
    actor_profile: ActorProfile | None = None,
    pinned_technique_ids: list[str] | None = None,
    pinned_technique_names: list[str] | None = None,
) -> tuple[AttackTree, LLMResult]:
    """Generate an attack tree for a scenario seed (Call 2).

    Delegates context building to :func:`build_call2_context`, then renders
    templates, calls the LLM (with one retry on YAML parse failure), and
    post-processes the tree.

    Returns:
        Tuple of (AttackTree, LLMResult).
    """
    ctx = build_call2_context(
        seed=seed,
        narrative=narrative,
        use_case=use_case,
        profile=profile,
        actor_profile=actor_profile,
        pinned_technique_ids=pinned_technique_ids,
        pinned_technique_names=pinned_technique_names,
    )

    skeleton = ctx["skeleton"]

    call2_system = render_prompt(
        "call2_system.j2",
        zones_active=profile.zones_active if profile else [],
        tool_inventory=ctx["tool_inventory"],
    )

    result = client.complete(
        system_prompt=call2_system,
        user_prompt=render_prompt("call2_user.j2", **ctx),
        response_format=None,
    )

    try:
        tree = _parse_attack_tree_yaml(result.content, seed)
    except Exception as first_error:
        # One retry with error feedback — Call 2 produces unstructured YAML
        # which is the most fragile output format in the pipeline.
        logger.warning("Attack tree YAML parse failed, retrying: %s", first_error)

        retry_user_prompt = (
            "Your previous output was not valid YAML. The error was:\n"
            f"  {first_error}\n\n"
            "Please produce valid YAML following the same structure "
            "described in the system prompt. Use the same seed_id, goal, "
            "and narrative context from the original request.\n\n"
            f'seed_id={seed.seed_id}, tree id="tree-{seed.seed_id}".'
        )

        retry_result = client.complete(
            system_prompt=call2_system,
            user_prompt=retry_user_prompt,
            response_format=None,
        )

        try:
            tree = _parse_attack_tree_yaml(retry_result.content, seed)
        except Exception:
            raise first_error

        tree = _enforce_zones_attack_tree(
            tree,
            profile.zones_active if profile else None,
        )
        _validate_mandatory_leaves(tree, skeleton, seed.seed_id)
        return tree, retry_result

    tree = _enforce_zones_attack_tree(
        tree,
        profile.zones_active if profile else None,
    )
    _validate_mandatory_leaves(tree, skeleton, seed.seed_id)
    return tree, result


# ---------------------------------------------------------------------------
# Post-processing: strip non-skeleton technique IDs
# ---------------------------------------------------------------------------


def _strip_non_skeleton_techniques_node(
    node: AttackTreeNode, skeleton_technique_ids: set[str]
) -> int:
    """Recursively strip technique_id from non-skeleton leaf nodes.

    Returns the number of technique_ids stripped.
    """
    stripped = 0
    if node.gate == GateType.LEAF:
        if (
            node.technique_id is not None
            and node.technique_id not in skeleton_technique_ids
        ):
            logger.debug(
                "Stripping non-skeleton technique_id '%s' from leaf '%s'",
                node.technique_id,
                node.id,
            )
            node.technique_id = None
            stripped += 1
    elif node.children:
        for child in node.children:
            stripped += _strip_non_skeleton_techniques_node(
                child, skeleton_technique_ids
            )
    return stripped


def _strip_non_skeleton_techniques(
    tree: AttackTree, skeleton_technique_ids: set[str]
) -> int:
    """Remove technique_id from leaves that are not in the skeleton.

    The skeleton builder places pinned techniques on mandatory leaves.
    The LLM tree generator often copies those technique IDs onto additional
    leaves it creates, producing decorative/semantically incorrect annotations.
    Only skeleton leaves (those whose technique_id is in the pinned set) should
    retain their technique annotations.

    Args:
        tree: The attack tree to post-process (mutated in place).
        skeleton_technique_ids: Set of pinned technique IDs that are allowed
            to remain on leaves. If empty, ALL leaf technique_ids are stripped.

    Returns:
        The number of technique_ids stripped.
    """
    return _strip_non_skeleton_techniques_node(tree.root, skeleton_technique_ids)


# ---------------------------------------------------------------------------
# Post-generation: technique-zone compatibility validation
# ---------------------------------------------------------------------------


def _validate_technique_zone_node(node: AttackTreeNode) -> int:
    """Recursively strip technique_ids that violate zone constraints.

    Returns the number of technique_ids stripped.
    """
    stripped = 0
    if node.gate == GateType.LEAF:
        if node.technique_id is not None:
            valid_zones = TECHNIQUE_ZONE_CONSTRAINTS.get(node.technique_id)
            if valid_zones is not None and node.zone not in valid_zones:
                logger.warning(
                    "Technique-zone mismatch: stripping %s from node %s "
                    "(zone=%s, valid_zones=%s)",
                    node.technique_id,
                    node.id,
                    node.zone,
                    sorted(valid_zones),
                )
                node.technique_id = None
                stripped += 1
    elif node.children:
        for child in node.children:
            stripped += _validate_technique_zone_node(child)
    return stripped


def _validate_technique_zone_compatibility(tree: AttackTree) -> int:
    """Strip technique_ids that violate TECHNIQUE_ZONE_CONSTRAINTS.

    Walks the tree and removes technique_id from any leaf node where
    the technique is not valid in the node's zone per the constraint map.
    Techniques absent from the map are unconstrained and pass.

    Returns the number of technique_ids stripped.
    """
    return _validate_technique_zone_node(tree.root)


# ---------------------------------------------------------------------------
# Post-generation consistency enforcement
# ---------------------------------------------------------------------------

def _count_leaves(node: AttackTreeNode) -> int:
    """Count leaf nodes in an attack tree rooted at *node*."""
    if node.gate == GateType.LEAF:
        return 1
    total = 0
    if node.children:
        for child in node.children:
            total += _count_leaves(child)
    return total


def _check_consistency(
    tree: AttackTree,
    narrative: NarrativeLayer,
    parsimony_budget: int,
    step_node_floor: float = _STEP_NODE_CORRESPONDENCE_FLOOR,
) -> list[str]:
    """Run post-generation consistency checks on the attack tree.

    Returns a list of violation descriptions (empty if all checks pass).
    Checks:
      1. Parsimony — leaf count must not exceed budget.
      2. Zone-sequence — every narrative zone must appear in the tree.
      3. Step-node correspondence — ratio must meet the floor.
    """
    violations: list[str] = []

    # Check 1: parsimony
    leaf_count = _count_leaves(tree.root)
    if leaf_count > parsimony_budget:
        violations.append(
            f"parsimony: {leaf_count} leaves > {parsimony_budget} budget"
        )

    # Check 2: zone-sequence consistency
    narrative_zones = set(narrative.zone_sequence)
    tree_zones = _collect_zones_from_tree(tree.root)
    missing_zones = narrative_zones - tree_zones
    if missing_zones:
        violations.append(
            f"zone-sequence: zones {missing_zones} in narrative but not tree"
        )

    # Check 3: step-node correspondence
    step_count = len(narrative.steps)
    if leaf_count > 0 and step_count > 0:
        correspondence = min(step_count, leaf_count) / max(
            step_count, leaf_count
        )
        if correspondence < step_node_floor:
            violations.append(
                f"step-node: {correspondence:.2f} < {step_node_floor} floor"
            )
    elif step_count == 0:
        # No steps — cannot compute, not a violation
        pass
    elif leaf_count == 0:
        violations.append("step-node: 0 leaves in tree")

    return violations
