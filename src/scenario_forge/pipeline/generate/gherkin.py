"""Call 3: Behavior Spec (Gherkin) generation logic.

Action-aware Gherkin projection (cmps.9):
- ``external_precondition`` → Given / Background
- ``initial_ingress`` and attack actions (ai_system_action, tool_invocation,
  integration_interaction) → When / And
- ``impact`` → Then (projected before the LLM assertion block)
- Human labels remain display text only; the action discriminator
  determines step kind, not label text.

422o.4: Call 3 returns a structured response keyed by exact projected
step/postcondition IDs.  The structured response is validated against the
projection and Gherkin is rendered from the accepted structure.  The LLM
output is never silently replaced.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from scenario_forge.data.atlas import ATLAS_TECHNIQUE_NAMES
from scenario_forge.llm.client import LLMClient, LLMResult
from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import CapabilityProfile
from scenario_forge.models.realization import ProjectedStepRealization
from scenario_forge.models.scenario import (
    BehaviorAction,
    BehaviorAssertion,
    BehaviorSpec,
    NarrativeLayer,
)
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


# ---------------------------------------------------------------------------#
# Structured Call 3 response model (422o.4)
# ---------------------------------------------------------------------------#


class Call3Action(BaseModel):
    """A structured behavior action from Call 3, keyed by projected step IDs."""

    action_id: str = Field(min_length=1)
    projected_step_ids: tuple[str, ...] = Field(min_length=1)
    source_leaf_id: str = Field(pattern=r"^n\d+(\.\d+){0,4}$")
    gherkin_keyword: Literal["Given", "When", "Then"]
    text: str = Field(min_length=1)
    # 422o.4 blocker #3: per-step canonical realization records.
    realizations: tuple[ProjectedStepRealization, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_realization_ids(self) -> Call3Action:
        """Exactly one realization per projected_step_id, no duplicates."""
        realization_ids = [r.projected_step_id for r in self.realizations]
        if len(set(realization_ids)) != len(realization_ids):
            raise ValueError(
                f"Call3Action {self.action_id} has duplicate realization "
                f"records (same projected_step_id appears more than once)"
            )
        if len(realization_ids) != len(self.projected_step_ids):
            raise ValueError(
                f"Call3Action {self.action_id} has {len(realization_ids)} "
                f"realization records but {len(self.projected_step_ids)} "
                f"projected_step_ids — exactly one per ID required"
            )
        if set(realization_ids) != set(self.projected_step_ids):
            raise ValueError(
                f"Call3Action {self.action_id} realization IDs "
                f"{set(realization_ids)} do not match projected_step_ids "
                f"{set(self.projected_step_ids)}"
            )
        return self


class Call3Assertion(BaseModel):
    """A structured behavior assertion from Call 3, keyed by postcondition IDs."""

    assertion_id: str = Field(min_length=1)
    source_step_ids: tuple[str, ...] = Field(min_length=1)
    projected_postcondition_ids: tuple[str, ...] = Field(min_length=1)
    text: str = Field(min_length=1)


class Call3Response(BaseModel):
    """Structured response from Call 3, validated against the projection."""

    actions: list[Call3Action] = Field(min_length=1)
    assertions: list[Call3Assertion] = Field(default_factory=list)


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


def _format_leaf_step_text(
    leaf: AttackTreeNode,
    profile: CapabilityProfile | None = None,
) -> str:
    """Build the display text for a leaf node's Gherkin step.

    Labels are display prose only.  The technique ID is appended if present.
    For typed initial-ingress actions, the display name and zone must come
    from the resolved canonical entry-point ID — never from the leaf label.
    If the ID cannot be resolved and a profile is supplied, this is a fatal
    error (unknown IDs are never silently replaced by prose).
    """
    step_text = leaf.label
    step_zone = leaf.zone

    if (
        leaf.action is not None
        and leaf.action.kind == "initial_ingress"
        and profile is not None
    ):
        entry_point = next(
            (
                candidate
                for candidate in profile.entry_points
                if candidate.entry_point_id == leaf.action.entry_point_id
            ),
            None,
        )
        if entry_point is None:
            raise ValueError(
                f"initial_ingress action references unresolved entry_point_id "
                f"'{leaf.action.entry_point_id}'. Cannot derive display name "
                f"from prose — the ID must resolve to a canonical entry point."
            )
        step_text = entry_point.name
        step_zone = entry_point.effective_ingress_zone

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
    if step_zone is not None:
        step_text += f" ({step_zone})"
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
    - shared ``external_precondition`` leaves → Background Given steps
    - branch-only ``external_precondition`` leaves → Scenario Given steps
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

    # --- Collect leaf nodes for zone scoping ---
    leaf_nodes = _collect_leaf_nodes_dfs(attack_tree.root)
    tree_zones = {leaf.zone for leaf in leaf_nodes if leaf.zone is not None}

    # --- Enumerate attack paths (OR-gate aware) ---
    paths = _enumerate_paths(attack_tree.root)

    # Compute shared preconditions across the complete path set, before any
    # rendering cap is applied.
    precondition_ids_by_path = [
        {leaf.id for leaf in path if _leaf_step_kind(leaf) == _STEP_KIND_GIVEN}
        for path in paths
    ]
    background_precondition_ids = (
        set.intersection(*precondition_ids_by_path)
        if precondition_ids_by_path
        else set()
    )

    if len(paths) > MAX_OR_PATHS:
        logger.warning(
            "Attack tree produces %d paths (OR-gate cross-product), capping at %d",
            len(paths),
            MAX_OR_PATHS,
        )
        paths = paths[:MAX_OR_PATHS]

    # Only external preconditions common to every attack path belong in the
    # Background. Branch-only preconditions remain in their Scenario blocks.
    background_preconditions = [
        leaf
        for leaf in leaf_nodes
        if leaf.id in background_precondition_ids
        and _leaf_step_kind(leaf) == _STEP_KIND_GIVEN
    ]

    # --- Background: preconditions ---
    lines.append("  Background: Preconditions")

    for i, prec_leaf in enumerate(background_preconditions):
        prec_text = _format_leaf_step_text(prec_leaf, profile)
        keyword = "Given" if i == 0 else "And"
        lines.append(f"    {keyword} {prec_text}")
    background_step_added = bool(background_preconditions)

    # Additional zone/capability preconditions — scoped to zones
    # actually present in the tree's leaf nodes, not the full profile
    from scenario_forge.models.capability_profile import ZONE_DISPLAY_NAMES

    for zone in profile.zones_active:
        if zone not in tree_zones:
            continue  # zone not used in this scenario's tree

        display_name = ZONE_DISPLAY_NAMES.get(zone, zone)
        keyword = "And" if background_step_added else "Given"
        lines.append(
            f"    {keyword} the system has {display_name} capabilities ({zone})"
        )
        background_step_added = True
    lines.append("")

    multi_path = len(paths) > 1

    for path_idx, path_leaves in enumerate(paths, 1):
        # --- Separate leaves by step kind ---
        scenario_preconditions: list[AttackTreeNode] = []
        when_leaves: list[AttackTreeNode] = []
        then_leaves: list[AttackTreeNode] = []
        for leaf in path_leaves:
            kind = _leaf_step_kind(leaf)
            if kind == _STEP_KIND_GIVEN:
                if leaf.id not in background_precondition_ids:
                    scenario_preconditions.append(leaf)
            elif kind == _STEP_KIND_THEN:
                then_leaves.append(leaf)
            else:
                when_leaves.append(leaf)

        # Initial ingress is always the first attack action, independent of
        # incidental tree traversal order.
        when_leaves.sort(
            key=lambda leaf: (
                leaf.action is None or leaf.action.kind != "initial_ingress"
            )
        )

        # --- Scenario header ---
        if multi_path:
            lines.append(f"  Scenario: {narrative.title} (Path {path_idx})")
        else:
            lines.append(f"  Scenario: {narrative.title}")
        lines.append("    Given the system is in its normal operating state")

        for prec_leaf in scenario_preconditions:
            prec_text = _format_leaf_step_text(prec_leaf, profile)
            lines.append(f"    And {prec_text}")
        lines.append("")

        # --- Attack steps (When/And) from action leaves ---
        for i, leaf in enumerate(when_leaves):
            step_text = _format_leaf_step_text(leaf, profile)
            keyword = "When" if i == 0 else "And"
            lines.append(f"    {keyword} {step_text}")

        # --- Impact steps (Then) from impact leaves ---
        for leaf in then_leaves:
            step_text = _format_leaf_step_text(leaf, profile)
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
    projection_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build prompt template variables for Call 3 (Behavior Spec).

    Pure data-preparation function that constructs all template variables
    needed by ``call3_user.j2``.  No LLM calls.

    422o.4: Provides a leaf catalog (leaf_id, projected step IDs, action
    kind, zone, eligible Gherkin keyword) and a postcondition ownership
    table (postcondition ID, owning step ID, semantics) so the LLM can
    emit a structured Call3Response keyed by exact projected IDs.

    Returns:
        Dict mapping template variable names to their values.
    """
    # Collect defensive control points from attack tree nodes
    control_points = _collect_control_points(attack_tree.root)

    # Build leaf catalog from actual tree leaves.
    leaf_catalog: list[dict[str, Any]] = []
    for leaf in _collect_leaf_nodes_dfs(attack_tree.root):
        step_kind = _leaf_step_kind(leaf)
        eligible = (
            "Given"
            if step_kind == _STEP_KIND_GIVEN
            else "Then"
            if step_kind == _STEP_KIND_THEN
            else "When"
        )
        action_kind = leaf.action.kind if leaf.action else "unknown"
        leaf_entry: dict[str, Any] = {
            "leaf_id": leaf.id,
            "projected_step_ids": list(leaf.projected_step_ids),
            "action_kind": action_kind,
            "zone": leaf.zone,
            "eligible_keyword": eligible,
        }
        # Enrich with full per-step canonical semantics from projection
        # context so the LLM can emit complete realization records.
        if projection_context:
            step_semantics = {}
            for sd in projection_context.get("selected_steps", []):
                step_semantics[sd["step_id"]] = sd
            leaf_step_data = []
            for sid in leaf.projected_step_ids:
                sd = step_semantics.get(sid)
                if sd:
                    # Use the nested canonical realization record directly.
                    realization = sd.get("realization", {})
                    leaf_step_data.append(
                        {
                            "step_id": sid,
                            "action_kind": realization.get("action_kind", ""),
                            "executor_role": realization.get("executor_role", ""),
                            "boundary_position": realization.get(
                                "boundary_position", ""
                            ),
                            "consumed_ref_ids": realization.get("consumed_ref_ids", []),
                            "produced_ref_ids": realization.get("produced_ref_ids", []),
                            "produced_effect_ids": realization.get(
                                "produced_effect_ids", []
                            ),
                            "outcome_link_pc_ids": realization.get(
                                "outcome_link_pc_ids", []
                            ),
                            "postcondition_ids": realization.get(
                                "postcondition_ids", []
                            ),
                            "resource_ref_ids": realization.get("resource_ref_ids", []),
                        }
                    )
            leaf_entry["step_semantics"] = leaf_step_data
        leaf_catalog.append(leaf_entry)

    # Build postcondition ownership table from projection context.
    postcondition_ownership: list[dict[str, Any]] = []
    if projection_context:
        for step_data in projection_context.get("selected_steps", []):
            for pc in step_data.get("observable_postconditions", []):
                postcondition_ownership.append(
                    {
                        "postcondition_id": pc["postcondition_id"],
                        "owning_step_id": step_data["step_id"],
                        "description": pc["description"],
                        "security_relevant": pc["security_relevant"],
                        "terminal": pc["terminal"],
                    }
                )

    return {
        "narrative": narrative,
        "seed": seed,
        "control_points": control_points,
        "projection_context": projection_context,
        "leaf_catalog": leaf_catalog,
        "postcondition_ownership": postcondition_ownership,
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
    projection_context: dict[str, Any] | None = None,
) -> tuple[BehaviorSpec, LLMResult]:
    """Generate a structured behavior spec for a scenario seed (Call 3).

    422o.4: The LLM returns a structured Call3Response keyed by exact
    projected step/postcondition IDs.  The response is validated against
    the projection context and the attack tree, then Gherkin is rendered
    from the accepted structure.  The LLM output is never silently
    replaced — if the structured response does not match the projection,
    a ValueError is raised.

    Returns:
        Tuple of (BehaviorSpec, LLMResult).
    """
    ctx = build_call3_context(
        seed=seed,
        narrative=narrative,
        attack_tree=attack_tree,
        profile=profile,
        scenario_tag=scenario_tag,
        projection_context=projection_context,
    )

    result = client.complete(
        system_prompt=render_prompt("call3_system.j2"),
        user_prompt=render_prompt("call3_user.j2", **ctx),
        response_format=Call3Response,
    )

    call3_response: Call3Response = result.content

    # Validate the structured response against the projection and tree.
    _validate_call3_response(call3_response, attack_tree, projection_context)

    # Convert validated Call3Response into BehaviorSpec.
    behavior_spec = _call3_response_to_behavior_spec(call3_response, attack_tree, ctx)

    return behavior_spec, result


def _validate_call3_response(
    response: Call3Response,
    attack_tree: AttackTree,
    projection_context: dict[str, Any] | None,
) -> None:
    """Validate a Call3Response against the projection and attack tree.

    422o.4 blocker #3: Validates exact ownership, not just global membership.
    - action.projected_step_ids must exactly equal source leaf's projected_step_ids
    - one action per required mapped leaf (every leaf with non-empty projected_step_ids)
    - unique source_leaf_id
    - deterministic action ID (ba-<leaf_id>)
    - exact eligible keyword
    - complete exact realization equality (unconditional)
    - assertion deterministic IDs
    - every postcondition owned by its stated source steps
    - full security-relevant postcondition coverage
    - reject action sourcing an empty/unmapped external leaf
    """
    if projection_context is None:
        raise ValueError("Call 3 requires projection context (422o.4)")

    selected_step_ids = set(projection_context.get("selected_step_ids", []))
    all_leaves = _collect_leaf_nodes_dfs(attack_tree.root)
    leaf_by_id = {leaf.id: leaf for leaf in all_leaves}
    valid_leaf_ids = set(leaf_by_id)

    # Build postcondition ownership: pc_id → owning step_id
    pc_ownership: dict[str, str] = {}
    security_relevant_pcs: set[str] = set()
    for step_data in projection_context.get("selected_steps", []):
        sid = step_data["step_id"]
        for pc in step_data.get("observable_postconditions", []):
            pc_ownership[pc["postcondition_id"]] = sid
            if pc.get("security_relevant"):
                security_relevant_pcs.add(pc["postcondition_id"])

    # Build eligible keyword map from tree leaf action kinds directly
    eligible_keywords: dict[str, str] = {}
    for leaf in all_leaves:
        step_kind = _leaf_step_kind(leaf)
        eligible_keywords[leaf.id] = (
            "Given"
            if step_kind == _STEP_KIND_GIVEN
            else "Then"
            if step_kind == _STEP_KIND_THEN
            else "When"
        )

    # Build step data lookup for realization equality checking (422o.4)
    step_by_id = {
        sd["step_id"]: sd for sd in projection_context.get("selected_steps", [])
    }

    # --- Action validation ---
    action_ids: set[str] = set()
    seen_source_leaf_ids: set[str] = set()
    covered_steps: set[str] = set()
    required_mapped_leaves = {leaf.id for leaf in all_leaves if leaf.projected_step_ids}

    for action in response.actions:
        if action.action_id in action_ids:
            raise ValueError(
                f"Duplicate behavior action ID '{action.action_id}' in Call 3 response"
            )
        action_ids.add(action.action_id)

        # Deterministic action ID: ba-<leaf_id>
        expected_id = f"ba-{action.source_leaf_id}"
        if action.action_id != expected_id:
            raise ValueError(
                f"Behavior action ID '{action.action_id}' does not match "
                f"deterministic expected ID '{expected_id}' (ba-<leaf_id>)"
            )

        if action.source_leaf_id not in valid_leaf_ids:
            raise ValueError(
                f"Behavior action '{action.action_id}' references "
                f"nonexistent tree leaf '{action.source_leaf_id}'"
            )

        # Reject action sourcing an empty/unmapped external leaf
        leaf = leaf_by_id[action.source_leaf_id]
        if not leaf.projected_step_ids:
            raise ValueError(
                f"Behavior action '{action.action_id}' sources leaf "
                f"'{action.source_leaf_id}' which has no projected_step_ids "
                f"(external/unmapped leaf — cannot source behavior actions)"
            )

        # Unique source_leaf_id
        if action.source_leaf_id in seen_source_leaf_ids:
            raise ValueError(
                f"Behavior action '{action.action_id}' reuses source_leaf_id "
                f"'{action.source_leaf_id}' — each leaf must have exactly one action"
            )
        seen_source_leaf_ids.add(action.source_leaf_id)

        # Duplicate realization records (defense in depth — model validator
        # also catches this, but model_copy can bypass it).
        realization_ids = [r.projected_step_id for r in action.realizations]
        if len(set(realization_ids)) != len(realization_ids):
            raise ValueError(
                f"Behavior action '{action.action_id}' has duplicate "
                f"realization records (same projected_step_id appears "
                f"more than once)"
            )

        # Exact projected_step_ids match: action IDs must equal leaf IDs
        # as ordered tuples (reversal must fail).
        if tuple(action.projected_step_ids) != tuple(leaf.projected_step_ids):
            raise ValueError(
                f"Behavior action '{action.action_id}' projected_step_ids "
                f"{list(action.projected_step_ids)} do not exactly match "
                f"source leaf '{action.source_leaf_id}' projected_step_ids "
                f"{list(leaf.projected_step_ids)}"
            )

        for sid in action.projected_step_ids:
            if sid not in selected_step_ids:
                raise ValueError(
                    f"Behavior action '{action.action_id}' references "
                    f"unprojected step '{sid}'"
                )
            covered_steps.add(sid)

        # Exact eligible keyword
        expected_kw = eligible_keywords.get(action.source_leaf_id)
        if expected_kw and action.gherkin_keyword != expected_kw:
            raise ValueError(
                f"Behavior action '{action.action_id}' keyword "
                f"'{action.gherkin_keyword}' does not match eligible "
                f"keyword '{expected_kw}' for leaf '{action.source_leaf_id}'"
            )

        # Complete exact realization equality (422o.4 blocker #3)
        for r in action.realizations:
            sd = step_by_id.get(r.projected_step_id)
            if sd is None:
                raise ValueError(
                    f"Behavior action '{action.action_id}' realization "
                    f"for step '{r.projected_step_id}' not found in "
                    f"projection context"
                )
            # Reconstruct canonical realization from the nested context
            # field using model_validate — no manual field-by-field.
            expected_r = ProjectedStepRealization.model_validate(sd["realization"])
            if r != expected_r:
                raise ValueError(
                    f"Behavior action '{action.action_id}' realization "
                    f"for step '{r.projected_step_id}' does not match "
                    f"canonical projection context: "
                    f"got action_kind={r.action_kind}, "
                    f"expected={expected_r.action_kind}; "
                    f"got resource_ref_ids={r.resource_ref_ids}, "
                    f"expected={expected_r.resource_ref_ids}; "
                    f"got produced_ref_ids={r.produced_ref_ids}, "
                    f"expected={expected_r.produced_ref_ids}"
                )

    # One action per required mapped leaf
    missing_leaves = required_mapped_leaves - seen_source_leaf_ids
    if missing_leaves:
        raise ValueError(
            f"Call 3 response does not provide actions for mapped leaves: "
            f"{sorted(missing_leaves)}"
        )

    # Full step coverage
    uncovered = selected_step_ids - covered_steps
    if uncovered:
        raise ValueError(
            f"Call 3 response does not cover projected steps: {sorted(uncovered)}"
        )

    # --- Assertion validation ---
    # Contract: one assertion per (owning step, postcondition) pair.
    # - assertion_id == "assert-{source_step_id}-{postcondition_id}"
    # - source_step_ids is a single-element tuple containing the owner
    # - projected_postcondition_ids is a single-element tuple
    # - No unrelated extra source steps (exact ownership, not membership)
    assertion_ids: set[str] = set()
    covered_security_pcs: set[str] = set()
    seen_assertion_pairs: set[tuple[str, str]] = set()
    for assertion in response.assertions:
        if assertion.assertion_id in assertion_ids:
            raise ValueError(
                f"Duplicate assertion ID '{assertion.assertion_id}' in Call 3 response"
            )
        assertion_ids.add(assertion.assertion_id)

        # Exactly one source step and one postcondition per assertion.
        if len(assertion.source_step_ids) != 1:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' has "
                f"{len(assertion.source_step_ids)} source_step_ids — "
                f"exactly one (the owning step) is required"
            )
        if len(assertion.projected_postcondition_ids) != 1:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' has "
                f"{len(assertion.projected_postcondition_ids)} "
                f"projected_postcondition_ids — exactly one per assertion "
                f"is required (one assertion per owning-step/postcondition pair)"
            )

        source_step = assertion.source_step_ids[0]
        pc_id = assertion.projected_postcondition_ids[0]

        if source_step not in selected_step_ids:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' references "
                f"unprojected source step '{source_step}'"
            )

        if pc_id not in pc_ownership:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' references "
                f"unknown postcondition '{pc_id}'"
            )

        # Exact ownership: source_step must be THE owner, not just a member.
        owning_step = pc_ownership[pc_id]
        if source_step != owning_step:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' states source step "
                f"'{source_step}' but postcondition '{pc_id}' is owned by "
                f"step '{owning_step}' — source_step_ids must exactly equal "
                f"the postcondition owner, not merely contain it"
            )

        # Deterministic assertion ID: assert-<owner_step>-<postcondition>
        expected_assertion_id = f"assert-{owning_step}-{pc_id}"
        if assertion.assertion_id != expected_assertion_id:
            raise ValueError(
                f"Assertion ID '{assertion.assertion_id}' does not match "
                f"deterministic expected ID '{expected_assertion_id}' "
                f"(assert-<owning_step_id>-<postcondition_id>)"
            )

        # No duplicate (step, postcondition) pairs.
        pair = (owning_step, pc_id)
        if pair in seen_assertion_pairs:
            raise ValueError(
                f"Assertion '{assertion.assertion_id}' duplicates the "
                f"(step, postcondition) pair ({owning_step}, {pc_id}) "
                f"already covered by another assertion"
            )
        seen_assertion_pairs.add(pair)

        if pc_id in security_relevant_pcs:
            covered_security_pcs.add(pc_id)

    # Full security-relevant postcondition coverage
    uncovered_security_pcs = security_relevant_pcs - covered_security_pcs
    if uncovered_security_pcs:
        raise ValueError(
            f"Call 3 response does not cover security-relevant "
            f"postconditions: {sorted(uncovered_security_pcs)}"
        )


def _call3_response_to_behavior_spec(
    response: Call3Response,
    attack_tree: AttackTree,
    ctx: dict[str, Any],
) -> BehaviorSpec:
    """Convert a validated Call3Response into a BehaviorSpec.

    Gherkin is deterministically rendered from the structured actions and
    assertions — not from an independently authored LLM text output.
    """
    actions = tuple(
        BehaviorAction(
            action_id=a.action_id,
            projected_step_ids=a.projected_step_ids,
            source_leaf_id=a.source_leaf_id,
            gherkin_keyword=a.gherkin_keyword,
            text=a.text,
            realizations=a.realizations,
        )
        for a in response.actions
    )
    assertions = tuple(
        BehaviorAssertion(
            assertion_id=a.assertion_id,
            source_step_ids=a.source_step_ids,
            projected_postcondition_ids=a.projected_postcondition_ids,
            gherkin_keyword="Then",
            text=a.text,
        )
        for a in response.assertions
    )

    # Build zone map from tree leaves for Gherkin zone annotations.
    zone_map: dict[str, str] = {}
    for leaf in _collect_leaf_nodes_dfs(attack_tree.root):
        if leaf.zone is not None:
            for action in response.actions:
                if action.source_leaf_id == leaf.id:
                    zone_map[action.action_id] = leaf.zone

    from scenario_forge.pipeline.generate.assembly import (
        render_gherkin_from_behavior_spec,
    )

    rendered = render_gherkin_from_behavior_spec(
        list(actions), list(assertions), zone_map=zone_map
    )

    return BehaviorSpec(
        actions=actions,
        assertions=assertions,
        gherkin_text=rendered,
    )
