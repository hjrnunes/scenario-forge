"""Standalone projection traceability validation for ScenarioEnvelope.

Validates that every generated artifact (narrative, attack tree, behavior
spec) is completely and faithfully traced to the deeply immutable canonical
projection persisted on the envelope (bead ``scenario-forge-422o.4``).

This module defines the **violations and validation**, not the final
retry/quarantine state machine (deferred to cmps.5).  It exposes typed
validation inputs and results that cmps.5 will consume.

Checks performed:

1. **Projection integrity** — the embedded :class:`ProjectionSnapshot` is
   self-validating (digest-verified).  When authoritative source inputs
   are supplied, the projection and execution requirements are recomputed
   and compared to detect drift or nested mutation.

2. **Coverage** — every selected projected step is covered by narrative
   actions, attack-tree leaves, and behavior actions.

3. **Order preservation** — realization mappings preserve the total order
   of projected steps within each artifact stage.

4. **No unprojected steps** — no realization mapping or generated action
   claims a step ID absent from the projection.

5. **Resource binding correctness** — generated actions referencing
   canonical resources match the projection's resource bindings.

6. **Ingress identity** — the canonical initial ingress ID is consistent
   across the projection, envelope, actor, narrative, and attack tree.

7. **OR-tree prohibition** — authoritative scenario trees prohibit OR
   nodes in v1; AND decomposition represents one concrete execution only.

8. **Assertion mapping** — behavior assertions map to projected observable
   postconditions, not to setup steps.

9. **Forged opaque IDs** — generated content must not reference opaque IDs
   absent from the projection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scenario_forge.models.attack_pattern import (
    AttackPattern,
    EntryPointResourceReference,
    TaxonomyResolver,
    validate_attack_pattern,
)
from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from scenario_forge.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityResult,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)
from scenario_forge.pipeline.projection import (
    CapabilityFactSnapshot,
    _derive_execution_requirements,
    _fail_closed_if_no_requirements,
    _normalize_semantic_order,
    _pattern_pin,
    _projected_mappings,
)

if TYPE_CHECKING:
    from scenario_forge.models.scenario import ScenarioEnvelope


# ---------------------------------------------------------------------------#
# Public API
# ---------------------------------------------------------------------------#


def validate_projection_traceability(
    envelope: ScenarioEnvelope,
    *,
    authoritative_pattern: dict[str, Any] | None = None,
    taxonomy_resolver: TaxonomyResolver | None = None,
    capability_snapshot: CapabilityFactSnapshot | None = None,
    expected_catalog_pin: str | None = None,
) -> ProjectionTraceabilityResult:
    """Validate projection traceability on a scenario envelope.

    Standalone: does not require a taxonomy checkout when only the
    envelope's embedded projection is available.  When authoritative
    source inputs (``authoritative_pattern``, ``taxonomy_resolver``,
    ``capability_snapshot``, ``expected_catalog_pin``) are supplied, the
    projection and execution requirements are recomputed and compared to
    detect drift or nested mutation.

    Returns a :class:`ProjectionTraceabilityResult` with typed violations
    attributed to the earliest responsible generated stage.
    """
    violations: list[ProjectionTraceabilityViolation] = []

    block = envelope.projection
    if block is None:
        return ProjectionTraceabilityResult(valid=True, violations=[])

    # --- Check 1: projection integrity & drift (contract §2) ---
    violations.extend(
        _check_projection_drift(
            block,
            authoritative_pattern=authoritative_pattern,
            taxonomy_resolver=taxonomy_resolver,
            capability_snapshot=capability_snapshot,
            expected_catalog_pin=expected_catalog_pin,
        )
    )

    # --- Check 6: ingress identity (contract §7) ---
    violations.extend(_check_ingress_identity(envelope, block))

    # --- Check 7: OR-tree prohibition (contract §6) ---
    violations.extend(_check_or_tree_prohibition(envelope, block))

    # --- Checks 2-5, 8-9: artifact realization coverage ---
    violations.extend(_check_narrative_realizations(envelope, block))
    violations.extend(_check_tree_realizations(envelope, block))
    violations.extend(_check_behavior_realizations(envelope, block))
    violations.extend(_check_assertion_realizations(envelope, block))

    # Deduplicate violations by (code, stage, element_id, projected_step_id).
    seen: set[tuple[str, str, str | None, str | None]] = set()
    unique: list[ProjectionTraceabilityViolation] = []
    for v in violations:
        key = (v.code.value, v.stage.value, v.element_id, v.projected_step_id)
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return ProjectionTraceabilityResult(
        valid=len(unique) == 0,
        violations=unique,
    )


# ---------------------------------------------------------------------------#
# Check 1: projection drift and nested mutation (contract §2)
# ---------------------------------------------------------------------------#


def _check_projection_drift(
    block: ProjectionEnvelopeBlock,
    *,
    authoritative_pattern: dict[str, Any] | None,
    taxonomy_resolver: TaxonomyResolver | None,
    capability_snapshot: CapabilityFactSnapshot | None,
    expected_catalog_pin: str | None,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []

    # The ProjectionSnapshot is self-validating on construction.  But we
    # must detect nested mutation of the *already-persisted* block.  We
    # re-validate the snapshot's digest by re-serializing and checking
    # against the stored projection_digest.
    try:
        from scenario_forge.models.attack_pattern import compute_projection_digest

        recomputed = compute_projection_digest(block.projection)
        if recomputed != block.projection.projection_digest:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.nested_mutation,
                    stage=ProjectionTraceabilityStage.actor_profile,
                    detail=(
                        "persisted projection_digest does not match recomputed "
                        "digest; the projection snapshot was mutated after capture"
                    ),
                )
            )
    except (TypeError, ValueError, AttributeError):
        # If recompute fails, the snapshot is structurally corrupt.
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.nested_mutation,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="projection snapshot re-serialization failed; "
                "structurally corrupt",
            )
        )

    # Recompute execution requirements digest.  Handle both model instances
    # and plain dicts (model_construct bypass may produce dicts for
    # discriminated-union fields).
    from scenario_forge.pipeline.projection import (
        compute_execution_requirements_digest,
    )

    expected_req_digest = compute_execution_requirements_digest(
        block.execution_requirements
    )
    if expected_req_digest != block.execution_requirements_digest:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    "execution_requirements_digest does not match recomputed "
                    "digest; requirements were mutated after derivation"
                ),
            )
        )

    # When authoritative source inputs are available, recompute and compare.
    if (
        authoritative_pattern is not None
        and taxonomy_resolver is not None
        and capability_snapshot is not None
        and expected_catalog_pin is not None
    ):
        violations.extend(
            _recompute_and_compare(
                block,
                authoritative_pattern,
                taxonomy_resolver,
                capability_snapshot,
                expected_catalog_pin,
            )
        )

    return violations


def _recompute_and_compare(
    block: ProjectionEnvelopeBlock,
    authoritative_pattern: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    capability_snapshot: CapabilityFactSnapshot,
    expected_catalog_pin: str,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []

    try:
        pattern = validate_attack_pattern(authoritative_pattern, taxonomy_resolver)
        pattern = AttackPattern.model_validate(
            _normalize_semantic_order(pattern.model_dump(mode="json"))
        )
    except (TypeError, ValueError) as exc:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=f"authoritative pattern qualification failed: {exc}",
            )
        )
        return violations

    chain = pattern.canonical_chain
    projection = block.projection

    # Compare source chain.
    if projection.source_chain != chain:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted source chain does not match authoritative pattern",
            )
        )
        return violations

    # Compare pins.
    pattern_pin = _pattern_pin(pattern)
    if projection.pattern_pin != pattern_pin:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted pattern_pin does not match authoritative pattern",
            )
        )
    if projection.catalog_pin != expected_catalog_pin:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted catalog_pin does not match trusted catalog",
            )
        )
    if (
        projection.capability_fact_snapshot_digest
        != capability_snapshot.snapshot_digest
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="persisted capability_fact_snapshot_digest does not match",
            )
        )

    # Recompute execution requirements from the projection.
    reqs, issue = _derive_execution_requirements(
        pattern.id, chain, projection, capability_snapshot
    )
    reqs, issue = _fail_closed_if_no_requirements(pattern.id, reqs, issue)
    if issue is not None:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=f"recomputation failed: {issue.detail}",
            )
        )
    elif reqs != block.execution_requirements:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.requirement_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="recomputed execution requirements do not match persisted",
            )
        )

    # Recompute projected mappings.
    expected_mappings = _projected_mappings(chain, projection.selected_step_ids)
    if expected_mappings != block.projected_mappings:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.projection_drift,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail="recomputed projected mappings do not match persisted",
            )
        )

    return violations


# ---------------------------------------------------------------------------#
# Check 6: ingress identity (contract §7)
# ---------------------------------------------------------------------------#


def _check_ingress_identity(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    expected = block.canonical_ingress.entry_point_id

    # Envelope-level initial_entry_point_id.
    if envelope.initial_entry_point_id != expected:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"envelope initial_entry_point_id "
                    f"'{envelope.initial_entry_point_id}' does not match "
                    f"projection canonical_ingress '{expected}'"
                ),
            )
        )

    # Actor access provenance.
    actor = envelope.actor_profile
    if (
        actor is not None
        and actor.access is not None
        and actor.access.initial_entry_point_id != expected
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                stage=ProjectionTraceabilityStage.actor_profile,
                detail=(
                    f"actor access initial_entry_point_id "
                    f"'{actor.access.initial_entry_point_id}' does not "
                    f"match projection canonical_ingress '{expected}'"
                ),
            )
        )

    # Narrative access realization.
    narrative = envelope.narrative
    if (
        narrative.access_realization is not None
        and narrative.access_realization.initial_entry_point_id != expected
    ):
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                stage=ProjectionTraceabilityStage.narrative,
                detail=(
                    f"narrative access_realization initial_entry_point_id "
                    f"'{narrative.access_realization.initial_entry_point_id}' "
                    f"does not match projection canonical_ingress '{expected}'"
                ),
                element_id=str(narrative.access_realization.responsible_step_number),
            )
        )

    # Attack tree initial_ingress leaves.
    tree = envelope.attack_tree
    if tree is not None:
        for leaf in _iter_leaves(tree.root):
            if (
                leaf.action is not None
                and isinstance(leaf.action, InitialIngressAction)
                and leaf.action.entry_point_id != expected
            ):
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.ingress_identity_mismatch,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' initial_ingress "
                            f"entry_point_id '{leaf.action.entry_point_id}' "
                            f"does not match projection canonical_ingress "
                            f"'{expected}'"
                        ),
                        element_id=leaf.id,
                    )
                )

    return violations


# ---------------------------------------------------------------------------#
# Check 7: OR-tree prohibition (contract §6)
# ---------------------------------------------------------------------------#


def _check_or_tree_prohibition(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    tree = envelope.attack_tree
    if tree is None:
        return violations

    for node in _iter_all_nodes(tree.root):
        if node.gate == GateType.OR:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.or_tree_prohibited,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"OR node '{node.id}' is prohibited in v1 "
                        "authoritative scenario trees; AND decomposition/"
                        "hierarchy represents one concrete execution only"
                    ),
                    element_id=node.id,
                )
            )

    return violations


# ---------------------------------------------------------------------------#
# Check 2-5: narrative realizations (contract §4, §5)
# ---------------------------------------------------------------------------#


def _check_narrative_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.narrative_realizations
    narrative = envelope.narrative
    selected = set(block.selected_step_ids)
    order = block.projected_step_order

    # Check element IDs reference actual narrative steps.
    valid_step_numbers = {str(s.step_number) for s in narrative.steps}
    for r in realizations:
        if r.artifact_stage != ArtifactStage.narrative:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative realization element '{r.element_id}' has "
                        f"wrong artifact_stage '{r.artifact_stage.value}'"
                    ),
                    element_id=r.element_id,
                )
            )
        if r.element_id not in valid_step_numbers:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.narrative,
                    detail=(
                        f"narrative realization references nonexistent "
                        f"step number '{r.element_id}'"
                    ),
                    element_id=r.element_id,
                )
            )

    # Check no unprojected steps claimed.
    violations.extend(
        _check_no_unprojected_steps(
            realizations, selected, ProjectionTraceabilityStage.narrative
        )
    )

    # Check complete coverage.
    violations.extend(
        _check_complete_coverage(
            realizations,
            selected,
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )
    )

    # Check order preservation.
    violations.extend(
        _check_order_preservation(
            realizations, order, ProjectionTraceabilityStage.narrative, "narrative"
        )
    )

    # Check duplicated steps across mappings.
    violations.extend(
        _check_no_duplicated_steps(
            realizations,
            block,
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )
    )

    return violations


# ---------------------------------------------------------------------------#
# Check 2-5: attack tree realizations (contract §4, §5)
# ---------------------------------------------------------------------------#


def _check_tree_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.tree_realizations
    tree = envelope.attack_tree
    if tree is None:
        # If there are realizations but no tree, that's a forged claim.
        if realizations:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail="tree realizations exist but attack_tree is absent",
                )
            )
        return violations

    selected = set(block.selected_step_ids)
    order = block.projected_step_order

    # Check element IDs reference actual tree leaves.
    valid_leaf_ids = {leaf.id for leaf in _iter_leaves(tree.root)}
    for r in realizations:
        if r.artifact_stage != ArtifactStage.attack_tree:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree realization element '{r.element_id}' has "
                        f"wrong artifact_stage '{r.artifact_stage.value}'"
                    ),
                    element_id=r.element_id,
                )
            )
        if r.element_id not in valid_leaf_ids:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"tree realization references nonexistent "
                        f"leaf node '{r.element_id}'"
                    ),
                    element_id=r.element_id,
                )
            )

    violations.extend(
        _check_no_unprojected_steps(
            realizations, selected, ProjectionTraceabilityStage.attack_tree
        )
    )
    violations.extend(
        _check_complete_coverage(
            realizations,
            selected,
            ProjectionTraceabilityStage.attack_tree,
            "attack_tree",
        )
    )
    violations.extend(
        _check_order_preservation(
            realizations, order, ProjectionTraceabilityStage.attack_tree, "attack_tree"
        )
    )
    violations.extend(
        _check_no_duplicated_steps(
            realizations,
            block,
            ProjectionTraceabilityStage.attack_tree,
            "attack_tree",
        )
    )

    # Check resource binding correctness: tree leaves with typed actions
    # referencing canonical resources must match projection bindings.
    violations.extend(_check_tree_resource_bindings(tree, block))

    # Every security-bearing tree leaf must map to ≥1 projected step.
    violations.extend(_check_security_actions_mapped(tree, realizations, block))

    return violations


def _check_tree_resource_bindings(
    tree: AttackTree,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Verify tree leaf resource references match projection bindings."""
    violations: list[ProjectionTraceabilityViolation] = []
    chain = block.projection.source_chain
    bindings_by_slot = {b.slot_id: b.resource_ref for b in block.projection.bindings}

    for leaf in _iter_leaves(tree.root):
        action = leaf.action
        if action is None:
            continue
        if isinstance(action, InitialIngressAction):
            # Checked by ingress identity — but also verify it matches the
            # ingress slot binding.
            ingress_binding = bindings_by_slot.get(chain.initial_ingress_slot_id)
            if (
                isinstance(ingress_binding, EntryPointResourceReference)
                and action.entry_point_id != ingress_binding.entry_point_id
            ):
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_ingress_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' initial_ingress "
                            f"entry_point_id does not match projection "
                            f"ingress binding"
                        ),
                        element_id=leaf.id,
                    )
                )
        elif isinstance(action, ToolInvocationAction):
            # The tool_id must match a tool slot binding.
            found = False
            for ref in bindings_by_slot.values():
                from scenario_forge.models.attack_pattern import (
                    ToolResourceReference,
                )

                if (
                    isinstance(ref, ToolResourceReference)
                    and ref.tool_id == action.tool_id
                ):
                    found = True
                    break
            if not found:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' tool_id does not match "
                            f"any projection tool binding"
                        ),
                        element_id=leaf.id,
                    )
                )
        elif isinstance(action, IntegrationInteractionAction):
            from scenario_forge.models.attack_pattern import (
                IntegrationResourceReference,
            )

            found = False
            for ref in bindings_by_slot.values():
                if (
                    isinstance(ref, IntegrationResourceReference)
                    and ref.integration_id == action.integration_id
                ):
                    found = True
                    break
            if not found:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.incorrect_resource_binding,
                        stage=ProjectionTraceabilityStage.attack_tree,
                        detail=(
                            f"tree leaf '{leaf.id}' integration_id does not "
                            f"match any projection integration binding"
                        ),
                        element_id=leaf.id,
                    )
                )

    return violations


def _check_security_actions_mapped(
    tree: AttackTree,
    realizations: tuple[ArtifactRealizationMapping, ...],
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Every security-bearing generated action maps to ≥1 projected step."""
    violations: list[ProjectionTraceabilityViolation] = []
    mapped_leaves = {r.element_id for r in realizations}

    for leaf in _iter_leaves(tree.root):
        # Security-bearing: attacker-controlled action kinds that are not
        # external_precondition.  In the projection, attacker-controlled
        # steps carry the security-relevant semantics.
        if leaf.action is None:
            continue
        kind = leaf.action.kind
        if kind == "external_precondition":
            continue
        # All attack-action leaves (initial_ingress, ai_system_action,
        # tool_invocation, integration_interaction, impact) are
        # security-bearing and must map to ≥1 projected step.
        if leaf.id not in mapped_leaves:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.unprojected_security_action,
                    stage=ProjectionTraceabilityStage.attack_tree,
                    detail=(
                        f"security-bearing tree leaf '{leaf.id}' (action "
                        f"kind '{kind}') is not mapped to any projected step"
                    ),
                    element_id=leaf.id,
                )
            )

    return violations


# ---------------------------------------------------------------------------#
# Check 2-5: behavior realizations (contract §4, §5)
# ---------------------------------------------------------------------------#


def _check_behavior_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    realizations = block.behavior_realizations
    selected = set(block.selected_step_ids)
    order = block.projected_step_order

    # Behavior spec is stored as opaque text (Gherkin).  We cannot
    # structurally verify element IDs without parsing the Gherkin, which
    # is beyond this bead's scope (no adapter registries).  We validate
    # the realization mappings themselves.
    for r in realizations:
        if r.artifact_stage != ArtifactStage.behavior:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                    stage=ProjectionTraceabilityStage.behavior_spec,
                    detail=(
                        f"behavior realization element '{r.element_id}' has "
                        f"wrong artifact_stage '{r.artifact_stage.value}'"
                    ),
                    element_id=r.element_id,
                )
            )

    violations.extend(
        _check_no_unprojected_steps(
            realizations, selected, ProjectionTraceabilityStage.behavior_spec
        )
    )
    violations.extend(
        _check_complete_coverage(
            realizations,
            selected,
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )
    )
    violations.extend(
        _check_order_preservation(
            realizations,
            order,
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )
    )
    violations.extend(
        _check_no_duplicated_steps(
            realizations,
            block,
            ProjectionTraceabilityStage.behavior_spec,
            "behavior",
        )
    )

    return violations


# ---------------------------------------------------------------------------#
# Check 8: assertion realizations (contract §4)
# ---------------------------------------------------------------------------#


def _check_assertion_realizations(
    envelope: ScenarioEnvelope,
    block: ProjectionEnvelopeBlock,
) -> list[ProjectionTraceabilityViolation]:
    """Assertions map to projected observable postconditions, not setup steps."""
    violations: list[ProjectionTraceabilityViolation] = []
    chain = block.projection.source_chain
    selected = set(block.selected_step_ids)

    # Build a lookup of postcondition_id → step_id for all selected steps.
    pc_to_step: dict[str, str] = {}
    for step in chain.steps:
        if step.step_id not in selected:
            continue
        for pc in step.observable_postconditions:
            pc_to_step[pc.postcondition_id] = step.step_id

    security_pcs = block.security_relevant_postconditions()
    all_security_pc_ids: set[str] = set()
    for pc_ids in security_pcs.values():
        all_security_pc_ids.update(pc_ids)

    for ar in block.assertion_realizations:
        # Check source step IDs are selected projected steps.
        for sid in ar.source_step_ids:
            if sid not in selected:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' references "
                            f"unprojected source step '{sid}'"
                        ),
                        element_id=ar.element_id,
                        projected_step_id=sid,
                    )
                )

        # Check postcondition IDs are resolvable in source steps.
        for pc_id in ar.projected_postcondition_ids:
            owning_step = pc_to_step.get(pc_id)
            if owning_step is None:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' references "
                            f"postcondition '{pc_id}' not found in any "
                            f"selected projected step"
                        ),
                        element_id=ar.element_id,
                        projected_step_id=pc_id,
                    )
                )
            elif owning_step not in ar.source_step_ids:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.postcondition_assertion_mismatch,
                        stage=ProjectionTraceabilityStage.behavior_spec,
                        detail=(
                            f"assertion '{ar.element_id}' claims postcondition "
                            f"'{pc_id}' from step '{owning_step}' but does not "
                            f"list that step in source_step_ids"
                        ),
                        element_id=ar.element_id,
                        projected_step_id=pc_id,
                    )
                )

    # Check that every security-relevant postcondition is asserted.
    asserted_pc_ids: set[str] = set()
    for ar in block.assertion_realizations:
        asserted_pc_ids.update(ar.projected_postcondition_ids)
    missing_security = all_security_pc_ids - asserted_pc_ids
    if missing_security:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                stage=ProjectionTraceabilityStage.behavior_spec,
                detail=(
                    f"security-relevant postconditions not covered by any "
                    f"assertion: {sorted(missing_security)}"
                ),
                projected_step_id=min(missing_security) if missing_security else None,
            )
        )

    return violations


# ---------------------------------------------------------------------------#
# Shared realization checks
# ---------------------------------------------------------------------------#


def _check_no_unprojected_steps(
    realizations: tuple[ArtifactRealizationMapping, ...],
    selected: set[str],
    stage: ProjectionTraceabilityStage,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    for r in realizations:
        for sid in r.projected_step_ids:
            if sid not in selected:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.forged_opaque_id,
                        stage=stage,
                        detail=(
                            f"realization element '{r.element_id}' claims "
                            f"unprojected step '{sid}'"
                        ),
                        element_id=r.element_id,
                        projected_step_id=sid,
                    )
                )
    return violations


def _check_complete_coverage(
    realizations: tuple[ArtifactRealizationMapping, ...],
    selected: set[str],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    violations: list[ProjectionTraceabilityViolation] = []
    covered: set[str] = set()
    for r in realizations:
        covered.update(r.projected_step_ids)
    omitted = selected - covered
    if omitted:
        violations.append(
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.incomplete_coverage,
                stage=stage,
                detail=(
                    f"projected steps not covered by {artifact_name} "
                    f"realizations: {sorted(omitted)}"
                ),
                projected_step_id=min(omitted) if omitted else None,
            )
        )
    return violations


def _check_order_preservation(
    realizations: tuple[ArtifactRealizationMapping, ...],
    order: dict[str, int],
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    """Verify realization element ordering preserves projected step total order.

    For each pair of mappings (A, B) where A precedes B in the realization
    tuple, the maximum ordinal of A's steps must not exceed the minimum
    ordinal of B's steps — unless they share steps (many-to-many overlap).
    Split/combine is allowed only while preserving total order.
    """
    violations: list[ProjectionTraceabilityViolation] = []
    # Sort realizations by their position in the tuple (artifact element order).
    # For each element, compute the min and max projected step ordinal.
    elements: list[tuple[str, int, int]] = []
    for r in realizations:
        ords = [order[sid] for sid in r.projected_step_ids if sid in order]
        if not ords:
            continue
        elements.append((r.element_id, min(ords), max(ords)))

    # Check that the element sequence is non-decreasing in min-ordinal.
    # A later element may not have a min-ordinal strictly less than an
    # earlier element's min-ordinal unless they share steps (split).
    for i in range(len(elements)):
        for j in range(i + 1, len(elements)):
            _, _, i_max = elements[i]
            j_id, j_min, _ = elements[j]
            # If j's min is before i's max AND they don't share any steps,
            # that's a reorder.  Sharing steps means split/combine, which
            # is allowed.
            r_i = realizations[i]
            r_j = realizations[j]
            shared = set(r_i.projected_step_ids) & set(r_j.projected_step_ids)
            if j_min < i_max and not shared:
                violations.append(
                    ProjectionTraceabilityViolation(
                        code=ProjectionTraceabilityViolationCode.reordered_projected_step,
                        stage=stage,
                        detail=(
                            f"{artifact_name} element '{j_id}' (min ordinal "
                            f"{j_min}) precedes earlier element "
                            f"'{r_i.element_id}' (max ordinal {i_max}) "
                            f"without shared steps — total order violated"
                        ),
                        element_id=j_id,
                    )
                )
                break  # one reorder per element is enough to flag

    return violations


def _check_no_duplicated_steps(
    realizations: tuple[ArtifactRealizationMapping, ...],
    block: ProjectionEnvelopeBlock,
    stage: ProjectionTraceabilityStage,
    artifact_name: str,
) -> list[ProjectionTraceabilityViolation]:
    """Check that no projected step is claimed by more than one element.

    Many-to-many split is allowed: one step MAY be realized by multiple
    elements.  But full **duplication** (same step claimed identically by
    two elements with identical mappings) is suspicious.  We flag only
    when the exact same projected_step_ids tuple appears in two mappings
    — that's a mechanical duplicate, not a semantic split.

    Actually, per contract §5, split/combine is allowed.  The prohibition
    is on *mechanical* duplication (the same element_id appearing twice,
    or identical mappings).  We check for duplicate element_ids.
    """
    violations: list[ProjectionTraceabilityViolation] = []
    seen_elements: set[str] = set()
    for r in realizations:
        if r.element_id in seen_elements:
            violations.append(
                ProjectionTraceabilityViolation(
                    code=ProjectionTraceabilityViolationCode.duplicated_projected_step,
                    stage=stage,
                    detail=(
                        f"{artifact_name} element '{r.element_id}' appears "
                        f"more than once in realizations"
                    ),
                    element_id=r.element_id,
                )
            )
        seen_elements.add(r.element_id)
    return violations


# ---------------------------------------------------------------------------#
# Tree traversal helpers
# ---------------------------------------------------------------------------#


def _iter_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all leaf nodes from an attack tree (DFS order)."""
    if node.gate == GateType.LEAF:
        return [node]
    if node.children:
        result: list[AttackTreeNode] = []
        for child in node.children:
            result.extend(_iter_leaves(child))
        return result
    return []


def _iter_all_nodes(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all nodes (internal + leaf) from an attack tree (DFS)."""
    result: list[AttackTreeNode] = [node]
    if node.children:
        for child in node.children:
            result.extend(_iter_all_nodes(child))
    return result
