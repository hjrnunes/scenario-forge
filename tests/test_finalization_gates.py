"""Focused Phase 3A snapshot and parsimony boundary tests."""

from __future__ import annotations

import copy
import math
import unicodedata
from dataclasses import replace

import pytest

from scenario_forge.models.attack_pattern import StepResourceLink
from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from scenario_forge.pipeline import finalization_gates
from scenario_forge.pipeline.coverage_planning import CoveragePlanEntry
from scenario_forge.pipeline.finalization import (
    GENERATION_ORDER,
    AdmissionDecision,
    CandidateFinalizationContext,
    CandidateValidation,
    FinalTreeSnapshot,
    GeneratedArtifacts,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    TargetFinalizationMachine,
    earliest_generated_owner,
)
from scenario_forge.pipeline.finalization_gates import (
    ActorSemanticSnapshot,
    FinalTreeSemanticSnapshot,
    GateCode,
    NarrativeSemanticSnapshot,
    ProjectionSemanticSnapshot,
    RepairRecord,
    TreeParsimonyResult,
    finalize_tree_parsimony,
    make_prebehavior_finalizer,
    run_prebehavior_gates,
)
from scenario_forge.pipeline.generate.assembly import _build_projection_block
from scenario_forge.pipeline.projection import canonical_json_bytes
from scenario_forge.pipeline.projection_validation import (
    _check_narrative_physical_order,
    _check_technique_mapping,
    _check_tree_physical_order,
    _check_tree_resource_bindings,
)
from scenario_forge.pipeline.validation import (
    check_scenario_semantics,
    validate_scenario_semantics,
)
from tests.helpers.projection_factory import (
    get_projected_candidate,
    get_test_profile,
    get_test_snapshot,
)
from tests.helpers.realization_helper import make_realizations
from tests.test_projection_traceability import (
    _make_envelope,
    _make_narrative,
    _make_tree,
)


def test_projection_snapshot_roundtrip_is_fresh_and_input_independent() -> None:
    candidate = get_projected_candidate()
    snapshot = ProjectionSemanticSnapshot.capture(candidate)

    snapshot.verify_digest()
    materialized = snapshot.materialize()

    assert materialized == candidate
    assert materialized is not candidate
    assert materialized.projection is not candidate.projection


def test_snapshot_rejects_tampered_canonical_bytes() -> None:
    snapshot = ProjectionSemanticSnapshot.capture(get_projected_candidate())
    tampered = replace(snapshot, canonical_bytes=snapshot.canonical_bytes + b" ")

    with pytest.raises(ValueError, match="canonical bytes"):
        tampered.verify_digest()


def test_snapshot_rejects_nested_model_drift() -> None:
    snapshot = ProjectionSemanticSnapshot.capture(get_projected_candidate())
    # Projection models are frozen at the top level, but nested collections
    # remain attackable through low-level mutation and must be detected.
    object.__setattr__(snapshot.model.projection.source_chain.steps[0], "order", 999)

    with pytest.raises(ValueError, match="model drifted"):
        snapshot.verify_digest()


def test_final_tree_snapshot_implements_runtime_protocol_and_returns_fresh_copies() -> (
    None
):
    _, _, _, tree = _valid_parts()
    snapshot = FinalTreeSemanticSnapshot.capture(tree)

    assert isinstance(snapshot, FinalTreeSnapshot)
    assert snapshot.tree == tree
    assert snapshot.tree is not snapshot.tree
    snapshot.verify_digest()


@pytest.mark.parametrize(
    ("snapshot_type", "model_index"),
    [
        (ActorSemanticSnapshot, 1),
        (NarrativeSemanticSnapshot, 2),
        (FinalTreeSemanticSnapshot, 3),
    ],
)
def test_snapshot_canonical_json_normalizes_unicode_nfc(
    snapshot_type, model_index
) -> None:
    _, actor, narrative, tree = _valid_parts()
    models = [None, actor, narrative, tree]
    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", nfc)
    if snapshot_type is ActorSemanticSnapshot:
        left = actor.model_copy(update={"beliefs": [nfc]})
        right = actor.model_copy(update={"beliefs": [nfd]})
    elif snapshot_type is NarrativeSemanticSnapshot:
        left = narrative.model_copy(update={"title": nfc})
        right = narrative.model_copy(update={"title": nfd})
    else:
        left = tree.model_copy(update={"goal": nfc})
        right = tree.model_copy(update={"goal": nfd})

    left_snapshot = snapshot_type.capture(left)
    right_snapshot = snapshot_type.capture(right)

    assert models[model_index] is not None
    assert left_snapshot.canonical_bytes == right_snapshot.canonical_bytes
    assert left_snapshot.digest == right_snapshot.digest


@pytest.mark.parametrize("kind", ["projection", "actor", "narrative", "tree"])
def test_all_semantic_snapshots_reject_non_finite_drift(kind: str) -> None:
    candidate, actor, narrative, tree = _valid_parts()
    if kind == "projection":
        snapshot = ProjectionSemanticSnapshot.capture(candidate)
        object.__setattr__(snapshot.model, "pattern_id", math.nan)
    elif kind == "actor":
        snapshot = ActorSemanticSnapshot.capture(actor)
        snapshot.model.beliefs[0] = math.nan
    elif kind == "narrative":
        snapshot = NarrativeSemanticSnapshot.capture(narrative)
        snapshot.model.steps[0].action = math.nan
    else:
        snapshot = FinalTreeSemanticSnapshot.capture(tree)
        snapshot.model.root.label = math.nan

    with (
        pytest.warns(UserWarning, match="Pydantic serializer warnings"),
        pytest.raises(ValueError, match="snapshot model drifted"),
    ):
        snapshot.verify_digest()


def test_public_canonical_encoder_rejects_nan() -> None:
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_json_bytes({"value": math.nan})


def _valid_parts():
    candidate = get_projected_candidate()
    ingress_id = candidate.canonical_ingress.entry_point_id
    envelope = _make_envelope(
        tree=_make_tree(ingress_id), narrative=_make_narrative(ingress_id)
    )
    return candidate, envelope.actor_profile, envelope.narrative, envelope.attack_tree


def _run(actor=None, narrative=None, tree=None):
    candidate, valid_actor, valid_narrative, valid_tree = _valid_parts()
    return run_prebehavior_gates(
        candidate,
        actor or valid_actor,
        narrative or valid_narrative,
        tree or valid_tree,
        get_test_snapshot(),
        get_test_profile(),
    )


def _block(narrative, tree):
    return _build_projection_block(
        get_projected_candidate(), narrative, tree, None, get_test_snapshot()
    )


def _replace_leaf(
    tree: AttackTree, leaf_id: str, replacement: AttackTreeNode
) -> AttackTree:
    def replace_node(node: AttackTreeNode) -> AttackTreeNode:
        if node.id == leaf_id:
            return replacement
        if node.children:
            return node.model_copy(
                update={"children": [replace_node(child) for child in node.children]}
            )
        return node

    return tree.model_copy(update={"root": replace_node(tree.root)})


def test_valid_prebehavior_artifacts_pass_without_mutation() -> None:
    candidate, actor, narrative, tree = _valid_parts()
    before = (
        candidate.model_dump(),
        actor.model_dump(),
        narrative.model_dump(),
        tree.model_dump(),
    )

    result = _run(actor, narrative, tree)

    assert result.passed
    assert before == (
        candidate.model_dump(),
        actor.model_dump(),
        narrative.model_dump(),
        tree.model_dump(),
    )


def test_extracted_legacy_single_envelope_check_is_pure() -> None:
    candidate, _, _, _ = _valid_parts()
    envelope = _make_envelope()
    before = envelope.model_dump(mode="json")

    semantic = check_scenario_semantics(envelope, get_test_profile())

    assert semantic is not None
    assert envelope.model_dump(mode="json") == before
    assert envelope.candidate_id == candidate.candidate_id


def test_legacy_batch_wrapper_matches_pure_check_without_artifact_mutation() -> None:
    envelope = _make_envelope()
    profile = get_test_profile()
    expected = check_scenario_semantics(envelope, profile)
    generated_fields = {"validation", "validation_passed"}
    artifact_before = envelope.model_dump(mode="json", exclude=generated_fields)

    validate_scenario_semantics([envelope], profile)

    assert envelope.validation.semantic == expected
    assert envelope.model_dump(mode="json", exclude=generated_fields) == artifact_before


def test_controlled_overlapping_realizations_are_not_rejected() -> None:
    _, _, narrative, _ = _valid_parts()
    first, second, _third = narrative.steps
    overlap = narrative.model_copy(
        update={
            "steps": [
                first.model_copy(
                    update={
                        "projected_step_ids": ("step.1", "step.2"),
                        "realizations": make_realizations(("step.1", "step.2")),
                    }
                ),
                second.model_copy(
                    update={
                        "projected_step_ids": ("step.2", "step.3"),
                        "realizations": make_realizations(("step.2", "step.3")),
                    }
                ),
            ]
        }
    )

    assert _run(narrative=overlap).valid


def test_narrative_order_rejects_reversed_ids_and_crossing_spans() -> None:
    _, _, narrative, tree = _valid_parts()
    first, second, _third = narrative.steps
    reversed_ids = narrative.model_copy(
        update={
            "steps": [
                first.model_copy(update={"projected_step_ids": ("step.2", "step.1")}),
                *narrative.steps[1:],
            ]
        }
    )
    assert _check_narrative_physical_order(reversed_ids, _block(reversed_ids, tree))

    crossing = narrative.model_copy(
        update={
            "steps": [
                first.model_copy(update={"projected_step_ids": ("step.1", "step.3")}),
                second.model_copy(update={"projected_step_ids": ("step.2", "step.3")}),
            ]
        }
    )
    assert _check_narrative_physical_order(crossing, _block(crossing, tree))


def test_tree_dfs_order_rejects_reversed_ids_and_crossing_spans() -> None:
    _, _, narrative, tree = _valid_parts()
    first, second, third = tree.root.children
    reversed_tree = tree.model_copy(
        update={
            "root": tree.root.model_copy(
                update={
                    "children": [
                        first.model_copy(
                            update={"projected_step_ids": ("step.2", "step.1")}
                        ),
                        second,
                        third,
                    ]
                }
            )
        }
    )
    assert _check_tree_physical_order(reversed_tree, _block(narrative, reversed_tree))

    crossing_tree = tree.model_copy(
        update={
            "root": tree.root.model_copy(
                update={
                    "children": [
                        first.model_copy(
                            update={"projected_step_ids": ("step.1", "step.3")}
                        ),
                        second.model_copy(
                            update={"projected_step_ids": ("step.2", "step.3")}
                        ),
                    ]
                }
            )
        }
    )
    assert _check_tree_physical_order(crossing_tree, _block(narrative, crossing_tree))


def test_duplicate_and_omitted_realizations_are_hard_failures() -> None:
    _, _, narrative, _ = _valid_parts()
    omitted = narrative.model_copy(update={"steps": narrative.steps[:-1]})
    assert any(
        v.code is GateCode.narrative_realization
        for v in _run(narrative=omitted).violations
    )

    duplicate = narrative.model_copy(
        update={
            "steps": [
                *narrative.steps[:-1],
                narrative.steps[-1].model_copy(
                    update={
                        "projected_step_ids": (
                            *narrative.steps[-1].projected_step_ids,
                            narrative.steps[-1].projected_step_ids[0],
                        )
                    }
                ),
            ]
        }
    )
    assert any(
        v.code is GateCode.narrative_realization
        for v in _run(narrative=duplicate).violations
    )


def test_capability_snapshot_nested_drift_is_projection_owned() -> None:
    candidate, actor, narrative, tree = _valid_parts()
    snapshot = copy.deepcopy(get_test_snapshot())
    snapshot.profile.zones_active.append("memory")

    result = run_prebehavior_gates(
        candidate, actor, narrative, tree, snapshot, snapshot.profile
    )

    assert not result.valid
    assert result.violations[0].code is GateCode.candidate_identity
    assert result.violations[0].owner is None


def test_aggregate_generated_violations_are_in_earliest_owner_order() -> None:
    _, actor, narrative, tree = _valid_parts()
    actor = actor.model_copy(
        update={
            "access": actor.access.model_copy(
                update={"initial_entry_point_id": "ep:v1:" + "f" * 32}
            )
        }
    )
    tree = tree.model_copy(
        update={"root": tree.root.model_copy(update={"gate": GateType.OR})}
    )

    result = _run(actor=actor, narrative=narrative, tree=tree)
    owners = [item.owner for item in result.violations]

    assert GeneratedStage.actor in owners
    assert GeneratedStage.narrative in owners
    assert GeneratedStage.tree in owners
    assert owners == sorted(owners, key=GENERATION_ORDER.index)
    assert (
        earliest_generated_owner(tuple(item.lifecycle() for item in result.violations))
        is GeneratedStage.actor
    )


def test_or_tree_and_empty_mapping_are_hard_tree_gates() -> None:
    _, _, _, tree = _valid_parts()
    or_tree = tree.model_copy(
        update={"root": tree.root.model_copy(update={"gate": GateType.OR})}
    )
    result = _run(tree=or_tree)
    assert any(v.code is GateCode.or_tree for v in result.violations)
    assert all(v.owner is GeneratedStage.tree for v in result.violations)

    leaf = tree.root.children[0]
    unmapped = leaf.model_copy(update={"projected_step_ids": (), "realizations": ()})
    result = _run(tree=_replace_leaf(tree, leaf.id, unmapped))
    assert any(v.code is GateCode.tree_realization for v in result.violations)


def test_phantom_resource_is_hard_but_zone_and_count_heuristics_are_diagnostic() -> (
    None
):
    _, _, narrative, tree = _valid_parts()
    leaf = tree.root.children[1]
    phantom = leaf.model_copy(
        update={
            "zone": "tool_execution",
            "action": ToolInvocationAction(tool_id="tool:v1:" + "f" * 32),
        }
    )
    result = _run(tree=_replace_leaf(tree, leaf.id, phantom))
    assert any(v.code is GateCode.canonical_identity for v in result.violations)

    changed_steps = [
        step.model_copy(update={"zone": "memory"}) if step.step_number == 2 else step
        for step in narrative.steps
    ]
    diagnostic_narrative = narrative.model_copy(
        update={"steps": changed_steps, "zone_sequence": ["input", "memory"]}
    )
    result = _run(narrative=diagnostic_narrative)
    assert result.valid
    assert {item.code for item in result.diagnostics} == {GateCode.zone_difference}


def _tool_and_integration_ids() -> tuple[str, str]:
    candidate = get_projected_candidate()
    tool_id = next(
        binding.resource_ref.tool_id
        for binding in candidate.projection.bindings
        if hasattr(binding.resource_ref, "tool_id")
    )
    integration_id = next(
        binding.resource_ref.integration_id
        for binding in candidate.projection.bindings
        if hasattr(binding.resource_ref, "integration_id")
    )
    return tool_id, integration_id


@pytest.mark.parametrize(
    "integration_id",
    ["int:v1:" + "f" * 32, None],
)
def test_tool_integration_must_be_projection_linked_not_merely_profile_valid(
    integration_id: str | None,
) -> None:
    _, _, narrative, tree = _valid_parts()
    tool_id, profile_integration_id = _tool_and_integration_ids()
    emitted_id = integration_id or profile_integration_id
    leaf = tree.root.children[1].model_copy(
        update={
            "zone": "tool_execution",
            "action": ToolInvocationAction(tool_id=tool_id, integration_id=emitted_id),
        }
    )
    changed = _replace_leaf(tree, leaf.id, leaf)

    violations = _check_tree_resource_bindings(changed, _block(narrative, changed))

    assert violations
    assert "not an integration binding linked" in violations[0].detail


def test_required_projected_integration_cannot_be_omitted() -> None:
    _, _, narrative, tree = _valid_parts()
    tool_id, _ = _tool_and_integration_ids()
    leaf = tree.root.children[1].model_copy(
        update={
            "zone": "tool_execution",
            "action": ToolInvocationAction(tool_id=tool_id),
        }
    )
    changed = _replace_leaf(tree, leaf.id, leaf)
    block = _block(narrative, changed)
    chain = block.projection.source_chain
    steps = list(chain.steps)
    steps[1] = steps[1].model_copy(
        update={
            "resource_links": (
                *steps[1].resource_links,
                StepResourceLink(
                    slot_id="source",
                    role="source_influence",
                    trust_boundary_slot_id="boundary",
                    target_ingress_slot_id="ingress",
                ),
            )
        }
    )
    changed_chain = chain.model_copy(update={"steps": tuple(steps)})
    changed_projection = block.projection.model_copy(
        update={"source_chain": changed_chain}
    )
    changed_block = block.model_copy(update={"projection": changed_projection})

    violations = _check_tree_resource_bindings(changed, changed_block)

    assert any("omits integration_id required" in item.detail for item in violations)


def _many_to_many_integration_violations(second_integration_id: str, action_type):
    _, _, narrative, tree = _valid_parts()
    tool_id, first_integration_id = _tool_and_integration_ids()
    block = _block(narrative, tree)
    chain = block.projection.source_chain
    steps = list(chain.steps)
    source_link = StepResourceLink(
        slot_id="source",
        role="source_influence",
        trust_boundary_slot_id="boundary",
        target_ingress_slot_id="ingress",
    )
    steps[0] = steps[0].model_copy(
        update={"resource_links": (*steps[0].resource_links, source_link)}
    )
    bindings = list(block.projection.bindings)
    resource_slots = list(chain.resource_slots)
    second_slot_id = "source"
    if second_integration_id != first_integration_id:
        source_binding = next(
            binding
            for binding in bindings
            if hasattr(binding.resource_ref, "integration_id")
        )
        second_slot_id = "source2"
        source_slot = next(slot for slot in resource_slots if slot.slot_id == "source")
        resource_slots.append(
            source_slot.model_copy(update={"slot_id": second_slot_id})
        )
        bindings.append(
            source_binding.model_copy(
                update={
                    "slot_id": second_slot_id,
                    "resource_ref": source_binding.resource_ref.model_copy(
                        update={"integration_id": second_integration_id}
                    ),
                }
            )
        )
    steps[1] = steps[1].model_copy(
        update={
            "resource_links": (
                *steps[1].resource_links,
                source_link.model_copy(update={"slot_id": second_slot_id}),
            )
        }
    )
    projection = block.projection.model_copy(
        update={
            "source_chain": chain.model_copy(
                update={
                    "steps": tuple(steps),
                    "resource_slots": tuple(resource_slots),
                }
            ),
            "bindings": tuple(bindings),
        }
    )
    changed_block = block.model_copy(update={"projection": projection})
    leaf = tree.root.children[1].model_copy(
        update={
            "projected_step_ids": ("step.1", "step.2"),
            "action": (
                ToolInvocationAction(
                    tool_id=tool_id, integration_id=first_integration_id
                )
                if action_type is ToolInvocationAction
                else IntegrationInteractionAction(integration_id=first_integration_id)
            ),
        }
    )
    changed_tree = _replace_leaf(tree, leaf.id, leaf)
    return _check_tree_resource_bindings(changed_tree, changed_block)


@pytest.mark.parametrize(
    "action_type", [ToolInvocationAction, IntegrationInteractionAction]
)
def test_many_to_many_action_rejects_distinct_step_integrations(action_type) -> None:
    violations = _many_to_many_integration_violations("int:v1:" + "e" * 32, action_type)

    assert len(violations) == 1
    assert "linked to every mapped projected step" in violations[0].detail


@pytest.mark.parametrize(
    "action_type", [ToolInvocationAction, IntegrationInteractionAction]
)
def test_many_to_many_action_accepts_same_step_integration(action_type) -> None:
    _, integration_id = _tool_and_integration_ids()

    assert not _many_to_many_integration_violations(integration_id, action_type)


def test_unprojected_connector_technique_is_rejected() -> None:
    _, _, narrative, tree = _valid_parts()
    changed = tree.model_copy(
        update={"root": tree.root.model_copy(update={"technique_id": "AML.T9999"})}
    )

    violations = _check_technique_mapping(changed, _block(narrative, changed))

    assert violations[0].element_id == "n1"


def _tree_with_required_preconditions() -> AttackTree:
    _, _, _, tree = _valid_parts()
    children = list(tree.root.children)
    for index in range(4, 7):
        children.append(
            AttackTreeNode(
                id=f"n1.{index}",
                label=f"Redundant setup {index}",
                gate=GateType.LEAF,
                action=ExternalPreconditionAction(
                    access_provenance=f"required-stage-{index}"
                ),
            )
        )
    return tree.model_copy(
        update={"root": tree.root.model_copy(update={"children": children})}
    )


def test_typed_external_preconditions_are_never_pruned() -> None:
    tree = _tree_with_required_preconditions()
    before = FinalTreeSemanticSnapshot.capture(tree)

    result = finalize_tree_parsimony(tree)

    assert result.violations[0].owner is GeneratedStage.tree
    assert result.record is not None and not result.record.accepted
    assert result.record.removed_ids == ()
    assert result.record.before_digest == result.record.after_digest == before.digest
    assert FinalTreeSemanticSnapshot.capture(result.tree).digest == before.digest
    assert FinalTreeSemanticSnapshot.capture(tree).digest == before.digest


def test_protected_over_budget_tree_is_rejected_and_returned_unchanged() -> None:
    tree = _tree_with_required_preconditions()
    before = FinalTreeSemanticSnapshot.capture(tree)

    result = finalize_tree_parsimony(tree, budget=5)

    assert result.violations[0].owner is GeneratedStage.tree
    assert result.record is not None and not result.record.accepted
    assert result.record.removed_ids == ()
    assert FinalTreeSemanticSnapshot.capture(result.tree).digest == before.digest
    assert FinalTreeSemanticSnapshot.capture(tree).digest == before.digest


def test_unique_required_and_branch_is_not_removed() -> None:
    _, _, _, tree = _valid_parts()
    connector = AttackTreeNode(
        id="n1.4",
        label="Redundant setup connector",
        gate=GateType.AND,
        children=[
            AttackTreeNode(
                id=f"n1.4.{index}",
                label=f"Redundant setup {index}",
                gate=GateType.LEAF,
                action=ExternalPreconditionAction(),
            )
            for index in (1, 2)
        ],
    )
    expanded = tree.model_copy(
        update={
            "root": tree.root.model_copy(
                update={"children": [*tree.root.children, connector]}
            )
        }
    )

    result = finalize_tree_parsimony(expanded, budget=4)

    assert result.violations
    assert result.record is not None and not result.record.accepted
    assert result.record.removed_ids == ()
    assert FinalTreeSemanticSnapshot.capture(result.tree).digest == (
        FinalTreeSemanticSnapshot.capture(expanded).digest
    )
    assert len(expanded.root.children) == 4


def test_finalizer_rejects_any_repair_that_lowers_complexity(monkeypatch) -> None:
    candidate, actor, narrative, tree = _valid_parts()
    external = AttackTreeNode(
        id="n1.4",
        label="Required staged access",
        gate=GateType.LEAF,
        action=ExternalPreconditionAction(access_provenance="staged-access"),
    )
    before_tree = tree.model_copy(
        update={
            "root": tree.root.model_copy(
                update={"children": [*tree.root.children, external]}
            )
        }
    )
    before_snapshot = FinalTreeSemanticSnapshot.capture(before_tree)
    after_snapshot = FinalTreeSemanticSnapshot.capture(tree)

    def fake_repair(_tree):
        return TreeParsimonyResult(
            tree,
            record=RepairRecord(
                before_snapshot.digest,
                after_snapshot.digest,
                ("n1.4",),
                ("step.1", "step.2", "step.3"),
                True,
                "unsafe test repair",
            ),
        )

    original_assess = finalization_gates.assess_final_complexity
    calls = 0

    def staged_assess(*args, **kwargs):
        nonlocal calls
        calls += 1
        assessment = original_assess(*args, **kwargs)
        if calls == 2 and assessment.final is not None:
            assessment = assessment.model_copy(
                update={
                    "final": assessment.final.model_copy(
                        update={"required_level": "advanced"}
                    )
                }
            )
        return assessment

    monkeypatch.setattr(finalization_gates, "finalize_tree_parsimony", fake_repair)
    monkeypatch.setattr(finalization_gates, "assess_final_complexity", staged_assess)
    port = make_prebehavior_finalizer(get_test_snapshot())
    context = CandidateFinalizationContext(
        candidate, ProjectionSemanticSnapshot.capture(candidate)
    )

    result = port(
        context,
        GeneratedArtifacts(actor=actor, narrative=narrative, tree=before_tree),
    )

    assert result.snapshot is None
    assert result.violations[0].code == GateCode.parsimony.value
    assert result.violations[0].owner is GeneratedStage.tree


class _Persistence:
    def record_transition(self, transition) -> None:
        pass

    def record_stage_result(self, invocation, result) -> None:
        pass

    def record_candidate_result(self, candidate_id, result) -> None:
        pass


def test_concrete_finalizer_fails_closed_without_verified_candidate_context() -> None:
    candidate, actor, narrative, tree = _valid_parts()
    result = make_prebehavior_finalizer(get_test_snapshot())(
        candidate,
        GeneratedArtifacts(actor=actor, narrative=narrative, tree=tree),
    )

    assert result.snapshot is None
    assert result.violations[0].code == GateCode.candidate_identity.value
    assert not result.violations[0].retryable


def test_candidate_mutated_after_revalidation_never_reaches_behavior() -> None:
    candidate, actor, narrative, tree = _valid_parts()
    candidate = copy.deepcopy(candidate)
    events: list[str] = []

    def stage_callback(live_candidate, invocation):
        events.append(invocation.stage.value)
        if invocation.stage is GeneratedStage.actor:
            object.__setattr__(
                live_candidate.projection.source_chain.steps[0], "order", 999
            )
        return GeneratedStageResult(
            {
                GeneratedStage.actor: actor,
                GeneratedStage.narrative: narrative,
                GeneratedStage.tree: tree,
                GeneratedStage.behavior: "must-not-run",
            }[invocation.stage]
        )

    entry = CoveragePlanEntry(
        entry_point_id=candidate.canonical_ingress.entry_point_id,
        entry_point_name="test",
        ordered_choices=[{"candidate_id": candidate.candidate_id}],
        primary_candidate_id=candidate.candidate_id,
        primary_state="selected",
        fallback_available=[],
    )
    machine = TargetFinalizationMachine(
        entry=entry,
        stage_callbacks={stage: stage_callback for stage in GENERATION_ORDER},
        candidate_revalidator=lambda ref: CandidateValidation(candidate),
        prebehavior_finalizer=make_prebehavior_finalizer(get_test_snapshot()),
        admission_callback=lambda candidate_arg, artifacts, snapshot: AdmissionDecision(
            True
        ),
        persistence=_Persistence(),
        attempted_candidate_ids=set(),
    )

    result = machine.run()

    assert result.state is LifecycleState.exhausted
    assert events == ["actor", "narrative", "tree"]
    assert any(v.code == GateCode.candidate_identity.value for v in result.violations)


def test_concrete_callback_allows_behavior_only_after_verified_snapshot() -> None:
    candidate, actor, narrative, tree = _valid_parts()
    original_digest = FinalTreeSemanticSnapshot.capture(tree).digest
    events: list[str] = []
    verified_snapshots = []

    def stage_callback(_candidate, invocation):
        events.append(invocation.stage.value)
        artifact = {
            GeneratedStage.actor: actor,
            GeneratedStage.narrative: narrative,
            GeneratedStage.tree: tree,
            GeneratedStage.behavior: "behavior-output",
        }[invocation.stage]
        if invocation.stage is GeneratedStage.behavior:
            finalized_tree = invocation.artifacts.tree
            assert (
                FinalTreeSemanticSnapshot.capture(finalized_tree).digest
                == original_digest
            )
            finalized_tree.root.label = "behavior-visible mutation"
            assert (
                verified_snapshots[0].materialize().root.label
                != finalized_tree.root.label
            )
            verified_snapshots[0].verify_digest()
        return GeneratedStageResult(artifact)

    finalizer = make_prebehavior_finalizer(get_test_snapshot())

    def finalize(candidate_arg, artifacts):
        assert artifacts.behavior is None
        result = finalizer(candidate_arg, artifacts)
        assert result.snapshot is not None
        result.snapshot.verify_digest()
        verified_snapshots.append(result.snapshot)
        events.append("verified-snapshot")
        return result

    entry = CoveragePlanEntry(
        entry_point_id=candidate.canonical_ingress.entry_point_id,
        entry_point_name="test",
        ordered_choices=[{"candidate_id": candidate.candidate_id}],
        primary_candidate_id=candidate.candidate_id,
        primary_state="selected",
        fallback_available=[],
    )
    machine = TargetFinalizationMachine(
        entry=entry,
        stage_callbacks={stage: stage_callback for stage in GENERATION_ORDER},
        candidate_revalidator=lambda ref: CandidateValidation(candidate),
        prebehavior_finalizer=finalize,
        admission_callback=lambda candidate_arg, artifacts, snapshot: AdmissionDecision(
            True, value=snapshot.digest
        ),
        persistence=_Persistence(),
        attempted_candidate_ids=set(),
    )

    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert events == ["actor", "narrative", "tree", "verified-snapshot", "behavior"]
