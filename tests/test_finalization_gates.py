"""Focused Phase 3A snapshot and parsimony boundary tests."""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    ToolInvocationAction,
)
from scenario_forge.pipeline.coverage_planning import CoveragePlanEntry
from scenario_forge.pipeline.finalization import (
    GENERATION_ORDER,
    AdmissionDecision,
    CandidateValidation,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    TargetFinalizationMachine,
)
from scenario_forge.pipeline.finalization_gates import (
    FinalTreeSemanticSnapshot,
    GateCode,
    ProjectionSemanticSnapshot,
    finalize_tree_parsimony,
    make_prebehavior_finalizer,
    run_prebehavior_gates,
)
from scenario_forge.pipeline.validation import check_scenario_semantics
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


def _tree_with_redundant_leaves(*, protected: bool = False) -> AttackTree:
    _, _, _, tree = _valid_parts()
    children = list(tree.root.children)
    for index in range(4, 7):
        children.append(
            AttackTreeNode(
                id=f"n1.{index}",
                label=f"Redundant setup {index}",
                gate=GateType.LEAF,
                action=ExternalPreconditionAction(),
                technique_id="AML.T0001" if protected else None,
            )
        )
    return tree.model_copy(
        update={"root": tree.root.model_copy(update={"children": children})}
    )


def test_safe_parsimony_records_provenance_and_never_mutates_input() -> None:
    tree = _tree_with_redundant_leaves()
    before = tree.model_dump(mode="json")

    result = finalize_tree_parsimony(tree)

    assert not result.violations
    assert result.record is not None and result.record.accepted
    assert result.record.removed_ids
    assert result.record.before_digest != result.record.after_digest
    assert result.record.preserved_projected_ids == ("step.1", "step.2", "step.3")
    assert tree.model_dump(mode="json") == before


def test_protected_over_budget_tree_is_rejected_and_returned_unchanged() -> None:
    tree = _tree_with_redundant_leaves(protected=True)
    before = FinalTreeSemanticSnapshot.capture(tree)

    result = finalize_tree_parsimony(tree, budget=5)

    assert result.violations[0].owner is GeneratedStage.tree
    assert result.record is not None and not result.record.accepted
    assert result.record.removed_ids == ()
    assert FinalTreeSemanticSnapshot.capture(result.tree).digest == before.digest
    assert FinalTreeSemanticSnapshot.capture(tree).digest == before.digest


def test_connector_pruning_allows_safe_overshoot_and_records_every_removed_id() -> None:
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

    assert not result.violations
    assert result.record is not None and result.record.accepted
    assert result.record.removed_ids == ("n1.4", "n1.4.1", "n1.4.2")
    assert len(result.tree.root.children) == 3
    assert len(expanded.root.children) == 4


class _Persistence:
    def record_transition(self, transition) -> None:
        pass

    def record_stage_result(self, invocation, result) -> None:
        pass

    def record_candidate_result(self, candidate_id, result) -> None:
        pass


def test_concrete_callback_allows_behavior_only_after_verified_snapshot() -> None:
    candidate, actor, narrative, _ = _valid_parts()
    tree = _tree_with_redundant_leaves()
    original_digest = FinalTreeSemanticSnapshot.capture(tree).digest
    events: list[str] = []

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
            assert FinalTreeSemanticSnapshot.capture(finalized_tree).digest != (
                original_digest
            )
            assert len(finalized_tree.root.children) == 5
        return GeneratedStageResult(artifact)

    finalizer = make_prebehavior_finalizer(get_test_snapshot())

    def finalize(candidate_arg, artifacts):
        assert artifacts.behavior is None
        result = finalizer(candidate_arg, artifacts)
        assert result.snapshot is not None
        result.snapshot.verify_digest()
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
