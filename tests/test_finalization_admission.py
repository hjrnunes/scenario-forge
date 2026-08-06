"""State-machine invariants for cmps.5 finalization/admission."""

from __future__ import annotations

from scenario_forge.models.projection_envelope import (
    ProjectionTraceabilityResult,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
)
from scenario_forge.pipeline.finalization import (
    MAX_TARGETED_RETRIES,
    FinalizationAdmissionMachine,
    LifecycleStage,
    LifecycleState,
)


def _trace_failure(stage: ProjectionTraceabilityStage) -> ProjectionTraceabilityResult:
    return ProjectionTraceabilityResult(
        valid=False,
        violations=[
            ProjectionTraceabilityViolation(
                code=ProjectionTraceabilityViolationCode.omitted_projected_step,
                stage=stage,
                detail="fixture violation",
            )
        ],
    )


def test_traceability_retries_earliest_owner_and_regenerates_downstream() -> None:
    calls: list[LifecycleStage] = []
    verify_count = 0

    def generate(stage, artifacts):
        calls.append(stage)
        return {"stage": stage.value, "call": len(calls)}, {"prompt": stage.value}

    def verify(artifacts):
        nonlocal verify_count
        verify_count += 1
        if verify_count == 1:
            return _trace_failure(ProjectionTraceabilityStage.narrative)
        return ProjectionTraceabilityResult(valid=True)

    machine = FinalizationAdmissionMachine(
        candidate_id="cand:v2:test",
        entry_point_id="ep:v1:test",
        generator=generate,
        verifier=verify,
        hard_gate=lambda _: [],
    )

    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert calls == [
        LifecycleStage.actor,
        LifecycleStage.narrative,
        LifecycleStage.tree,
        LifecycleStage.behavior,
        LifecycleStage.narrative,
        LifecycleStage.tree,
        LifecycleStage.behavior,
    ]
    assert machine.retry_counts == {LifecycleStage.narrative: 1}
    assert all(log.prompt or log.failure for log in result.attempts)


def test_retry_exhaustion_quarantines_and_never_admits() -> None:
    calls: list[LifecycleStage] = []

    def generate(stage, artifacts):
        calls.append(stage)
        return {"stage": stage.value}, {"prompt": stage.value}

    machine = FinalizationAdmissionMachine(
        candidate_id="cand:v2:test",
        entry_point_id="ep:v1:test",
        generator=generate,
        verifier=lambda _: _trace_failure(ProjectionTraceabilityStage.attack_tree),
        hard_gate=lambda _: [],
    )

    result = machine.run()

    assert result.state is LifecycleState.quarantined
    assert machine.retry_counts[LifecycleStage.tree] == MAX_TARGETED_RETRIES
    # Actor/narrative remain immutable when tree is the earliest owner.
    assert calls.count(LifecycleStage.actor) == 1
    assert calls.count(LifecycleStage.narrative) == 1
    assert calls.count(LifecycleStage.tree) == MAX_TARGETED_RETRIES + 1


def test_post_projection_tree_mutation_cannot_be_admitted() -> None:
    calls: list[LifecycleStage] = []

    def generate(stage, artifacts):
        calls.append(stage)
        if stage is LifecycleStage.behavior:
            artifacts.tree["orphan"] = True
        return {"stage": stage.value}, {"prompt": stage.value}

    machine = FinalizationAdmissionMachine(
        candidate_id="cand:v2:test",
        entry_point_id="ep:v1:test",
        generator=generate,
        verifier=lambda _: ProjectionTraceabilityResult(valid=True),
        hard_gate=lambda _: [],
    )

    result = machine.run()

    assert result.state is LifecycleState.quarantined
    assert calls.count(LifecycleStage.tree) == MAX_TARGETED_RETRIES + 1
    assert calls.count(LifecycleStage.behavior) == MAX_TARGETED_RETRIES + 1
