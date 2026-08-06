"""Target finalization lifecycle invariants for cmps.5 phase 2."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from scenario_forge.pipeline.coverage_planning import CoveragePlanEntry
from scenario_forge.pipeline.finalization import (
    GENERATION_ORDER,
    MAX_OWNER_RETRIES,
    AdmissionDecision,
    CandidateValidation,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleViolation,
    PrebehaviorFinalizationResult,
    TargetFinalizationMachine,
    earliest_generated_owner,
    ordered_target_choice_refs,
)


@dataclass(frozen=True)
class Candidate:
    candidate_id: str


@dataclass(frozen=True)
class Snapshot:
    tree: object
    digest: str = "digest"


class PersistenceFake:
    def __init__(self) -> None:
        self.transitions = []
        self.stage_results = []
        self.candidate_results = []

    def record_transition(self, transition) -> None:
        self.transitions.append(transition)

    def record_stage_result(self, invocation, result) -> None:
        self.stage_results.append((invocation, result))

    def record_candidate_result(self, candidate_id, decision) -> None:
        self.candidate_results.append((candidate_id, decision))


def _ref(candidate_id: str) -> dict:
    return {"candidate_id": candidate_id}


def _entry(
    *, primary: str = "primary", fallbacks: tuple[str, ...] = ("fallback",)
) -> CoveragePlanEntry:
    # Deliberately put primary second to prove selected-primary ordering wins.
    ordered = [_ref(candidate_id) for candidate_id in (*fallbacks, primary)]
    return CoveragePlanEntry(
        entry_point_id="ep:v1:test",
        entry_point_name="test",
        ordered_choices=ordered,
        primary_candidate_id=primary,
        primary_state="selected",
        fallback_available=[_ref(candidate_id) for candidate_id in fallbacks],
    )


def _machine(
    *,
    entry: CoveragePlanEntry | None = None,
    callbacks=None,
    revalidate=None,
    finalize=None,
    admit=None,
    attempted=None,
):
    calls: list[GeneratedStage] = []

    def default_stage(candidate, invocation):
        calls.append(invocation.stage)
        return GeneratedStageResult(
            artifact=f"{candidate.candidate_id}:{invocation.stage.value}:{invocation.invocation_index}"
        )

    persistence = PersistenceFake()
    machine = TargetFinalizationMachine(
        entry=entry or _entry(fallbacks=()),
        stage_callbacks=callbacks
        or {stage: default_stage for stage in GENERATION_ORDER},
        candidate_revalidator=revalidate
        or (lambda ref: CandidateValidation(Candidate(ref["candidate_id"]))),
        prebehavior_finalizer=finalize
        or (
            lambda candidate, artifacts: PrebehaviorFinalizationResult(
                Snapshot(artifacts.tree)
            )
        ),
        admission_callback=admit
        or (lambda candidate, artifacts, snapshot: AdmissionDecision(True)),
        persistence=persistence,
        attempted_candidate_ids=attempted if attempted is not None else set(),
    )
    return machine, calls, persistence


@pytest.mark.parametrize("owner", GENERATION_ORDER)
def test_retry_matrix_regenerates_exact_owner_and_downstream(owner) -> None:
    admission_calls = 0

    def admit(candidate, artifacts, snapshot):
        nonlocal admission_calls
        admission_calls += 1
        if admission_calls == 1:
            return AdmissionDecision(False, (LifecycleViolation("retry", owner=owner),))
        return AdmissionDecision(True)

    machine, calls, _ = _machine(admit=admit)
    result = machine.run()

    assert result.state is LifecycleState.admitted
    owner_offset = GENERATION_ORDER.index(owner)
    for index, stage in enumerate(GENERATION_ORDER):
        assert calls.count(stage) == (1 if index < owner_offset else 2)
    assert machine.owner_retry_counts == {owner: 1}


def test_upstream_retry_increments_downstream_invocation_not_retry_budget() -> None:
    admission_calls = 0

    def admit(candidate, artifacts, snapshot):
        nonlocal admission_calls
        admission_calls += 1
        if admission_calls == 1:
            return AdmissionDecision(
                False, (LifecycleViolation("actor owns", owner=GeneratedStage.actor),)
            )
        return AdmissionDecision(True)

    machine, _, persistence = _machine(admit=admit)
    machine.run()

    behavior_invocations = [
        invocation
        for invocation, _ in persistence.stage_results
        if invocation.stage is GeneratedStage.behavior
    ]
    assert [item.invocation_index for item in behavior_invocations] == [0, 1]
    assert [item.owner_retry_index for item in behavior_invocations] == [0, 0]
    assert machine.owner_retry_counts == {GeneratedStage.actor: 1}


def test_owner_retry_budgets_are_separate() -> None:
    owners = iter(
        (
            GeneratedStage.tree,
            GeneratedStage.narrative,
            GeneratedStage.narrative,
        )
    )

    def admit(candidate, artifacts, snapshot):
        try:
            owner = next(owners)
        except StopIteration:
            return AdmissionDecision(True)
        return AdmissionDecision(False, (LifecycleViolation("retry", owner=owner),))

    machine, _, _ = _machine(admit=admit)
    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert machine.owner_retry_counts == {
        GeneratedStage.tree: 1,
        GeneratedStage.narrative: MAX_OWNER_RETRIES,
    }


def test_aggregate_violations_choose_earliest_generated_owner() -> None:
    violations = (
        LifecycleViolation("behavior", owner=GeneratedStage.behavior),
        LifecycleViolation("tree", owner=GeneratedStage.tree),
        LifecycleViolation("narrative", owner=GeneratedStage.narrative),
    )
    assert earliest_generated_owner(violations) is GeneratedStage.narrative


def test_projection_owned_violation_is_nonretryable_and_advances_choice() -> None:
    generated_candidates: list[str] = []

    def revalidate(ref):
        if ref["candidate_id"] == "primary":
            return CandidateValidation(
                None,
                (
                    LifecycleViolation(
                        "projection mismatch", code="projection", retryable=False
                    ),
                ),
            )
        return CandidateValidation(Candidate(ref["candidate_id"]))

    def stage(candidate, invocation):
        generated_candidates.append(candidate.candidate_id)
        return GeneratedStageResult(invocation.stage.value)

    machine, _, _ = _machine(
        entry=_entry(),
        revalidate=revalidate,
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
    )
    result = machine.run()

    assert result.candidate_id == "fallback"
    assert generated_candidates == ["fallback"] * len(GENERATION_ORDER)


def test_primary_is_first_then_fallbacks_bounded_to_three() -> None:
    entry = _entry(primary="p", fallbacks=("f1", "f2", "f3", "f4"))
    assert [ref["candidate_id"] for ref in ordered_target_choice_refs(entry)] == [
        "p",
        "f1",
        "f2",
    ]


def test_fallback_progression_exhaustion_and_global_no_reuse() -> None:
    attempted = {"primary"}
    revalidated: list[str] = []

    def reject(ref):
        revalidated.append(ref["candidate_id"])
        return CandidateValidation(
            None,
            (LifecycleViolation("invalid", retryable=False),),
        )

    machine, calls, _ = _machine(
        entry=_entry(fallbacks=("f1", "f2", "f3")),
        revalidate=reject,
        attempted=attempted,
    )
    result = machine.run()

    assert result.state is LifecycleState.exhausted
    assert revalidated == ["f1", "f2"]  # max three includes skipped primary
    assert calls == []
    assert attempted == {"primary", "f1", "f2"}


def test_no_fallback_or_revalidation_after_admission() -> None:
    revalidated: list[str] = []

    def revalidate(ref):
        revalidated.append(ref["candidate_id"])
        return CandidateValidation(Candidate(ref["candidate_id"]))

    machine, _, _ = _machine(entry=_entry(), revalidate=revalidate)
    result = machine.run()

    assert result.state is LifecycleState.admitted
    assert revalidated == ["primary"]


def test_prebehavior_finalization_is_reachable_and_precedes_behavior() -> None:
    events: list[str] = []

    def stage(candidate, invocation):
        events.append(invocation.stage.value)
        return GeneratedStageResult(invocation.stage.value)

    def finalize(candidate, artifacts):
        events.append("finalize")
        assert artifacts.tree is not None
        assert artifacts.behavior is None
        return PrebehaviorFinalizationResult(Snapshot(artifacts.tree))

    machine, _, _ = _machine(
        callbacks={stage_name: stage for stage_name in GENERATION_ORDER},
        finalize=finalize,
    )
    machine.run()

    assert events == ["actor", "narrative", "tree", "finalize", "behavior"]
