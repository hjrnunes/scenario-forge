"""Target-scoped finalization/admission lifecycle for cmps.5 phases 1--2.

This controller is deliberately not wired into the production runner.  It
owns candidate choice, targeted retry routing, and admission sequencing while
all generation, validation, finalization, admission, and persistence effects
remain dependency-injected ports.  Hard gates, Call 3 cutover, manifest v3,
quarantine persistence, and runner integration belong to later phases.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from scenario_forge.models.scenario import CallName
from scenario_forge.pipeline.coverage_planning import (
    CoveragePlan,
    CoveragePlanEntry,
    deserialize_qualified_candidate,
    revalidate_qualified_candidate,
)
from scenario_forge.pipeline.generate.stages import StageAttemptFailure

MAX_OWNER_RETRIES = 2
MAX_TARGETED_RETRIES = MAX_OWNER_RETRIES  # Compatibility name.
MAX_TARGET_CHOICES = 3


class GeneratedStage(str, Enum):
    """Only stages that own generated artifacts and retry budgets."""

    actor = "actor"
    narrative = "narrative"
    tree = "tree"
    behavior = "behavior"


GENERATION_ORDER: tuple[GeneratedStage, ...] = (
    GeneratedStage.actor,
    GeneratedStage.narrative,
    GeneratedStage.tree,
    GeneratedStage.behavior,
)


class LifecycleState(str, Enum):
    pending = "pending"
    revalidating_candidate = "revalidating_candidate"
    generating_actor = "generating_actor"
    generating_narrative = "generating_narrative"
    generating_tree = "generating_tree"
    finalizing_prebehavior = "finalizing_prebehavior"
    generating_behavior = "generating_behavior"
    admitting = "admitting"
    admitted = "admitted"
    exhausted = "exhausted"


class CandidateTerminalStatus(str, Enum):
    admitted = "admitted"
    rejected = "rejected"
    generation_or_finalization_failed = "generation_or_finalization_failed"


@dataclass(frozen=True, slots=True)
class LifecycleViolation:
    """Typed lifecycle failure; ``owner=None`` is candidate/projection-owned."""

    detail: str
    owner: GeneratedStage | None = None
    code: str = "invalid"
    retryable: bool = True

    @property
    def can_retry_generation(self) -> bool:
        return self.retryable and self.owner is not None


@dataclass(slots=True)
class GeneratedArtifacts:
    actor: Any | None = None
    narrative: Any | None = None
    tree: Any | None = None
    behavior: Any | None = None

    def get(self, stage: GeneratedStage) -> Any | None:
        return getattr(self, stage.value)

    def set(self, stage: GeneratedStage, value: Any) -> None:
        setattr(self, stage.value, value)

    def invalidate_from(self, owner: GeneratedStage) -> None:
        start = GENERATION_ORDER.index(owner)
        for stage in GENERATION_ORDER[start:]:
            self.set(stage, None)


@runtime_checkable
class FinalTreeSnapshot(Protocol):
    """Immutable finalized-tree view consumed by future Call 3/gate wiring.

    Phase 2 defines this boundary only.  The production immutable snapshot,
    hard gates, parsimony checks, and assertions-only Call 3 contract are not
    implemented here.
    """

    @property
    def tree(self) -> Any: ...

    @property
    def digest(self) -> str: ...


@dataclass(frozen=True, slots=True)
class CandidateValidation:
    candidate: Any | None
    violations: tuple[LifecycleViolation, ...] = ()

    @property
    def valid(self) -> bool:
        return self.candidate is not None and not self.violations


@dataclass(frozen=True, slots=True)
class StageInvocation:
    candidate_id: str
    stage: GeneratedStage
    invocation_index: int
    owner_retry_index: int
    artifacts: GeneratedArtifacts


@dataclass(frozen=True, slots=True)
class GeneratedStageResult:
    artifact: Any | None
    evidence: Any = None
    violations: tuple[LifecycleViolation, ...] = ()


@dataclass(frozen=True, slots=True)
class PrebehaviorFinalizationResult:
    snapshot: FinalTreeSnapshot | None
    violations: tuple[LifecycleViolation, ...] = ()


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    admitted: bool
    violations: tuple[LifecycleViolation, ...] = ()
    value: Any = None


@dataclass(frozen=True, slots=True)
class CandidateTerminalResult:
    """Exactly one terminal lifecycle outcome for one reserved plan choice."""

    candidate_id: str
    status: CandidateTerminalStatus
    violations: tuple[LifecycleViolation, ...] = ()
    admission: AdmissionDecision | None = None


@dataclass(frozen=True, slots=True)
class LifecycleTransition:
    previous: LifecycleState
    current: LifecycleState
    candidate_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class TargetFinalizationResult:
    state: LifecycleState
    candidate_id: str | None
    admission: AdmissionDecision | None
    attempted_candidate_ids: tuple[str, ...]
    violations: tuple[LifecycleViolation, ...]
    transitions: tuple[LifecycleTransition, ...]


StageCallback = Callable[[Any, StageInvocation], GeneratedStageResult]
CandidateRevalidator = Callable[[dict[str, Any]], CandidateValidation]
PrebehaviorFinalizer = Callable[
    [Any, GeneratedArtifacts], PrebehaviorFinalizationResult
]
AdmissionCallback = Callable[
    [Any, GeneratedArtifacts, FinalTreeSnapshot], AdmissionDecision
]


class FinalizationPersistencePort(Protocol):
    """Effect boundary; manifest-v3/quarantine implementations are deferred."""

    def record_transition(self, transition: LifecycleTransition) -> None: ...

    def record_stage_result(
        self, invocation: StageInvocation, result: GeneratedStageResult
    ) -> None: ...

    def record_candidate_result(
        self, candidate_id: str, result: CandidateTerminalResult
    ) -> None: ...


def earliest_generated_owner(
    violations: Sequence[LifecycleViolation],
) -> GeneratedStage | None:
    """Choose the earliest retryable generated owner across all violations.

    Any candidate/projection-owned violation is nonretryable regardless of
    generated-stage failures present in the same aggregate.
    """
    if any(not violation.can_retry_generation for violation in violations):
        return None
    owners = {violation.owner for violation in violations}
    return next((stage for stage in GENERATION_ORDER if stage in owners), None)


def ordered_target_choice_refs(entry: CoveragePlanEntry) -> tuple[dict[str, Any], ...]:
    """Primary first, then persisted fallback availability, bounded and unique."""
    all_refs = [*entry.ordered_choices, *entry.fallback_available]
    primary = next(
        (
            ref
            for ref in all_refs
            if ref.get("candidate_id") == entry.primary_candidate_id
        ),
        None,
    )
    ordered = ([primary] if primary is not None else []) + list(
        entry.fallback_available
    )
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for ref in ordered:
        candidate_id = ref.get("candidate_id")
        if not isinstance(candidate_id, str) or candidate_id in seen:
            continue
        seen.add(candidate_id)
        result.append(ref)
        if len(result) == MAX_TARGET_CHOICES:
            break
    return tuple(result)


@dataclass
class TargetFinalizationMachine:
    """Lifecycle controller for one coverage target and up to three choices."""

    entry: CoveragePlanEntry
    stage_callbacks: Mapping[GeneratedStage, StageCallback]
    candidate_revalidator: CandidateRevalidator
    prebehavior_finalizer: PrebehaviorFinalizer
    admission_callback: AdmissionCallback
    persistence: FinalizationPersistencePort
    attempted_candidate_ids: set[str]
    state: LifecycleState = LifecycleState.pending
    artifacts: GeneratedArtifacts = field(default_factory=GeneratedArtifacts)
    invocation_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    owner_retry_counts: dict[GeneratedStage, int] = field(default_factory=dict)
    transitions: list[LifecycleTransition] = field(default_factory=list)
    violations: list[LifecycleViolation] = field(default_factory=list)

    def _transition(
        self, state: LifecycleState, candidate_id: str | None, reason: str
    ) -> None:
        transition = LifecycleTransition(self.state, state, candidate_id, reason)
        self.state = state
        self.transitions.append(transition)
        self.persistence.record_transition(transition)

    def _invoke_stage(
        self, candidate: Any, candidate_id: str, stage: GeneratedStage
    ) -> tuple[LifecycleViolation, ...]:
        self._transition(
            LifecycleState(f"generating_{stage.value}"), candidate_id, "invoke stage"
        )
        invocation_index = self.invocation_counts.get(stage, 0)
        self.invocation_counts[stage] = invocation_index + 1
        invocation = StageInvocation(
            candidate_id=candidate_id,
            stage=stage,
            invocation_index=invocation_index,
            owner_retry_index=self.owner_retry_counts.get(stage, 0),
            artifacts=self.artifacts,
        )
        try:
            result = self.stage_callbacks[stage](candidate, invocation)
        except StageAttemptFailure as exc:
            result = GeneratedStageResult(
                artifact=None,
                evidence=exc,
                violations=(
                    LifecycleViolation(
                        owner=stage,
                        code="stage_attempt_failed",
                        detail=f"{exc.exception_type}: {exc.detail}",
                    ),
                ),
            )
        except Exception as exc:  # noqa: BLE001 - callback failure is lifecycle data
            call_name = {
                GeneratedStage.actor: CallName.actor_profile,
                GeneratedStage.narrative: CallName.narrative,
                GeneratedStage.tree: CallName.attack_tree,
                GeneratedStage.behavior: CallName.behavior_spec,
            }[stage]
            failure = StageAttemptFailure(
                call_name=call_name,
                exception=exc,
                phase="before_invocation",
                invoked=False,
            )
            result = GeneratedStageResult(
                artifact=None,
                evidence=failure,
                violations=(
                    LifecycleViolation(
                        owner=stage,
                        code="stage_exception",
                        detail=f"{failure.exception_type}: {failure.detail}",
                    ),
                ),
            )
        self.persistence.record_stage_result(invocation, result)
        if not result.violations:
            self.artifacts.set(stage, result.artifact)
        return result.violations

    def _route_violations(
        self, violations: Sequence[LifecycleViolation]
    ) -> GeneratedStage | None:
        self.violations.extend(violations)
        owner = earliest_generated_owner(violations)
        if owner is None:
            return None
        used = self.owner_retry_counts.get(owner, 0)
        if used >= MAX_OWNER_RETRIES:
            return None
        self.owner_retry_counts[owner] = used + 1
        self.artifacts.invalidate_from(owner)
        return owner

    def _run_candidate(
        self, candidate: Any, candidate_id: str
    ) -> CandidateTerminalResult:
        next_stage = GeneratedStage.actor
        snapshot: FinalTreeSnapshot | None = None
        while True:
            for stage in GENERATION_ORDER[GENERATION_ORDER.index(next_stage) :]:
                if stage is GeneratedStage.behavior:
                    if snapshot is None:
                        self._transition(
                            LifecycleState.finalizing_prebehavior,
                            candidate_id,
                            "tree complete",
                        )
                        finalized = self.prebehavior_finalizer(
                            candidate, self.artifacts
                        )
                        if finalized.violations:
                            owner = self._route_violations(finalized.violations)
                            if owner is None:
                                return CandidateTerminalResult(
                                    candidate_id,
                                    CandidateTerminalStatus.generation_or_finalization_failed,
                                    tuple(finalized.violations),
                                )
                            next_stage = owner
                            break
                        if finalized.snapshot is None:
                            violation = LifecycleViolation(
                                code="missing_final_tree_snapshot",
                                detail="prebehavior finalizer returned no snapshot",
                                retryable=False,
                            )
                            self.violations.append(violation)
                            return CandidateTerminalResult(
                                candidate_id,
                                CandidateTerminalStatus.generation_or_finalization_failed,
                                (violation,),
                            )
                        snapshot = finalized.snapshot

                stage_violations = self._invoke_stage(candidate, candidate_id, stage)
                if stage_violations:
                    owner = self._route_violations(stage_violations)
                    if owner is None:
                        return CandidateTerminalResult(
                            candidate_id,
                            CandidateTerminalStatus.generation_or_finalization_failed,
                            tuple(stage_violations),
                        )
                    if owner is not GeneratedStage.behavior:
                        snapshot = None
                    next_stage = owner
                    break
            else:
                if snapshot is None:
                    raise RuntimeError(
                        "behavior completed without finalized tree snapshot"
                    )
                self._transition(
                    LifecycleState.admitting, candidate_id, "stages complete"
                )
                decision = self.admission_callback(candidate, self.artifacts, snapshot)
                if decision.admitted:
                    self._transition(LifecycleState.admitted, candidate_id, "admitted")
                    return CandidateTerminalResult(
                        candidate_id,
                        CandidateTerminalStatus.admitted,
                        admission=decision,
                    )
                owner = self._route_violations(decision.violations)
                if owner is None:
                    return CandidateTerminalResult(
                        candidate_id,
                        CandidateTerminalStatus.rejected,
                        tuple(decision.violations),
                        decision,
                    )
                if owner is not GeneratedStage.behavior:
                    snapshot = None
                next_stage = owner
                continue
            continue

    def run(self) -> TargetFinalizationResult:
        for ref in ordered_target_choice_refs(self.entry):
            ref_id = ref["candidate_id"]
            if ref_id in self.attempted_candidate_ids:
                continue
            # Mark before authoritative validation so a failed choice cannot be
            # reused by another target in the same run.
            self.attempted_candidate_ids.add(ref_id)
            self._transition(
                LifecycleState.revalidating_candidate,
                ref_id,
                "authoritative revalidation",
            )
            try:
                validation = self.candidate_revalidator(ref)
            except Exception as exc:  # noqa: BLE001 - terminal lifecycle evidence
                violation = LifecycleViolation(
                    code="candidate_revalidation_exception",
                    detail=f"{type(exc).__name__}: {exc}",
                    retryable=False,
                )
                self.violations.append(violation)
                terminal = CandidateTerminalResult(
                    ref_id, CandidateTerminalStatus.rejected, (violation,)
                )
            else:
                canonical_id = (
                    getattr(validation.candidate, "candidate_id", None)
                    if validation.candidate is not None
                    else None
                )
                identity_violation = (
                    LifecycleViolation(
                        code="candidate_identity_mismatch",
                        detail=(
                            f"revalidated candidate_id {canonical_id!r} does not match "
                            f"persisted candidate_id {ref_id!r}"
                        ),
                        retryable=False,
                    )
                    if validation.candidate is not None and canonical_id != ref_id
                    else None
                )
                if validation.violations or not validation.valid or identity_violation:
                    violations = list(validation.violations)
                    if identity_violation is not None:
                        violations.append(identity_violation)
                    if not violations:
                        violations.append(
                            LifecycleViolation(
                                code="candidate_revalidation_failed",
                                detail="authoritative candidate revalidation failed",
                                retryable=False,
                            )
                        )
                    self.violations.extend(violations)
                    terminal = CandidateTerminalResult(
                        ref_id, CandidateTerminalStatus.rejected, tuple(violations)
                    )
                else:
                    self.artifacts = GeneratedArtifacts()
                    self.owner_retry_counts = {}
                    try:
                        terminal = self._run_candidate(validation.candidate, ref_id)
                    except Exception as exc:  # noqa: BLE001 - terminal lifecycle evidence
                        violation = LifecycleViolation(
                            code="lifecycle_callback_exception",
                            detail=f"{type(exc).__name__}: {exc}",
                            retryable=False,
                        )
                        self.violations.append(violation)
                        terminal = CandidateTerminalResult(
                            ref_id,
                            CandidateTerminalStatus.generation_or_finalization_failed,
                            (violation,),
                        )

            # The sole terminal persistence point for every reserved choice.
            self.persistence.record_candidate_result(ref_id, terminal)
            if terminal.status is CandidateTerminalStatus.admitted:
                return TargetFinalizationResult(
                    state=self.state,
                    candidate_id=ref_id,
                    admission=terminal.admission,
                    attempted_candidate_ids=tuple(sorted(self.attempted_candidate_ids)),
                    violations=tuple(self.violations),
                    transitions=tuple(self.transitions),
                )

        self._transition(LifecycleState.exhausted, None, "candidate choices exhausted")
        return TargetFinalizationResult(
            state=self.state,
            candidate_id=None,
            admission=None,
            attempted_candidate_ids=tuple(sorted(self.attempted_candidate_ids)),
            violations=tuple(self.violations),
            transitions=tuple(self.transitions),
        )


def fallback_candidates_for_target(
    plan: CoveragePlan,
    entry_point_id: str,
    *,
    taxonomy_resolver: Any,
    snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
    attempted_candidate_ids: set[str],
) -> list[Any]:
    """Compatibility loader with primary-first authoritative revalidation."""
    entry = next(
        (item for item in plan.targets if item.entry_point_id == entry_point_id), None
    )
    if entry is None:
        return []
    candidates: list[Any] = []
    for ref in ordered_target_choice_refs(entry):
        candidate = deserialize_qualified_candidate(ref)
        if candidate.candidate_id in attempted_candidate_ids:
            continue
        attempted_candidate_ids.add(candidate.candidate_id)
        revalidate_qualified_candidate(
            ref, taxonomy_resolver, snapshot, trusted_catalog
        )
        candidates.append(candidate)
    return candidates


# Compatibility alias for callers that used the checkpoint's stage name.
LifecycleStage = GeneratedStage
