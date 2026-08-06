"""Unwired cmps.5 Phase 4 persistence contracts and manifest-v3 validation.

These contracts deliberately do not activate manifest v3 or invoke the
finalization machine from the production runner.  They are adapters for the
Phase 5 dependency-injection boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import threading
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator
import yaml

from scenario_forge.manifest import (
    ArtifactEntry,
    ArtifactRole,
    ManifestIntegrityError,
    RunStatus,
    atomic_write_text,
    build_artifact_entry,
)
from scenario_forge.pipeline.finalization import (
    MAX_OWNER_RETRIES,
    CandidateTerminalResult,
    CandidateTerminalStatus,
    GeneratedStage,
    GeneratedStageResult,
    FinalizationPersistenceError,
    LifecycleState,
    LifecycleTransition,
    StageInvocation,
)
from scenario_forge.pipeline.coverage_planning import (
    QualifiedCandidate,
    deserialize_qualified_candidate,
)
from scenario_forge.pipeline.projection import canonical_json_bytes
from scenario_forge.pipeline.generate.stages import (
    StageAttemptFailure,
    StageCallEvidence,
)

COVERAGE_PLAN_VERSION = "2"
FINALIZATION_INVENTORY_VERSION = "1"
QUARANTINE_BUNDLE_VERSION = "1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_TARGET_CHOICES = 3


class StrictModel(BaseModel):
    """Persistence base: unknown fields are never silently accepted."""

    model_config = {"extra": "forbid", "use_enum_values": False}


class TargetState(str, Enum):
    selected = "selected"
    admitted = "admitted"
    exhausted = "exhausted"


class QualifiedCandidateRef(StrictModel):
    """Complete candidate-v2 materialization plus merged filter provenance."""

    candidate_id: str = Field(min_length=1)
    filter_candidate_id: str
    pattern_id: str = Field(min_length=1)
    entry_point_id: str = Field(min_length=1)
    rank: int = Field(ge=0)
    projected_candidate: dict[str, Any]
    accepted_filters: list[dict[str, Any]]
    accepted_rationale: str
    origins: list[dict[str, Any]]
    rejection_rationales: list[dict[str, Any]]
    pinned_entry_point: str
    pinned_technique_ids: list[str]
    pinned_technique_names: list[str]

    @model_validator(mode="after")
    def _identity_matches_materialization(self) -> QualifiedCandidateRef:
        raw = self.model_dump(mode="json")
        deserialized = deserialize_qualified_candidate(raw)
        expected = QualifiedCandidate(
            projected=deserialized.projected,
            accepted_filters=deserialized.accepted_filters,
            rank=deserialized.rank,
        ).to_plan_ref()
        if canonical_json_bytes(raw) != canonical_json_bytes(expected):
            raise ValueError("qualified candidate provenance mirrors are not canonical")
        return self


class CoverageTargetEntry(StrictModel):
    entry_point_id: str = Field(min_length=1)
    entry_point_name: str = Field(min_length=1)
    ordered_choices: list[QualifiedCandidateRef] = Field(max_length=MAX_TARGET_CHOICES)
    primary_candidate_id: str | None
    attempted_candidate_ids: list[str]
    admitted_candidate_id: str | None
    target_state: TargetState
    fallback_available: list[QualifiedCandidateRef] = Field(
        max_length=MAX_TARGET_CHOICES
    )

    @model_validator(mode="after")
    def _validate_queue(self) -> CoverageTargetEntry:
        ids = [choice.candidate_id for choice in self.ordered_choices]
        if len(ids) != len(set(ids)):
            raise ValueError("ordered choices contain duplicate candidate IDs")
        if len(self.attempted_candidate_ids) != len(set(self.attempted_candidate_ids)):
            raise ValueError("attempted_candidate_ids contains duplicates")
        if self.primary_candidate_id is not None:
            if not ids or ids[0] != self.primary_candidate_id:
                raise ValueError("primary candidate must be the first ordered choice")
        attempted = set(self.attempted_candidate_ids)
        if self.attempted_candidate_ids != ids[: len(self.attempted_candidate_ids)]:
            raise ValueError("attempted_candidate_ids must be the exact ordered prefix")
        if ids and self.primary_candidate_id is None:
            raise ValueError("nonempty ordered choices require a primary candidate")
        if not ids and self.target_state is not TargetState.exhausted:
            raise ValueError("empty target queues must already be exhausted")
        fallbacks = [choice.candidate_id for choice in self.fallback_available]
        if attempted.intersection(fallbacks):
            raise ValueError("fallback_available must exclude attempted candidates")
        expected_fallbacks = (
            []
            if self.target_state is TargetState.admitted
            else [candidate_id for candidate_id in ids if candidate_id not in attempted]
        )
        if fallbacks != expected_fallbacks:
            raise ValueError(
                "fallback_available must preserve unattempted ordered-choice order"
            )
        ordered_by_id = {choice.candidate_id: choice for choice in self.ordered_choices}
        if any(
            choice != ordered_by_id[choice.candidate_id]
            for choice in self.fallback_available
        ):
            raise ValueError(
                "fallback_available entries must exactly equal their ordered choices"
            )
        ranks = [choice.rank for choice in self.ordered_choices]
        if ranks != list(range(len(ranks))):
            raise ValueError("ordered choice queue ranks must be contiguous from zero")
        if any(
            choice.entry_point_id != self.entry_point_id
            for choice in self.ordered_choices
        ):
            raise ValueError("every ordered choice must match its coverage target")
        if self.admitted_candidate_id is not None:
            if self.admitted_candidate_id not in attempted:
                raise ValueError("admitted candidate must have been attempted")
            if self.target_state is not TargetState.admitted:
                raise ValueError("admitted candidate requires target_state=admitted")
            admitted_index = ids.index(self.admitted_candidate_id)
            if len(self.attempted_candidate_ids) != admitted_index + 1:
                raise ValueError("admitted target cannot contain later attempts")
        elif self.target_state is TargetState.admitted:
            raise ValueError("target_state=admitted requires admitted_candidate_id")
        if self.target_state is TargetState.selected:
            if self.admitted_candidate_id is not None:
                raise ValueError("selected target must be nonterminal and not admitted")
        if self.target_state is TargetState.exhausted:
            if (
                self.admitted_candidate_id is not None
                or self.attempted_candidate_ids != ids
            ):
                raise ValueError(
                    "exhausted target requires all choices attempted and none admitted"
                )
        return self


class CoveragePlanV2(StrictModel):
    schema_version: Literal["2"]
    completeness: Literal["not_applicable", "confirmed_complete"]
    evidence_refs: list[str]
    targets: list[CoverageTargetEntry]
    selection_limitation_target_ids: list[str]

    @model_validator(mode="after")
    def _unique_targets_and_candidates(self) -> CoveragePlanV2:
        target_ids = [target.entry_point_id for target in self.targets]
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("coverage plan contains duplicate target IDs")
        candidates = [
            choice.candidate_id
            for target in self.targets
            for choice in target.ordered_choices
        ]
        if len(candidates) != len(set(candidates)):
            raise ValueError("candidate IDs must be unique across coverage targets")
        limitations = self.selection_limitation_target_ids
        if len(limitations) != len(set(limitations)) or not set(limitations).issubset(
            target_ids
        ):
            raise ValueError(
                "selection limitations must uniquely reference coverage targets"
            )
        if self.completeness == "confirmed_complete" and not self.evidence_refs:
            raise ValueError("confirmed completeness requires evidence references")
        if self.completeness == "not_applicable" and self.evidence_refs:
            raise ValueError("not-applicable completeness forbids evidence references")
        return self


class ViolationRecord(StrictModel):
    code: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    owner: GeneratedStage | None
    retryable: bool


class PromptRecord(StrictModel):
    system_prompt: str | None
    user_prompt: str | None


class StageInputRecord(StrictModel):
    candidate: JsonValue
    candidate_id: str = Field(min_length=1)
    stage: GeneratedStage
    invocation_index: int = Field(ge=0)
    owner_retry_index: int = Field(ge=0, le=MAX_OWNER_RETRIES)
    visible_artifacts: dict[str, JsonValue]
    prompt: PromptRecord | None
    final_tree_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)


class LLMResultRecord(StrictModel):
    content: JsonValue
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    system_prompt: str
    user_prompt: str


class CallMetadataRecord(StrictModel):
    call: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    duration_ms: int = Field(ge=0)


class StageCallEvidenceRecord(StrictModel):
    call_name: str
    result: LLMResultRecord
    metadata: CallMetadataRecord


class StageAttemptFailureRecord(StrictModel):
    call_name: str
    exception_type: str = Field(min_length=1)
    detail: str
    phase: Literal["before_invocation", "invocation", "post_response"]
    invoked: bool
    prompt: PromptRecord | None
    result: LLMResultRecord | None
    raw_response: JsonValue | None


class StageAttemptRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    stage: GeneratedStage
    invocation_index: int = Field(ge=0)
    owner_retry_index: int = Field(ge=0, le=MAX_OWNER_RETRIES)
    prompt: PromptRecord | None
    call: StageCallEvidenceRecord | None
    result: JsonValue | None
    failure: StageAttemptFailureRecord | None
    input: StageInputRecord
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    final_tree_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    output_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    violations: list[ViolationRecord]

    @model_validator(mode="after")
    def _one_result_shape(self) -> StageAttemptRecord:
        if self.result is not None and self.failure is not None:
            raise ValueError("stage attempt cannot contain both result and failure")
        if self.input_sha256 != canonical_sha256(self.input):
            raise ValueError("stage input digest mismatch")
        if self.candidate_snapshot_sha256 != canonical_sha256(self.input.candidate):
            raise ValueError("candidate snapshot digest mismatch")
        if self.final_tree_snapshot_sha256 != self.input.final_tree_digest:
            raise ValueError("final-tree snapshot digest mismatch")
        expected_output = (
            canonical_sha256(self.result) if self.result is not None else None
        )
        if self.output_sha256 != expected_output:
            raise ValueError("stage output digest mismatch")
        if (
            self.input.candidate_id != self.candidate_id
            or self.input.stage is not self.stage
            or self.input.invocation_index != self.invocation_index
            or self.input.owner_retry_index != self.owner_retry_index
        ):
            raise ValueError("stage input identity/index mismatch")
        return self


class CandidateAttemptRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    queue_rank: int = Field(ge=0)
    is_primary: bool
    stage_attempt_ids: list[str]


class TransitionRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    target_entry_point_id: str = Field(min_length=1)
    index: int = Field(ge=0)
    previous: LifecycleState
    current: LifecycleState
    candidate_id: str | None
    reason: str = Field(min_length=1)


class ParsimonyRepairRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    candidate_attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    before_digest: str = Field(pattern=SHA256_PATTERN)
    after_digest: str = Field(pattern=SHA256_PATTERN)
    removed_ids: list[str]
    preserved_projected_ids: list[str]
    accepted: bool
    detail: str


class GateResultRecord(StrictModel):
    gate: str = Field(min_length=1)
    passed: bool
    violations: list[ViolationRecord]
    diagnostics: list[ViolationRecord]


class AdmissionDecisionRecord(StrictModel):
    event_id: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    sequence: int = Field(ge=0)
    candidate_id: str = Field(min_length=1)
    status: CandidateTerminalStatus
    admitted: bool
    gate_results: list[GateResultRecord]
    candidate_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    actor_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    narrative_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    final_tree_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    violations: list[ViolationRecord]

    @model_validator(mode="after")
    def _status_matches_admission(self) -> AdmissionDecisionRecord:
        if self.admitted != (self.status is CandidateTerminalStatus.admitted):
            raise ValueError("admitted flag must match terminal candidate status")
        snapshots = (
            self.candidate_snapshot_sha256,
            self.actor_snapshot_sha256,
            self.narrative_snapshot_sha256,
            self.final_tree_snapshot_sha256,
        )
        if self.admitted and any(digest is None for digest in snapshots):
            raise ValueError("admitted decision requires all four snapshot digests")
        return self


class ArtifactReceipt(StrictModel):
    candidate_id: str = Field(min_length=1)
    role: ArtifactRole
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)
    scenario_id: str | None

    @field_validator("path")
    @classmethod
    def _canonical_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not value
            or path.is_absolute()
            or path.as_posix() != value
            or ".." in path.parts
            or "." in path.parts
            or "\\" in value
        ):
            raise ValueError("artifact receipt path must be canonical and relative")
        return value

    @model_validator(mode="after")
    def _role_identity(self) -> ArtifactReceipt:
        if self.role in {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}:
            if not self.scenario_id:
                raise ValueError("normal scenario receipts require scenario_id")
        elif self.role is ArtifactRole.QUARANTINE_BUNDLE:
            if self.scenario_id is not None:
                raise ValueError("quarantine receipts forbid scenario_id")
        else:
            raise ValueError("unsupported finalization artifact receipt role")
        return self


class FinalizationInventoryV1(StrictModel):
    schema_version: Literal["1"]
    run_id: str = Field(min_length=1)
    coverage_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_attempts: list[CandidateAttemptRecord]
    stage_attempts: list[StageAttemptRecord]
    transitions: list[TransitionRecord]
    repairs: list[ParsimonyRepairRecord]
    admission_decisions: list[AdmissionDecisionRecord]
    admitted_inventory: list[ArtifactReceipt]
    quarantine_inventory: list[ArtifactReceipt]

    @model_validator(mode="after")
    def _local_integrity(self) -> FinalizationInventoryV1:
        events = [
            *self.candidate_attempts,
            *self.stage_attempts,
            *self.transitions,
            *self.repairs,
            *self.admission_decisions,
        ]
        event_ids = [item.event_id for item in events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("duplicate durable event IDs")
        if sorted(item.sequence for item in events) != list(range(len(events))):
            raise ValueError("durable event sequences must be contiguous from zero")
        for label, values in (
            (
                "candidate attempt",
                [item.attempt_id for item in self.candidate_attempts],
            ),
            ("stage attempt", [item.attempt_id for item in self.stage_attempts]),
            ("candidate", [item.candidate_id for item in self.candidate_attempts]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate {label} IDs")
        transitions_by_target: dict[str, list[TransitionRecord]] = {}
        for transition in self.transitions:
            transitions_by_target.setdefault(
                transition.target_entry_point_id, []
            ).append(transition)
        for target_transitions in transitions_by_target.values():
            if [item.index for item in target_transitions] != list(
                range(len(target_transitions))
            ):
                raise ValueError("transition indexes must be contiguous per target")
            for previous, current in zip(target_transitions, target_transitions[1:]):
                if previous.current is not current.previous:
                    raise ValueError(
                        "transition state chain is noncontiguous per target"
                    )
        generating_state = {
            GeneratedStage.actor: LifecycleState.generating_actor,
            GeneratedStage.narrative: LifecycleState.generating_narrative,
            GeneratedStage.tree: LifecycleState.generating_tree,
            GeneratedStage.behavior: LifecycleState.generating_behavior,
        }
        active = {
            LifecycleState.generating_actor,
            LifecycleState.generating_narrative,
            LifecycleState.generating_tree,
            LifecycleState.finalizing_prebehavior,
            LifecycleState.generating_behavior,
            LifecycleState.admitting,
        }
        legal_edges = {
            (LifecycleState.pending, LifecycleState.revalidating_candidate),
            (LifecycleState.pending, LifecycleState.exhausted),
            (LifecycleState.rejected, LifecycleState.revalidating_candidate),
            (LifecycleState.rejected, LifecycleState.exhausted),
            (LifecycleState.revalidating_candidate, LifecycleState.generating_actor),
            (LifecycleState.revalidating_candidate, LifecycleState.rejected),
            (LifecycleState.generating_actor, LifecycleState.generating_narrative),
            (LifecycleState.generating_narrative, LifecycleState.generating_tree),
            (LifecycleState.generating_tree, LifecycleState.finalizing_prebehavior),
            (LifecycleState.finalizing_prebehavior, LifecycleState.generating_behavior),
            (LifecycleState.generating_behavior, LifecycleState.admitting),
            (LifecycleState.admitting, LifecycleState.admitted),
            (LifecycleState.admitting, LifecycleState.rejected),
        }
        legal_edges.update(
            (source, destination)
            for source in active
            for destination in generating_state.values()
        )
        legal_edges.update((source, LifecycleState.rejected) for source in active)
        for transition in self.transitions:
            if (transition.previous, transition.current) not in legal_edges:
                raise ValueError(
                    f"illegal lifecycle edge {transition.previous.value}->{transition.current.value}"
                )
            if (
                transition.previous is not LifecycleState.rejected
                and transition.previous is not LifecycleState.pending
                and transition.current is not LifecycleState.exhausted
            ):
                prior = transitions_by_target[transition.target_entry_point_id][
                    transition.index - 1
                ]
                if prior.candidate_id != transition.candidate_id:
                    raise ValueError(
                        "lifecycle candidate changed inside an active trace"
                    )
        stage_by_id = {item.attempt_id: item for item in self.stage_attempts}
        referenced_stage_ids: set[str] = set()
        for attempt in self.candidate_attempts:
            for stage_id in attempt.stage_attempt_ids:
                stage = stage_by_id.get(stage_id)
                if stage is None or stage.candidate_id != attempt.candidate_id:
                    raise ValueError(
                        "candidate attempt references an invalid stage attempt"
                    )
                referenced_stage_ids.add(stage_id)
        if referenced_stage_ids != set(stage_by_id):
            raise ValueError(
                "stage attempts and candidate references must match exactly"
            )
        attempts_by_id = {item.attempt_id: item for item in self.candidate_attempts}
        for repair in self.repairs:
            attempt = attempts_by_id.get(repair.candidate_attempt_id)
            if (
                attempt is None
                or repair.candidate_id != attempt.candidate_id
                or repair.target_entry_point_id != attempt.target_entry_point_id
            ):
                raise ValueError("repair record does not match its candidate attempt")
            behavior_inputs = [
                item.final_tree_snapshot_sha256
                for item in self.stage_attempts
                if item.candidate_id == repair.candidate_id
                and item.stage is GeneratedStage.behavior
            ]
            if behavior_inputs and repair.after_digest not in behavior_inputs:
                raise ValueError(
                    "repair output is not bound to behavior final-tree input"
                )
        by_candidate_stage: dict[
            tuple[str, GeneratedStage], list[StageAttemptRecord]
        ] = {}
        for item in self.stage_attempts:
            by_candidate_stage.setdefault((item.candidate_id, item.stage), []).append(
                item
            )
        for records in by_candidate_stage.values():
            records.sort(key=lambda item: item.invocation_index)
            if [item.invocation_index for item in records] != list(range(len(records))):
                raise ValueError("stage invocation indexes must be contiguous")
            if any(
                right.owner_retry_index < left.owner_retry_index
                for left, right in zip(records, records[1:])
            ):
                raise ValueError("stage owner retry indexes must be monotonic")
        generating_transitions = [
            item
            for item in self.transitions
            if item.current in set(generating_state.values())
        ]
        ordered_stage_attempts = sorted(
            self.stage_attempts, key=lambda item: item.sequence
        )
        if len(generating_transitions) not in {
            len(ordered_stage_attempts),
            len(ordered_stage_attempts) + 1,
        }:
            raise ValueError(
                "generating transitions must correspond 1:1 to stage attempts"
            )
        for transition, stage in zip(generating_transitions, ordered_stage_attempts):
            if (
                transition.current is not generating_state[stage.stage]
                or transition.candidate_id != stage.candidate_id
                or transition.sequence >= stage.sequence
            ):
                raise ValueError("generating transition/stage attempt trace mismatch")
        decisions = [item.candidate_id for item in self.admission_decisions]
        if len(decisions) != len(set(decisions)):
            raise ValueError("duplicate terminal admission decisions")
        terminal_edges = {
            item.candidate_id: item.current
            for item in self.transitions
            if item.current in {LifecycleState.admitted, LifecycleState.rejected}
        }
        for decision in self.admission_decisions:
            expected = (
                LifecycleState.admitted
                if decision.admitted
                else LifecycleState.rejected
            )
            if terminal_edges.get(decision.candidate_id) is not expected:
                raise ValueError(
                    "admission decision requires matching admitting terminal transition"
                )
            if decision.admitted:
                candidate_stages = [
                    item
                    for item in self.stage_attempts
                    if item.candidate_id == decision.candidate_id
                ]
                latest_outputs = {
                    stage: next(
                        (
                            item
                            for item in reversed(candidate_stages)
                            if item.stage is stage and item.output_sha256 is not None
                        ),
                        None,
                    )
                    for stage in GeneratedStage
                }
                behavior = latest_outputs[GeneratedStage.behavior]
                expected_snapshots = (
                    candidate_stages[-1].candidate_snapshot_sha256
                    if candidate_stages
                    else None,
                    latest_outputs[GeneratedStage.actor].output_sha256
                    if latest_outputs[GeneratedStage.actor]
                    else None,
                    latest_outputs[GeneratedStage.narrative].output_sha256
                    if latest_outputs[GeneratedStage.narrative]
                    else None,
                    behavior.final_tree_snapshot_sha256 if behavior else None,
                )
                actual_snapshots = (
                    decision.candidate_snapshot_sha256,
                    decision.actor_snapshot_sha256,
                    decision.narrative_snapshot_sha256,
                    decision.final_tree_snapshot_sha256,
                )
                if actual_snapshots != expected_snapshots:
                    raise ValueError(
                        "admission snapshot digests do not match stage evidence"
                    )
        self._verify_event_hashes()
        return self

    def _verify_event_hashes(self) -> None:
        for item in self.candidate_attempts:
            payload = {
                "candidate_id": item.candidate_id,
                "target_entry_point_id": item.target_entry_point_id,
                "queue_rank": item.queue_rank,
            }
            _verify_event(item, "candidate_attempt", item.candidate_id, payload)
        for item in self.transitions:
            payload = {
                "previous": item.previous.value,
                "current": item.current.value,
                "candidate_id": item.candidate_id,
                "reason": item.reason,
                "transition_index": item.index,
                "target_entry_point_id": item.target_entry_point_id,
            }
            _verify_event(
                item,
                "transition",
                [item.target_entry_point_id, item.index],
                payload,
            )
        for item in self.stage_attempts:
            payload = {
                "attempt_id": item.attempt_id,
                "input": item.input.model_dump(mode="json"),
                "call": item.call.model_dump(mode="json") if item.call else None,
                "failure": (
                    item.failure.model_dump(mode="json") if item.failure else None
                ),
                "result": item.result,
                "violations": [
                    violation.model_dump(mode="json") for violation in item.violations
                ],
            }
            _verify_event(item, "stage_attempt", item.attempt_id, payload)
        for item in self.repairs:
            payload = {
                "candidate_id": item.candidate_id,
                "before_digest": item.before_digest,
                "after_digest": item.after_digest,
                "removed_ids": item.removed_ids,
                "preserved_projected_ids": item.preserved_projected_ids,
                "accepted": item.accepted,
                "detail": item.detail,
            }
            _verify_event(
                item,
                "parsimony_repair",
                [item.candidate_id, item.before_digest],
                payload,
            )
        for item in self.admission_decisions:
            snapshots = {
                "candidate_snapshot_sha256": item.candidate_snapshot_sha256,
                "actor_snapshot_sha256": item.actor_snapshot_sha256,
                "narrative_snapshot_sha256": item.narrative_snapshot_sha256,
                "final_tree_snapshot_sha256": item.final_tree_snapshot_sha256,
            }
            payload = {
                "candidate_id": item.candidate_id,
                "status": item.status.value,
                "violations": [
                    violation.model_dump(mode="json") for violation in item.violations
                ],
                "gate_results": [
                    gate.model_dump(mode="json") for gate in item.gate_results
                ],
                "snapshots": snapshots,
            }
            _verify_event(item, "candidate_result", item.candidate_id, payload)


class PersistenceJournalV1(StrictModel):
    """Recoverable two-document state update; never part of a final manifest."""

    schema_version: Literal["1"]
    coverage_plan: CoveragePlanV2
    finalization_inventory: FinalizationInventoryV1
    quarantine_bundle: QuarantineBundleV1 | None = None
    admitted_publication: AdmittedArtifactPublication | None = None

    @model_validator(mode="after")
    def _hash_link(self) -> PersistenceJournalV1:
        expected = hashlib.sha256(canonical_json_bytes(self.coverage_plan)).hexdigest()
        if self.finalization_inventory.coverage_plan_sha256 != expected:
            raise ValueError(
                "journal inventory does not reference journal coverage plan"
            )
        return self


class QuarantineBundleV1(StrictModel):
    """Forensic generated layers; deliberately not a ScenarioEnvelope."""

    schema_version: Literal["1"]
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    actor: JsonValue | None
    narrative: JsonValue | None
    tree: JsonValue | None
    behavior: JsonValue | None
    artifact_sha256: dict[GeneratedStage, str]
    violations: list[ViolationRecord] = Field(min_length=1)

    @field_validator("attempt_id")
    @classmethod
    def _safe_attempt_id(cls, value: str) -> str:
        if (
            not value
            or any(char in value for char in ("/", "\\"))
            or value in {".", ".."}
        ):
            raise ValueError("attempt_id must be a safe filename component")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def _valid_digests(
        cls, value: dict[GeneratedStage, str]
    ) -> dict[GeneratedStage, str]:
        for digest in value.values():
            if len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                raise ValueError("quarantine artifact digest must be canonical SHA-256")
        return value

    @model_validator(mode="after")
    def _digests_match_artifacts(self) -> QuarantineBundleV1:
        for stage in GeneratedStage:
            artifact = getattr(self, stage.value)
            digest = self.artifact_sha256.get(stage)
            if (artifact is None) != (digest is None):
                raise ValueError(
                    "each serialized quarantine artifact requires one digest"
                )
            if artifact is not None and digest != canonical_sha256(artifact):
                raise ValueError(f"quarantine {stage.value} digest mismatch")
        return self


class AdmittedArtifactPublication(StrictModel):
    """Exact admitted file bytes carried through the recovery journal."""

    candidate_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    yaml_text: str
    feature_text: str

    @field_validator("scenario_id")
    @classmethod
    def _safe_scenario_id(cls, value: str) -> str:
        if value in {".", ".."} or any(char in value for char in ("/", "\\")):
            raise ValueError("scenario_id must be a safe filename component")
        return value

    @model_validator(mode="after")
    def _serialized_identity(self) -> AdmittedArtifactPublication:
        try:
            document = yaml.safe_load(self.yaml_text)
        except yaml.YAMLError as exc:
            raise ValueError(f"admitted YAML is invalid: {exc}") from exc
        if not isinstance(document, dict):
            raise ValueError("admitted YAML must serialize an object")
        if document.get("scenario_id") != self.scenario_id:
            raise ValueError("admitted YAML scenario_id mismatch")
        if document.get("candidate_id") != self.candidate_id:
            raise ValueError("admitted YAML candidate_id mismatch")
        return self


class AdmittedTerminalPayload(StrictModel):
    """Successful gate evidence and exact publication bytes as one value."""

    gate_results: list[GateResultRecord]
    publication: AdmittedArtifactPublication


PersistenceJournalV1.model_rebuild()


def _json_value(value: Any) -> JsonValue:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif isinstance(value, tuple):
        value = list(value)
    # Round-trip only through the one public canonical encoder.  This both
    # normalizes NFC and rejects unsupported/non-finite values.
    return json.loads(canonical_json_bytes(value))


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _write_model(run_dir: Path, rel_path: str, model: BaseModel) -> Path:
    # Revalidate after any adapter-side list mutation so an invalid in-memory
    # object can never replace the last valid on-disk document.
    model = type(model).model_validate(model.model_dump(mode="python"))
    content = canonical_json_bytes(model)
    return atomic_write_text(run_dir / rel_path, content.decode("utf-8"))


def _canonical_parts(rel_path: str) -> tuple[str, ...]:
    path = PurePosixPath(rel_path)
    if (
        not rel_path
        or path.is_absolute()
        or path.as_posix() != rel_path
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in rel_path
    ):
        raise ManifestIntegrityError(f"Persistence path is not canonical: {rel_path}")
    return path.parts


def _open_parent(
    run_dir: Path, rel_path: str, *, create: bool = False
) -> tuple[int, str]:
    parts = _canonical_parts(rel_path)
    fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, dir_fd=fd)
                os.fsync(fd)
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except Exception:
        os.close(fd)
        raise


def _safe_read(run_dir: Path, rel_path: str) -> bytes:
    data = b""
    try:
        parent_fd, name = _open_parent(run_dir, rel_path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ManifestIntegrityError(
                        f"Persistence artifact is not a file: {rel_path}"
                    )
                while chunk := os.read(fd, 65536):
                    data += chunk
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise ManifestIntegrityError(
            f"Cannot safely read {run_dir / rel_path}: {exc}"
        ) from exc
    return data


def _exclusive_create(run_dir: Path, rel_path: str, content: bytes) -> None:
    parent_fd, name = _open_parent(run_dir, rel_path, create=True)
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            if _safe_read(run_dir, rel_path) != content:
                raise ManifestIntegrityError(
                    f"Immutable evidence collision at {name}"
                ) from None
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def write_coverage_plan(run_dir: Path, plan: CoveragePlanV2) -> ArtifactEntry:
    _write_model(run_dir, "coverage-plan.json", plan)
    return build_artifact_entry(
        ArtifactRole.COVERAGE_PLAN,
        run_dir,
        "coverage-plan.json",
        schema_version=COVERAGE_PLAN_VERSION,
    )


def read_coverage_plan(
    run_dir: Path, entry: ArtifactEntry | None = None
) -> CoveragePlanV2:
    return _read_model(
        run_dir, entry, ArtifactRole.COVERAGE_PLAN, "coverage-plan.json", CoveragePlanV2
    )


def write_finalization_inventory(
    run_dir: Path, inventory: FinalizationInventoryV1
) -> ArtifactEntry:
    _write_model(run_dir, "finalization-inventory.json", inventory)
    return build_artifact_entry(
        ArtifactRole.FINALIZATION_INVENTORY,
        run_dir,
        "finalization-inventory.json",
        schema_version=FINALIZATION_INVENTORY_VERSION,
    )


def read_finalization_inventory(
    run_dir: Path, entry: ArtifactEntry | None = None
) -> FinalizationInventoryV1:
    return _read_model(
        run_dir,
        entry,
        ArtifactRole.FINALIZATION_INVENTORY,
        "finalization-inventory.json",
        FinalizationInventoryV1,
    )


def write_quarantine_bundle(run_dir: Path, bundle: QuarantineBundleV1) -> ArtifactEntry:
    rel_path = f"quarantine/{bundle.attempt_id}.json"
    bundle = QuarantineBundleV1.model_validate(bundle.model_dump(mode="python"))
    _exclusive_create(run_dir, rel_path, canonical_json_bytes(bundle))
    return build_artifact_entry(
        ArtifactRole.QUARANTINE_BUNDLE,
        run_dir,
        rel_path,
        schema_version=QUARANTINE_BUNDLE_VERSION,
        candidate_id=bundle.candidate_id,
    )


def read_quarantine_bundle(run_dir: Path, entry: ArtifactEntry) -> QuarantineBundleV1:
    expected = PurePosixPath(entry.path)
    if (
        expected.as_posix() != entry.path
        or ".." in expected.parts
        or len(expected.parts) != 2
        or expected.parts[0] != "quarantine"
    ):
        raise ManifestIntegrityError(f"Invalid quarantine bundle path: {entry.path}")
    return _read_model(
        run_dir, entry, ArtifactRole.QUARANTINE_BUNDLE, entry.path, QuarantineBundleV1
    )


def _recover_journal(run_dir: Path) -> CoveragePlanV2 | None:
    """Complete an interrupted synchronized plan/inventory state replacement."""

    journal_path = run_dir / ".finalization-state.json"
    if not journal_path.exists():
        return None
    try:
        journal = PersistenceJournalV1.model_validate_json(
            _safe_read(run_dir, journal_path.name)
        )
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid finalization state journal: {exc}"
        ) from exc
    if journal.quarantine_bundle is not None:
        write_quarantine_bundle(run_dir, journal.quarantine_bundle)
    if journal.admitted_publication is not None:
        _write_admitted_publication(run_dir, journal.admitted_publication)
    write_finalization_inventory(run_dir, journal.finalization_inventory)
    write_coverage_plan(run_dir, journal.coverage_plan)
    journal_path.unlink()
    dir_fd = os.open(run_dir, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return journal.coverage_plan


def _read_model(
    run_dir: Path,
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
    model_type: type[StrictModel],
) -> Any:
    if entry is not None:
        if entry.role is not role or entry.path != expected_path:
            raise ManifestIntegrityError(
                f"{role.value} role/path mismatch: {entry.role.value} {entry.path}"
            )
        content = _safe_read(run_dir, expected_path)
        actual = hashlib.sha256(content).hexdigest()
        if actual != entry.sha256:
            raise ManifestIntegrityError(f"Hash mismatch for {entry.path}")
    try:
        return model_type.model_validate_json(
            content if entry is not None else _safe_read(run_dir, expected_path)
        )
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid {role.value}: {exc}") from exc


def validate_v3_inventories(resolver: Any) -> None:
    """Reconcile manifest v3, coverage, finalization, and quarantine receipts."""

    if (resolver.run_dir / ".finalization-state.json").exists():
        raise ManifestIntegrityError(
            "Manifest v3 cannot finalize with an unresolved journal"
        )
    coverage_entry = resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN)
    final_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
    if coverage_entry is None or final_entry is None:
        raise ManifestIntegrityError("Manifest v3 persistence singletons are missing")
    try:
        coverage = CoveragePlanV2.model_validate(resolver.read_json(coverage_entry))
        final = FinalizationInventoryV1.model_validate(resolver.read_json(final_entry))
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Invalid manifest v3 persistence model: {exc}"
        ) from exc
    if final.run_id != resolver.manifest.run_id:
        raise ManifestIntegrityError("Finalization inventory run_id mismatch")
    if final.coverage_plan_sha256 != coverage_entry.sha256:
        raise ManifestIntegrityError("Finalization coverage plan hash mismatch")

    plan_by_candidate = {
        choice.candidate_id: (target, choice)
        for target in coverage.targets
        for choice in target.ordered_choices
    }
    plan_target_ids = {target.entry_point_id for target in coverage.targets}
    for transition in final.transitions:
        if transition.target_entry_point_id not in plan_target_ids:
            raise ManifestIntegrityError(
                "Lifecycle transition target is absent from plan"
            )
        if transition.candidate_id is not None:
            planned = plan_by_candidate.get(transition.candidate_id)
            if (
                planned is None
                or planned[0].entry_point_id != transition.target_entry_point_id
            ):
                raise ManifestIntegrityError(
                    "Lifecycle transition candidate/target is absent from plan"
                )
    admitted = {receipt.candidate_id for receipt in final.admitted_inventory}
    quarantined = {receipt.candidate_id for receipt in final.quarantine_inventory}
    if admitted & quarantined:
        raise ManifestIntegrityError("Admitted and quarantine inventories overlap")
    for attempt in final.candidate_attempts:
        planned = plan_by_candidate.get(attempt.candidate_id)
        if planned is None:
            raise ManifestIntegrityError(
                "Finalization attempt is absent from coverage plan"
            )
        target, choice = planned
        if (
            attempt.target_entry_point_id != target.entry_point_id
            or attempt.queue_rank != choice.rank
        ):
            raise ManifestIntegrityError(
                "Finalization attempt does not match coverage plan"
            )

    attempts_by_target: dict[str, list[CandidateAttemptRecord]] = {}
    for attempt in final.candidate_attempts:
        attempts_by_target.setdefault(attempt.target_entry_point_id, []).append(attempt)
    attempts_by_target_id = {
        target_id: [item.candidate_id for item in attempts]
        for target_id, attempts in attempts_by_target.items()
    }
    for target in coverage.targets:
        if target.attempted_candidate_ids != attempts_by_target_id.get(
            target.entry_point_id, []
        ):
            raise ManifestIntegrityError(
                "Coverage plan attempted candidates do not match finalization inventory"
            )
    admitted_decisions = {
        decision.candidate_id
        for decision in final.admission_decisions
        if decision.admitted
    }
    attempted_candidates = {item.candidate_id for item in final.candidate_attempts}
    terminal_candidates = {item.candidate_id for item in final.admission_decisions}
    if attempted_candidates != terminal_candidates:
        raise ManifestIntegrityError(
            "Every attempted candidate requires exactly one terminal decision"
        )
    nonadmitted_decisions = terminal_candidates - admitted_decisions
    if admitted != admitted_decisions:
        raise ManifestIntegrityError(
            "Admitted receipts must exactly match admitted terminal decisions"
        )
    if quarantined != nonadmitted_decisions:
        raise ManifestIntegrityError(
            "Quarantine receipts must exactly match non-admitted terminal decisions"
        )
    for attempts in attempts_by_target.values():
        ranks = [item.queue_rank for item in attempts]
        if any(right <= left for left, right in zip(ranks, ranks[1:])):
            raise ManifestIntegrityError(
                "Fallback attempts must have increasing queue rank"
            )
        if attempts and not attempts[0].is_primary:
            raise ManifestIntegrityError(
                "Primary candidate must be attempted before fallback"
            )
        if any(item.is_primary for item in attempts[1:]):
            raise ManifestIntegrityError("Only the first target attempt may be primary")
        for index, attempt in enumerate(attempts[:-1]):
            if attempt.candidate_id in admitted_decisions:
                raise ManifestIntegrityError(
                    "Fallback attempted after target admission"
                )
    for target in coverage.targets:
        target_admitted = [
            candidate_id
            for candidate_id in target.attempted_candidate_ids
            if candidate_id in admitted_decisions
        ]
        if target.target_state is TargetState.admitted:
            if target_admitted != [target.admitted_candidate_id]:
                raise ManifestIntegrityError(
                    "Coverage target admission does not match terminal decision"
                )
        elif target.target_state is not TargetState.exhausted:
            raise ManifestIntegrityError(
                "Completed manifest v3 targets must be admitted or exhausted"
            )
        target_transitions = [
            item
            for item in final.transitions
            if item.target_entry_point_id == target.entry_point_id
        ]
        expected_terminal = (
            LifecycleState.admitted
            if target.target_state is TargetState.admitted
            else LifecycleState.exhausted
        )
        if (
            not target_transitions
            or target_transitions[-1].current is not expected_terminal
        ):
            raise ManifestIntegrityError(
                "Coverage target state does not match its terminal transition"
            )

    manifest_entries = {
        (entry.role, entry.path, entry.candidate_id, entry.scenario_id, entry.sha256)
        for entry in resolver.manifest.inventory
        if entry.role
        in {
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
            ArtifactRole.QUARANTINE_BUNDLE,
        }
    }
    receipt_entries = {
        (item.role, item.path, item.candidate_id, item.scenario_id, item.sha256)
        for item in [*final.admitted_inventory, *final.quarantine_inventory]
    }
    if manifest_entries != receipt_entries:
        raise ManifestIntegrityError(
            "Finalization receipts and manifest entries must match exactly"
        )

    for candidate_id in admitted:
        receipts = [
            item
            for item in final.admitted_inventory
            if item.candidate_id == candidate_id
        ]
        if sorted(
            (item.role for item in receipts), key=lambda role: role.value
        ) != sorted(
            [ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE],
            key=lambda role: role.value,
        ):
            raise ManifestIntegrityError(
                "Every admitted candidate requires one YAML/feature pair"
            )
        if len({item.scenario_id for item in receipts}) != 1:
            raise ManifestIntegrityError(
                "Admitted YAML/feature receipts require the same scenario_id"
            )
    for candidate_id in quarantined:
        receipts = [
            item
            for item in final.quarantine_inventory
            if item.candidate_id == candidate_id
        ]
        if len(receipts) != 1 or receipts[0].role is not ArtifactRole.QUARANTINE_BUNDLE:
            raise ManifestIntegrityError(
                "Every quarantined candidate requires one bundle only"
            )

    eval_candidates = {
        entry.candidate_id
        for entry in resolver.manifest.inventory
        if entry.role is ArtifactRole.EVAL_SCORECARD and entry.candidate_id
    }
    if eval_candidates & quarantined:
        raise ManifestIntegrityError(
            "Evaluation inventory contains quarantined candidate"
        )
    bundle_candidates = {
        entry.candidate_id
        for entry in resolver.manifest.inventory
        if entry.role is ArtifactRole.QUARANTINE_BUNDLE
    }
    normal_candidates = {
        entry.candidate_id
        for entry in resolver.manifest.inventory
        if entry.role in {ArtifactRole.SCENARIO_YAML, ArtifactRole.SCENARIO_FEATURE}
    }
    if bundle_candidates & normal_candidates:
        raise ManifestIntegrityError(
            "Quarantine candidate carries a normal scenario role"
        )
    if normal_candidates != admitted:
        raise ManifestIntegrityError(
            "Normal scenario inventory must contain admitted candidates only"
        )
    for entry in resolver.entries_by_role(ArtifactRole.QUARANTINE_BUNDLE):
        try:
            bundle = QuarantineBundleV1.model_validate(resolver.read_json(entry))
        except Exception as exc:
            raise ManifestIntegrityError(
                f"Invalid quarantine bundle {entry.path}: {exc}"
            ) from exc
        if (
            bundle.run_id != resolver.manifest.run_id
            or bundle.candidate_id != entry.candidate_id
            or entry.path != f"quarantine/{bundle.attempt_id}.json"
        ):
            raise ManifestIntegrityError(
                f"Quarantine bundle identity/path mismatch: {entry.path}"
            )
        attempt = next(
            (
                item
                for item in final.candidate_attempts
                if item.candidate_id == bundle.candidate_id
            ),
            None,
        )
        if (
            attempt is None
            or attempt.attempt_id != bundle.attempt_id
            or attempt.target_entry_point_id != bundle.target_entry_point_id
        ):
            raise ManifestIntegrityError(
                f"Quarantine bundle does not match candidate attempt: {entry.path}"
            )
        decision = next(
            item
            for item in final.admission_decisions
            if item.candidate_id == bundle.candidate_id
        )
        if bundle.violations != decision.violations:
            raise ManifestIntegrityError(
                f"Quarantine bundle violations mismatch terminal decision: {entry.path}"
            )
        for stage in GeneratedStage:
            latest = next(
                (
                    item
                    for item in reversed(final.stage_attempts)
                    if item.candidate_id == bundle.candidate_id
                    and item.stage is stage
                    and item.result is not None
                ),
                None,
            )
            if getattr(bundle, stage.value) != (
                latest.result if latest is not None else None
            ):
                raise ManifestIntegrityError(
                    f"Quarantine bundle {stage.value} evidence mismatch: {entry.path}"
                )
    expected_status = (
        RunStatus.COMPLETED_WITH_ERRORS if quarantined else RunStatus.COMPLETED
    )
    if resolver.manifest.status is not expected_status:
        raise ManifestIntegrityError(
            "Manifest v3 completed_with_errors iff quarantine inventory is nonempty"
        )


def _violations(values: Any) -> list[ViolationRecord]:
    records: list[ViolationRecord] = []
    for value in values:
        owner = getattr(value, "owner", None)
        code = getattr(value, "code", "invalid")
        if isinstance(code, Enum):
            serialized_code = code.value
        elif isinstance(code, str):
            serialized_code = code
        else:
            raise TypeError("violation code must be a string or enum")
        records.append(
            ViolationRecord(
                code=serialized_code,
                detail=value.detail,
                owner=owner,
                retryable=getattr(value, "retryable", owner is not None),
            )
        )
    return records


def make_admitted_terminal_payload(
    report: Any, publication: AdmittedArtifactPublication
) -> AdmittedTerminalPayload:
    """Phase 5 seam joining concrete admission gates to publication bytes."""

    return AdmittedTerminalPayload(
        gate_results=[
            GateResultRecord(
                gate=f"admission_gate_{index}",
                passed=gate.passed,
                violations=_violations(gate.violations),
                diagnostics=_violations(gate.diagnostics),
            )
            for index, gate in enumerate(getattr(report, "gate_results", ()))
        ],
        publication=publication,
    )


def _llm_result(value: Any) -> LLMResultRecord:
    return LLMResultRecord(
        content=_json_value(value.content),
        prompt_tokens=value.prompt_tokens,
        completion_tokens=value.completion_tokens,
        duration_ms=value.duration_ms,
        system_prompt=value.system_prompt,
        user_prompt=value.user_prompt,
    )


def _call_evidence(value: StageCallEvidence) -> StageCallEvidenceRecord:
    return StageCallEvidenceRecord(
        call_name=value.call_name.value,
        result=_llm_result(value.result),
        metadata=CallMetadataRecord(
            call=value.metadata.call.value,
            prompt_tokens=value.metadata.prompt_tokens,
            completion_tokens=value.metadata.completion_tokens,
            duration_ms=value.metadata.duration_ms,
        ),
    )


def _attempt_failure(value: StageAttemptFailure) -> StageAttemptFailureRecord:
    prompt = (
        PromptRecord(
            system_prompt=value.system_prompt,
            user_prompt=value.user_prompt,
        )
        if value.system_prompt is not None or value.user_prompt is not None
        else None
    )
    return StageAttemptFailureRecord(
        call_name=value.call_name.value,
        exception_type=value.exception_type,
        detail=value.detail,
        phase=value.phase,
        invoked=value.invoked,
        prompt=prompt,
        result=_llm_result(value.result) if value.result is not None else None,
        raw_response=(
            _json_value(value.raw_response) if value.raw_response is not None else None
        ),
    )


def _event_key(kind: str, identity: Any) -> str:
    return canonical_sha256({"kind": kind, "identity": identity})


def _verify_event(item: Any, kind: str, identity: Any, payload: Any) -> None:
    if item.event_id != _event_key(kind, identity):
        raise ValueError(f"{kind} event ID mismatch")
    if item.payload_sha256 != canonical_sha256(payload):
        raise ValueError(f"{kind} payload digest mismatch")


def _publication_receipts(
    publication: AdmittedArtifactPublication,
) -> list[ArtifactReceipt]:
    return [
        ArtifactReceipt(
            candidate_id=publication.candidate_id,
            role=role,
            path=f"scenarios/{publication.scenario_id}{suffix}",
            sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            scenario_id=publication.scenario_id,
        )
        for role, suffix, content in (
            (ArtifactRole.SCENARIO_YAML, ".yaml", publication.yaml_text),
            (ArtifactRole.SCENARIO_FEATURE, ".feature", publication.feature_text),
        )
    ]


def _write_admitted_publication(
    run_dir: Path, publication: AdmittedArtifactPublication
) -> None:
    for receipt, content in zip(
        _publication_receipts(publication),
        (publication.yaml_text, publication.feature_text),
        strict=True,
    ):
        _exclusive_create(run_dir, receipt.path, content.encode("utf-8"))


class FinalizationPersistenceAdapter:
    """Journaled, durable implementation of ``FinalizationPersistencePort``."""

    def __init__(
        self,
        run_dir: Path,
        inventory: FinalizationInventoryV1,
        coverage_plan: CoveragePlanV2,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.inventory = inventory
        self.coverage_plan = coverage_plan
        self._lock = threading.Lock()
        self._candidate_plan = {
            choice.candidate_id: (target.entry_point_id, choice.rank)
            for target in coverage_plan.targets
            for choice in target.ordered_choices
        }
        self._events = {
            item.event_id: item.payload_sha256
            for item in [
                *inventory.candidate_attempts,
                *inventory.stage_attempts,
                *inventory.transitions,
                *inventory.repairs,
                *inventory.admission_decisions,
            ]
        }
        self._failed = False

    def _sequence(self, inventory: FinalizationInventoryV1) -> int:
        return sum(
            len(items)
            for items in (
                inventory.candidate_attempts,
                inventory.stage_attempts,
                inventory.transitions,
                inventory.repairs,
                inventory.admission_decisions,
            )
        )

    def _replayed(self, event_id: str, payload_sha256: str) -> bool:
        existing = self._events.get(event_id)
        if existing is None:
            return False
        if existing != payload_sha256:
            raise ManifestIntegrityError(
                f"Conflicting duplicate persistence event {event_id}"
            )
        return True

    def _derive_plan(self, inventory: FinalizationInventoryV1) -> CoveragePlanV2:
        decisions = {item.candidate_id: item for item in inventory.admission_decisions}
        next_targets: list[CoverageTargetEntry] = []
        for target in self.coverage_plan.targets:
            attempted = [
                item.candidate_id
                for item in sorted(
                    inventory.candidate_attempts, key=lambda item: item.sequence
                )
                if item.target_entry_point_id == target.entry_point_id
            ]
            admitted = next(
                (
                    candidate_id
                    for candidate_id in attempted
                    if candidate_id in decisions and decisions[candidate_id].admitted
                ),
                None,
            )
            choice_ids = [item.candidate_id for item in target.ordered_choices]
            terminal = bool(attempted) and all(
                candidate_id in decisions for candidate_id in attempted
            )
            if admitted is not None:
                state = TargetState.admitted
                fallback: list[QualifiedCandidateRef] = []
            elif attempted == choice_ids and terminal:
                state = TargetState.exhausted
                fallback = []
            elif not choice_ids and any(
                item.target_entry_point_id == target.entry_point_id
                and item.current is LifecycleState.exhausted
                for item in inventory.transitions
            ):
                state = TargetState.exhausted
                fallback = []
            else:
                state = TargetState.selected
                fallback = target.ordered_choices[len(attempted) :]
            next_targets.append(
                target.model_copy(
                    update={
                        "attempted_candidate_ids": attempted,
                        "admitted_candidate_id": admitted,
                        "target_state": state,
                        "fallback_available": fallback,
                    }
                )
            )
        return CoveragePlanV2.model_validate(
            self.coverage_plan.model_copy(update={"targets": next_targets}).model_dump(
                mode="python"
            )
        )

    def _commit(
        self,
        next_inventory: FinalizationInventoryV1,
        *,
        quarantine_bundle: QuarantineBundleV1 | None = None,
        admitted_publication: AdmittedArtifactPublication | None = None,
    ) -> None:
        if self._failed:
            raise FinalizationPersistenceError(
                "Persistence adapter requires journal recovery before reuse"
            )
        if (self.run_dir / ".finalization-state.json").exists():
            self._failed = True
            raise FinalizationPersistenceError(
                "Unresolved finalization journal must be recovered before another event"
            )
        next_plan = self._derive_plan(next_inventory)
        plan_sha256 = hashlib.sha256(canonical_json_bytes(next_plan)).hexdigest()
        next_inventory = FinalizationInventoryV1.model_validate(
            next_inventory.model_copy(
                update={"coverage_plan_sha256": plan_sha256}
            ).model_dump(mode="python")
        )
        journal = PersistenceJournalV1(
            schema_version="1",
            coverage_plan=next_plan,
            finalization_inventory=next_inventory,
            quarantine_bundle=quarantine_bundle,
            admitted_publication=admitted_publication,
        )
        try:
            _write_model(self.run_dir, ".finalization-state.json", journal)
            if quarantine_bundle is not None:
                write_quarantine_bundle(self.run_dir, quarantine_bundle)
            if admitted_publication is not None:
                _write_admitted_publication(self.run_dir, admitted_publication)
            write_finalization_inventory(self.run_dir, next_inventory)
            write_coverage_plan(self.run_dir, next_plan)
            journal_path = self.run_dir / ".finalization-state.json"
            journal_path.unlink()
            dir_fd = os.open(self.run_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception as exc:
            self._failed = True
            raise FinalizationPersistenceError(
                f"Finalization state commit failed: {exc}"
            ) from exc
        self.inventory = next_inventory
        self.coverage_plan = next_plan
        self._events = {
            item.event_id: item.payload_sha256
            for item in [
                *next_inventory.candidate_attempts,
                *next_inventory.stage_attempts,
                *next_inventory.transitions,
                *next_inventory.repairs,
                *next_inventory.admission_decisions,
            ]
        }

    def _candidate_attempt(
        self, inventory: FinalizationInventoryV1, candidate_id: str
    ) -> CandidateAttemptRecord:
        attempt = next(
            (
                item
                for item in inventory.candidate_attempts
                if item.candidate_id == candidate_id
            ),
            None,
        )
        if attempt is None:
            raise ManifestIntegrityError(
                f"Persistence callback has no CandidateAttemptRecord for {candidate_id}"
            )
        return attempt

    def record_transition(self, transition: LifecycleTransition) -> None:
        with self._lock:
            payload = {
                "previous": transition.previous.value,
                "current": transition.current.value,
                "candidate_id": transition.candidate_id,
                "reason": transition.reason,
                "transition_index": transition.transition_index,
            }
            target_id = transition.target_entry_point_id
            if target_id is None and transition.candidate_id in self._candidate_plan:
                target_id = self._candidate_plan[transition.candidate_id][0]
            if target_id is None:
                raise ManifestIntegrityError(
                    "Lifecycle transition requires target identity"
                )
            payload["target_entry_point_id"] = target_id
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key(
                "transition", [target_id, transition.transition_index]
            )
            if self._replayed(event_id, payload_sha256):
                return
            next_inventory = self.inventory.model_copy(deep=True)
            if transition.current is LifecycleState.revalidating_candidate:
                candidate_id = transition.candidate_id
                if candidate_id not in self._candidate_plan:
                    raise ManifestIntegrityError(
                        f"Unknown coverage-plan candidate {candidate_id!r}"
                    )
                if not any(
                    item.candidate_id == candidate_id
                    for item in next_inventory.candidate_attempts
                ):
                    target_id, queue_rank = self._candidate_plan[candidate_id]
                    candidate_payload = {
                        "candidate_id": candidate_id,
                        "target_entry_point_id": target_id,
                        "queue_rank": queue_rank,
                    }
                    candidate_event = _event_key("candidate_attempt", candidate_id)
                    candidate_digest = canonical_sha256(candidate_payload)
                    if not self._replayed(candidate_event, candidate_digest):
                        next_inventory.candidate_attempts.append(
                            CandidateAttemptRecord(
                                event_id=candidate_event,
                                payload_sha256=candidate_digest,
                                sequence=self._sequence(next_inventory),
                                attempt_id=f"{candidate_id}:candidate",
                                candidate_id=candidate_id,
                                target_entry_point_id=target_id,
                                queue_rank=queue_rank,
                                is_primary=queue_rank == 0,
                                stage_attempt_ids=[],
                            )
                        )
            elif transition.candidate_id is not None:
                self._candidate_attempt(next_inventory, transition.candidate_id)
            next_inventory.transitions.append(
                TransitionRecord(
                    event_id=event_id,
                    payload_sha256=payload_sha256,
                    sequence=self._sequence(next_inventory),
                    target_entry_point_id=target_id,
                    index=transition.transition_index,
                    previous=transition.previous,
                    current=transition.current,
                    candidate_id=transition.candidate_id,
                    reason=transition.reason,
                )
            )
            self._commit(next_inventory)

    def record_stage_result(
        self, invocation: StageInvocation, result: GeneratedStageResult
    ) -> None:
        with self._lock:
            attempt_id = (
                f"{invocation.candidate_id}:{invocation.stage.value}:"
                f"{invocation.invocation_index}"
            )
            next_inventory = self.inventory.model_copy(deep=True)
            candidate_attempt = self._candidate_attempt(
                next_inventory, invocation.candidate_id
            )
            if isinstance(result.evidence, StageCallEvidence):
                call = _call_evidence(result.evidence)
                failure = None
                prompt = PromptRecord(
                    system_prompt=call.result.system_prompt,
                    user_prompt=call.result.user_prompt,
                )
            elif isinstance(result.evidence, StageAttemptFailure):
                call = None
                failure = _attempt_failure(result.evidence)
                prompt = failure.prompt
            else:
                raise TypeError(
                    "stage persistence requires StageCallEvidence or StageAttemptFailure"
                )
            visible_artifacts = {
                stage.value: _json_value(invocation.artifacts.get(stage))
                for stage in GeneratedStage
                if invocation.artifacts.get(stage) is not None
            }
            if invocation.candidate_snapshot is None:
                raise TypeError("stage persistence requires a candidate snapshot")
            candidate = _json_value(invocation.candidate_snapshot)
            output = (
                _json_value(result.artifact) if result.artifact is not None else None
            )
            input_record = StageInputRecord(
                candidate=candidate,
                candidate_id=invocation.candidate_id,
                stage=invocation.stage,
                invocation_index=invocation.invocation_index,
                owner_retry_index=invocation.owner_retry_index,
                visible_artifacts=visible_artifacts,
                prompt=prompt,
                final_tree_digest=invocation.final_tree_digest,
            )
            input_payload = input_record.model_dump(mode="json")
            payload = {
                "attempt_id": attempt_id,
                "input": input_payload,
                "call": call.model_dump(mode="json") if call else None,
                "failure": failure.model_dump(mode="json") if failure else None,
                "result": output,
                "violations": [
                    item.model_dump(mode="json")
                    for item in _violations(result.violations)
                ],
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key("stage_attempt", attempt_id)
            if self._replayed(event_id, payload_sha256):
                return
            record = StageAttemptRecord(
                event_id=event_id,
                payload_sha256=payload_sha256,
                sequence=self._sequence(next_inventory),
                attempt_id=attempt_id,
                candidate_id=invocation.candidate_id,
                stage=invocation.stage,
                invocation_index=invocation.invocation_index,
                owner_retry_index=invocation.owner_retry_index,
                prompt=prompt,
                call=call,
                result=output,
                failure=failure,
                input=input_record,
                input_sha256=canonical_sha256(input_payload),
                candidate_snapshot_sha256=canonical_sha256(candidate),
                final_tree_snapshot_sha256=invocation.final_tree_digest,
                output_sha256=(
                    canonical_sha256(result.artifact)
                    if result.artifact is not None
                    else None
                ),
                violations=_violations(result.violations),
            )
            next_inventory.stage_attempts.append(record)
            candidate_attempt.stage_attempt_ids.append(attempt_id)
            self._commit(next_inventory)

    def record_candidate_result(
        self, candidate_id: str, result: CandidateTerminalResult
    ) -> None:
        with self._lock:
            if result.candidate_id != candidate_id:
                raise ValueError("candidate terminal result identity mismatch")
            next_inventory = self.inventory.model_copy(deep=True)
            candidate_attempt = self._candidate_attempt(next_inventory, candidate_id)
            report = result.admission.value if result.admission is not None else None
            terminal_payload = (
                AdmittedTerminalPayload.model_validate(report)
                if result.status is CandidateTerminalStatus.admitted
                else None
            )
            gate_results = (
                terminal_payload.gate_results
                if terminal_payload is not None
                else [
                    GateResultRecord(
                        gate=f"admission_gate_{index}",
                        passed=gate.passed,
                        violations=_violations(gate.violations),
                        diagnostics=_violations(gate.diagnostics),
                    )
                    for index, gate in enumerate(getattr(report, "gate_results", ()))
                ]
            )
            target_transitions = [
                item
                for item in next_inventory.transitions
                if item.target_entry_point_id == candidate_attempt.target_entry_point_id
            ]
            if not target_transitions:
                raise ManifestIntegrityError(
                    "Terminal result requires a preceding target transition"
                )
            terminal_state = (
                LifecycleState.admitted
                if result.status is CandidateTerminalStatus.admitted
                else LifecycleState.rejected
            )
            transition_index = len(target_transitions)
            transition_payload = {
                "previous": target_transitions[-1].current.value,
                "current": terminal_state.value,
                "candidate_id": candidate_id,
                "reason": f"candidate terminal status: {result.status.value}",
                "transition_index": transition_index,
                "target_entry_point_id": candidate_attempt.target_entry_point_id,
            }
            transition_event_id = _event_key(
                "transition",
                [candidate_attempt.target_entry_point_id, transition_index],
            )
            transition_payload_sha256 = canonical_sha256(transition_payload)
            stages = [
                item
                for item in next_inventory.stage_attempts
                if item.candidate_id == candidate_id
            ]
            latest = {stage: None for stage in GeneratedStage}
            for item in stages:
                if item.output_sha256 is not None:
                    latest[item.stage] = item
            snapshots = {
                "candidate_snapshot_sha256": stages[-1].candidate_snapshot_sha256
                if stages
                else None,
                "actor_snapshot_sha256": latest[GeneratedStage.actor].output_sha256
                if latest[GeneratedStage.actor]
                else None,
                "narrative_snapshot_sha256": latest[
                    GeneratedStage.narrative
                ].output_sha256
                if latest[GeneratedStage.narrative]
                else None,
                "final_tree_snapshot_sha256": next(
                    (
                        item.final_tree_snapshot_sha256
                        for item in reversed(stages)
                        if item.stage is GeneratedStage.behavior
                        and item.final_tree_snapshot_sha256 is not None
                    ),
                    None,
                ),
            }
            payload = {
                "candidate_id": candidate_id,
                "status": result.status.value,
                "violations": [
                    item.model_dump(mode="json")
                    for item in _violations(result.violations)
                ],
                "gate_results": [item.model_dump(mode="json") for item in gate_results],
                "snapshots": snapshots,
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key("candidate_result", candidate_id)
            if self._replayed(event_id, payload_sha256):
                return
            next_inventory.transitions.append(
                TransitionRecord(
                    event_id=transition_event_id,
                    payload_sha256=transition_payload_sha256,
                    sequence=self._sequence(next_inventory),
                    target_entry_point_id=candidate_attempt.target_entry_point_id,
                    index=transition_index,
                    previous=target_transitions[-1].current,
                    current=terminal_state,
                    candidate_id=candidate_id,
                    reason=transition_payload["reason"],
                )
            )
            decision = AdmissionDecisionRecord(
                event_id=event_id,
                payload_sha256=payload_sha256,
                sequence=self._sequence(next_inventory),
                candidate_id=candidate_id,
                status=result.status,
                admitted=result.status is CandidateTerminalStatus.admitted,
                gate_results=gate_results,
                violations=_violations(result.violations),
                **snapshots,
            )
            next_inventory.admission_decisions.append(decision)
            bundle = None
            publication = None
            if decision.admitted:
                assert terminal_payload is not None
                publication = terminal_payload.publication
                if publication.candidate_id != candidate_id:
                    raise ManifestIntegrityError(
                        "Admitted publication candidate identity mismatch"
                    )
                next_inventory.admitted_inventory.extend(
                    _publication_receipts(publication)
                )
            else:
                target_id = candidate_attempt.target_entry_point_id
                artifacts = {
                    stage: latest[stage].result if latest[stage] is not None else None
                    for stage in GeneratedStage
                }
                digests = {
                    stage: canonical_sha256(artifact)
                    for stage, artifact in artifacts.items()
                    if artifact is not None
                }
                bundle = QuarantineBundleV1(
                    schema_version="1",
                    run_id=next_inventory.run_id,
                    attempt_id=candidate_attempt.attempt_id,
                    candidate_id=candidate_id,
                    target_entry_point_id=target_id,
                    actor=artifacts[GeneratedStage.actor],
                    narrative=artifacts[GeneratedStage.narrative],
                    tree=artifacts[GeneratedStage.tree],
                    behavior=artifacts[GeneratedStage.behavior],
                    artifact_sha256=digests,
                    violations=_violations(result.violations),
                )
                bundle_path = f"quarantine/{bundle.attempt_id}.json"
                next_inventory.quarantine_inventory.append(
                    ArtifactReceipt(
                        candidate_id=candidate_id,
                        role=ArtifactRole.QUARANTINE_BUNDLE,
                        path=bundle_path,
                        sha256=hashlib.sha256(canonical_json_bytes(bundle)).hexdigest(),
                        scenario_id=None,
                    )
                )
            self._commit(
                next_inventory,
                quarantine_bundle=bundle,
                admitted_publication=publication,
            )

    def record_repair(self, candidate_id: str, record: Any) -> None:
        with self._lock:
            next_inventory = self.inventory.model_copy(deep=True)
            attempt = self._candidate_attempt(next_inventory, candidate_id)
            payload = {
                "candidate_id": candidate_id,
                "before_digest": record.before_digest,
                "after_digest": record.after_digest,
                "removed_ids": list(record.removed_ids),
                "preserved_projected_ids": list(record.preserved_projected_ids),
                "accepted": record.accepted,
                "detail": record.detail,
            }
            payload_sha256 = canonical_sha256(payload)
            event_id = _event_key(
                "parsimony_repair", [candidate_id, record.before_digest]
            )
            if self._replayed(event_id, payload_sha256):
                return
            next_inventory.repairs.append(
                ParsimonyRepairRecord(
                    event_id=event_id,
                    payload_sha256=payload_sha256,
                    sequence=self._sequence(next_inventory),
                    candidate_attempt_id=attempt.attempt_id,
                    candidate_id=candidate_id,
                    target_entry_point_id=attempt.target_entry_point_id,
                    before_digest=record.before_digest,
                    after_digest=record.after_digest,
                    removed_ids=list(record.removed_ids),
                    preserved_projected_ids=list(record.preserved_projected_ids),
                    accepted=record.accepted,
                    detail=record.detail,
                )
            )
            self._commit(next_inventory)


def make_finalization_persistence_adapter(
    run_dir: Path,
    *,
    run_id: str,
    coverage_plan: CoveragePlanV2,
) -> FinalizationPersistenceAdapter:
    """Phase 5 factory; creates no runner coupling and activates no manifest version."""

    run_dir = Path(run_dir)
    recovered_plan = _recover_journal(run_dir)
    if recovered_plan is not None:
        coverage_plan = recovered_plan
    coverage_plan = CoveragePlanV2.model_validate(
        coverage_plan.model_dump(mode="python")
    )
    coverage_plan_sha256 = hashlib.sha256(
        canonical_json_bytes(coverage_plan)
    ).hexdigest()
    plan_path = run_dir / "coverage-plan.json"
    if plan_path.exists():
        persisted_plan = read_coverage_plan(run_dir)
        if persisted_plan != coverage_plan:
            raise ManifestIntegrityError(
                "Supplied coverage plan differs from persisted plan"
            )
    else:
        write_coverage_plan(run_dir, coverage_plan)
    path = run_dir / "finalization-inventory.json"
    if path.exists():
        inventory = read_finalization_inventory(Path(run_dir))
        if (
            inventory.run_id != run_id
            or inventory.coverage_plan_sha256 != coverage_plan_sha256
        ):
            raise ManifestIntegrityError(
                "Existing finalization inventory identity mismatch"
            )
    else:
        inventory = FinalizationInventoryV1(
            schema_version="1",
            run_id=run_id,
            coverage_plan_sha256=coverage_plan_sha256,
            candidate_attempts=[],
            stage_attempts=[],
            transitions=[],
            repairs=[],
            admission_decisions=[],
            admitted_inventory=[],
            quarantine_inventory=[],
        )
        write_finalization_inventory(run_dir, inventory)
    return FinalizationPersistenceAdapter(run_dir, inventory, coverage_plan)
