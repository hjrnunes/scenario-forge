"""Unwired cmps.5 Phase 4 persistence contracts and manifest-v3 validation.

These contracts deliberately do not activate manifest v3 or invoke the
finalization machine from the production runner.  They are adapters for the
Phase 5 dependency-injection boundary.
"""

from __future__ import annotations

import hashlib
import json
import threading
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

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
    LifecycleState,
    LifecycleTransition,
    StageInvocation,
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
        projected_id = self.projected_candidate.get("candidate_id")
        if projected_id != self.candidate_id:
            raise ValueError(
                "projected_candidate candidate_id does not match reference"
            )
        if self.entry_point_id != self.projected_candidate.get(
            "canonical_ingress", {}
        ).get("entry_point_id"):
            raise ValueError("projected_candidate ingress does not match reference")
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
        ranks = [choice.rank for choice in self.ordered_choices]
        if any(right <= left for left, right in zip(ranks, ranks[1:])):
            raise ValueError("ordered choice queue ranks must be strictly increasing")
        if self.admitted_candidate_id is not None:
            if self.admitted_candidate_id not in attempted:
                raise ValueError("admitted candidate must have been attempted")
            if self.target_state is not TargetState.admitted:
                raise ValueError("admitted candidate requires target_state=admitted")
        elif self.target_state is TargetState.admitted:
            raise ValueError("target_state=admitted requires admitted_candidate_id")
        if self.target_state is TargetState.exhausted and self.fallback_available:
            raise ValueError("exhausted target cannot retain fallback availability")
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
        return self


class ViolationRecord(StrictModel):
    code: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    owner: GeneratedStage | None
    retryable: bool


class StageAttemptRecord(StrictModel):
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    stage: GeneratedStage
    invocation_index: int = Field(ge=0)
    owner_retry_index: int = Field(ge=0, le=MAX_OWNER_RETRIES)
    prompt: Any | None
    call: Any | None
    result: Any | None
    failure: Any | None
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    output_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    violations: list[ViolationRecord]

    @model_validator(mode="after")
    def _one_result_shape(self) -> StageAttemptRecord:
        if self.result is not None and self.failure is not None:
            raise ValueError("stage attempt cannot contain both result and failure")
        return self


class CandidateAttemptRecord(StrictModel):
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    queue_rank: int = Field(ge=0)
    is_primary: bool
    stage_attempt_ids: list[str]


class TransitionRecord(StrictModel):
    index: int = Field(ge=0)
    previous: LifecycleState
    current: LifecycleState
    candidate_id: str | None
    reason: str = Field(min_length=1)


class RepairRecord(StrictModel):
    repair_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    owner: GeneratedStage
    retry_index: int = Field(ge=1, le=MAX_OWNER_RETRIES)
    triggering_violation_codes: list[str] = Field(min_length=1)
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    output_sha256: str = Field(pattern=SHA256_PATTERN)


class GateResultRecord(StrictModel):
    gate: str = Field(min_length=1)
    passed: bool
    violations: list[ViolationRecord]
    diagnostics: list[ViolationRecord]


class AdmissionDecisionRecord(StrictModel):
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
        if (
            PurePosixPath(value).as_posix() != value
            or ".." in PurePosixPath(value).parts
        ):
            raise ValueError("artifact receipt path must be canonical and relative")
        return value


class FinalizationInventoryV1(StrictModel):
    schema_version: Literal["1"]
    run_id: str = Field(min_length=1)
    coverage_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_attempts: list[CandidateAttemptRecord]
    stage_attempts: list[StageAttemptRecord]
    transitions: list[TransitionRecord]
    repairs: list[RepairRecord]
    admission_decisions: list[AdmissionDecisionRecord]
    admitted_inventory: list[ArtifactReceipt]
    quarantine_inventory: list[ArtifactReceipt]

    @model_validator(mode="after")
    def _local_integrity(self) -> FinalizationInventoryV1:
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
        if [item.index for item in self.transitions] != list(
            range(len(self.transitions))
        ):
            raise ValueError("transition indexes must be contiguous from zero")
        for previous, current in zip(self.transitions, self.transitions[1:]):
            if previous.current is not current.previous:
                raise ValueError("transition state chain is noncontiguous")
        stage_by_id = {item.attempt_id: item for item in self.stage_attempts}
        for attempt in self.candidate_attempts:
            for stage_id in attempt.stage_attempt_ids:
                stage = stage_by_id.get(stage_id)
                if stage is None or stage.candidate_id != attempt.candidate_id:
                    raise ValueError(
                        "candidate attempt references an invalid stage attempt"
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
        decisions = [item.candidate_id for item in self.admission_decisions]
        if len(decisions) != len(set(decisions)):
            raise ValueError("duplicate terminal admission decisions")
        return self


class QuarantineBundleV1(StrictModel):
    """Forensic generated layers; deliberately not a ScenarioEnvelope."""

    schema_version: Literal["1"]
    run_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    target_entry_point_id: str = Field(min_length=1)
    actor: Any | None
    narrative: Any | None
    tree: Any | None
    behavior: Any | None
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


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return {key: _jsonable(item) for key, item in vars(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _write_model(run_dir: Path, rel_path: str, model: BaseModel) -> Path:
    # Revalidate after any adapter-side list mutation so an invalid in-memory
    # object can never replace the last valid on-disk document.
    model = type(model).model_validate(model.model_dump(mode="python"))
    content = (
        json.dumps(
            model.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False
        )
        + "\n"
    )
    return atomic_write_text(run_dir / rel_path, content)


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
    _write_model(run_dir, rel_path, bundle)
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


def _read_model(
    run_dir: Path,
    entry: ArtifactEntry | None,
    role: ArtifactRole,
    expected_path: str,
    model_type: type[StrictModel],
) -> Any:
    path = run_dir / expected_path
    if entry is not None:
        if entry.role is not role or entry.path != expected_path:
            raise ManifestIntegrityError(
                f"{role.value} role/path mismatch: {entry.role.value} {entry.path}"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry.sha256:
            raise ManifestIntegrityError(f"Hash mismatch for {entry.path}")
    try:
        return model_type.model_validate_json(path.read_bytes())
    except Exception as exc:
        raise ManifestIntegrityError(f"Invalid {role.value}: {exc}") from exc


def validate_v3_inventories(resolver: Any) -> None:
    """Reconcile manifest v3, coverage, finalization, and quarantine receipts."""

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

    manifest_entries = {
        (entry.role, entry.path, entry.candidate_id): entry
        for entry in resolver.manifest.inventory
    }
    for receipt in [*final.admitted_inventory, *final.quarantine_inventory]:
        key = (receipt.role, receipt.path, receipt.candidate_id)
        entry = manifest_entries.get(key)
        if entry is None or entry.sha256 != receipt.sha256:
            raise ManifestIntegrityError("Finalization receipt does not match manifest")

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
        records.append(
            ViolationRecord(
                code=code.value if isinstance(code, Enum) else str(code),
                detail=value.detail,
                owner=owner,
                retryable=getattr(value, "retryable", owner is not None),
            )
        )
    return records


class FinalizationPersistenceAdapter:
    """Atomic, exactly-once implementation of ``FinalizationPersistencePort``."""

    def __init__(
        self,
        run_dir: Path,
        inventory: FinalizationInventoryV1,
        candidate_plan: dict[str, tuple[str, int, bool]] | None = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.inventory = inventory
        self._lock = threading.Lock()
        self._transition_objects: set[int] = set()
        self._stage_ids = {item.attempt_id for item in inventory.stage_attempts}
        self._candidate_ids = {
            item.candidate_id for item in inventory.admission_decisions
        }
        self._candidate_plan = candidate_plan or {}
        self._final_tree_digests: dict[str, str] = {}

    def _ensure_candidate_attempt(self, candidate_id: str | None) -> None:
        if candidate_id is None or any(
            item.candidate_id == candidate_id
            for item in self.inventory.candidate_attempts
        ):
            return
        metadata = self._candidate_plan.get(candidate_id)
        if metadata is None:
            return
        target_id, queue_rank, is_primary = metadata
        self.inventory.candidate_attempts.append(
            CandidateAttemptRecord(
                attempt_id=f"{candidate_id}:candidate",
                candidate_id=candidate_id,
                target_entry_point_id=target_id,
                queue_rank=queue_rank,
                is_primary=is_primary,
                stage_attempt_ids=[],
            )
        )

    def _flush(self) -> None:
        write_finalization_inventory(self.run_dir, self.inventory)

    def record_transition(self, transition: LifecycleTransition) -> None:
        with self._lock:
            event_identity = id(transition)
            if event_identity in self._transition_objects:
                return
            self._transition_objects.add(event_identity)
            if transition.current is LifecycleState.revalidating_candidate:
                self._ensure_candidate_attempt(transition.candidate_id)
            self.inventory.transitions.append(
                TransitionRecord(
                    index=len(self.inventory.transitions),
                    previous=transition.previous,
                    current=transition.current,
                    candidate_id=transition.candidate_id,
                    reason=transition.reason,
                )
            )
            self._flush()

    def record_stage_result(
        self, invocation: StageInvocation, result: GeneratedStageResult
    ) -> None:
        with self._lock:
            attempt_id = (
                f"{invocation.candidate_id}:{invocation.stage.value}:"
                f"{invocation.invocation_index}"
            )
            if attempt_id in self._stage_ids:
                return
            self._stage_ids.add(attempt_id)
            if invocation.final_tree_digest is not None:
                self._final_tree_digests[invocation.candidate_id] = (
                    invocation.final_tree_digest
                )
            artifacts = {
                stage.value: _jsonable(invocation.artifacts.get(stage))
                for stage in GeneratedStage
                if invocation.artifacts.get(stage) is not None
            }
            evidence = _jsonable(result.evidence)
            failure = evidence if result.violations else None
            record = StageAttemptRecord(
                attempt_id=attempt_id,
                candidate_id=invocation.candidate_id,
                stage=invocation.stage,
                invocation_index=invocation.invocation_index,
                owner_retry_index=invocation.owner_retry_index,
                prompt=(evidence.get("prompt") if isinstance(evidence, dict) else None),
                call=(evidence.get("call") if isinstance(evidence, dict) else evidence),
                result=None if result.violations else _jsonable(result.artifact),
                failure=failure,
                input_sha256=canonical_sha256(artifacts),
                output_sha256=(
                    canonical_sha256(result.artifact)
                    if result.artifact is not None
                    else None
                ),
                violations=_violations(result.violations),
            )
            self.inventory.stage_attempts.append(record)
            for attempt in self.inventory.candidate_attempts:
                if attempt.candidate_id == invocation.candidate_id:
                    attempt.stage_attempt_ids.append(attempt_id)
                    break
            self._flush()

    def record_candidate_result(
        self, candidate_id: str, result: CandidateTerminalResult
    ) -> None:
        with self._lock:
            if candidate_id in self._candidate_ids:
                return
            if result.candidate_id != candidate_id:
                raise ValueError("candidate terminal result identity mismatch")
            self._candidate_ids.add(candidate_id)
            report = result.admission.value if result.admission is not None else None
            gate_results = [
                GateResultRecord(
                    gate=f"admission_gate_{index}",
                    passed=gate.passed,
                    violations=_violations(gate.violations),
                    diagnostics=_violations(gate.diagnostics),
                )
                for index, gate in enumerate(getattr(report, "gate_results", ()))
            ]
            self.inventory.admission_decisions.append(
                AdmissionDecisionRecord(
                    candidate_id=candidate_id,
                    status=result.status,
                    admitted=result.status is CandidateTerminalStatus.admitted,
                    gate_results=gate_results,
                    final_tree_snapshot_sha256=self._final_tree_digests.get(
                        candidate_id
                    ),
                    violations=_violations(result.violations),
                )
            )
            self._flush()


def make_finalization_persistence_adapter(
    run_dir: Path,
    *,
    run_id: str,
    coverage_plan_sha256: str,
    coverage_plan: CoveragePlanV2 | None = None,
) -> FinalizationPersistenceAdapter:
    """Phase 5 factory; creates no runner coupling and activates no manifest version."""

    path = Path(run_dir) / "finalization-inventory.json"
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
        write_finalization_inventory(Path(run_dir), inventory)
    candidate_plan = (
        {
            choice.candidate_id: (
                target.entry_point_id,
                choice.rank,
                choice.candidate_id == target.primary_candidate_id,
            )
            for target in coverage_plan.targets
            for choice in target.ordered_choices
        }
        if coverage_plan is not None
        else None
    )
    return FinalizationPersistenceAdapter(Path(run_dir), inventory, candidate_plan)
