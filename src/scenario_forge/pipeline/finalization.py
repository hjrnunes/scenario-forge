"""The single finalization/admission lifecycle for projected candidates.

This module deliberately keeps generation and persistence at explicit
boundaries.  A caller supplies the existing Call 0--3 generators and the
existing validators; this state machine owns retry routing, admission,
quarantine, and the durable forensic record.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from scenario_forge.models.projection_envelope import (
    ProjectionTraceabilityResult,
    ProjectionTraceabilityStage,
)
from scenario_forge.pipeline.coverage_planning import (
    CoveragePlan,
    deserialize_qualified_candidate,
    revalidate_qualified_candidate,
)

FINALIZATION_SCHEMA_VERSION = "1"
MAX_TARGETED_RETRIES = 2


class LifecycleStage(str, Enum):
    actor = "actor"
    narrative = "narrative"
    tree = "tree"
    behavior = "behavior"
    admission = "admission"
    quarantine = "quarantine"


class LifecycleState(str, Enum):
    pending = "pending"
    generating_actor = "generating_actor"
    generating_narrative = "generating_narrative"
    generating_tree = "generating_tree"
    generating_behavior = "generating_behavior"
    verifying = "verifying"
    admitted = "admitted"
    quarantined = "quarantined"


_TRACE_STAGE_OWNER = {
    ProjectionTraceabilityStage.actor_profile: LifecycleStage.actor,
    ProjectionTraceabilityStage.narrative: LifecycleStage.narrative,
    ProjectionTraceabilityStage.attack_tree: LifecycleStage.tree,
    ProjectionTraceabilityStage.behavior_spec: LifecycleStage.behavior,
}


class AttemptLog(BaseModel):
    """One forensic call or verification attempt, persisted in order."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    stage: LifecycleStage
    retry_number: int = Field(ge=0, le=MAX_TARGETED_RETRIES)
    prompt: str | None = None
    call: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    failure: dict[str, Any] | None = None


class RepairProvenance(BaseModel):
    """A deterministic pre-projection repair, never a semantic rewrite."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    before_digest: str
    after_digest: str
    detail: str


class AdmissionResult(BaseModel):
    """Versioned durable outcome for one candidate."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = FINALIZATION_SCHEMA_VERSION
    candidate_id: str
    entry_point_id: str
    state: LifecycleState
    violations: list[dict[str, Any]] = Field(default_factory=list)
    attempts: list[AttemptLog] = Field(default_factory=list)
    repairs: list[RepairProvenance] = Field(default_factory=list)


@dataclass
class GeneratedArtifacts:
    """Mutable only until behavior is generated; tree is then fingerprinted."""

    actor: Any | None = None
    narrative: Any | None = None
    tree: Any | None = None
    behavior: Any | None = None
    tree_digest: str | None = None


Generator = Callable[[LifecycleStage, GeneratedArtifacts], tuple[Any, dict[str, Any]]]
Verifier = Callable[[GeneratedArtifacts], ProjectionTraceabilityResult]
Gate = Callable[[GeneratedArtifacts], Sequence[dict[str, Any]]]
Repair = Callable[
    [GeneratedArtifacts], tuple[GeneratedArtifacts, RepairProvenance | None]
]


def _digest(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    ).hexdigest()


def earliest_retry_owner(result: ProjectionTraceabilityResult) -> LifecycleStage:
    """Return the earliest producer responsible for traceability failure."""
    if not result.violations:
        raise ValueError("a valid traceability result has no retry owner")
    owners = {_TRACE_STAGE_OWNER[v.stage] for v in result.violations}
    return min(owners, key=lambda stage: list(LifecycleStage).index(stage))


@dataclass
class FinalizationAdmissionMachine:
    """Explicit finite-state lifecycle for exactly one projected candidate.

    ``generator`` must use the pre-existing Call 0--3 contract.  No callback
    is permitted to mutate an upstream artifact: retries delete all downstream
    values and invoke the earliest responsible producer again.
    """

    candidate_id: str
    entry_point_id: str
    generator: Generator
    verifier: Verifier
    hard_gate: Gate
    repair: Repair | None = None
    state: LifecycleState = LifecycleState.pending
    artifacts: GeneratedArtifacts = field(default_factory=GeneratedArtifacts)
    attempts: list[AttemptLog] = field(default_factory=list)
    repairs: list[RepairProvenance] = field(default_factory=list)
    retry_counts: dict[LifecycleStage, int] = field(default_factory=dict)

    def _discard_downstream(self, owner: LifecycleStage) -> None:
        stages = list(LifecycleStage)[:4]
        start = stages.index(owner)
        for stage in stages[start:]:
            setattr(self.artifacts, stage.value, None)
        if owner in (
            LifecycleStage.actor,
            LifecycleStage.narrative,
            LifecycleStage.tree,
        ):
            self.artifacts.tree_digest = None

    def _generate_from(self, owner: LifecycleStage) -> None:
        stages = list(LifecycleStage)[:4]
        for stage in stages[stages.index(owner) :]:
            self.state = LifecycleState(f"generating_{stage.value}")
            retry_number = self.retry_counts.get(stage, 0)
            try:
                artifact, call = self.generator(stage, self.artifacts)
                setattr(self.artifacts, stage.value, artifact)
                self.attempts.append(
                    AttemptLog(
                        candidate_id=self.candidate_id,
                        stage=stage,
                        retry_number=retry_number,
                        prompt=call.get("prompt"),
                        call=call,
                        result={"status": "ok"},
                    )
                )
                if stage is LifecycleStage.tree:
                    self.artifacts.tree_digest = _digest(artifact)
                if (
                    stage is LifecycleStage.behavior
                    and self.artifacts.tree_digest != _digest(self.artifacts.tree)
                ):
                    raise ValueError("tree changed after behavior projection")
            except Exception as exc:  # noqa: BLE001 - preserve every LLM failure
                self.attempts.append(
                    AttemptLog(
                        candidate_id=self.candidate_id,
                        stage=stage,
                        retry_number=retry_number,
                        result={"status": "failed"},
                        failure={"type": type(exc).__name__, "detail": str(exc)},
                    )
                )
                owner = (
                    LifecycleStage.tree
                    if stage is LifecycleStage.behavior
                    and self.artifacts.tree_digest != _digest(self.artifacts.tree)
                    else stage
                )
                self._retry_or_quarantine(
                    owner, [{"stage": owner.value, "detail": str(exc)}]
                )
                return

    def _retry_or_quarantine(
        self, owner: LifecycleStage, violations: list[dict[str, Any]]
    ) -> None:
        used = self.retry_counts.get(owner, 0)
        if used >= MAX_TARGETED_RETRIES:
            self.state = LifecycleState.quarantined
            self._terminal_violations = violations
            return
        self.retry_counts[owner] = used + 1
        self._discard_downstream(owner)
        self._generate_from(owner)

    def run(self) -> AdmissionResult:
        self._terminal_violations: list[dict[str, Any]] = []
        self._generate_from(LifecycleStage.actor)
        while self.state not in (LifecycleState.admitted, LifecycleState.quarantined):
            self.state = LifecycleState.verifying
            # Repairs may run only before behavior exists; semantic repair is
            # rejected by requiring a provenance record and unchanged tree/projection.
            if self.repair is not None and self.artifacts.behavior is None:
                repaired, provenance = self.repair(self.artifacts)
                if provenance is not None:
                    self.artifacts = repaired
                    self.repairs.append(provenance)
            trace = self.verifier(self.artifacts)
            if not trace.valid:
                owner = earliest_retry_owner(trace)
                violations = [v.model_dump(mode="json") for v in trace.violations]
                self.attempts.append(
                    AttemptLog(
                        candidate_id=self.candidate_id,
                        stage=owner,
                        retry_number=self.retry_counts.get(owner, 0),
                        result={"status": "traceability_failed"},
                        failure={"violations": violations},
                    )
                )
                self._retry_or_quarantine(owner, violations)
                continue
            violations = list(self.hard_gate(self.artifacts))
            if violations:
                # Hard gates are verify-only after behavior.  They never mutate;
                # their owner is explicit in evidence, defaulting to tree.
                owner = LifecycleStage(violations[0].get("owner", "tree"))
                self._retry_or_quarantine(owner, violations)
                continue
            if self.artifacts.tree_digest != _digest(self.artifacts.tree):
                self._retry_or_quarantine(
                    LifecycleStage.tree, [{"detail": "post-projection tree mutation"}]
                )
                continue
            self.state = LifecycleState.admitted
        return AdmissionResult(
            candidate_id=self.candidate_id,
            entry_point_id=self.entry_point_id,
            state=self.state,
            violations=self._terminal_violations,
            attempts=self.attempts,
            repairs=self.repairs,
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
    """Revalidate persisted primary/fallback candidates, never reusing one.

    The coverage plan is bounded upstream to three choices; this function
    enforces that bound again when loading untrusted persisted data.
    """
    entry = next(
        (item for item in plan.targets if item.entry_point_id == entry_point_id), None
    )
    if entry is None:
        return []
    refs = entry.ordered_choices[:3]
    candidates = []
    for ref in refs:
        candidate = deserialize_qualified_candidate(ref)
        if candidate.candidate_id in attempted_candidate_ids:
            continue
        # The merged API is deliberately invoked for every persisted choice.
        revalidate_qualified_candidate(
            ref, taxonomy_resolver, snapshot, trusted_catalog
        )
        candidates.append(candidate)
    return candidates
