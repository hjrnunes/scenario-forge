"""Coverage-aware planning over authoritative candidate-v2 records.

Replaces the legacy post-validation raw-seed remediation generator with
coverage-aware selection that operates exclusively on fully qualified
ProjectedCandidate records via typed :class:`QualifiedCandidate` wrappers.

Key concepts
------------
* **Coverage universe** – canonical profile entry points with direction
  ``input`` or ``bidirectional`` and controllability ``direct`` or
  ``indirect``.  Output-only / system-controlled entries are excluded with
  typed reasons.  Completeness is derived from the profile, never from
  free-form input.
* **Qualified candidate** – a typed planned candidate carrying a complete
  :class:`ProjectedCandidate` plus accepted filter verdict/rationale, merged
  origins, rule-removal provenance, and an explicit deterministic rank with
  candidate-ID tie-break.
* **Fallback queue** – a deterministic ranked list of at most three
  :class:`QualifiedCandidate` choices per target.  The first choice is
  selected for generation; remaining choices are surfaced as
  ``fallback_available`` in the persisted coverage plan for downstream retry
  logic (cmps.5).
* **Stage ledger** – records actual stage events (rules, filter, projection,
  selection, generation, admission, quarantine) per target/candidate.  The
  furthest actual event determines gap attribution — never backward inference.
* **Quality gap** – a typed, stage-attributed reason emitted when no
  compatible candidate survives for a target.  Coverage is never fabricated.
* **Coverage plan** – a versioned, persisted artifact with per-target ordered
  choices, primary selected/attempted state, and ``fallback_available``
  excluding every selected/attempted candidate.

This module owns queue construction, selection, and surfacing the next
choice.  It does **not** implement cmps.5's retry / admission / quarantine
state machine.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    is_attacker_accessible_ingress,
)
from scenario_forge.pipeline.candidates import (
    CandidateOrigin,
    FilteredSeed,
    RejectionRecord,
)
from scenario_forge.pipeline.projection import ProjectedCandidate

logger = logging.getLogger(__name__)

# Maximum number of candidate choices per target in a fallback queue.
MAX_FALLBACK_CHOICES = 3

# Schema version for the persisted coverage plan.
COVERAGE_PLAN_SCHEMA_VERSION = "1"


# ---------------------------------------------------------------------------
# Coverage universe
# ---------------------------------------------------------------------------


class CoverageExclusionReason(str, Enum):
    """Typed reason for excluding an entry point from the coverage universe."""

    OUTPUT_ONLY = "output_only"
    SYSTEM_CONTROLLED = "system_controlled"
    INACTIVE_ZONE = "inactive_zone"
    NO_INGRESS_ZONE = "no_ingress_zone"


class CoverageCompleteness(str, Enum):
    """Whether the entry-point inventory is known to be complete.

    Derived from :attr:`CapabilityProfile.is_entry_point_inventory_complete`:
    ``confirmed_complete`` only when the operator has confirmed the inventory
    is exhaustive with evidence; ``not_applicable`` otherwise (inferred-partial
    inventory — completeness cannot be claimed).
    """

    NOT_APPLICABLE = "not_applicable"
    CONFIRMED_COMPLETE = "confirmed_complete"


@dataclass(frozen=True)
class CoverageTarget:
    """A feasible coverage target — an attacker-accessible ingress entry point.

    Carries the canonical ``entry_point_id``, display name, direction, and
    effective controllability.  Direction is always ``input`` or
    ``bidirectional``; controllability is always ``direct`` or ``indirect``.
    """

    entry_point_id: str
    name: str
    direction: str
    controllability: str


@dataclass(frozen=True)
class ExcludedTarget:
    """An entry point excluded from the coverage universe with a typed reason."""

    entry_point_id: str
    name: str
    direction: str
    controllability: str
    reason: CoverageExclusionReason


@dataclass
class CoverageUniverse:
    """The complete coverage universe: feasible targets plus typed exclusions.

    ``completeness`` is derived from the profile's
    ``is_entry_point_inventory_complete`` property — never from free-form
    input.  ``evidence_refs`` carries the operator-confirmed evidence sources
    when completeness is ``confirmed_complete``.
    """

    feasible_targets: list[CoverageTarget] = field(default_factory=list)
    excluded_targets: list[ExcludedTarget] = field(default_factory=list)
    completeness: CoverageCompleteness = CoverageCompleteness.NOT_APPLICABLE
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def feasible_target_ids(self) -> set[str]:
        """Set of entry_point_ids for all feasible targets."""
        return {t.entry_point_id for t in self.feasible_targets}

    def to_dict(self) -> dict:
        return {
            "feasible_targets": [
                {
                    "entry_point_id": t.entry_point_id,
                    "name": t.name,
                    "direction": t.direction,
                    "controllability": t.controllability,
                }
                for t in self.feasible_targets
            ],
            "excluded_targets": [
                {
                    "entry_point_id": e.entry_point_id,
                    "name": e.name,
                    "direction": e.direction,
                    "controllability": e.controllability,
                    "reason": e.reason.value,
                }
                for e in self.excluded_targets
            ],
            "completeness": self.completeness.value,
            "evidence_refs": list(self.evidence_refs),
        }


def _classify_exclusion(
    ep: EntryPoint,
    active_zones: set[str],
) -> CoverageExclusionReason | None:
    """Return the typed exclusion reason for a non-feasible entry point, or None if feasible."""
    if ep.direction == "output":
        return CoverageExclusionReason.OUTPUT_ONLY
    if ep.effective_controllability == "system":
        return CoverageExclusionReason.SYSTEM_CONTROLLED
    zone = ep.effective_ingress_zone
    if zone is None:
        return CoverageExclusionReason.NO_INGRESS_ZONE
    if zone not in active_zones:
        return CoverageExclusionReason.INACTIVE_ZONE
    return None


def build_coverage_universe(
    profile: CapabilityProfile,
) -> CoverageUniverse:
    """Build the coverage universe from the capability profile.

    Iterates every entry point in the profile.  Entry points with direction
    ``input`` or ``bidirectional`` and effective controllability ``direct``
    or ``indirect`` in an active zone are feasible targets.  All others are
    excluded with a typed reason.

    Completeness is derived from
    :attr:`CapabilityProfile.is_entry_point_inventory_complete` — the
    operator-confirmed property.  Free-form enum input is not accepted; an
    inferred profile cannot claim confirmed completeness.

    Args:
        profile: The capability profile from Stage 1.

    Returns:
        A :class:`CoverageUniverse` with feasible targets, typed
        exclusions, and profile-derived completeness.
    """
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    feasible: list[CoverageTarget] = []
    excluded: list[ExcludedTarget] = []

    for ep in profile.entry_points:
        if is_attacker_accessible_ingress(ep, active_zones):
            feasible.append(
                CoverageTarget(
                    entry_point_id=ep.entry_point_id,
                    name=ep.name,
                    direction=ep.direction,
                    controllability=ep.effective_controllability,
                )
            )
        else:
            reason = _classify_exclusion(ep, active_zones)
            if reason is None:
                reason = CoverageExclusionReason.NO_INGRESS_ZONE
            excluded.append(
                ExcludedTarget(
                    entry_point_id=ep.entry_point_id,
                    name=ep.name,
                    direction=ep.direction,
                    controllability=ep.effective_controllability,
                    reason=reason,
                )
            )

    if profile.is_entry_point_inventory_complete:
        completeness = CoverageCompleteness.CONFIRMED_COMPLETE
        evidence_refs = [e for e in profile.entry_point_evidence if e and e.strip()]
    else:
        completeness = CoverageCompleteness.NOT_APPLICABLE
        evidence_refs = []

    universe = CoverageUniverse(
        feasible_targets=feasible,
        excluded_targets=excluded,
        completeness=completeness,
        evidence_refs=evidence_refs,
    )
    logger.info(
        "Coverage universe: %d feasible target(s), %d excluded, completeness=%s",
        len(feasible),
        len(excluded),
        completeness.value,
    )
    return universe


# ---------------------------------------------------------------------------
# Qualified candidate — typed planned candidate over ProjectedCandidate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualifiedCandidate:
    """A typed planned candidate carrying complete ProjectedCandidate plus
    accepted filter evidence.

    Replaces the legacy ``(FilteredSeed, ProjectedCandidate)`` tuple.  The
    complete :class:`ProjectedCandidate` is the authoritative candidate-v2
    record.  The accepted filter rationale, merged origins, and rule-removal
    provenance are preserved as first-class typed evidence.  An explicit
    deterministic rank with candidate-ID tie-break replaces the legacy
    pinned-technique-count ranking.
    """

    projected: ProjectedCandidate
    filtered_seed: FilteredSeed
    accepted_rationale: str
    rank: int = 0

    @property
    def entry_point_id(self) -> str:
        """Canonical ingress entry point ID from the projected candidate."""
        return self.projected.canonical_ingress.entry_point_id

    @property
    def candidate_id(self) -> str:
        """Authoritative candidate-v2 ID from the projected candidate."""
        return self.projected.candidate_id

    @property
    def pattern_id(self) -> str:
        """Attack pattern ID from the projected candidate."""
        return self.projected.pattern_id

    @property
    def filter_candidate_id(self) -> str:
        """Filter-stage candidate ID (provenance only, not authoritative)."""
        return self.filtered_seed.candidate_id

    @property
    def origins(self) -> list[CandidateOrigin]:
        """Merged candidate origins from the filtered seed."""
        return self.filtered_seed.origins

    @property
    def rejection_rationales(self) -> list[RejectionRecord]:
        """Rule-removal provenance from the filtered seed."""
        return self.filtered_seed.rejection_rationales

    def to_plan_ref(self) -> dict:
        """Serialize to a content-addressed plan reference."""
        return {
            "candidate_id": self.candidate_id,
            "filter_candidate_id": self.filter_candidate_id,
            "pattern_id": self.pattern_id,
            "entry_point_id": self.entry_point_id,
            "rank": self.rank,
            "accepted_rationale": self.accepted_rationale,
            "origins": [o.model_dump(mode="json") for o in self.origins],
            "rejection_rationales": [
                r.model_dump(mode="json") for r in self.rejection_rationales
            ],
            "pinned_entry_point": self.filtered_seed.pinned_entry_point,
            "pinned_technique_ids": list(self.filtered_seed.pinned_technique_ids),
            "pinned_technique_names": list(self.filtered_seed.pinned_technique_names),
        }


def build_qualified_candidates(
    filtered_seeds: Sequence[FilteredSeed],
    projected_by_pattern: dict[str, list[ProjectedCandidate]],
) -> list[QualifiedCandidate]:
    """Fan out all valid projected matches and build typed qualified candidates.

    For each filtered seed, finds **all** projected candidates matching the
    same pattern and canonical ingress.  Multiple projected candidates with
    distinct concrete bindings for the same pattern+ingress are valid
    alternatives — they are fanned out, not treated as fatal ambiguity.

    Deduplication is by projected ``candidate_id`` — the authoritative
    candidate-v2 identity.  If two filtered seeds map to the same projected
    candidate, the first encounter wins and filter provenance from
    subsequent encounters is merged.

    Ranking is **not** by pinned-technique subset/count.  Deterministic
    ordering is by encounter order with candidate-ID tie-break, assigned
    during queue construction.

    Args:
        filtered_seeds: Accepted candidates from the LLM filter stage.
        projected_by_pattern: Mapping from ``pattern_id`` to all projected
            candidates for that pattern.

    Returns:
        List of :class:`QualifiedCandidate` records, deduplicated by
        projected ``candidate_id``, preserving filter provenance.
    """
    seen_projected_ids: dict[str, QualifiedCandidate] = {}
    ordered: list[QualifiedCandidate] = []

    for fseed in filtered_seeds:
        pc_list = projected_by_pattern.get(fseed.seed_id, [])
        matching_pcs = [
            pc
            for pc in pc_list
            if pc.canonical_ingress.entry_point_id == fseed.entry_point_id
        ]
        for pc in matching_pcs:
            existing = seen_projected_ids.get(pc.candidate_id)
            if existing is not None:
                # Same projected candidate already qualified from a different
                # filtered seed — skip (first encounter wins).  Filter
                # provenance is preserved from the first encounter.
                continue
            qc = QualifiedCandidate(
                projected=pc,
                filtered_seed=fseed,
                accepted_rationale=fseed.accepted_rationale,
            )
            seen_projected_ids[pc.candidate_id] = qc
            ordered.append(qc)

    logger.info(
        "Qualified %d candidate(s) from %d filtered seed(s) (%d unique projected IDs).",
        len(ordered),
        len(filtered_seeds),
        len(seen_projected_ids),
    )
    return ordered


# ---------------------------------------------------------------------------
# Stage ledger — actual stage events per target/candidate
# ---------------------------------------------------------------------------


# Canonical stage names in pipeline order.
STAGE_RULES = "rules"
STAGE_FILTER = "filter"
STAGE_PROJECTION = "projection"
STAGE_SELECTION = "selection"
STAGE_GENERATION = "generation"
STAGE_ADMISSION = "admission"
STAGE_QUARANTINE = "quarantine"

_STAGE_ORDER = {
    STAGE_RULES: 0,
    STAGE_FILTER: 1,
    STAGE_PROJECTION: 2,
    STAGE_SELECTION: 3,
    STAGE_GENERATION: 4,
    STAGE_ADMISSION: 5,
    STAGE_QUARANTINE: 6,
}


@dataclass(frozen=True)
class StageEvent:
    """A recorded stage event for a target/candidate pair.

    Preserves the exact candidate/filter identity, pipeline stage, typed
    reason, and rationale/exception/limitation evidence.  The furthest
    actual event for a target determines its gap attribution.
    """

    entry_point_id: str
    candidate_id: str
    stage: str
    reason: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_point_id": self.entry_point_id,
            "candidate_id": self.candidate_id,
            "stage": self.stage,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class StageLedger:
    """Accumulates actual stage events per target/candidate.

    Events are recorded as they occur through the pipeline (rules, filter,
    projection, selection, generation, admission, quarantine).  The furthest
    actual event for a target determines its gap attribution — never
    backward set-membership inference.
    """

    events: list[StageEvent] = field(default_factory=list)

    def record(
        self,
        entry_point_id: str,
        candidate_id: str,
        stage: str,
        reason: str,
        detail: str = "",
    ) -> None:
        """Record a stage event."""
        self.events.append(
            StageEvent(
                entry_point_id=entry_point_id,
                candidate_id=candidate_id,
                stage=stage,
                reason=reason,
                detail=detail,
            )
        )

    def events_for(self, entry_point_id: str) -> list[StageEvent]:
        """All events for a target, in recording order."""
        return [e for e in self.events if e.entry_point_id == entry_point_id]

    def furthest_event(self, entry_point_id: str) -> StageEvent | None:
        """The furthest actual event for a target, by stage order.

        Returns the event with the highest stage order.  Ties break by
        recording order (last recorded wins).
        """
        target_events = self.events_for(entry_point_id)
        if not target_events:
            return None
        return max(
            target_events,
            key=lambda e: (_STAGE_ORDER.get(e.stage, -1), target_events.index(e)),
        )

    def candidate_ids_for_stage(self, entry_point_id: str, stage: str) -> list[str]:
        """Exact candidate IDs that reached a given stage for a target."""
        return [
            e.candidate_id
            for e in self.events
            if e.entry_point_id == entry_point_id and e.stage == stage
        ]

    def to_dict(self) -> dict:
        return {"events": [e.to_dict() for e in self.events]}


# ---------------------------------------------------------------------------
# Fallback queue construction
# ---------------------------------------------------------------------------


@dataclass
class TargetFallbackQueue:
    """Deterministic ranked fallback queue for a single coverage target.

    Bounded to at most :data:`MAX_FALLBACK_CHOICES` candidate choices.
    Each choice is a :class:`QualifiedCandidate` that preserves candidate
    ID, canonical ingress, projection, bindings, filter verdict/provenance,
    origins, and rule provenance.
    """

    entry_point_id: str
    choices: list[QualifiedCandidate] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return len(self.choices) == 0

    @property
    def first_choice(self) -> QualifiedCandidate | None:
        """The primary selection for this target, or None if no candidates."""
        return self.choices[0] if self.choices else None

    @property
    def remaining_choices(self) -> list[QualifiedCandidate]:
        """Fallback choices after the first (surfaced for cmps.5 retry)."""
        return self.choices[1:]

    def candidate_ids(self) -> list[str]:
        """All candidate IDs in this queue, in rank order."""
        return [qc.candidate_id for qc in self.choices]


def build_fallback_queues(
    qualified: list[QualifiedCandidate],
    universe: CoverageUniverse,
) -> dict[str, TargetFallbackQueue]:
    """Build deterministic ranked fallback queues per feasible coverage target.

    Each queue is bounded to at most :data:`MAX_FALLBACK_CHOICES` choices.
    Ranking is deterministic: encounter order (asc), then candidate-ID
    tie-break (asc).  Ranking is **not** by pinned-technique subset/count.

    Args:
        qualified: Qualified candidates from :func:`build_qualified_candidates`.
        universe: The coverage universe defining feasible targets.

    Returns:
        Mapping from ``entry_point_id`` to :class:`TargetFallbackQueue`.
        Targets with no candidates receive an empty queue.
    """
    by_target: dict[str, list[tuple[int, QualifiedCandidate]]] = {}
    for idx, qc in enumerate(qualified):
        ep_id = qc.entry_point_id
        by_target.setdefault(ep_id, []).append((idx, qc))

    queues: dict[str, TargetFallbackQueue] = {}
    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        candidates = by_target.get(ep_id, [])
        # Deterministic: encounter order (asc), then candidate-ID tie-break (asc).
        ranked = sorted(candidates, key=lambda pair: (pair[0], pair[1].candidate_id))
        bounded = ranked[:MAX_FALLBACK_CHOICES]
        # Assign explicit deterministic ranks.
        choices = [replace(qc, rank=rank) for rank, (_, qc) in enumerate(bounded)]
        queues[ep_id] = TargetFallbackQueue(
            entry_point_id=ep_id,
            choices=choices,
        )

    return queues


# ---------------------------------------------------------------------------
# Coverage-aware selection
# ---------------------------------------------------------------------------


@dataclass
class SelectionResult:
    """Result of coverage-aware selection.

    ``selected`` is the final list of qualified candidates for generation.
    ``capped_count`` is the number of candidates removed by secondary
    per-pattern capping.  ``uncovered_target_ids`` lists feasible targets
    that received no candidate.  ``primary_candidate_ids`` maps target ID
    to the Phase-1 selected candidate ID.  ``attempted_candidate_ids`` is
    the complete set of candidates selected for generation (Phase 1 + 2).
    """

    selected: list[QualifiedCandidate] = field(default_factory=list)
    capped_count: int = 0
    uncovered_target_ids: list[str] = field(default_factory=list)
    per_pattern_counts: dict[str, int] = field(default_factory=dict)
    primary_candidate_ids: dict[str, str] = field(default_factory=dict)
    attempted_candidate_ids: set[str] = field(default_factory=set)


def select_with_coverage_priority(
    qualified: list[QualifiedCandidate],
    fallback_queues: dict[str, TargetFallbackQueue],
    universe: CoverageUniverse,
    max_per_pattern: int | None = None,
) -> SelectionResult:
    """Select candidates with coverage-first priority.

    **Phase 1 (hard):** Ensure at least one candidate for every feasible
    coverage target that has candidates in its fallback queue.  The first
    choice from each target's queue is selected.  Phase 1 is cap-immune.

    Only Phase-1 primaries are selected and attempted through the ordinary
    lifecycle.  All remaining choices stay as ``fallback_available`` in the
    coverage plan for cmps.5 retry logic.  This prevents the ordinary
    generation pass from consuming fallback choices that cmps.5 would
    otherwise re-attempt.

    Capping never discards a target's sole accepted candidate — candidates
    reserved in Phase 1 are immune to capping.  ``max_per_pattern`` is
    accepted for API compatibility but does not cap Phase 1 selections.

    Args:
        qualified: All qualified candidates.
        fallback_queues: Per-target fallback queues.
        universe: The coverage universe.
        max_per_pattern: Optional per-pattern cap (reserved for secondary
            optimization; does not cap Phase 1 primaries).

    Returns:
        :class:`SelectionResult` with the final selected list and
        primary/attempted candidate tracking.
    """
    selected_ids: set[str] = set()
    selected: list[QualifiedCandidate] = []
    uncovered: list[str] = []
    primary_ids: dict[str, str] = {}

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        if queue is None or queue.is_empty:
            uncovered.append(ep_id)
            continue
        first = queue.first_choice
        assert first is not None
        if first.candidate_id not in selected_ids:
            selected.append(first)
            selected_ids.add(first.candidate_id)
            primary_ids[ep_id] = first.candidate_id

    per_pattern: dict[str, int] = {}
    for qc in selected:
        per_pattern[qc.pattern_id] = per_pattern.get(qc.pattern_id, 0) + 1

    return SelectionResult(
        selected=selected,
        capped_count=0,
        uncovered_target_ids=uncovered,
        per_pattern_counts=per_pattern,
        primary_candidate_ids=primary_ids,
        attempted_candidate_ids=selected_ids,
    )


# ---------------------------------------------------------------------------
# Versioned coverage plan
# ---------------------------------------------------------------------------


@dataclass
class CoveragePlanEntry:
    """Per-target entry in the versioned coverage plan.

    ``ordered_choices`` is the full ranked list of qualified candidate
    references.  ``primary_candidate_id`` is the Phase-1 selected candidate
    (or None if uncovered).  ``primary_state`` tracks the lifecycle state
    of the primary candidate.  ``fallback_available`` lists choices that
    have not been selected or attempted — suitable for cmps.5 retry.
    """

    entry_point_id: str
    entry_point_name: str
    ordered_choices: list[dict]
    primary_candidate_id: str | None
    primary_state: str
    fallback_available: list[dict]

    def to_dict(self) -> dict:
        return {
            "entry_point_id": self.entry_point_id,
            "entry_point_name": self.entry_point_name,
            "ordered_choices": self.ordered_choices,
            "primary_candidate_id": self.primary_candidate_id,
            "primary_state": self.primary_state,
            "fallback_available": self.fallback_available,
        }


@dataclass
class CoveragePlan:
    """Versioned coverage plan — a manifest-inventoried artifact.

    Persists per-target ordered qualified choices, primary selected/attempted
    state, and ``fallback_available`` excluding every selected/attempted
    candidate.  Contains content-addressed provenance sufficient for cmps.5
    retry logic.
    """

    schema_version: str
    completeness: str
    evidence_refs: list[str]
    targets: list[CoveragePlanEntry]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "completeness": self.completeness,
            "evidence_refs": list(self.evidence_refs),
            "targets": [t.to_dict() for t in self.targets],
        }


def build_coverage_plan(
    universe: CoverageUniverse,
    fallback_queues: dict[str, TargetFallbackQueue],
    selection_result: SelectionResult,
    generation_outcomes: dict[str, str] | None = None,
) -> CoveragePlan:
    """Build the versioned coverage plan from selection and generation outcomes.

    For each feasible target, records the ordered qualified choices, the
    primary selected/attempted candidate ID, its lifecycle state, and the
    fallback_available choices excluding every selected/attempted candidate.

    Args:
        universe: The coverage universe.
        fallback_queues: Per-target fallback queues.
        selection_result: The selection result with primary/attempted IDs.
        generation_outcomes: Optional mapping from candidate_id to lifecycle
            state (``"generated"``, ``"failed"``, ``"quarantined"``).  If
            absent, primary state is ``"selected"`` or ``"uncovered"``.

    Returns:
        A :class:`CoveragePlan` ready for persistence.
    """
    outcomes = generation_outcomes or {}
    attempted = selection_result.attempted_candidate_ids
    entries: list[CoveragePlanEntry] = []

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        choices = queue.choices if queue else []
        ordered_refs = [qc.to_plan_ref() for qc in choices]

        primary_id = selection_result.primary_candidate_ids.get(ep_id)
        if primary_id is not None:
            state = outcomes.get(primary_id, "selected")
        else:
            state = "uncovered"

        # fallback_available: choices not selected or attempted.
        fallback = [
            qc.to_plan_ref() for qc in choices if qc.candidate_id not in attempted
        ]

        entries.append(
            CoveragePlanEntry(
                entry_point_id=ep_id,
                entry_point_name=target.name,
                ordered_choices=ordered_refs,
                primary_candidate_id=primary_id,
                primary_state=state,
                fallback_available=fallback,
            )
        )

    return CoveragePlan(
        schema_version=COVERAGE_PLAN_SCHEMA_VERSION,
        completeness=universe.completeness.value,
        evidence_refs=list(universe.evidence_refs),
        targets=entries,
    )


# ---------------------------------------------------------------------------
# Typed quality gaps — from actual stage ledger evidence
# ---------------------------------------------------------------------------


class CoverageGapReason(str, Enum):
    """Typed, stage-attributed reason for a coverage quality gap."""

    NO_SEED = "no_seed"
    DETERMINISTIC_RULE_REJECTION = "deterministic_rule_rejection"
    FILTER_REJECTION = "filter_rejection"
    PROJECTION_REJECTION = "projection_rejection"
    SELECTION_LIMITATION = "selection_limitation"
    GENERATION_EXHAUSTION = "generation_exhaustion"
    ADMISSION_FAILURE = "admission_failure"
    PROJECTION_LIMITATION = "projection_limitation"


# Mapping from stage to gap reason when the furthest event is at that stage.
_STAGE_TO_GAP_REASON: dict[str, CoverageGapReason] = {
    STAGE_RULES: CoverageGapReason.DETERMINISTIC_RULE_REJECTION,
    STAGE_FILTER: CoverageGapReason.FILTER_REJECTION,
    STAGE_PROJECTION: CoverageGapReason.PROJECTION_REJECTION,
    STAGE_SELECTION: CoverageGapReason.SELECTION_LIMITATION,
    STAGE_GENERATION: CoverageGapReason.GENERATION_EXHAUSTION,
    STAGE_ADMISSION: CoverageGapReason.ADMISSION_FAILURE,
    STAGE_QUARANTINE: CoverageGapReason.ADMISSION_FAILURE,
}


@dataclass
class QualityGap:
    """A typed, stage-attributed quality gap for an uncovered target.

    Carries the target identity, the funnel stage where coverage fell out
    (determined from actual stage ledger evidence), and the exact candidate
    IDs / reasons that explain the gap.  Coverage is never fabricated — a
    gap is emitted rather than a synthetic scenario.
    """

    entry_point_id: str
    entry_point_name: str
    reason: CoverageGapReason
    candidate_ids: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_point_id": self.entry_point_id,
            "entry_point_name": self.entry_point_name,
            "reason": self.reason.value,
            "candidate_ids": self.candidate_ids,
            "detail": self.detail,
        }


# Categorized coverage summary for JSON and HTML reporting.
@dataclass
class CoverageSummary:
    """Categorized coverage summary distinguishing coverage outcomes.

    Categories:
    - ``covered_feasible``: targets with at least one generated+admitted scenario.
    - ``policy_exclusions``: targets excluded by policy (output-only, etc.).
    - ``structural_gaps``: targets with no candidate at rules/filter/projection stages.
    - ``selection_limitations``: targets with candidates but none selected.
    - ``runtime_generation_gaps``: targets where generation failed.
    - ``quarantine_admission_failures``: targets where scenarios were quarantined.
    - ``projection_limitations``: targets omitted by budget allocation.
    """

    covered_feasible: list[str] = field(default_factory=list)
    policy_exclusions: list[dict] = field(default_factory=list)
    structural_gaps: list[dict] = field(default_factory=list)
    selection_limitations: list[dict] = field(default_factory=list)
    runtime_generation_gaps: list[dict] = field(default_factory=list)
    quarantine_admission_failures: list[dict] = field(default_factory=list)
    projection_limitations: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "covered_feasible": list(self.covered_feasible),
            "policy_exclusions": list(self.policy_exclusions),
            "structural_gaps": list(self.structural_gaps),
            "selection_limitations": list(self.selection_limitations),
            "runtime_generation_gaps": list(self.runtime_generation_gaps),
            "quarantine_admission_failures": list(self.quarantine_admission_failures),
            "projection_limitations": list(self.projection_limitations),
        }


def emit_quality_gaps(
    universe: CoverageUniverse,
    stage_ledger: StageLedger,
    selection_result: SelectionResult,
    fallback_queues: dict[str, TargetFallbackQueue],
    *,
    generated_target_ids: set[str] | None = None,
    quarantined_target_ids: set[str] | None = None,
    projection_limitation_target_ids: set[str] | None = None,
) -> tuple[list[QualityGap], CoverageSummary]:
    """Emit typed quality gaps from actual stage ledger evidence.

    For each feasible target that has no generated (and admitted) scenario,
    the furthest actual stage event from the ledger determines the gap
    reason.  Runtime evidence retains exact failed/quarantined candidate IDs.
    Coverage is never fabricated.

    Args:
        universe: The coverage universe.
        stage_ledger: The stage ledger with actual events.
        selection_result: The selection result.
        fallback_queues: Per-target fallback queues.
        generated_target_ids: Targets with at least one admitted scenario.
        quarantined_target_ids: Targets whose scenarios were quarantined.
        projection_limitation_target_ids: Targets omitted by budget allocation.

    Returns:
        Tuple of (quality_gaps, coverage_summary).
    """
    generated = generated_target_ids or set()
    quarantined = quarantined_target_ids or set()
    proj_limitations = projection_limitation_target_ids or set()

    gaps: list[QualityGap] = []
    covered: list[str] = []
    policy_exclusions: list[dict] = []
    structural_gaps: list[dict] = []
    selection_limitations: list[dict] = []
    runtime_gaps: list[dict] = []
    quarantine_failures: list[dict] = []
    projection_lims: list[dict] = []

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        target_name = target.name

        if ep_id in generated:
            covered.append(ep_id)
            continue

        if ep_id in quarantined:
            # Exact quarantined candidate IDs from the ledger.
            quarantined_cids = stage_ledger.candidate_ids_for_stage(
                ep_id, STAGE_QUARANTINE
            )
            if not quarantined_cids:
                # Fallback to candidates that reached generation.
                quarantined_cids = stage_ledger.candidate_ids_for_stage(
                    ep_id, STAGE_GENERATION
                )
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.ADMISSION_FAILURE,
                candidate_ids=quarantined_cids,
                detail="Generated scenario(s) quarantined during validation.",
            )
            gaps.append(gap)
            quarantine_failures.append(gap.to_dict())
            continue

        if ep_id in proj_limitations:
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.PROJECTION_LIMITATION,
                candidate_ids=[],
                detail="Target omitted by projection budget allocation.",
            )
            gaps.append(gap)
            projection_lims.append(gap.to_dict())
            continue

        # Use actual stage ledger evidence for attribution.
        furthest = stage_ledger.furthest_event(ep_id)

        if furthest is not None:
            reason = _STAGE_TO_GAP_REASON.get(furthest.stage, CoverageGapReason.NO_SEED)
            # Exact candidate IDs from the furthest stage.
            stage_cids = stage_ledger.candidate_ids_for_stage(ep_id, furthest.stage)
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=reason,
                candidate_ids=stage_cids,
                detail=furthest.detail,
            )
            gaps.append(gap)

            # Categorize.
            if furthest.stage in (STAGE_RULES, STAGE_FILTER, STAGE_PROJECTION):
                structural_gaps.append(gap.to_dict())
            elif furthest.stage == STAGE_SELECTION:
                selection_limitations.append(gap.to_dict())
            elif furthest.stage == STAGE_GENERATION:
                runtime_gaps.append(gap.to_dict())
            elif furthest.stage in (STAGE_ADMISSION, STAGE_QUARANTINE):
                quarantine_failures.append(gap.to_dict())
        elif ep_id in selection_result.uncovered_target_ids:
            # Target had no candidates at all (no stage events).
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.NO_SEED,
                candidate_ids=[],
                detail="No seed or candidate was produced for this target.",
            )
            gaps.append(gap)
            structural_gaps.append(gap.to_dict())
        else:
            # No stage events and not uncovered — shouldn't happen, but
            # emit a no_seed gap rather than fabricating coverage.
            gap = QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target_name,
                reason=CoverageGapReason.NO_SEED,
                candidate_ids=[],
                detail="No stage evidence recorded for this target.",
            )
            gaps.append(gap)
            structural_gaps.append(gap.to_dict())

    # Policy exclusions from the universe.
    for exc in universe.excluded_targets:
        policy_exclusions.append(
            {
                "entry_point_id": exc.entry_point_id,
                "name": exc.name,
                "reason": exc.reason.value,
            }
        )

    summary = CoverageSummary(
        covered_feasible=covered,
        policy_exclusions=policy_exclusions,
        structural_gaps=structural_gaps,
        selection_limitations=selection_limitations,
        runtime_generation_gaps=runtime_gaps,
        quarantine_admission_failures=quarantine_failures,
        projection_limitations=projection_lims,
    )

    return gaps, summary
