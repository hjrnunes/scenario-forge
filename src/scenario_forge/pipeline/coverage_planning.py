"""Coverage-aware planning over authoritative candidate-v2 records.

Replaces the legacy post-validation raw-seed remediation generator with
coverage-aware selection that operates exclusively on fully qualified
ProjectedCandidate records joined to FilteredSeed entries.

Key concepts
------------
* **Coverage universe** – canonical profile entry points with direction
  ``input`` or ``bidirectional`` and controllability ``direct`` or
  ``indirect``.  Output-only / system-controlled entries are excluded with
  typed reasons.
* **Feasible target** – an entry point in the coverage universe for which
  at least one joined candidate exists.
* **Fallback queue** – a deterministic ranked list of at most three
  ProjectedCandidate choices per target.  The first choice is selected for
  generation; the remaining choices are surfaced for downstream retry
  logic (cmps.5).
* **Quality gap** – a typed, stage-attributed reason emitted when no
  compatible candidate survives for a target.  Coverage is never
  fabricated.

This module owns queue construction, selection, and surfacing the next
choice.  It does **not** implement cmps.5's retry / admission / quarantine
state machine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    is_attacker_accessible_ingress,
)
from scenario_forge.pipeline.candidates import FilteredSeed
from scenario_forge.pipeline.projection import ProjectedCandidate

logger = logging.getLogger(__name__)

# Maximum number of candidate choices per target in a fallback queue.
MAX_FALLBACK_CHOICES = 3


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

    ``not_applicable`` is the default for inferred / partial inventory.
    ``confirmed_complete`` is set only when the operator has confirmed the
    inventory is exhaustive.
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

    ``completeness`` defaults to ``not_applicable`` for inferred / partial
    inventory.  It is set to ``confirmed_complete`` only when the operator
    has confirmed the entry-point inventory is exhaustive.
    """

    feasible_targets: list[CoverageTarget] = field(default_factory=list)
    excluded_targets: list[ExcludedTarget] = field(default_factory=list)
    completeness: CoverageCompleteness = CoverageCompleteness.NOT_APPLICABLE

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
    *,
    completeness: CoverageCompleteness = CoverageCompleteness.NOT_APPLICABLE,
) -> CoverageUniverse:
    """Build the coverage universe from the capability profile.

    Iterates every entry point in the profile.  Entry points with direction
    ``input`` or ``bidirectional`` and effective controllability ``direct``
    or ``indirect`` in an active zone are feasible targets.  All others are
    excluded with a typed reason.

    Args:
        profile: The capability profile from Stage 1.
        completeness: Whether the inventory is operator-confirmed complete.

    Returns:
        A :class:`CoverageUniverse` with feasible targets and typed
        exclusions.
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

    universe = CoverageUniverse(
        feasible_targets=feasible,
        excluded_targets=excluded,
        completeness=completeness,
    )
    logger.info(
        "Coverage universe: %d feasible target(s), %d excluded, completeness=%s",
        len(feasible),
        len(excluded),
        completeness.value,
    )
    return universe


# ---------------------------------------------------------------------------
# Fallback queue construction
# ---------------------------------------------------------------------------


@dataclass
class TargetFallbackQueue:
    """Deterministic ranked fallback queue for a single coverage target.

    Bounded to at most :data:`MAX_FALLBACK_CHOICES` candidate choices.
    Each choice is a ``(FilteredSeed, ProjectedCandidate)`` pair that
    preserves candidate ID, canonical ingress, projection, bindings,
    filter verdict/provenance, origins, and rule provenance.
    """

    entry_point_id: str
    choices: list[tuple[FilteredSeed, ProjectedCandidate]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return len(self.choices) == 0

    @property
    def first_choice(self) -> tuple[FilteredSeed, ProjectedCandidate] | None:
        """The primary selection for this target, or None if no candidates."""
        return self.choices[0] if self.choices else None

    @property
    def remaining_choices(self) -> list[tuple[FilteredSeed, ProjectedCandidate]]:
        """Fallback choices after the first (surfaced for cmps.5 retry)."""
        return self.choices[1:]

    def candidate_ids(self) -> list[str]:
        """All candidate IDs in this queue, in rank order."""
        return [pc.candidate_id for _, pc in self.choices]


def build_fallback_queues(
    joined_seeds: list[tuple[FilteredSeed, ProjectedCandidate]],
    universe: CoverageUniverse,
) -> dict[str, TargetFallbackQueue]:
    """Build deterministic ranked fallback queues per feasible coverage target.

    Each queue is bounded to at most :data:`MAX_FALLBACK_CHOICES` choices.
    Ranking is deterministic: technique count (desc), then encounter order
    (asc).  Every choice is a fully qualified ``(FilteredSeed,
    ProjectedCandidate)`` pair.

    Args:
        joined_seeds: Prejoined candidates from the projection stage.
        universe: The coverage universe defining feasible targets.

    Returns:
        Mapping from ``entry_point_id`` to :class:`TargetFallbackQueue`.
        Targets with no candidates receive an empty queue.
    """
    by_target: dict[str, list[tuple[int, FilteredSeed, ProjectedCandidate]]] = {}
    for idx, (fseed, pc) in enumerate(joined_seeds):
        ep_id = pc.canonical_ingress.entry_point_id
        by_target.setdefault(ep_id, []).append((idx, fseed, pc))

    queues: dict[str, TargetFallbackQueue] = {}
    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        candidates = by_target.get(ep_id, [])
        ranked = sorted(
            candidates,
            key=lambda triple: (
                -len(triple[1].pinned_technique_ids),
                triple[0],
            ),
        )
        bounded = ranked[:MAX_FALLBACK_CHOICES]
        queues[ep_id] = TargetFallbackQueue(
            entry_point_id=ep_id,
            choices=[(fseed, pc) for _, fseed, pc in bounded],
        )

    return queues


# ---------------------------------------------------------------------------
# Coverage-aware selection
# ---------------------------------------------------------------------------


@dataclass
class SelectionResult:
    """Result of coverage-aware selection.

    ``selected`` is the final list of joined candidates for generation.
    ``capped_count`` is the number of candidates removed by secondary
    per-pattern capping.  ``uncovered_target_ids`` lists feasible targets
    that received no candidate.
    """

    selected: list[tuple[FilteredSeed, ProjectedCandidate]] = field(
        default_factory=list
    )
    capped_count: int = 0
    uncovered_target_ids: list[str] = field(default_factory=list)
    per_pattern_counts: dict[str, int] = field(default_factory=dict)


def select_with_coverage_priority(
    joined_seeds: list[tuple[FilteredSeed, ProjectedCandidate]],
    fallback_queues: dict[str, TargetFallbackQueue],
    universe: CoverageUniverse,
    max_per_pattern: int | None = None,
) -> SelectionResult:
    """Select candidates with coverage-first priority.

    **Phase 1 (hard):** Ensure at least one candidate for every feasible
    coverage target that has candidates in its fallback queue.  The first
    choice from each target's queue is selected.

    **Phase 2 (soft):** Admit additional candidates from each queue's
    remaining choices, subject to per-pattern caps.  Capping never
    discards a target's sole accepted candidate — candidates reserved in
    Phase 1 are immune to capping.

    Args:
        joined_seeds: All prejoined candidates.
        fallback_queues: Per-target fallback queues.
        universe: The coverage universe.
        max_per_pattern: Optional per-pattern cap (secondary objective).

    Returns:
        :class:`SelectionResult` with the final selected list.
    """
    selected_ids: set[str] = set()
    phase1: list[tuple[FilteredSeed, ProjectedCandidate]] = []
    uncovered: list[str] = []

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        if queue is None or queue.is_empty:
            uncovered.append(ep_id)
            continue
        first = queue.first_choice
        assert first is not None
        fseed, pc = first
        if pc.candidate_id not in selected_ids:
            phase1.append((fseed, pc))
            selected_ids.add(pc.candidate_id)

    per_pattern: dict[str, int] = {}
    for _, pc in phase1:
        per_pattern[pc.pattern_id] = per_pattern.get(pc.pattern_id, 0) + 1

    phase2: list[tuple[FilteredSeed, ProjectedCandidate]] = []
    capped = 0

    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        queue = fallback_queues.get(ep_id)
        if queue is None:
            continue
        for fseed, pc in queue.remaining_choices:
            if pc.candidate_id in selected_ids:
                continue
            if max_per_pattern is not None:
                current = per_pattern.get(pc.pattern_id, 0)
                if current >= max_per_pattern:
                    capped += 1
                    continue
            phase2.append((fseed, pc))
            selected_ids.add(pc.candidate_id)
            per_pattern[pc.pattern_id] = per_pattern.get(pc.pattern_id, 0) + 1

    selected = phase1 + phase2
    return SelectionResult(
        selected=selected,
        capped_count=capped,
        uncovered_target_ids=uncovered,
        per_pattern_counts=per_pattern,
    )


# ---------------------------------------------------------------------------
# Typed quality gaps
# ---------------------------------------------------------------------------


class CoverageGapReason(str, Enum):
    """Typed, stage-attributed reason for a coverage quality gap."""

    NO_SEED = "no_seed"
    DETERMINISTIC_RULE_REJECTION = "deterministic_rule_rejection"
    FILTER_REJECTION = "filter_rejection"
    SELECTION_LIMITATION = "selection_limitation"
    GENERATION_EXHAUSTION = "generation_exhaustion"
    ADMISSION_FAILURE = "admission_failure"
    PROJECTION_REJECTION = "projection_rejection"


@dataclass
class QualityGap:
    """A typed, stage-attributed quality gap for an uncovered target.

    Carries the target identity, the funnel stage where coverage fell out,
    and the candidate IDs / reasons that explain the gap.  Coverage is
    never fabricated — a gap is emitted rather than a synthetic scenario.
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


def emit_quality_gaps(
    universe: CoverageUniverse,
    selection_result: SelectionResult,
    fallback_queues: dict[str, TargetFallbackQueue],
    *,
    generated_target_ids: set[str] | None = None,
    quarantined_target_ids: set[str] | None = None,
    rule_rejected_by_target: dict[str, list[str]] | None = None,
    filter_rejected_by_target: dict[str, list[str]] | None = None,
    projection_rejected_by_target: dict[str, list[str]] | None = None,
) -> list[QualityGap]:
    """Emit typed quality gaps for feasible targets without coverage.

    For each feasible target that has no generated (and admitted) scenario,
    walks the funnel backwards to attribute the gap to the earliest stage
    where the target's candidate(s) fell out.

    Args:
        universe: The coverage universe.
        selection_result: The selection result.
        fallback_queues: Per-target fallback queues.
        generated_target_ids: Targets with at least one generated scenario.
        quarantined_target_ids: Targets whose only scenarios were quarantined.
        rule_rejected_by_target: Candidate IDs rejected by rules, per target.
        filter_rejected_by_target: Candidate IDs rejected by LLM filter, per target.
        projection_rejected_by_target: Candidate IDs rejected at projection, per target.

    Returns:
        List of :class:`QualityGap` records for uncovered targets.
    """
    generated = generated_target_ids or set()
    quarantined = quarantined_target_ids or set()
    rule_rejected = rule_rejected_by_target or {}
    filter_rejected = filter_rejected_by_target or {}
    projection_rejected = projection_rejected_by_target or {}

    gaps: list[QualityGap] = []
    for target in universe.feasible_targets:
        ep_id = target.entry_point_id
        if ep_id in generated:
            continue
        if ep_id in quarantined:
            queue = fallback_queues.get(ep_id)
            cands = queue.candidate_ids() if queue else []
            gaps.append(
                QualityGap(
                    entry_point_id=ep_id,
                    entry_point_name=target.name,
                    reason=CoverageGapReason.ADMISSION_FAILURE,
                    candidate_ids=cands,
                    detail="All generated scenarios for this target were quarantined.",
                )
            )
            continue

        queue = fallback_queues.get(ep_id)
        if queue is not None and not queue.is_empty:
            cands = queue.candidate_ids()
            if ep_id in selection_result.uncovered_target_ids:
                gaps.append(
                    QualityGap(
                        entry_point_id=ep_id,
                        entry_point_name=target.name,
                        reason=CoverageGapReason.SELECTION_LIMITATION,
                        candidate_ids=cands,
                        detail="No candidate selected for this target.",
                    )
                )
            else:
                gaps.append(
                    QualityGap(
                        entry_point_id=ep_id,
                        entry_point_name=target.name,
                        reason=CoverageGapReason.GENERATION_EXHAUSTION,
                        candidate_ids=cands,
                        detail="Selected candidate(s) failed during generation.",
                    )
                )
            continue

        proj_rejected = projection_rejected.get(ep_id, [])
        if proj_rejected:
            gaps.append(
                QualityGap(
                    entry_point_id=ep_id,
                    entry_point_name=target.name,
                    reason=CoverageGapReason.PROJECTION_REJECTION,
                    candidate_ids=proj_rejected,
                    detail="Candidate(s) rejected at projection stage (no exact ingress match).",
                )
            )
            continue

        filter_rej = filter_rejected.get(ep_id, [])
        if filter_rej:
            gaps.append(
                QualityGap(
                    entry_point_id=ep_id,
                    entry_point_name=target.name,
                    reason=CoverageGapReason.FILTER_REJECTION,
                    candidate_ids=filter_rej,
                    detail="Candidate(s) rejected by LLM filter.",
                )
            )
            continue

        rule_rej = rule_rejected.get(ep_id, [])
        if rule_rej:
            gaps.append(
                QualityGap(
                    entry_point_id=ep_id,
                    entry_point_name=target.name,
                    reason=CoverageGapReason.DETERMINISTIC_RULE_REJECTION,
                    candidate_ids=rule_rej,
                    detail="Candidate(s) rejected by deterministic rules.",
                )
            )
            continue

        gaps.append(
            QualityGap(
                entry_point_id=ep_id,
                entry_point_name=target.name,
                reason=CoverageGapReason.NO_SEED,
                candidate_ids=[],
                detail="No seed or candidate was produced for this target.",
            )
        )

    return gaps
