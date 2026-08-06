"""Regression tests for cmps.4: coverage-aware planning.

Tests that:
- Selection does not default to first raw seed (Req 8).
- Caps preserve sole target coverage (Req 3, 8).
- Coverage universe excludes output-only/system-controlled with typed
  reasons (Req 1).
- Fallback queue construction is bounded to 3 and deterministic (Req 4).
- Typed quality gaps are emitted for uncovered targets (Req 5).
- No scenario is generated from a raw/unfiltered seed (Req 2).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from scenario_forge.pipeline.coverage_planning import (
    MAX_FALLBACK_CHOICES,
    CoverageCompleteness,
    CoverageExclusionReason,
    CoverageGapReason,
    CoverageTarget,
    CoverageUniverse,
    QualityGap,
    build_coverage_universe,
    build_fallback_queues,
    emit_quality_gaps,
    select_with_coverage_priority,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(
    entry_points: list[EntryPoint],
    zones_active: list[str] | None = None,
) -> CapabilityProfile:
    """Build a minimal CapabilityProfile for testing."""
    return CapabilityProfile(
        zones_active=zones_active or ["input", "reasoning", "tool_execution"],
        entry_points=entry_points,
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
    )


def _make_fseed(
    seed_id: str = "AP-T1-01",
    entry_point_id: str = "ep-1",
    candidate_id: str = "cand-filter-1",
    pinned_technique_ids: tuple[str, ...] = ("T1",),
    pinned_entry_point: str = "user prompt",
    threat_id: str = "T1",
) -> MagicMock:
    """Build a mock FilteredSeed for testing."""
    m = MagicMock()
    m.seed_id = seed_id
    m.entry_point_id = entry_point_id
    m.candidate_id = candidate_id
    m.pinned_technique_ids = pinned_technique_ids
    m.pinned_entry_point = pinned_entry_point
    m.threat_id = threat_id
    m.attack_pattern_name = "Test Pattern"
    return m


def _make_pc(
    candidate_id: str = "cand:v2:aaa",
    pattern_id: str = "AP-T1-01",
    entry_point_id: str = "ep-1",
) -> MagicMock:
    """Build a mock ProjectedCandidate for testing."""
    m = MagicMock()
    m.candidate_id = candidate_id
    m.pattern_id = pattern_id
    m.canonical_ingress = MagicMock()
    m.canonical_ingress.entry_point_id = entry_point_id
    return m


# ---------------------------------------------------------------------------
# Coverage universe tests (Req 1)
# ---------------------------------------------------------------------------


class TestBuildCoverageUniverse:
    """Tests for coverage universe construction."""

    def test_input_direct_is_feasible(self) -> None:
        ep = EntryPoint(name="user prompt", direction="input", controllability="direct")
        profile = _make_profile([ep])
        universe = build_coverage_universe(profile)
        assert len(universe.feasible_targets) == 1
        assert universe.feasible_targets[0].entry_point_id == ep.entry_point_id
        assert universe.feasible_targets[0].direction == "input"
        assert universe.feasible_targets[0].controllability == "direct"

    def test_bidirectional_indirect_is_feasible(self) -> None:
        ep = EntryPoint(
            name="rag knowledge base",
            direction="bidirectional",
            controllability="indirect",
        )
        profile = _make_profile([ep])
        universe = build_coverage_universe(profile)
        assert len(universe.feasible_targets) == 1
        assert universe.feasible_targets[0].controllability == "indirect"

    def test_output_only_excluded_with_typed_reason(self) -> None:
        ep = EntryPoint(name="system log output", direction="output")
        profile = _make_profile([ep])
        universe = build_coverage_universe(profile)
        assert len(universe.feasible_targets) == 0
        assert len(universe.excluded_targets) == 1
        assert (
            universe.excluded_targets[0].reason == CoverageExclusionReason.OUTPUT_ONLY
        )

    def test_system_controlled_excluded_with_typed_reason(self) -> None:
        ep = EntryPoint(
            name="internal API",
            direction="input",
            controllability="system",
        )
        profile = _make_profile([ep])
        universe = build_coverage_universe(profile)
        assert len(universe.feasible_targets) == 0
        assert len(universe.excluded_targets) == 1
        assert (
            universe.excluded_targets[0].reason
            == CoverageExclusionReason.SYSTEM_CONTROLLED
        )

    def test_inactive_zone_excluded(self) -> None:
        ep = EntryPoint(
            name="memory store",
            direction="input",
            controllability="indirect",
            ingress_zone="memory",
        )
        # memory not in active zones
        profile = _make_profile([ep], zones_active=["input", "reasoning"])
        universe = build_coverage_universe(profile)
        assert len(universe.feasible_targets) == 0
        assert len(universe.excluded_targets) == 1
        assert (
            universe.excluded_targets[0].reason == CoverageExclusionReason.INACTIVE_ZONE
        )

    def test_completeness_defaults_to_not_applicable(self) -> None:
        ep = EntryPoint(name="user prompt", direction="input", controllability="direct")
        profile = _make_profile([ep])
        universe = build_coverage_universe(profile)
        assert universe.completeness == CoverageCompleteness.NOT_APPLICABLE

    def test_completeness_confirmed_complete(self) -> None:
        ep = EntryPoint(name="user prompt", direction="input", controllability="direct")
        profile = _make_profile([ep])
        universe = build_coverage_universe(
            profile, completeness=CoverageCompleteness.CONFIRMED_COMPLETE
        )
        assert universe.completeness == CoverageCompleteness.CONFIRMED_COMPLETE

    def test_mixed_profile(self) -> None:
        eps = [
            EntryPoint(name="user prompt", direction="input", controllability="direct"),
            EntryPoint(name="system log", direction="output"),
            EntryPoint(
                name="internal API",
                direction="input",
                controllability="system",
            ),
            EntryPoint(
                name="rag docs",
                direction="bidirectional",
                controllability="indirect",
            ),
        ]
        profile = _make_profile(eps)
        universe = build_coverage_universe(profile)
        assert len(universe.feasible_targets) == 2
        assert len(universe.excluded_targets) == 2
        reasons = {e.reason for e in universe.excluded_targets}
        assert CoverageExclusionReason.OUTPUT_ONLY in reasons
        assert CoverageExclusionReason.SYSTEM_CONTROLLED in reasons


# ---------------------------------------------------------------------------
# Fallback queue tests (Req 4)
# ---------------------------------------------------------------------------


class TestBuildFallbackQueues:
    """Tests for fallback queue construction."""

    def test_queue_bounded_to_max_three(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[CoverageTarget("ep-1", "test", "input", "direct")],
        )
        joined = []
        for i in range(10):
            joined.append(
                (
                    _make_fseed(
                        candidate_id=f"cf-{i}", pinned_technique_ids=(f"T{i}",)
                    ),
                    _make_pc(candidate_id=f"cand:v2:{i:032x}", entry_point_id="ep-1"),
                )
            )
        queues = build_fallback_queues(joined, universe)
        assert len(queues["ep-1"].choices) == MAX_FALLBACK_CHOICES

    def test_queue_empty_for_target_with_no_candidates(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[CoverageTarget("ep-1", "test", "input", "direct")],
        )
        queues = build_fallback_queues([], universe)
        assert queues["ep-1"].is_empty

    def test_queue_deterministic_ranking(self) -> None:
        """Queue is ranked by technique count desc, then encounter order."""
        universe = CoverageUniverse(
            feasible_targets=[CoverageTarget("ep-1", "test", "input", "direct")],
        )
        joined = [
            (
                _make_fseed(candidate_id="cf-a", pinned_technique_ids=("T1",)),
                _make_pc(candidate_id="cand:v2:aaa", entry_point_id="ep-1"),
            ),
            (
                _make_fseed(
                    candidate_id="cf-b", pinned_technique_ids=("T1", "T2", "T3")
                ),
                _make_pc(candidate_id="cand:v2:bbb", entry_point_id="ep-1"),
            ),
            (
                _make_fseed(candidate_id="cf-c", pinned_technique_ids=("T1", "T2")),
                _make_pc(candidate_id="cand:v2:ccc", entry_point_id="ep-1"),
            ),
        ]
        queues = build_fallback_queues(joined, universe)
        ids = queues["ep-1"].candidate_ids()
        # Most techniques first
        assert ids[0] == "cand:v2:bbb"
        assert ids[1] == "cand:v2:ccc"
        assert ids[2] == "cand:v2:aaa"

    def test_queue_first_choice_and_remaining(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[CoverageTarget("ep-1", "test", "input", "direct")],
        )
        joined = [
            (
                _make_fseed(candidate_id="cf-a", pinned_technique_ids=("T1",)),
                _make_pc(candidate_id="cand:v2:aaa", entry_point_id="ep-1"),
            ),
            (
                _make_fseed(candidate_id="cf-b", pinned_technique_ids=("T1", "T2")),
                _make_pc(candidate_id="cand:v2:bbb", entry_point_id="ep-1"),
            ),
        ]
        queues = build_fallback_queues(joined, universe)
        q = queues["ep-1"]
        assert q.first_choice is not None
        assert q.first_choice[1].candidate_id == "cand:v2:bbb"
        assert len(q.remaining_choices) == 1
        assert q.remaining_choices[0][1].candidate_id == "cand:v2:aaa"

    def test_queue_per_target_isolation(self) -> None:
        """Candidates for different targets go to different queues."""
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
                CoverageTarget("ep-2", "test2", "input", "direct"),
            ],
        )
        joined = [
            (_make_fseed(entry_point_id="ep-1"), _make_pc(entry_point_id="ep-1")),
            (_make_fseed(entry_point_id="ep-2"), _make_pc(entry_point_id="ep-2")),
        ]
        queues = build_fallback_queues(joined, universe)
        assert len(queues["ep-1"].choices) == 1
        assert len(queues["ep-2"].choices) == 1


# ---------------------------------------------------------------------------
# Coverage-aware selection tests (Req 3, 8)
# ---------------------------------------------------------------------------


class TestSelectWithCoveragePriority:
    """Tests for coverage-aware selection."""

    def test_one_candidate_per_feasible_target(self) -> None:
        """Phase 1: one candidate per feasible target."""
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
                CoverageTarget("ep-2", "test2", "input", "direct"),
            ],
        )
        joined = [
            (
                _make_fseed(entry_point_id="ep-1"),
                _make_pc(candidate_id="cand:v2:001", entry_point_id="ep-1"),
            ),
            (
                _make_fseed(entry_point_id="ep-2"),
                _make_pc(candidate_id="cand:v2:002", entry_point_id="ep-2"),
            ),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(joined, queues, universe)
        assert len(result.selected) == 2
        assert result.uncovered_target_ids == []

    def test_uncovered_target_when_no_candidate(self) -> None:
        """Target with no candidate is uncovered."""
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
                CoverageTarget("ep-2", "test2", "input", "direct"),
            ],
        )
        joined = [
            (_make_fseed(entry_point_id="ep-1"), _make_pc(entry_point_id="ep-1")),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(joined, queues, universe)
        assert len(result.selected) == 1
        assert "ep-2" in result.uncovered_target_ids

    def test_cap_preserves_sole_target_coverage(self) -> None:
        """Capping must not discard a target's sole accepted candidate (Req 3, 8)."""
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
                CoverageTarget("ep-2", "test2", "input", "direct"),
            ],
        )
        # Two candidates for same pattern, different targets.
        # Cap=1 should still keep one per target.
        joined = [
            (
                _make_fseed(seed_id="AP-T1-01", entry_point_id="ep-1"),
                _make_pc(
                    candidate_id="cand:v2:001",
                    pattern_id="AP-T1-01",
                    entry_point_id="ep-1",
                ),
            ),
            (
                _make_fseed(seed_id="AP-T1-01", entry_point_id="ep-2"),
                _make_pc(
                    candidate_id="cand:v2:002",
                    pattern_id="AP-T1-01",
                    entry_point_id="ep-2",
                ),
            ),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(
            joined, queues, universe, max_per_pattern=1
        )
        # Both targets must have coverage despite cap=1 on the shared pattern.
        assert len(result.selected) == 2
        assert result.uncovered_target_ids == []

    def test_cap_applies_to_secondary_choices(self) -> None:
        """Cap limits secondary choices but not Phase 1."""
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        # Three candidates for same pattern and target.
        joined = [
            (
                _make_fseed(candidate_id="cf-1", pinned_technique_ids=("T1",)),
                _make_pc(
                    candidate_id="cand:v2:001",
                    pattern_id="AP-T1-01",
                    entry_point_id="ep-1",
                ),
            ),
            (
                _make_fseed(candidate_id="cf-2", pinned_technique_ids=("T1", "T2")),
                _make_pc(
                    candidate_id="cand:v2:002",
                    pattern_id="AP-T1-01",
                    entry_point_id="ep-1",
                ),
            ),
            (
                _make_fseed(
                    candidate_id="cf-3", pinned_technique_ids=("T1", "T2", "T3")
                ),
                _make_pc(
                    candidate_id="cand:v2:003",
                    pattern_id="AP-T1-01",
                    entry_point_id="ep-1",
                ),
            ),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(
            joined, queues, universe, max_per_pattern=1
        )
        # Phase 1: 1 candidate (first choice). Phase 2: 0 (cap=1).
        assert len(result.selected) == 1
        assert result.capped_count == 2

    def test_selection_does_not_default_to_first_raw_seed(self) -> None:
        """Regression: selection does not default to first raw seed (Req 8).

        The first candidate encountered is NOT automatically selected if
        a higher-technique-count candidate exists for the same target.
        Selection uses the fallback queue's deterministic ranking, not
        raw seed encounter order.
        """
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        joined = [
            # First encountered: 1 technique
            (
                _make_fseed(candidate_id="cf-raw-1", pinned_technique_ids=("T1",)),
                _make_pc(candidate_id="cand:v2:raw1", entry_point_id="ep-1"),
            ),
            # Second encountered: 3 techniques (should be ranked first)
            (
                _make_fseed(
                    candidate_id="cf-raw-2", pinned_technique_ids=("T1", "T2", "T3")
                ),
                _make_pc(candidate_id="cand:v2:raw2", entry_point_id="ep-1"),
            ),
        ]
        queues = build_fallback_queues(joined, universe)
        # With max_per_pattern=1, only the first-ranked candidate is selected.
        result = select_with_coverage_priority(
            joined, queues, universe, max_per_pattern=1
        )
        assert len(result.selected) == 1
        # The selected candidate should be the one with more techniques,
        # NOT the first raw seed encountered.
        assert result.selected[0][1].candidate_id == "cand:v2:raw2"


# ---------------------------------------------------------------------------
# Quality gap tests (Req 5)
# ---------------------------------------------------------------------------


class TestEmitQualityGaps:
    """Tests for typed quality gap emission."""

    def test_no_gap_for_covered_target(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        joined = [
            (_make_fseed(entry_point_id="ep-1"), _make_pc(entry_point_id="ep-1")),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(joined, queues, universe)
        gaps = emit_quality_gaps(
            universe,
            result,
            queues,
            generated_target_ids={"ep-1"},
        )
        assert gaps == []

    def test_no_seed_gap_for_target_with_no_candidates(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        queues = build_fallback_queues([], universe)
        result = select_with_coverage_priority([], queues, universe)
        gaps = emit_quality_gaps(universe, result, queues)
        assert len(gaps) == 1
        assert gaps[0].reason == CoverageGapReason.NO_SEED
        assert gaps[0].entry_point_id == "ep-1"

    def test_generation_exhaustion_for_failed_generation(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        joined = [
            (_make_fseed(entry_point_id="ep-1"), _make_pc(entry_point_id="ep-1")),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(joined, queues, universe)
        # No generated scenarios
        gaps = emit_quality_gaps(universe, result, queues)
        assert len(gaps) == 1
        assert gaps[0].reason == CoverageGapReason.GENERATION_EXHAUSTION

    def test_admission_failure_for_quarantined_target(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        joined = [
            (_make_fseed(entry_point_id="ep-1"), _make_pc(entry_point_id="ep-1")),
        ]
        queues = build_fallback_queues(joined, universe)
        result = select_with_coverage_priority(joined, queues, universe)
        # Target quarantined: only in quarantined_target_ids, not generated.
        gaps = emit_quality_gaps(
            universe,
            result,
            queues,
            generated_target_ids=set(),
            quarantined_target_ids={"ep-1"},
        )
        assert len(gaps) == 1
        assert gaps[0].reason == CoverageGapReason.ADMISSION_FAILURE

    def test_filter_rejection_gap(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        queues = build_fallback_queues([], universe)
        result = select_with_coverage_priority([], queues, universe)
        gaps = emit_quality_gaps(
            universe,
            result,
            queues,
            filter_rejected_by_target={"ep-1": ["cf-1", "cf-2"]},
        )
        assert len(gaps) == 1
        assert gaps[0].reason == CoverageGapReason.FILTER_REJECTION
        assert "cf-1" in gaps[0].candidate_ids
        assert "cf-2" in gaps[0].candidate_ids

    def test_deterministic_rule_rejection_gap(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        queues = build_fallback_queues([], universe)
        result = select_with_coverage_priority([], queues, universe)
        gaps = emit_quality_gaps(
            universe,
            result,
            queues,
            rule_rejected_by_target={"ep-1": ["cf-1"]},
        )
        assert len(gaps) == 1
        assert gaps[0].reason == CoverageGapReason.DETERMINISTIC_RULE_REJECTION

    def test_projection_rejection_gap(self) -> None:
        universe = CoverageUniverse(
            feasible_targets=[
                CoverageTarget("ep-1", "test1", "input", "direct"),
            ],
        )
        queues = build_fallback_queues([], universe)
        result = select_with_coverage_priority([], queues, universe)
        gaps = emit_quality_gaps(
            universe,
            result,
            queues,
            projection_rejected_by_target={"ep-1": ["cf-1"]},
        )
        assert len(gaps) == 1
        assert gaps[0].reason == CoverageGapReason.PROJECTION_REJECTION

    def test_quality_gap_to_dict(self) -> None:
        gap = QualityGap(
            entry_point_id="ep-1",
            entry_point_name="test",
            reason=CoverageGapReason.NO_SEED,
            candidate_ids=[],
            detail="No seed.",
        )
        d = gap.to_dict()
        assert d["entry_point_id"] == "ep-1"
        assert d["reason"] == "no_seed"
        assert d["detail"] == "No seed."


# ---------------------------------------------------------------------------
# No raw seed generation (Req 2)
# ---------------------------------------------------------------------------


class TestNoRawSeedGeneration:
    """Regression: no scenario is generated from a raw/unfiltered seed."""

    def test_remediation_function_removed(self) -> None:
        """The _remediate_coverage_gaps function no longer exists in runner."""
        from scenario_forge.pipeline import runner

        assert not hasattr(runner, "_remediate_coverage_gaps")

    def test_pick_best_seed_removed(self) -> None:
        """The _pick_best_seed_for_entry_point function no longer exists."""
        from scenario_forge.pipeline import runner

        assert not hasattr(runner, "_pick_best_seed_for_entry_point")

    def test_no_remediation_in_run_pipeline_source(self) -> None:
        """run_pipeline source does not contain remediation invocation."""
        import inspect

        from scenario_forge.pipeline.runner import run_pipeline

        source = inspect.getsource(run_pipeline)
        assert "_remediate_coverage_gaps" not in source
        assert "Coverage Remediation Pass" not in source

    def test_coverage_aware_planning_in_run_pipeline_source(self) -> None:
        """run_pipeline source contains coverage-aware planning."""
        import inspect

        from scenario_forge.pipeline.runner import run_pipeline

        source = inspect.getsource(run_pipeline)
        assert "build_coverage_universe" in source
        assert "build_fallback_queues" in source
        assert "select_with_coverage_priority" in source
        assert "emit_quality_gaps" in source
