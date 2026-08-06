"""Comprehensive regression tests for cmps.4 coverage-aware planning."""

from __future__ import annotations

import inspect

import pytest

from scenario_forge.models.attack_pattern import EntryPointResourceReference
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import FilteredSeed
from scenario_forge.pipeline.coverage_planning import (
    MAX_FALLBACK_CHOICES,
    STAGE_ADMISSION,
    STAGE_FILTER,
    STAGE_GENERATION,
    STAGE_PROJECTION,
    STAGE_QUARANTINE,
    STAGE_RULES,
    STAGE_SELECTION,
    CoverageCompleteness,
    CoverageExclusionReason,
    CoverageGapReason,
    CoverageTarget,
    CoverageUniverse,
    ExcludedTarget,
    QualifiedCandidate,
    SelectionResult,
    StageLedger,
    build_coverage_plan,
    build_coverage_universe,
    build_fallback_queues,
    build_qualified_candidates,
    emit_quality_gaps,
    select_with_coverage_priority,
)
from scenario_forge.pipeline.projection import ProjectedCandidate
from tests.helpers.projection_factory import get_projected_candidate


def _profile(
    entries: list[EntryPoint],
    *,
    zones: list[str] | None = None,
    confirmed: bool = False,
) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=zones or ["input", "reasoning", "tool_execution"],
        entry_points=entries,
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
        entry_point_completeness=(
            InventoryCompleteness.operator_confirmed_complete
            if confirmed
            else InventoryCompleteness.inferred_partial
        ),
        entry_point_evidence=["operator-review:architecture-v3"] if confirmed else [],
    )


def _risk() -> RiskCardRef:
    return RiskCardRef(
        risk_id="risk-1",
        risk_name="Test risk",
        risk_description="Test risk description.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


# Real ProjectedCandidate fixture from the shared test projection factory.
# All test doubles below are derived from this via model_copy, producing
# real ProjectedCandidate instances (not permissive MagicMock).
_REAL_PC = get_projected_candidate()
_REAL_EP_ID = _REAL_PC.canonical_ingress.entry_point_id
_REAL_PATTERN_ID = _REAL_PC.pattern_id


def _ep_ref(entry_point_id: str) -> EntryPointResourceReference:
    """Build an EntryPointResourceReference with the given entry_point_id."""
    return EntryPointResourceReference(
        kind="entry_point",
        entry_point_id=entry_point_id,
    )


def _ep_id(num: int = 1) -> str:
    """Build a valid ep:v1: entry_point_id from an integer."""
    return f"ep:v1:{num:032x}"


def _make_fseed(
    *,
    seed_id: str = "AP-T1-01",
    entry_point_id: str = _REAL_EP_ID,
    candidate_id: str = "filter-candidate-1",
    techniques: tuple[str, ...] = ("AML.T0051",),
    rationale: str = "Accepted because it is feasible.",
) -> FilteredSeed:
    """Return a real validated FilteredSeed, not a permissive mock."""
    return FilteredSeed(
        seed_id=seed_id,
        threat_id="T1",
        threat_name="Test threat",
        attack_pattern_name="Test pattern",
        attack_pattern_description="Test attack pattern description.",
        risk_card_ref=_risk(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        pinned_entry_point="user prompt",
        pinned_technique_ids=techniques,
        pinned_technique_names=tuple(f"Technique {i}" for i in range(len(techniques))),
        entry_point_id=entry_point_id,
        candidate_id=candidate_id,
        accepted_rationale=rationale,
    )


def _make_pc(
    candidate_id: str = "cand:v2:00000000000000000000000000000001",
    *,
    pattern_id: str = _REAL_PATTERN_ID,
    entry_point_id: str = _REAL_EP_ID,
) -> ProjectedCandidate:
    """Make a real ProjectedCandidate test fixture via model_copy.

    Uses the shared test projection factory as a base and creates
    variants with different candidate_id, pattern_id, and canonical_ingress
    via model_copy (bypassing validators).  This produces real
    ProjectedCandidate instances, not permissive mocks.
    """
    return _REAL_PC.model_copy(
        update={
            "candidate_id": candidate_id,
            "pattern_id": pattern_id,
            "canonical_ingress": _ep_ref(entry_point_id),
        }
    )


def _qc(
    number: int,
    *,
    ep: str = _REAL_EP_ID,
    pattern: str = _REAL_PATTERN_ID,
    techniques: tuple[str, ...] = ("AML.T0051",),
) -> QualifiedCandidate:
    cid = f"cand:v2:{number:032x}"
    return QualifiedCandidate(
        projected=_make_pc(cid, pattern_id=pattern, entry_point_id=ep),
        filtered_seed=_make_fseed(
            seed_id=pattern,
            entry_point_id=ep,
            candidate_id=f"filter-{ep}-{number}",
            techniques=techniques,
        ),
        accepted_rationale="accepted",
    )


def _universe(*ids: str) -> CoverageUniverse:
    return CoverageUniverse(
        feasible_targets=[
            CoverageTarget(i, f"Target {i}", "input", "direct") for i in ids
        ]
    )


class TestBuildCoverageUniverse:
    def test_input_direct_is_feasible(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        assert (
            build_coverage_universe(_profile([ep])).feasible_targets[0].entry_point_id
            == ep.entry_point_id
        )

    def test_bidirectional_indirect_is_feasible(self) -> None:
        ep = EntryPoint(
            name="RAG documents", direction="bidirectional", controllability="indirect"
        )
        target = build_coverage_universe(_profile([ep])).feasible_targets[0]
        assert (target.direction, target.controllability) == (
            "bidirectional",
            "indirect",
        )

    @pytest.mark.parametrize(
        ("entry", "reason"),
        [
            (
                EntryPoint(name="logs", direction="output"),
                CoverageExclusionReason.OUTPUT_ONLY,
            ),
            (
                EntryPoint(
                    name="internal", direction="input", controllability="system"
                ),
                CoverageExclusionReason.SYSTEM_CONTROLLED,
            ),
            (
                EntryPoint(
                    name="memory",
                    direction="input",
                    controllability="indirect",
                    ingress_zone="memory",
                ),
                CoverageExclusionReason.INACTIVE_ZONE,
            ),
        ],
    )
    def test_typed_exclusions(
        self, entry: EntryPoint, reason: CoverageExclusionReason
    ) -> None:
        universe = build_coverage_universe(
            _profile([entry], zones=["input", "reasoning"])
        )
        assert universe.feasible_targets == []
        assert universe.excluded_targets[0].reason is reason

    def test_completeness_is_not_applicable_for_inferred_profile(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        assert (
            build_coverage_universe(_profile([ep])).completeness
            is CoverageCompleteness.NOT_APPLICABLE
        )

    def test_operator_confirmation_sets_complete_and_evidence(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=True))
        assert universe.completeness is CoverageCompleteness.CONFIRMED_COMPLETE
        assert universe.evidence_refs == ["operator-review:architecture-v3"]

    def test_caller_cannot_promote_inferred_profile_with_enum(self) -> None:
        assert (
            "completeness" not in inspect.signature(build_coverage_universe).parameters
        )

    def test_mixed_profile(self) -> None:
        entries = [
            EntryPoint(name="prompt", direction="input", controllability="direct"),
            EntryPoint(
                name="RAG", direction="bidirectional", controllability="indirect"
            ),
            EntryPoint(name="logs", direction="output"),
            EntryPoint(name="internal", direction="input", controllability="system"),
        ]
        universe = build_coverage_universe(_profile(entries))
        assert len(universe.feasible_targets) == 2
        assert {e.reason for e in universe.excluded_targets} == {
            CoverageExclusionReason.OUTPUT_ONLY,
            CoverageExclusionReason.SYSTEM_CONTROLLED,
        }


class TestBuildQualifiedCandidates:
    def test_fans_out_distinct_projected_bindings(self) -> None:
        seed = _make_fseed()
        pcs = [_make_pc(f"cand:v2:{i:032x}") for i in (1, 2)]
        result = build_qualified_candidates([seed], {seed.seed_id: pcs})
        assert [q.candidate_id for q in result] == [p.candidate_id for p in pcs]

    def test_dedupes_by_projected_candidate_id(self) -> None:
        seed = _make_fseed()
        pc = _make_pc()
        assert (
            len(build_qualified_candidates([seed, seed], {seed.seed_id: [pc, pc]})) == 1
        )

    def test_preserves_accepted_rationale(self) -> None:
        seed = _make_fseed(rationale="specific filter evidence")
        result = build_qualified_candidates([seed], {seed.seed_id: [_make_pc()]})
        assert result[0].accepted_rationale == "specific filter evidence"

    def test_no_matching_ingress_is_empty(self) -> None:
        seed = _make_fseed(entry_point_id=_REAL_EP_ID)
        assert (
            build_qualified_candidates(
                [seed], {seed.seed_id: [_make_pc(entry_point_id=_ep_id(2))]}
            )
            == []
        )


class TestBuildFallbackQueues:
    def test_queue_is_bounded(self) -> None:
        queue = build_fallback_queues(
            [_qc(i) for i in range(5)], _universe(_REAL_EP_ID)
        )[_REAL_EP_ID]
        assert len(queue.choices) == MAX_FALLBACK_CHOICES == 3

    def test_target_without_candidates_has_empty_queue(self) -> None:
        assert build_fallback_queues([], _universe(_REAL_EP_ID))[_REAL_EP_ID].is_empty

    def test_encounter_order_not_technique_count_controls_rank(self) -> None:
        first = _qc(9, techniques=("T1",))
        second = _qc(1, techniques=("T1", "T2", "T3"))
        queue = build_fallback_queues([first, second], _universe(_REAL_EP_ID))[
            _REAL_EP_ID
        ]
        assert queue.candidate_ids() == [first.candidate_id, second.candidate_id]
        assert [choice.rank for choice in queue.choices] == [0, 1]

    def test_first_and_remaining_choices(self) -> None:
        candidates = [_qc(i) for i in (1, 2, 3)]
        queue = build_fallback_queues(candidates, _universe(_REAL_EP_ID))[_REAL_EP_ID]
        assert queue.first_choice.candidate_id == candidates[0].candidate_id
        assert [q.candidate_id for q in queue.remaining_choices] == [
            q.candidate_id for q in candidates[1:]
        ]

    def test_queues_are_isolated_per_target(self) -> None:
        queues = build_fallback_queues(
            [_qc(1, ep=_ep_id(10)), _qc(2, ep=_ep_id(11))],
            _universe(_ep_id(10), _ep_id(11)),
        )
        assert queues[_ep_id(10)].candidate_ids() == [
            _qc(1, ep=_ep_id(10)).candidate_id
        ]
        assert queues[_ep_id(11)].candidate_ids() == [
            _qc(2, ep=_ep_id(11)).candidate_id
        ]

    def test_distinct_binding_alternatives_all_appear(self) -> None:
        choices = [_qc(i, pattern="same-pattern") for i in (1, 2, 3)]
        assert build_fallback_queues(choices, _universe(_REAL_EP_ID))[
            _REAL_EP_ID
        ].candidate_ids() == [q.candidate_id for q in choices]


class TestSelectWithCoveragePriority:
    def _select(
        self,
        candidates: list[QualifiedCandidate],
        universe: CoverageUniverse,
        cap: int | None = None,
    ):
        queues = build_fallback_queues(candidates, universe)
        return select_with_coverage_priority(candidates, queues, universe, cap), queues

    def test_phase_one_covers_each_feasible_target(self) -> None:
        result, _ = self._select(
            [_qc(1, ep=_ep_id(10)), _qc(2, ep=_ep_id(11))],
            _universe(_ep_id(10), _ep_id(11)),
        )
        assert set(result.primary_candidate_ids) == {_ep_id(10), _ep_id(11)}

    def test_reports_target_without_candidate(self) -> None:
        result, _ = self._select(
            [_qc(1, ep=_ep_id(10))], _universe(_ep_id(10), _ep_id(11))
        )
        assert result.uncovered_target_ids == [_ep_id(11)]

    def test_cap_is_immune_for_sole_target_coverage(self) -> None:
        result, _ = self._select(
            [_qc(1, ep=_ep_id(10)), _qc(2, ep=_ep_id(11))],
            _universe(_ep_id(10), _ep_id(11)),
            1,
        )
        assert len(result.selected) == 2
        assert result.per_pattern_counts[_REAL_PATTERN_ID] == 2

    def test_only_primaries_selected_not_fallbacks(self) -> None:
        """cmps.4 blocker 2: Only Phase-1 primaries are selected/attempted.
        Remaining choices are fallback_available, not consumed."""
        result, _queues = self._select([_qc(1), _qc(2), _qc(3)], _universe(_REAL_EP_ID))
        # Only the primary (first choice) is selected.
        assert [q.candidate_id for q in result.selected] == [_qc(1).candidate_id]
        # Remaining choices are NOT in attempted.
        assert _qc(2).candidate_id not in result.attempted_candidate_ids
        assert _qc(3).candidate_id not in result.attempted_candidate_ids

    def test_all_non_primary_choices_are_fallback_available(self) -> None:
        """cmps.4 blocker 2: Persisted plan's fallback_available excludes
        only the attempted primary; all other choices are recoverable."""
        result, queues = self._select([_qc(1), _qc(2), _qc(3)], _universe(_REAL_EP_ID))
        plan = build_coverage_plan(_universe(_REAL_EP_ID), queues, result)
        fb_ids = [r["candidate_id"] for r in plan.targets[0].fallback_available]
        assert _qc(1).candidate_id not in fb_ids
        assert _qc(2).candidate_id in fb_ids
        assert _qc(3).candidate_id in fb_ids

    def test_cap_does_not_apply_to_primaries(self) -> None:
        """With only Phase 1, cap never discards a sole target candidate."""
        result, _ = self._select([_qc(1), _qc(2)], _universe(_REAL_EP_ID), 1)
        assert [q.candidate_id for q in result.selected] == [_qc(1).candidate_id]
        assert result.capped_count == 0

    def test_selection_does_not_prefer_raw_seed_or_more_techniques(self) -> None:
        first = _qc(9, techniques=("T1",))
        richer = _qc(1, techniques=("T1", "T2"))
        result, _ = self._select([first, richer], _universe(_REAL_EP_ID))
        assert result.primary_candidate_ids[_REAL_EP_ID] == first.candidate_id


class TestStageLedger:
    def test_record_retrieve_and_serialize(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "c1", STAGE_FILTER, "rejected", "why")
        assert ledger.events_for("ep")[0].candidate_id == "c1"
        assert ledger.to_dict()["events"][0]["detail"] == "why"

    def test_furthest_event_uses_pipeline_order(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "generated", STAGE_GENERATION, "failed")
        ledger.record("ep", "early", STAGE_RULES, "rejected")
        assert ledger.furthest_event("ep").candidate_id == "generated"

    def test_candidate_ids_for_stage_are_exact(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "c1", STAGE_GENERATION, "failed")
        ledger.record("ep", "c2", STAGE_GENERATION, "failed")
        ledger.record("ep", "c3", STAGE_FILTER, "rejected")
        assert ledger.candidate_ids_for_stage("ep", STAGE_GENERATION) == ["c1", "c2"]

    def test_no_events_has_no_furthest_event(self) -> None:
        assert StageLedger().furthest_event("missing") is None


def _emit(
    universe: CoverageUniverse,
    ledger: StageLedger,
    *,
    generated=(),
    quarantined=(),
    limited=(),
):
    selection = SelectionResult(
        uncovered_target_ids=[t.entry_point_id for t in universe.feasible_targets]
    )
    return emit_quality_gaps(
        universe,
        ledger,
        selection,
        build_fallback_queues([], universe),
        generated_target_ids=set(generated),
        quarantined_target_ids=set(quarantined),
        projection_limitation_target_ids=set(limited),
    )


class TestEmitQualityGaps:
    def test_covered_target_has_no_gap(self) -> None:
        gaps, summary = _emit(_universe("ep"), StageLedger(), generated={"ep"})
        assert gaps == [] and summary.covered_feasible == ["ep"]

    def test_no_seed_without_events(self) -> None:
        gaps, _ = _emit(_universe("ep"), StageLedger())
        assert gaps[0].reason is CoverageGapReason.NO_SEED
        assert gaps[0].candidate_ids == []

    @pytest.mark.parametrize(
        ("stage", "reason", "summary_field"),
        [
            (
                STAGE_RULES,
                CoverageGapReason.DETERMINISTIC_RULE_REJECTION,
                "structural_gaps",
            ),
            (STAGE_FILTER, CoverageGapReason.FILTER_REJECTION, "structural_gaps"),
            (
                STAGE_PROJECTION,
                CoverageGapReason.PROJECTION_REJECTION,
                "structural_gaps",
            ),
            (
                STAGE_SELECTION,
                CoverageGapReason.SELECTION_LIMITATION,
                "selection_limitations",
            ),
            (
                STAGE_GENERATION,
                CoverageGapReason.GENERATION_EXHAUSTION,
                "runtime_generation_gaps",
            ),
            (
                STAGE_ADMISSION,
                CoverageGapReason.ADMISSION_FAILURE,
                "quarantine_admission_failures",
            ),
        ],
    )
    def test_actual_furthest_stage_drives_reason_and_summary(
        self, stage: str, reason: CoverageGapReason, summary_field: str
    ) -> None:
        ledger = StageLedger()
        ledger.record("ep", "exact-candidate", stage, "failed", "actual evidence")
        gaps, summary = _emit(_universe("ep"), ledger)
        assert gaps[0].reason is reason
        assert gaps[0].candidate_ids == ["exact-candidate"]
        assert gaps[0].detail == "actual evidence"
        assert getattr(summary, summary_field)[0]["candidate_ids"] == [
            "exact-candidate"
        ]

    def test_quarantine_preserves_exact_candidate_ids(self) -> None:
        ledger = StageLedger()
        ledger.record("ep", "q-1", STAGE_QUARANTINE, "invalid")
        ledger.record("ep", "q-2", STAGE_QUARANTINE, "invalid")
        gaps, summary = _emit(_universe("ep"), ledger, quarantined={"ep"})
        assert gaps[0].reason is CoverageGapReason.ADMISSION_FAILURE
        assert gaps[0].candidate_ids == ["q-1", "q-2"]
        assert summary.quarantine_admission_failures[0]["candidate_ids"] == [
            "q-1",
            "q-2",
        ]

    def test_projection_budget_limitation(self) -> None:
        gaps, summary = _emit(_universe("ep"), StageLedger(), limited={"ep"})
        assert gaps[0].reason is CoverageGapReason.PROJECTION_LIMITATION
        assert summary.projection_limitations[0]["entry_point_id"] == "ep"

    def test_summary_populates_all_categories_and_policy_exclusions(self) -> None:
        universe = _universe(
            "covered", "structural", "selection", "runtime", "quarantine", "limited"
        )
        universe.excluded_targets.append(
            ExcludedTarget(
                "out", "Output", "output", "system", CoverageExclusionReason.OUTPUT_ONLY
            )
        )
        ledger = StageLedger()
        ledger.record("structural", "s", STAGE_FILTER, "rejected")
        ledger.record("selection", "x", STAGE_SELECTION, "capped")
        ledger.record("runtime", "g", STAGE_GENERATION, "failed")
        ledger.record("quarantine", "q", STAGE_QUARANTINE, "invalid")
        _, summary = _emit(
            universe,
            ledger,
            generated={"covered"},
            quarantined={"quarantine"},
            limited={"limited"},
        )
        data = summary.to_dict()
        assert data["covered_feasible"] == ["covered"]
        assert data["policy_exclusions"][0]["reason"] == "output_only"
        for key in (
            "structural_gaps",
            "selection_limitations",
            "runtime_generation_gaps",
            "quarantine_admission_failures",
            "projection_limitations",
        ):
            assert data[key], key


class TestCoveragePlan:
    def test_round_trip_preserves_ordered_fallbacks_and_schema(self) -> None:
        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=[queues[_REAL_EP_ID].choices[0]],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        data = build_coverage_plan(universe, queues, selection).to_dict()
        assert data["schema_version"] == "1"
        assert [r["candidate_id"] for r in data["targets"][0]["ordered_choices"]] == [
            q.candidate_id for q in choices
        ]

    def test_fallback_available_excludes_every_attempted_candidate(self) -> None:
        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=queues[_REAL_EP_ID].choices[:2],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id, choices[1].candidate_id},
        )
        entry = build_coverage_plan(universe, queues, selection).targets[0]
        assert [r["candidate_id"] for r in entry.fallback_available] == [
            choices[2].candidate_id
        ]

    @pytest.mark.parametrize("outcome", ["generated", "failed", "quarantined"])
    def test_primary_state_reflects_generation_outcome(self, outcome: str) -> None:
        universe = _universe(_REAL_EP_ID)
        choice = _qc(1)
        queues = build_fallback_queues([choice], universe)
        selection = SelectionResult(
            primary_candidate_ids={_REAL_EP_ID: choice.candidate_id},
            attempted_candidate_ids={choice.candidate_id},
        )
        plan = build_coverage_plan(
            universe, queues, selection, {choice.candidate_id: outcome}
        )
        assert plan.targets[0].primary_state == outcome


class TestNoRawSeedGeneration:
    def test_legacy_remediation_helpers_removed(self) -> None:
        from scenario_forge.pipeline import runner

        assert not hasattr(runner, "_remediate_coverage_gaps")
        assert not hasattr(runner, "_pick_best_seed_for_entry_point")

    def test_run_pipeline_uses_coverage_aware_planning_without_remediation(
        self,
    ) -> None:
        from scenario_forge.pipeline.runner import run_pipeline

        source = inspect.getsource(run_pipeline)
        for call in (
            "build_coverage_universe(",
            "build_qualified_candidates(",
            "build_fallback_queues(",
            "select_with_coverage_priority(",
            "build_coverage_plan(",
            "emit_quality_gaps(",
        ):
            assert call in source
        assert "_remediate_coverage_gaps(" not in source


class TestProjectionBudgetAllocation:
    """cmps.4 blocker 5: coverage-aware projection budget allocation."""

    def test_coverage_target_ids_reserve_target_before_variants(self) -> None:
        """Projection with coverage_target_ids reserves one feasible candidate
        per coverage target before variant expansion."""
        from scenario_forge.pipeline.projection import (
            ProjectionBudget,
            project_authoritative_candidates,
        )

        pc = get_projected_candidate()
        target_id = pc.canonical_ingress.entry_point_id
        # Access cached projection internals for the raw pattern and resolver.
        from tests.helpers.projection_factory import _cached_project

        _, resolver, snapshot, raw = _cached_project()
        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids={target_id},
        )
        projected_ids = {c.canonical_ingress.entry_point_id for c in batch.candidates}
        assert target_id in projected_ids

    def test_multi_ingress_small_budget_reserves_one_and_reports_unreserved(
        self,
    ) -> None:
        """Genuine multi-ingress regression: a profile with two direct entry
        points and budget=1 must reserve one target and report the other as
        unreserved (cmps.4 blocker 5).

        This uses a real projection with two distinct bindings (different
        entry_point_ids) — not model_copy — so candidate_ids are genuinely
        computed from different projections.
        """
        from scenario_forge.models.attack_pattern import AttackPattern
        from scenario_forge.models.capability_profile import (
            CapabilityProfile,
            ConfidenceLevel,
        )
        from scenario_forge.pipeline.projection import (
            ProjectionBudget,
            capture_capability_snapshot,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            _evidence,
            _pattern,
            _TaxonomyResolver,
        )

        raw = _pattern()
        pattern = AttackPattern.model_validate(raw)
        resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        # Profile with TWO direct entry points → two distinct bindings.
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "chat", "direction": "input", "controllability": "direct"},
                {"name": "api", "direction": "input", "controllability": "direct"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=[{"name": "writer", "description": "changes state"}],
            tool_types=[
                {
                    "name": "writer",
                    "zone": "tool_execution",
                    "can_modify_state": True,
                    "data_sensitivity": "medium",
                    "code_execution": False,
                }
            ],
            external_integrations=[
                {
                    "name": "CRM",
                    "integration_type": "api",
                    "auth_method": "oauth",
                    "data_sensitivity": "high",
                }
            ],
            trust_boundaries=[
                {
                    "name": "user-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        )
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        target_ids = {ep.entry_point_id for ep in profile.entry_points}
        assert len(target_ids) == 2

        # Budget=1 with two coverage targets: one reserved, one unreserved.
        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids=target_ids,
        )
        assert len(batch.candidates) == 1
        reserved_ep = batch.candidates[0].canonical_ingress.entry_point_id
        unreserved = set(batch.unreserved_coverage_targets)
        # Exactly one target is unreserved.
        assert len(unreserved) == 1
        # The unreserved target is the one NOT in the projected candidates.
        assert reserved_ep not in unreserved
        # Budget limitation is reported.
        assert any(
            lim.code == "candidate_budget_exhausted" for lim in batch.limitations
        )

    def test_budget_below_target_count_emits_unreserved_targets(self) -> None:
        """When budget < feasible target count, projection reports exact
        unreserved target IDs (cmps.4 blocker 5)."""
        from scenario_forge.models.attack_pattern import AttackPattern
        from scenario_forge.models.capability_profile import (
            CapabilityProfile,
            ConfidenceLevel,
        )
        from scenario_forge.pipeline.projection import (
            ProjectionBudget,
            capture_capability_snapshot,
            project_authoritative_candidates,
        )
        from tests.helpers.projection_factory import (
            _evidence,
            _pattern,
            _TaxonomyResolver,
        )

        raw = _pattern()
        pattern = AttackPattern.model_validate(raw)
        resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
        profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                {"name": "chat", "direction": "input", "controllability": "direct"},
                {"name": "api", "direction": "input", "controllability": "direct"},
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1", "KC5.1"],
            tool_inventory=[{"name": "writer", "description": "changes state"}],
            tool_types=[
                {
                    "name": "writer",
                    "zone": "tool_execution",
                    "can_modify_state": True,
                    "data_sensitivity": "medium",
                    "code_execution": False,
                }
            ],
            external_integrations=[
                {
                    "name": "CRM",
                    "integration_type": "api",
                    "auth_method": "oauth",
                    "data_sensitivity": "high",
                }
            ],
            trust_boundaries=[
                {
                    "name": "user-to-agent",
                    "from_zone": "input",
                    "to_zone": "reasoning",
                    "confidence": "explicit",
                }
            ],
        )
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        target_ids = {ep.entry_point_id for ep in profile.entry_points}

        batch = project_authoritative_candidates(
            [raw],
            resolver,
            snapshot,
            budget=ProjectionBudget(max_candidates=1),
            coverage_target_ids=target_ids,
        )
        # Unreserved targets are the exact IDs not covered.
        assert len(batch.unreserved_coverage_targets) == 1
        unreserved_id = batch.unreserved_coverage_targets[0]
        assert unreserved_id in target_ids
        assert unreserved_id not in {
            c.canonical_ingress.entry_point_id for c in batch.candidates
        }


def _profile_for_projection() -> CapabilityProfile:
    """Build a profile with multiple entry points for projection tests."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="user prompt", direction="input", controllability="direct"),
            EntryPoint(
                name="RAG documents",
                direction="bidirectional",
                controllability="indirect",
            ),
        ],
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
        entry_point_completeness=InventoryCompleteness.inferred_partial,
    )


class TestCoverageReportHTML:
    """cmps.4: HTML report categories and exact failed/quarantine IDs."""

    def test_html_report_has_all_category_headings(self) -> None:
        from scenario_forge.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "has_gaps": True,
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_universe": {
                "completeness": "not_applicable",
                "feasible_targets": [],
                "excluded_targets": [],
            },
            "coverage_summary": {
                "covered_feasible": ["covered-ep"],
                "policy_exclusions": [
                    {"entry_point_id": "out", "name": "Output", "reason": "output_only"}
                ],
                "structural_gaps": [
                    {
                        "entry_point_id": "gap-ep",
                        "reason": "no_seed",
                        "candidate_ids": [],
                    }
                ],
                "selection_limitations": [],
                "runtime_generation_gaps": [
                    {
                        "entry_point_id": "fail-ep",
                        "reason": "generation_exhaustion",
                        "candidate_ids": ["cand:v2:abc"],
                    }
                ],
                "quarantine_admission_failures": [
                    {
                        "entry_point_id": "q-ep",
                        "reason": "admission_failure",
                        "candidate_ids": ["cand:v2:xyz"],
                    }
                ],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "not_applicable",
                "evidence_refs": [],
                "targets": [],
            },
            "quality_gaps": [],
        }
        html = build_coverage_section(coverage_data)
        assert "Covered Feasible Targets" in html
        assert "Policy Exclusions" in html
        assert "Structural / Projection Gaps" in html
        assert "Runtime Generation Gaps" in html
        assert "Quarantine / Admission Failures" in html

    def test_html_report_shows_exact_failed_candidate_ids(self) -> None:
        from scenario_forge.report.template import build_coverage_section

        coverage_data = {
            "coverage_gaps": {
                "has_gaps": False,
                "uncovered_entry_points": [],
                "uncovered_zones": [],
                "uncovered_threats": [],
                "uncovered_attack_patterns": [],
            },
            "coverage_summary": {
                "covered_feasible": [],
                "policy_exclusions": [],
                "structural_gaps": [],
                "selection_limitations": [],
                "runtime_generation_gaps": [
                    {
                        "entry_point_id": "fail-ep",
                        "reason": "generation_exhaustion",
                        "candidate_ids": ["cand:v2:aaa", "cand:v2:bbb"],
                    },
                ],
                "quarantine_admission_failures": [
                    {
                        "entry_point_id": "q-ep",
                        "reason": "admission_failure",
                        "candidate_ids": ["cand:v2:qqq"],
                    },
                ],
                "projection_limitations": [],
            },
            "coverage_plan": {
                "schema_version": "1",
                "completeness": "not_applicable",
                "evidence_refs": [],
                "targets": [],
            },
            "quality_gaps": [],
        }
        html = build_coverage_section(coverage_data)
        assert "cand:v2:aaa" in html
        assert "cand:v2:bbb" in html
        assert "cand:v2:qqq" in html


class TestProfileCompletenessDerivation:
    """cmps.4 blocker 4: completeness derived from profile, not free-form input."""

    def test_inferred_profile_reports_not_applicable(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=False))
        assert universe.completeness is CoverageCompleteness.NOT_APPLICABLE
        assert universe.completeness.value == "not_applicable"
        assert universe.evidence_refs == []

    def test_confirmed_profile_reports_confirmed_complete_with_evidence(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=True))
        assert universe.completeness is CoverageCompleteness.CONFIRMED_COMPLETE
        assert universe.completeness.value == "confirmed_complete"
        assert universe.evidence_refs == ["operator-review:architecture-v3"]

    def test_build_coverage_universe_has_no_completeness_parameter(self) -> None:
        assert (
            "completeness" not in inspect.signature(build_coverage_universe).parameters
        )

    def test_coverage_plan_serializes_not_applicable_for_inferred(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=False))
        queues = build_fallback_queues([], universe)
        selection = SelectionResult()
        plan = build_coverage_plan(universe, queues, selection)
        assert plan.completeness == "not_applicable"

    def test_coverage_plan_serializes_confirmed_complete_with_refs(self) -> None:
        ep = EntryPoint(name="prompt", direction="input", controllability="direct")
        universe = build_coverage_universe(_profile([ep], confirmed=True))
        queues = build_fallback_queues([], universe)
        selection = SelectionResult()
        plan = build_coverage_plan(universe, queues, selection)
        assert plan.completeness == "confirmed_complete"
        assert plan.evidence_refs == ["operator-review:architecture-v3"]


class TestPersistedPlanRoundTrip:
    """cmps.4 blocker 2: persisted plan round trip proving ordered fallbacks
    recoverable and exclude attempted primary."""

    def test_json_round_trip_preserves_ordered_choices_and_fallbacks(self) -> None:
        import json

        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=[queues[_REAL_EP_ID].choices[0]],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        plan = build_coverage_plan(universe, queues, selection)
        # Serialize to JSON and back.
        json_str = json.dumps(plan.to_dict())
        recovered = json.loads(json_str)
        target = recovered["targets"][0]
        # Ordered choices preserve all three candidates in rank order.
        assert [r["candidate_id"] for r in target["ordered_choices"]] == [
            q.candidate_id for q in choices
        ]
        # Primary is the first choice.
        assert target["primary_candidate_id"] == choices[0].candidate_id
        assert target["primary_state"] == "selected"
        # Fallback available excludes the attempted primary.
        fallback_ids = [r["candidate_id"] for r in target["fallback_available"]]
        assert choices[0].candidate_id not in fallback_ids
        assert choices[1].candidate_id in fallback_ids
        assert choices[2].candidate_id in fallback_ids

    def test_json_round_trip_with_generation_outcome(self) -> None:
        import json

        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2, 3)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            selected=[queues[_REAL_EP_ID].choices[0]],
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        plan = build_coverage_plan(
            universe,
            queues,
            selection,
            generation_outcomes={choices[0].candidate_id: "generated"},
        )
        recovered = json.loads(json.dumps(plan.to_dict()))
        target = recovered["targets"][0]
        assert target["primary_state"] == "generated"
        # Fallback still excludes the attempted (generated) primary.
        fallback_ids = [r["candidate_id"] for r in target["fallback_available"]]
        assert choices[0].candidate_id not in fallback_ids

    def test_plan_provenance_has_content_address(self) -> None:
        """Plan refs include sufficient provenance for cmps.5 retry."""
        universe = _universe(_REAL_EP_ID)
        choices = [_qc(i) for i in (1, 2)]
        queues = build_fallback_queues(choices, universe)
        selection = SelectionResult(
            primary_candidate_ids={_REAL_EP_ID: choices[0].candidate_id},
            attempted_candidate_ids={choices[0].candidate_id},
        )
        plan = build_coverage_plan(universe, queues, selection)
        ref = plan.targets[0].ordered_choices[0]
        # Provenance fields for cmps.5.
        assert "candidate_id" in ref
        assert "filter_candidate_id" in ref
        assert "pattern_id" in ref
        assert "entry_point_id" in ref
        assert "rank" in ref
        assert "accepted_rationale" in ref
        assert "origins" in ref
        assert "rejection_rationales" in ref
        assert "pinned_entry_point" in ref
        assert "pinned_technique_ids" in ref
