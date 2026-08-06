"""Focused production-wiring regressions for cmps.5 Phase 5."""

from __future__ import annotations

import inspect

from scenario_forge.pipeline.coverage_planning import CoveragePlan, CoveragePlanEntry
from scenario_forge.pipeline.runner import run_pipeline
from scenario_forge.pipeline.runner_finalization import strict_v3_coverage_plan
from tests.test_phase4_persistence import (
    ENTRY_POINT_ID,
    FALLBACK_ID,
    PRIMARY_ID,
    _choice,
)


def test_strict_v3_plan_is_primary_first_and_all_choices_start_available() -> None:
    fallback = _choice(FALLBACK_ID, 7).model_dump(mode="json")
    primary = _choice(PRIMARY_ID, 9).model_dump(mode="json")
    legacy = CoveragePlan(
        schema_version="1",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoveragePlanEntry(
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[fallback, primary],
                primary_candidate_id=PRIMARY_ID,
                primary_state="selected",
                fallback_available=[fallback],
            )
        ],
    )

    plan = strict_v3_coverage_plan(legacy)
    target = plan.targets[0]

    assert plan.schema_version == "2"
    assert [item.candidate_id for item in target.ordered_choices] == [
        PRIMARY_ID,
        FALLBACK_ID,
    ]
    assert [item.rank for item in target.ordered_choices] == [0, 1]
    assert target.fallback_available == target.ordered_choices
    assert target.attempted_candidate_ids == []


def test_strict_v3_plan_marks_structural_empty_target_exhausted() -> None:
    legacy = CoveragePlan(
        schema_version="1",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoveragePlanEntry(
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[],
                primary_candidate_id=None,
                primary_state="uncovered",
                fallback_available=[],
            )
        ],
    )

    target = strict_v3_coverage_plan(legacy).targets[0]

    assert target.target_state.value == "exhausted"
    assert target.primary_candidate_id is None
    assert target.fallback_available == []


def test_v3_production_branch_returns_before_legacy_mutation_calls() -> None:
    source = inspect.getsource(run_pipeline)
    v3_branch = source.split(
        "# --- Manifest v3: target-scoped finalization is the sole lifecycle ---",
        maxsplit=1,
    )[1].split("# cmps.4 blocker 5: Capture actual qualified", maxsplit=1)[0]

    assert "run_target_finalization(" in v3_branch
    assert "return _complete_v3_run(" in v3_branch
    for forbidden in (
        "generate_scenario(",
        "write_scenario_outputs(",
        "replace_scenario_outputs(",
        "validate_phantom_capabilities(",
        "enforce_parsimony(",
    ):
        assert forbidden not in v3_branch
