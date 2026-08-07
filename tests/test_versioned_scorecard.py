from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scenario_forge.eval.runner import run_evaluation
from scenario_forge.eval.scorecard import (
    MetricResult,
    MetricStatus,
    ScorecardV1,
    aggregate_qualification,
    ratio_metric,
)
from scenario_forge.eval.versioned_metrics import (
    evaluate_v3_scorecard,
    title_duplicate_components,
)
from scenario_forge.manifest import ArtifactRole, ManifestIntegrityError
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from scenario_forge.pipeline.persistence import CoveragePlanV2, FinalizationInventoryV1
from scenario_forge.report.template import build_scorecard_section
from tests.manifest_helpers import build_test_run_dir


@dataclass
class _Entry:
    role: ArtifactRole
    path: str
    scenario_id: str | None = None


class _Resolver:
    def __init__(self, *, confirmed: bool = False) -> None:
        self.manifest = SimpleNamespace(
            manifest_version="3",
            run_id="20260101T000000_abcdef0123456789abcdef0123456789",
        )
        self.plan = CoveragePlanV2(
            schema_version="2",
            completeness="confirmed_complete" if confirmed else "not_applicable",
            evidence_refs=["operator-review:test"] if confirmed else [],
            targets=[],
            selection_limitation_target_ids=[],
        )
        self.final = FinalizationInventoryV1(
            schema_version="1",
            run_id=self.manifest.run_id,
            coverage_plan_sha256="a" * 64,
            candidate_attempts=[],
            stage_attempts=[],
            transitions=[],
            repairs=[],
            admission_decisions=[],
            admitted_inventory=[],
            quarantine_inventory=[],
        )
        self.profile = CapabilityProfile(
            zones_active=["input"],
            entry_points=[EntryPoint(name="prompt", direction="input")],
            confidence=ConfidenceLevel.medium,
            kc_subcodes=["KC1.1"],
            entry_point_completeness=(
                InventoryCompleteness.operator_confirmed_complete
                if confirmed
                else InventoryCompleteness.inferred_partial
            ),
            entry_point_evidence=["operator-review:test"] if confirmed else [],
        )
        self.entries = {
            ArtifactRole.COVERAGE_PLAN: _Entry(
                ArtifactRole.COVERAGE_PLAN, "coverage-plan.json"
            ),
            ArtifactRole.FINALIZATION_INVENTORY: _Entry(
                ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json"
            ),
            ArtifactRole.CAPABILITY_PROFILE: _Entry(
                ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"
            ),
        }

    def entry_by_role(self, role: ArtifactRole) -> _Entry | None:
        return self.entries.get(role)

    def read_text(self, entry: _Entry) -> str:
        value = self.plan if entry.role is ArtifactRole.COVERAGE_PLAN else self.final
        return value.model_dump_json()

    def read_yaml(self, entry: _Entry) -> dict[str, Any]:
        assert entry.role is ArtifactRole.CAPABILITY_PROFILE
        return self.profile.model_dump(mode="json")

    def scenario_yaml_entries(self) -> list[_Entry]:
        return []

    def scenario_feature_entries(self) -> list[_Entry]:
        return []


def test_empty_denominator_is_not_applicable_and_has_no_value() -> None:
    result = ratio_metric(0, 0, evidence=["mutually empty projected sets"])
    assert result.status is MetricStatus.NOT_APPLICABLE
    assert result.value is None
    assert result.numerator == result.denominator == 0


def test_metric_values_are_bounded_and_exact() -> None:
    assert ratio_metric(1, 2, evidence=["test"]).value == 0.5
    with pytest.raises(ValueError, match="value must equal"):
        MetricResult(
            status=MetricStatus.PASS,
            numerator=1,
            denominator=2,
            value=0.75,
            evidence=["test"],
            affected_ids=[],
        )


def test_aggregate_excludes_na_and_surfaces_errors() -> None:
    result = aggregate_qualification(
        {
            "pass": ratio_metric(1, 1, evidence=["x"]),
            "na": ratio_metric(0, 0, evidence=["x"]),
            "error": MetricResult(
                status=MetricStatus.ERROR,
                evidence=["broken source"],
                affected_ids=["s1"],
            ),
        }
    )
    assert result.status is MetricStatus.ERROR
    assert result.applicable_gate_count == 2
    assert result.passed_gate_count == 1
    assert result.not_applicable_gate_ids == ["na"]


def test_exact_title_duplicates_differ_from_near_components() -> None:
    exact, near = title_duplicate_components(
        {
            "a": "Prompt Injection Attack!",
            "b": "prompt injection attack",
            "c": "Prompt Injection Attack via API",
            "d": "Unrelated memory poisoning",
        }
    )
    assert exact == [["a", "b"]]
    assert near == [["a", "b", "c"]]


def test_components_are_deterministic_across_input_order() -> None:
    first = {
        "a": "alpha beta gamma delta",
        "b": "alpha beta gamma delta x",
        "c": "alpha beta gamma delta x y",
    }
    second = dict(reversed(list(first.items())))
    assert title_duplicate_components(first) == title_duplicate_components(second)


def test_profile_completeness_controls_closed_world_gates() -> None:
    partial = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    complete = evaluate_v3_scorecard(_Resolver(confirmed=True))  # type: ignore[arg-type]
    assert (
        partial.release_qualification.metrics["capability_grounding"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert (
        complete.release_qualification.metrics["capability_grounding"].status
        is MetricStatus.PASS
    )


def test_empty_authoritative_sets_do_not_inflate_qualification() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    assert (
        scorecard.cross_artifact_agreement.metrics["pinned_technique_recall"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert (
        scorecard.cross_artifact_agreement.metrics["projected_step_recall"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert "pinned_technique_recall" in scorecard.qualification.not_applicable_gate_ids


def test_checked_in_schema_has_exact_generated_parity() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "src/scenario_forge/data/schemas/eval-scorecard-v1.schema.json"
    )
    assert json.loads(path.read_text()) == ScorecardV1.model_json_schema()


def test_report_renders_status_denominator_evidence_and_failures() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver()).model_dump(mode="json")  # type: ignore[arg-type]
    html = build_scorecard_section(scorecard)
    assert "Presence / Coverage" in html
    assert "Numerator / Denominator" in html
    assert "not_applicable" in html
    assert "Evidence" in html
    assert "Qualification failures" in html


def test_universal_kill_chain_metrics_are_explicit() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    agreement = scorecard.cross_artifact_agreement.metrics
    release = scorecard.release_qualification.metrics
    assert {
        "projection_conditional_decision_coverage",
        "projection_mapping_coverage",
        "projected_step_recall",
        "exact_tree_behavior_correspondence",
    } <= agreement.keys()
    assert {
        "catalog_taxonomy_pin_validity",
        "resource_binding_validity",
        "execution_requirement_drift",
        "kill_chain_quarantine_reasons",
    } <= release.keys()


def test_normal_evaluation_rejects_legacy_manifest_without_writes(
    tmp_path: Path,
) -> None:
    run_dir = build_test_run_dir(tmp_path / "run")
    before = {
        path.relative_to(run_dir): path.read_bytes()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    with pytest.raises(ManifestIntegrityError, match="Unsupported manifest version"):
        run_evaluation(run_dir)
    after = {
        path.relative_to(run_dir): path.read_bytes()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    assert after == before
