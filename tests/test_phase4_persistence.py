"""cmps.5 Phase 4 persistence contract and v3 activation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scenario_forge.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    RunManifest,
    RunStatus,
    atomic_write_yaml,
    build_artifact_entry,
    finalize_manifest,
    load_manifest,
    load_strict_resolver,
    required_singleton_roles,
)
from scenario_forge.pipeline.finalization import (
    CandidateTerminalResult,
    CandidateTerminalStatus,
    GeneratedArtifacts,
    GeneratedStage,
    GeneratedStageResult,
    LifecycleState,
    LifecycleTransition,
    StageInvocation,
)
from scenario_forge.pipeline.persistence import (
    AdmissionDecisionRecord,
    ArtifactReceipt,
    CandidateAttemptRecord,
    CoveragePlanV2,
    CoverageTargetEntry,
    FinalizationInventoryV1,
    FinalizationPersistenceAdapter,
    QualifiedCandidateRef,
    QuarantineBundleV1,
    TargetState,
    ViolationRecord,
    canonical_sha256,
    make_finalization_persistence_adapter,
    read_coverage_plan,
    read_finalization_inventory,
    read_quarantine_bundle,
    write_coverage_plan,
    write_finalization_inventory,
    write_quarantine_bundle,
)

RUN_ID = "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HASH = "0" * 64
SCHEMA_DIR = Path(__file__).resolve().parents[1] / "src/scenario_forge/data/schemas"


def _choice(candidate_id: str, rank: int = 0) -> QualifiedCandidateRef:
    return QualifiedCandidateRef(
        candidate_id=candidate_id,
        filter_candidate_id=f"filter-{rank}",
        pattern_id=f"pattern-{rank}",
        entry_point_id="ep-1",
        rank=rank,
        projected_candidate={
            "candidate_id": candidate_id,
            "canonical_ingress": {"entry_point_id": "ep-1"},
        },
        accepted_filters=[],
        accepted_rationale="accepted",
        origins=[],
        rejection_rationales=[],
        pinned_entry_point="ep-1",
        pinned_technique_ids=[],
        pinned_technique_names=[],
    )


def _plan(*, attempted: list[str] | None = None) -> CoveragePlanV2:
    choices = [_choice("candidate-primary", 0), _choice("candidate-fallback", 1)]
    attempted = attempted or []
    return CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoverageTargetEntry(
                entry_point_id="ep-1",
                entry_point_name="input",
                ordered_choices=choices,
                primary_candidate_id="candidate-primary",
                attempted_candidate_ids=attempted,
                admitted_candidate_id=None,
                target_state=TargetState.selected,
                fallback_available=[
                    choice for choice in choices if choice.candidate_id not in attempted
                ],
            )
        ],
        selection_limitation_target_ids=[],
    )


def _inventory(coverage_hash: str = HASH) -> FinalizationInventoryV1:
    return FinalizationInventoryV1(
        schema_version="1",
        run_id=RUN_ID,
        coverage_plan_sha256=coverage_hash,
        candidate_attempts=[],
        stage_attempts=[],
        transitions=[],
        repairs=[],
        admission_decisions=[],
        admitted_inventory=[],
        quarantine_inventory=[],
    )


@pytest.mark.parametrize(
    ("model", "filename"),
    [
        (CoveragePlanV2, "coverage-plan-v2.schema.json"),
        (FinalizationInventoryV1, "finalization-inventory-v1.schema.json"),
        (QuarantineBundleV1, "quarantine-bundle-v1.schema.json"),
    ],
)
def test_generated_schema_has_exact_hand_schema_parity(model, filename):
    assert json.loads((SCHEMA_DIR / filename).read_text()) == model.model_json_schema()


def test_models_reject_extra_missing_and_wrong_version():
    raw = _plan().model_dump(mode="json")
    raw["extra"] = True
    with pytest.raises(ValidationError, match="extra"):
        CoveragePlanV2.model_validate(raw)
    raw.pop("extra")
    raw.pop("targets")
    with pytest.raises(ValidationError, match="targets"):
        CoveragePlanV2.model_validate(raw)
    raw["targets"] = []
    raw["schema_version"] = "1"
    with pytest.raises(ValidationError, match="schema_version"):
        CoveragePlanV2.model_validate(raw)


def test_fallback_excludes_attempted_and_preserves_order():
    assert [
        choice.candidate_id
        for choice in _plan(attempted=["candidate-primary"])
        .targets[0]
        .fallback_available
    ] == ["candidate-fallback"]
    raw = _plan().model_dump(mode="json")
    raw["targets"][0]["attempted_candidate_ids"] = ["candidate-primary"]
    with pytest.raises(ValidationError, match="fallback_available"):
        CoveragePlanV2.model_validate(raw)


def test_coverage_plan_limits_choices_and_requires_increasing_rank():
    raw = _plan().model_dump(mode="json")
    raw["targets"][0]["ordered_choices"][1]["rank"] = 0
    with pytest.raises(ValidationError, match="ranks"):
        CoveragePlanV2.model_validate(raw)
    raw = _plan().model_dump(mode="json")
    raw["targets"][0]["ordered_choices"] *= 2
    with pytest.raises(ValidationError, match="3 items"):
        CoveragePlanV2.model_validate(raw)


def test_atomic_model_roundtrip_and_hash_reconciliation(tmp_path: Path):
    plan = _plan()
    entry = write_coverage_plan(tmp_path, plan)
    assert read_coverage_plan(tmp_path, entry) == plan
    (tmp_path / entry.path).write_text("{}")
    with pytest.raises(ManifestIntegrityError, match="Hash mismatch"):
        read_coverage_plan(tmp_path, entry)


def test_atomic_interruption_leaves_previous_valid_document(
    tmp_path: Path, monkeypatch
):
    import scenario_forge.manifest as manifest_module

    original = _plan()
    write_coverage_plan(tmp_path, original)

    def interrupted_replace(source, destination):
        raise OSError("simulated interruption")

    monkeypatch.setattr(manifest_module.os, "replace", interrupted_replace)
    with pytest.raises(OSError, match="interruption"):
        write_coverage_plan(tmp_path, original)
    assert read_coverage_plan(tmp_path) == original
    assert not list(tmp_path.glob("*.tmp"))


def test_quarantine_roundtrip_has_only_json_bundle_role(tmp_path: Path):
    actor = {"actor": "partial"}
    bundle = QuarantineBundleV1(
        schema_version="1",
        run_id=RUN_ID,
        attempt_id="attempt-1",
        candidate_id="candidate-primary",
        target_entry_point_id="ep-1",
        actor=actor,
        narrative=None,
        tree=None,
        behavior=None,
        artifact_sha256={GeneratedStage.actor: canonical_sha256(actor)},
        violations=[
            ViolationRecord(
                code="actor_access",
                detail="failed hard gate",
                owner=GeneratedStage.actor,
                retryable=True,
            )
        ],
    )
    entry = write_quarantine_bundle(tmp_path, bundle)
    assert entry.role is ArtifactRole.QUARANTINE_BUNDLE
    assert entry.path == "quarantine/attempt-1.json"
    assert read_quarantine_bundle(tmp_path, entry) == bundle
    assert not list(tmp_path.rglob("*.yaml"))
    assert not list(tmp_path.rglob("*.feature"))


def test_finalization_rejects_duplicate_and_noncontiguous_records():
    attempt = CandidateAttemptRecord(
        attempt_id="attempt-1",
        candidate_id="candidate-primary",
        target_entry_point_id="ep-1",
        queue_rank=0,
        is_primary=True,
        stage_attempt_ids=[],
    )
    raw = _inventory().model_dump(mode="json")
    raw["candidate_attempts"] = [
        attempt.model_dump(mode="json"),
        attempt.model_dump(mode="json"),
    ]
    with pytest.raises(ValidationError, match="duplicate candidate attempt"):
        FinalizationInventoryV1.model_validate(raw)
    raw = _inventory().model_dump(mode="json")
    raw["transitions"] = [
        {
            "index": 1,
            "previous": "pending",
            "current": "revalidating_candidate",
            "candidate_id": "candidate-primary",
            "reason": "start",
        }
    ]
    with pytest.raises(ValidationError, match="contiguous"):
        FinalizationInventoryV1.model_validate(raw)


def test_v2_default_roles_and_strict_v3_request_compatibility(tmp_path: Path):
    assert ArtifactRole.COVERAGE_PLAN not in required_singleton_roles(
        eval_enabled=False
    )
    assert ArtifactRole.COVERAGE_PLAN in required_singleton_roles(
        eval_enabled=False, manifest_version="3"
    )
    atomic_write_yaml(
        tmp_path / "run-manifest.yaml",
        RunManifest(
            manifest_version="2",
            status=RunStatus.COMPLETED,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
        ).model_dump(mode="json"),
    )
    assert load_manifest(tmp_path).manifest_version == "2"
    with pytest.raises(ManifestIntegrityError, match="explicitly requested"):
        load_manifest(tmp_path, requested_version="3")


def test_v3_requires_persistence_singletons(tmp_path: Path):
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
        ),
    )
    with pytest.raises(ManifestIntegrityError, match="requires exactly one"):
        load_strict_resolver(tmp_path, manifest_version="3")


def test_valid_empty_v3_inventory(tmp_path: Path):
    coverage_entry = write_coverage_plan(
        tmp_path,
        CoveragePlanV2(
            schema_version="2",
            completeness="not_applicable",
            evidence_refs=[],
            targets=[],
            selection_limitation_target_ids=[],
        ),
    )
    final_entry = write_finalization_inventory(
        tmp_path, _inventory(coverage_entry.sha256)
    )
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
            inventory=[coverage_entry, final_entry],
        ),
    )
    resolver = load_strict_resolver(tmp_path, manifest_version="3")
    assert resolver.entry_by_role(ArtifactRole.COVERAGE_PLAN) == coverage_entry


def _quarantine_v3_parts(tmp_path: Path):
    choice = _choice("candidate-primary")
    plan = CoveragePlanV2(
        schema_version="2",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoverageTargetEntry(
                entry_point_id="ep-1",
                entry_point_name="input",
                ordered_choices=[choice],
                primary_candidate_id=choice.candidate_id,
                attempted_candidate_ids=[choice.candidate_id],
                admitted_candidate_id=None,
                target_state=TargetState.exhausted,
                fallback_available=[],
            )
        ],
        selection_limitation_target_ids=[],
    )
    coverage_entry = write_coverage_plan(tmp_path, plan)
    violation = ViolationRecord(
        code="actor_access",
        detail="terminal hard-gate failure",
        owner=GeneratedStage.actor,
        retryable=False,
    )
    actor = {"partial": True}
    bundle_entry = write_quarantine_bundle(
        tmp_path,
        QuarantineBundleV1(
            schema_version="1",
            run_id=RUN_ID,
            attempt_id="attempt-1",
            candidate_id=choice.candidate_id,
            target_entry_point_id="ep-1",
            actor=actor,
            narrative=None,
            tree=None,
            behavior=None,
            artifact_sha256={GeneratedStage.actor: canonical_sha256(actor)},
            violations=[violation],
        ),
    )
    receipt = ArtifactReceipt(
        candidate_id=choice.candidate_id,
        role=bundle_entry.role,
        path=bundle_entry.path,
        sha256=bundle_entry.sha256,
        scenario_id=None,
    )
    final = _inventory(coverage_entry.sha256)
    final.candidate_attempts.append(
        CandidateAttemptRecord(
            attempt_id="attempt-1",
            candidate_id=choice.candidate_id,
            target_entry_point_id="ep-1",
            queue_rank=0,
            is_primary=True,
            stage_attempt_ids=[],
        )
    )
    final.admission_decisions.append(
        AdmissionDecisionRecord(
            candidate_id=choice.candidate_id,
            status=CandidateTerminalStatus.rejected,
            admitted=False,
            gate_results=[],
            violations=[violation],
        )
    )
    final.quarantine_inventory.append(receipt)
    final_entry = write_finalization_inventory(tmp_path, final)
    return coverage_entry, final_entry, bundle_entry, final


def _finalize_v3(tmp_path: Path, inventory):
    finalize_manifest(
        tmp_path,
        RunManifest(
            manifest_version="3",
            status=RunStatus.COMPLETED_WITH_ERRORS,
            run_id=RUN_ID,
            timestamp_start="2026-01-01T00:00:00Z",
            inventory=inventory,
        ),
    )


def test_valid_v3_quarantine_sets_completed_with_errors(tmp_path: Path):
    coverage, final, bundle, _ = _quarantine_v3_parts(tmp_path)
    _finalize_v3(tmp_path, [coverage, final, bundle])
    resolver = load_strict_resolver(tmp_path, manifest_version="3")
    assert resolver.manifest.status is RunStatus.COMPLETED_WITH_ERRORS


def test_v3_rejects_admitted_quarantine_overlap(tmp_path: Path):
    coverage, _, bundle, final = _quarantine_v3_parts(tmp_path)
    final.admitted_inventory.append(final.quarantine_inventory[0])
    final_entry = write_finalization_inventory(tmp_path, final)
    _finalize_v3(tmp_path, [coverage, final_entry, bundle])
    with pytest.raises(ManifestIntegrityError, match="overlap"):
        load_strict_resolver(tmp_path, manifest_version="3")


@pytest.mark.parametrize(
    "leak_role", [ArtifactRole.SCENARIO_YAML, ArtifactRole.EVAL_SCORECARD]
)
def test_v3_rejects_quarantine_normal_or_eval_role(tmp_path: Path, leak_role):
    coverage, final, bundle, _ = _quarantine_v3_parts(tmp_path)
    candidate_id = bundle.candidate_id
    if leak_role is ArtifactRole.SCENARIO_YAML:
        scenarios = tmp_path / "scenarios"
        scenarios.mkdir()
        (scenarios / "scenario-1.yaml").write_text(
            f"scenario_id: scenario-1\ncandidate_id: {candidate_id}\n"
        )
        (scenarios / "scenario-1.feature").write_text("Feature: leaked\n")
        leaked = [
            build_artifact_entry(
                ArtifactRole.SCENARIO_YAML,
                tmp_path,
                "scenarios/scenario-1.yaml",
                scenario_id="scenario-1",
                candidate_id=candidate_id,
            ),
            build_artifact_entry(
                ArtifactRole.SCENARIO_FEATURE,
                tmp_path,
                "scenarios/scenario-1.feature",
                scenario_id="scenario-1",
                candidate_id=candidate_id,
            ),
        ]
        match = "normal scenario role"
    else:
        (tmp_path / "eval-scorecard.yaml").write_text("evaluation: {}\n")
        leaked = [
            build_artifact_entry(
                ArtifactRole.EVAL_SCORECARD,
                tmp_path,
                "eval-scorecard.yaml",
                candidate_id=candidate_id,
            )
        ]
        match = "Evaluation inventory"
    _finalize_v3(tmp_path, [coverage, final, bundle, *leaked])
    with pytest.raises(ManifestIntegrityError, match=match):
        load_strict_resolver(tmp_path, manifest_version="3")


def test_adapter_persists_each_port_event_exactly_once(tmp_path: Path):
    inventory = _inventory()
    inventory.candidate_attempts.append(
        CandidateAttemptRecord(
            attempt_id="attempt-1",
            candidate_id="candidate-primary",
            target_entry_point_id="ep-1",
            queue_rank=0,
            is_primary=True,
            stage_attempt_ids=[],
        )
    )
    adapter = FinalizationPersistenceAdapter(tmp_path, inventory)
    transition = LifecycleTransition(
        LifecycleState.pending,
        LifecycleState.revalidating_candidate,
        "candidate-primary",
        "start",
    )
    adapter.record_transition(transition)
    adapter.record_transition(transition)
    invocation = StageInvocation(
        candidate_id="candidate-primary",
        stage=GeneratedStage.actor,
        invocation_index=0,
        owner_retry_index=0,
        artifacts=GeneratedArtifacts(),
    )
    result = GeneratedStageResult(artifact={"actor": "ok"})
    adapter.record_stage_result(invocation, result)
    adapter.record_stage_result(invocation, result)
    terminal = CandidateTerminalResult(
        candidate_id="candidate-primary",
        status=CandidateTerminalStatus.admitted,
    )
    adapter.record_candidate_result("candidate-primary", terminal)
    adapter.record_candidate_result("candidate-primary", terminal)
    reloaded = read_finalization_inventory(tmp_path)
    assert len(reloaded.transitions) == 1
    assert len(reloaded.stage_attempts) == 1
    assert len(reloaded.admission_decisions) == 1


def test_factory_maps_coverage_choices_for_machine_dependency_injection(
    tmp_path: Path,
):
    plan = _plan()
    adapter = make_finalization_persistence_adapter(
        tmp_path,
        run_id=RUN_ID,
        coverage_plan_sha256=HASH,
        coverage_plan=plan,
    )
    adapter.record_transition(
        LifecycleTransition(
            LifecycleState.pending,
            LifecycleState.revalidating_candidate,
            "candidate-primary",
            "authoritative revalidation",
        )
    )
    reloaded = read_finalization_inventory(tmp_path)
    assert reloaded.candidate_attempts == [
        CandidateAttemptRecord(
            attempt_id="candidate-primary:candidate",
            candidate_id="candidate-primary",
            target_entry_point_id="ep-1",
            queue_rank=0,
            is_primary=True,
            stage_attempt_ids=[],
        )
    ]
