from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from scenario_forge.catalog_qualification import (
    CampaignManifestV1,
    ForensicRunRef,
    QualificationReportV1,
    QualificationRunRef,
    ReviewedProfileMatrixV1,
    aggregate_campaign,
    load_matrix,
    preflight_matrix,
    validate_persisted_contract,
)
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.manifest import ManifestIntegrityError
from scenario_forge.models.attack_pattern import EvaluatedFactEvidence
from scenario_forge.pipeline.projection import (
    capture_capability_snapshot,
    project_authoritative_candidates,
)

ROOT = Path(__file__).parents[1]
MATRIX = ROOT / "data/catalog-qualification-matrix-v1.yaml"
SCHEMAS = ROOT / "src/scenario_forge/data/schemas"


def test_live_matrix_preflight_reports_known_blockers() -> None:
    report = preflight_matrix(MATRIX)
    assert report.catalog_denominator == 49
    assert (
        report.catalog_sha256
        == "f9805af1c0427fe3809806bc98b4fe1278e173b75e89d21f3030587da400fa3c"
    )
    assert report.missing_pattern_ids == ("AP-T1-06", "AP-T6-07")


def test_precondition_true_false_and_omitted_unknown_fail_closed() -> None:
    matrix = load_matrix(MATRIX)
    reviewed = next(
        item for item in matrix.profiles if "AP-T3-05" in item.applicable_pattern_ids
    )
    record = load_attack_patterns()["AP-T3-05"]
    resolver = load_taxonomy_resolver()
    fact = next(
        item
        for item in reviewed.facts
        if item.fact.fact_id == "control_interface_accessible"
    )

    true_batch = project_authoritative_candidates(
        [record], resolver, capture_capability_snapshot(reviewed.profile, [fact])
    )
    assert {item.pattern_id for item in true_batch.candidates} == {"AP-T3-05"}

    false_fact = EvaluatedFactEvidence(fact=fact.fact, status="present", value=False)
    false_batch = project_authoritative_candidates(
        [record], resolver, capture_capability_snapshot(reviewed.profile, [false_fact])
    )
    assert not false_batch.candidates
    assert false_batch.infeasibilities[0].code == "precondition_not_satisfied"

    unknown_batch = project_authoritative_candidates(
        [record], resolver, capture_capability_snapshot(reviewed.profile)
    )
    assert not unknown_batch.candidates
    assert unknown_batch.infeasibilities[0].code == "unresolved_condition"


def test_campaign_refs_are_immutable_duplicate_and_path_safe() -> None:
    sha = "a" * 64
    first = QualificationRunRef(
        profile_id="direct-conversational",
        run_manifest_path="runs/one/run-manifest.yaml",
        manifest_sha256=sha,
    )
    duplicate_path = QualificationRunRef(
        profile_id="state-changing-tools",
        run_manifest_path=first.run_manifest_path,
        manifest_sha256=sha,
    )
    with pytest.raises(ValidationError, match="paths must be unique"):
        CampaignManifestV1(
            catalog_sha256=sha,
            catalog_denominator=49,
            matrix_sha256=sha,
            qualification_runs=(first, duplicate_path),
        )
    with pytest.raises(ValidationError, match="must be separate"):
        CampaignManifestV1(
            catalog_sha256=sha,
            catalog_denominator=49,
            matrix_sha256=sha,
            qualification_runs=(first,),
            forensic_runs=(
                ForensicRunRef.model_validate(first.model_dump(mode="json")),
            ),
        )
    with pytest.raises(ValidationError, match="canonical, safe, relative"):
        QualificationRunRef(
            profile_id="direct-conversational",
            run_manifest_path="../escaped/run-manifest.yaml",
            manifest_sha256=sha,
        )
    with pytest.raises(ValidationError, match="frozen"):
        first.profile_id = "mutated"  # type: ignore[misc]


def test_campaign_keeps_strict_failed_run_as_forensic_only(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_bytes(MATRIX.read_bytes())
    preflight = preflight_matrix(matrix)
    run_dir = tmp_path / "runs" / "forensic"
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "manifest_version": "3",
                "status": "failed",
                "run_id": "20260807T000000_" + "a" * 32,
                "timestamp_start": "2026-08-07T00:00:00Z",
                "inventory": [],
            },
            sort_keys=False,
        )
    )
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    campaign_path = tmp_path / "campaign.yaml"
    campaign = CampaignManifestV1(
        catalog_sha256=preflight.catalog_sha256,
        catalog_denominator=preflight.catalog_denominator,
        matrix_sha256=preflight.matrix_sha256,
        forensic_runs=(
            ForensicRunRef(
                profile_id="direct-conversational",
                run_manifest_path="runs/forensic/run-manifest.yaml",
                manifest_sha256=manifest_sha,
            ),
        ),
    )
    campaign_path.write_text(
        yaml.safe_dump(campaign.model_dump(mode="json"), sort_keys=False)
    )

    report = aggregate_campaign(matrix, campaign_path)
    assert report.qualified_pattern_ids == ()
    assert len(report.missing_pattern_ids) == 49
    assert report.forensic_history[0].status == "failed"

    forged = campaign.model_copy(
        update={
            "forensic_runs": (),
            "qualification_runs": (
                QualificationRunRef.model_validate(
                    campaign.forensic_runs[0].model_dump(mode="json")
                ),
            ),
        }
    )
    campaign_path.write_text(
        yaml.safe_dump(forged.model_dump(mode="json"), sort_keys=False)
    )
    with pytest.raises(ManifestIntegrityError, match="not authoritative"):
        aggregate_campaign(matrix, campaign_path)


def test_standalone_contract_validation_does_not_run_preflight(tmp_path: Path) -> None:
    matrix = validate_persisted_contract(MATRIX, "matrix")
    assert isinstance(matrix, ReviewedProfileMatrixV1)
    report_path = tmp_path / "report.json"
    report_path.write_text(preflight_matrix(MATRIX).model_dump_json())
    report = validate_persisted_contract(report_path, "report")
    assert isinstance(report, QualificationReportV1)


def test_checked_in_schemas_have_exact_parity_and_validate_matrix() -> None:
    contracts = (
        (ReviewedProfileMatrixV1, "catalog-qualification-matrix-v1.schema.json"),
        (CampaignManifestV1, "catalog-qualification-campaign-v1.schema.json"),
        (QualificationReportV1, "catalog-qualification-report-v1.schema.json"),
    )
    for model, filename in contracts:
        checked_in = json.loads((SCHEMAS / filename).read_text())
        assert checked_in == model.model_json_schema()
        jsonschema.Draft202012Validator.check_schema(checked_in)
    raw = yaml.safe_load(MATRIX.read_bytes())
    jsonschema.validate(raw, ReviewedProfileMatrixV1.model_json_schema())
