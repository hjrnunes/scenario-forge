from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from scenario_forge.catalog_qualification import (
    CampaignManifestV1,
    ForensicRunRef,
    ProfilePreflight,
    QualificationReportV1,
    QualificationRunRef,
    ReviewedProfile,
    ReviewedProfileMatrixV1,
    aggregate_campaign,
    load_matrix,
    preflight_matrix,
    validate_persisted_contract,
)
from scenario_forge.data.loaders import load_attack_patterns
from scenario_forge.data.taxonomy_pins import load_taxonomy_resolver
from scenario_forge.eval.versioned_metrics import evaluate_v3_scorecard
from scenario_forge.manifest import ArtifactRole, ManifestIntegrityError
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
    assert report.kind == "preflight"
    assert report.campaign_manifest_sha256 is None
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


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw["preflight"].reverse(), "six canonical profiles"),
        (
            lambda raw: raw["preflight"][0]["reviewed_pattern_ids"].append(
                raw["preflight"][0]["reviewed_pattern_ids"][0]
            ),
            "sorted and unique",
        ),
        (
            lambda raw: raw["preflight"][0]["projected_pattern_ids"].append(
                "AP-NOT-REVIEWED"
            ),
            "sorted and unique|must be reviewed",
        ),
        (lambda raw: raw.update(missing_pattern_ids=[]), "report kind"),
        (
            lambda raw: raw.update(
                kind="campaign",
                campaign_manifest_sha256="a" * 64,
                qualified_pattern_ids=["AP-NOT-PROJECTED"],
            ),
            "must be projected",
        ),
    ],
)
def test_standalone_report_rejects_adversarial_accounting(
    mutation, message: str
) -> None:
    raw = preflight_matrix(MATRIX).model_dump(mode="json")
    mutation(raw)
    with pytest.raises(ValidationError, match=message):
        QualificationReportV1.model_validate(raw)


def test_qualification_yaml_rejects_duplicate_facts_key(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-facts.yaml"
    path.write_text(
        "schema_version: '1'\n"
        f"catalog_sha256: {'a' * 64}\n"
        "catalog_denominator: 1\n"
        "profiles:\n"
        "  - facts: []\n"
        "    facts: []\n"
    )
    with pytest.raises(ValueError, match="duplicate YAML key: facts"):
        load_matrix(path)


def test_campaign_rejects_internally_valid_forged_scorecard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_versioned_scorecard import _Resolver

    matrix = tmp_path / "matrix.yaml"
    matrix.write_bytes(MATRIX.read_bytes())
    preflight = preflight_matrix(matrix)
    canonical = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    forged_raw = canonical.model_dump(mode="json")
    diagnostic = next(
        iter(forged_raw["semantic_quality_diagnostics"]["metrics"].values())
    )
    diagnostic["evidence"].append("forged but internally non-gating evidence")
    forged = type(canonical).model_validate(forged_raw)
    assert forged != canonical

    entries = {
        role: SimpleNamespace(role=role)
        for role in (
            "eval_scorecard",
            "finalization_inventory",
            "capability_profile",
            "coverage_plan",
        )
    }

    class ForgedResolver:
        def entry_by_role(self, role):
            return entries.get(role.value)

        def read_text(self, entry):
            assert entry.role == "eval_scorecard"
            return yaml.safe_dump(forged.model_dump(mode="json"), sort_keys=False)

    monkeypatch.setattr(
        "scenario_forge.catalog_qualification._resolve_campaign_run",
        lambda *_args, **_kwargs: ForgedResolver(),
    )
    monkeypatch.setattr(
        "scenario_forge.catalog_qualification.evaluate_v3_scorecard",
        lambda _resolver: canonical,
    )
    campaign = CampaignManifestV1(
        catalog_sha256=preflight.catalog_sha256,
        catalog_denominator=preflight.catalog_denominator,
        matrix_sha256=preflight.matrix_sha256,
        qualification_runs=(
            QualificationRunRef(
                profile_id="direct-conversational",
                run_manifest_path="runs/forged/run-manifest.yaml",
                manifest_sha256="a" * 64,
            ),
        ),
    )
    campaign_path = tmp_path / "campaign.yaml"
    campaign_path.write_text(
        yaml.safe_dump(campaign.model_dump(mode="json"), sort_keys=False)
    )

    with pytest.raises(ValueError, match="canonical resolver evaluation"):
        aggregate_campaign(matrix, campaign_path)


def test_completed_v3_campaign_with_nonempty_facts_qualifies_one_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import patch

    from scenario_forge.eval.scorecard import (
        MetricResult,
        QUALIFICATION_GATE_PATHS,
        QUALIFICATION_RATIO_GATE_IDS,
        REQUIRED_QUALIFICATION_GATE_IDS,
        ScorecardV1,
        aggregate_qualification,
        ratio_metric,
        zero_gate,
    )
    from scenario_forge.manifest import RunStatus, load_manifest
    from scenario_forge.models.attack_pattern import AttackPattern
    from scenario_forge.models.capability_profile import InventoryCompleteness
    from scenario_forge.pipeline.projection import capture_capability_snapshot
    from scenario_forge.pipeline.runner import run_pipeline
    from tests.helpers.projection_factory import (
        _pattern,
        _TaxonomyResolver,
        get_projected_candidate,
        get_test_profile,
        get_test_snapshot,
    )
    from tests.test_projection_runner_integration import _arrange

    projected = get_projected_candidate()
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    profile = get_test_profile()
    profile.entry_point_completeness = InventoryCompleteness.operator_confirmed_complete
    profile.entry_point_evidence = ["operator-review:campaign-fixture"]
    profile.tool_inventory_completeness = (
        InventoryCompleteness.operator_confirmed_complete
    )
    profile.tool_inventory_evidence = ["operator-review:campaign-fixture"]
    patches["infer_capability_profile"].return_value = (
        profile,
        patches["infer_capability_profile"].return_value[1],
    )
    patches["capture_capability_snapshot"].return_value = capture_capability_snapshot(
        profile, get_test_snapshot().facts
    )
    facts_path = tmp_path / "qualification-facts.yaml"
    facts_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1",
                "facts": [
                    item.model_dump(mode="json") for item in get_test_snapshot().facts
                ],
            },
            sort_keys=False,
        )
    )

    def qualifying_evaluation(*, resolver, threats_path=None):
        raw = evaluate_v3_scorecard(resolver).model_dump(mode="json")
        for gate_id, (section, metric_id) in QUALIFICATION_GATE_PATHS.items():
            metric = (
                ratio_metric(1, 1, evidence=["campaign fixture qualifying evidence"])
                if gate_id in QUALIFICATION_RATIO_GATE_IDS
                else zero_gate(0, evidence=["campaign fixture qualifying evidence"])
            )
            raw[section]["metrics"][metric_id] = metric.model_dump(mode="json")
        gates = {
            gate_id: MetricResult.model_validate(raw[section]["metrics"][metric_id])
            for gate_id, (section, metric_id) in QUALIFICATION_GATE_PATHS.items()
        }
        raw["qualification"] = aggregate_qualification(
            gates, required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS
        ).model_dump(mode="json")
        return ScorecardV1.model_validate(raw).model_dump(mode="json")

    stack.enter_context(
        patch(
            "scenario_forge.eval.runner.run_evaluation",
            side_effect=qualifying_evaluation,
        )
    )
    with stack:
        result = run_pipeline(**args, qualification_facts_path=facts_path)

    assert load_manifest(result.run_dir).status is RunStatus.COMPLETED
    run_manifest = result.run_dir / "run-manifest.yaml"
    manifest_sha = hashlib.sha256(run_manifest.read_bytes()).hexdigest()
    profile_ids = (
        "direct-conversational",
        "influenceable-retrieval",
        "multi-agent-delegation",
        "state-changing-tools",
        "training-tool-supply-chain",
        "writable-persistent-state",
    )
    pattern_ids = (
        projected.pattern_id,
        "AP-X-02",
        "AP-X-03",
        "AP-X-04",
        "AP-X-05",
        "AP-X-06",
    )
    reviewed_profiles = tuple(
        ReviewedProfile(
            profile_id=profile_id,
            rationale="resolver-valid campaign fixture",
            profile=profile,
            facts=get_test_snapshot().facts,
            applicable_pattern_ids=(pattern_id,),
        )
        for profile_id, pattern_id in zip(profile_ids, pattern_ids, strict=True)
    )
    matrix = ReviewedProfileMatrixV1(
        catalog_sha256=projected.projection.catalog_pin,
        catalog_denominator=len(pattern_ids),
        profiles=reviewed_profiles,
    )
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text(
        yaml.safe_dump(matrix.model_dump(mode="json"), sort_keys=False)
    )
    matrix_sha = hashlib.sha256(matrix_path.read_bytes()).hexdigest()
    preflight = QualificationReportV1(
        kind="preflight",
        catalog_sha256=matrix.catalog_sha256,
        catalog_denominator=matrix.catalog_denominator,
        matrix_sha256=matrix_sha,
        preflight=tuple(
            ProfilePreflight(
                profile_id=item.profile_id,
                reviewed_pattern_ids=item.applicable_pattern_ids,
                projected_pattern_ids=item.applicable_pattern_ids,
                missing_pattern_ids=(),
                issues=(),
            )
            for item in reviewed_profiles
        ),
        missing_pattern_ids=(),
    )
    campaign = CampaignManifestV1(
        catalog_sha256=matrix.catalog_sha256,
        catalog_denominator=matrix.catalog_denominator,
        matrix_sha256=matrix_sha,
        qualification_runs=(
            QualificationRunRef(
                profile_id=profile_ids[0],
                run_manifest_path=f"runs/{result.run_id}/run-manifest.yaml",
                manifest_sha256=manifest_sha,
            ),
        ),
    )
    campaign_path = tmp_path / "campaign.yaml"
    campaign_path.write_text(
        yaml.safe_dump(campaign.model_dump(mode="json"), sort_keys=False)
    )
    record = _pattern()
    records = [
        record,
        *({**record, "id": pattern_id} for pattern_id in pattern_ids[1:]),
    ]
    taxonomy = _TaxonomyResolver(
        AttackPattern.model_validate(record).canonical_chain.taxonomy_context
    )
    monkeypatch.setattr(
        "scenario_forge.catalog_qualification.load_attack_patterns",
        lambda: {record["id"]: record for record in records},
    )
    monkeypatch.setattr(
        "scenario_forge.catalog_qualification.load_taxonomy_resolver", lambda: taxonomy
    )
    monkeypatch.setattr(
        "scenario_forge.catalog_qualification.compute_authoritative_catalog_pin",
        lambda *_args: matrix.catalog_sha256,
    )
    monkeypatch.setattr(
        "scenario_forge.catalog_qualification._preflight_matrix",
        lambda *_args, **_kwargs: preflight,
    )
    monkeypatch.setattr(
        "scenario_forge.catalog_qualification.evaluate_v3_scorecard",
        lambda resolver: ScorecardV1.model_validate(
            resolver.read_yaml(resolver.entry_by_role(ArtifactRole.EVAL_SCORECARD))
        ),
    )
    report = aggregate_campaign(matrix_path, campaign_path)
    assert report.kind == "campaign"
    assert (
        report.campaign_manifest_sha256
        == hashlib.sha256(campaign_path.read_bytes()).hexdigest()
    )
    assert report.qualified_pattern_ids == (projected.pattern_id,)
    assert get_test_snapshot().facts


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
