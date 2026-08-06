"""Runner-level regression coverage for the cmps.6 quarantine boundary."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

from scenario_forge.llm.client import LLMResult
from scenario_forge.manifest import (
    ArtifactRole,
    AttemptDisposition,
    RunStatus,
    load_manifest,
)
from scenario_forge.models.capability_profile import ConfidenceLevel
from scenario_forge.models.projection_envelope import ProjectionTraceabilityResult
from scenario_forge.models.scenario import ActorAccessProvenance
from scenario_forge.pipeline.candidates import FilteredSeed, StageRecord
from scenario_forge.pipeline.coverage import CoverageGaps
from scenario_forge.pipeline.generate import compute_scenario_id
from scenario_forge.pipeline.runner import run_pipeline
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.pipeline.threats import ThreatSurface
from tests.test_actor_entry_point_validation import _make_envelope, _make_profile


def test_runner_quarantines_semantically_invalid_scenario(tmp_path: Path) -> None:
    """Only admitted scenarios may cross the runner's eval/report boundary."""
    profile = _make_profile()
    profile.confidence = ConfidenceLevel.high
    entry_point = profile.entry_points[0]

    risk_ref = _make_envelope().faceting.risk_card
    seed = ScenarioSeed(
        seed_id="AP-T1-01",
        threat_id="T1",
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="A test attack pattern.",
        risk_card_ref=risk_ref,
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
    )

    def filtered(candidate_id: str) -> FilteredSeed:
        return FilteredSeed(
            **seed.model_dump(),
            pinned_entry_point=entry_point.name,
            pinned_technique_ids=("AML.T0051.000",),
            pinned_technique_names=("Prompt Injection",),
            entry_point_id=entry_point.entry_point_id,
            candidate_id=candidate_id,
        )

    valid_seed = filtered("cand:v1:11111111111111111111111111111111")
    invalid_seed = filtered("cand:v1:22222222222222222222222222222222")

    from scenario_forge.models.scenario import NarrativeAccessRealization

    valid_access = ActorAccessProvenance(
        initial_entry_point_id=entry_point.entry_point_id,
        ingress_mode="direct",
        access_class="public",
    )
    # This is structurally well-formed and ownership-consistent, but Rule 12
    # rejects supply-chain access paired with direct ingress.
    invalid_access = ActorAccessProvenance(
        initial_entry_point_id=entry_point.entry_point_id,
        ingress_mode="direct",
        access_class="supply_chain",
    )

    def generate(fseed, *args, **kwargs):
        access = valid_access if fseed is valid_seed else invalid_access
        envelope = _make_envelope(
            entry_point_id=entry_point.entry_point_id,
            access=deepcopy(access),
        )
        # Valid scenario must carry a matching access_realization so it
        # passes the cmps.6 narrative realization semantic check.
        if fseed is valid_seed:
            envelope.narrative.access_realization = NarrativeAccessRealization(
                initial_entry_point_id=entry_point.entry_point_id,
                responsible_step_number=1,
            )
        envelope.candidate_id = fseed.candidate_id
        envelope.scenario_id = compute_scenario_id(
            kwargs["run_id"], fseed.candidate_id, 1
        )
        envelope.attack_tree.root.threat_id = "T1"
        return envelope, []

    def expand_candidates(*args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="expansion", input_count=2, output_count=2, collapsed_count=0
            )
        )
        return [valid_seed, invalid_seed]

    def apply_rules(candidates, *args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="rule_pruning", input_count=2, output_count=2, collapsed_count=0
            )
        )
        return candidates, [], []

    client = MagicMock()
    client.model = "test-model"
    client.base_url = "mock://local"
    client.temperature = 0.0
    client.max_completion_tokens = 1000
    llm_result = LLMResult(
        content="mock",
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )
    coherence = MagicMock(has_warnings=False)
    gaps = CoverageGaps()
    eval_scenario_ids: list[str] = []
    report_scenario_ids: list[str] = []

    def evaluate(*, resolver, threats_path=None):
        eval_scenario_ids.extend(
            item.scenario_id
            for item in resolver.manifest.inventory
            if item.role is ArtifactRole.SCENARIO_YAML
        )
        return {"metrics": {}}

    def report(data, out_dir):
        report_scenario_ids.extend(
            scenario["scenario_id"] for scenario in data.scenarios
        )
        path = Path(out_dir) / "report.html"
        path.write_text("<html>dummy report</html>", encoding="utf-8")
        return path

    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]", encoding="utf-8")
    sssom_path = tmp_path / "mapping.tsv"
    sssom_path.write_text("", encoding="utf-8")

    with (
        patch("scenario_forge.pipeline.runner.LLMClient", return_value=client),
        patch(
            "scenario_forge.pipeline.runner.infer_capability_profile",
            return_value=(profile, llm_result),
        ),
        patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[]),
        patch(
            "scenario_forge.pipeline.runner.validate_risk_card_coherence",
            return_value=coherence,
        ),
        patch(
            "scenario_forge.pipeline.runner.determine_threat_surface",
            return_value=ThreatSurface(entries=[], governance_only=[]),
        ),
        patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[seed]),
        patch(
            "scenario_forge.pipeline.runner.expand_candidates",
            side_effect=expand_candidates,
        ),
        patch(
            "scenario_forge.pipeline.runner.apply_rule_based_filter",
            side_effect=apply_rules,
        ),
        patch(
            "scenario_forge.pipeline.runner.filter_candidates",
            return_value=([valid_seed, invalid_seed], []),
        ),
        patch("scenario_forge.pipeline.runner.generate_scenario", side_effect=generate),
        patch(
            "scenario_forge.pipeline.runner.analyze_coverage_gaps",
            return_value=gaps,
        ),
        patch(
            "scenario_forge.pipeline.runner.analyze_attacker_diversity",
            return_value=None,
        ),
        patch("scenario_forge.eval.runner.run_evaluation", side_effect=evaluate),
        patch("scenario_forge.report.generator.generate_report", side_effect=report),
        patch(
            "scenario_forge.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True, violations=[]),
        ),
    ):
        result = run_pipeline(
            use_case="A chatbot with a direct user prompt entry point.",
            risk_extraction_path=risk_path,
            sssom_path=sssom_path,
            output_dir=tmp_path / "runs",
        )

    valid_id = compute_scenario_id(result.run_id, valid_seed.candidate_id, 1)
    invalid_id = compute_scenario_id(result.run_id, invalid_seed.candidate_id, 1)
    assert [scenario.scenario_id for scenario in result.scenarios] == [valid_id]
    assert invalid_id not in {scenario.scenario_id for scenario in result.scenarios}
    assert eval_scenario_ids == [valid_id]
    assert report_scenario_ids == [valid_id]

    manifest = load_manifest(result.run_dir)
    assert manifest.funnel["quarantined"] > 0
    invalid_attempt = next(
        attempt for attempt in manifest.attempts if attempt.scenario_id == invalid_id
    )
    assert invalid_attempt.disposition is AttemptDisposition.QUARANTINED
    assert manifest.status is RunStatus.COMPLETED_WITH_ERRORS
    assert (result.run_dir / "report.html").is_file()
