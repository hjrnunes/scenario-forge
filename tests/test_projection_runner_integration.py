"""Integration coverage for the runner's projection prejoin and identities."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.llm.client import LLMResult
from scenario_forge.manifest import ArtifactRole, AttemptDisposition, load_manifest
from scenario_forge.models.capability_profile import ConfidenceLevel, EntryPoint
from scenario_forge.models.projection_envelope import ProjectionTraceabilityResult
from scenario_forge.models.scenario import (
    ActorAccessProvenance,
    NarrativeAccessRealization,
)
from scenario_forge.pipeline.candidates import FilteredSeed, StageRecord
from scenario_forge.pipeline.coverage import CoverageGaps, EntryPointGap
from scenario_forge.pipeline.generate import compute_scenario_id
from scenario_forge.pipeline.runner import ScenarioForgeIntegrityError, run_pipeline
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.pipeline.threats import ThreatSurface
from tests.helpers.projection_factory import (
    get_canonical_ingress_id,
    get_projected_candidate,
    get_test_snapshot,
)
from tests.test_actor_entry_point_validation import _make_envelope, _make_profile


def _arrange(tmp_path: Path, *, entry_point_id: str, projected_candidates: list):
    profile = _make_profile()
    profile.confidence = ConfidenceLevel.high
    profile.entry_points.append(
        EntryPoint(name="chat", direction="input", controllability="direct")
    )
    seed = ScenarioSeed(
        seed_id="AP-T1-01",
        threat_id="T1",
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="A test attack pattern.",
        risk_card_ref=_make_envelope().faceting.risk_card,
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
    )
    filtered = FilteredSeed(
        **seed.model_dump(),
        pinned_entry_point=profile.entry_points[0].name,
        pinned_technique_ids=("AML.T0051.000",),
        pinned_technique_names=("Prompt Injection",),
        entry_point_id=entry_point_id,
        candidate_id="cand:v2:" + "f" * 32,
    )

    client = MagicMock(
        model="test-model",
        base_url="mock://local",
        temperature=0.0,
        max_completion_tokens=1000,
    )
    llm_result = LLMResult(
        content="mock",
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )
    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]", encoding="utf-8")
    sssom_path = tmp_path / "mapping.tsv"
    sssom_path.write_text("", encoding="utf-8")

    def expand(*args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="expansion", input_count=1, output_count=1, collapsed_count=0
            )
        )
        return [filtered]

    def rules(candidates, *args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="rule_pruning", input_count=1, output_count=1, collapsed_count=0
            )
        )
        return candidates, [], []

    generate = MagicMock()
    stack = ExitStack()
    patches = {
        "LLMClient": MagicMock(return_value=client),
        "infer_capability_profile": MagicMock(return_value=(profile, llm_result)),
        "load_risk_extraction": MagicMock(return_value=[]),
        "validate_risk_card_coherence": MagicMock(
            return_value=MagicMock(has_warnings=False)
        ),
        "determine_threat_surface": MagicMock(
            return_value=ThreatSurface(entries=[], governance_only=[])
        ),
        "expand_seeds": MagicMock(return_value=[seed]),
        "expand_candidates": MagicMock(side_effect=expand),
        "apply_rule_based_filter": MagicMock(side_effect=rules),
        "filter_candidates": MagicMock(return_value=([filtered], [])),
        "generate_scenario": generate,
        "project_authoritative_candidates": MagicMock(
            return_value=MagicMock(
                candidates=projected_candidates, infeasibilities=[], limitations=[]
            )
        ),
        "capture_capability_snapshot": MagicMock(return_value=get_test_snapshot()),
        "analyze_coverage_gaps": MagicMock(return_value=CoverageGaps()),
        "analyze_attacker_diversity": MagicMock(return_value=None),
    }
    for name, replacement in patches.items():
        stack.enter_context(
            patch(f"scenario_forge.pipeline.runner.{name}", replacement)
        )

    def evaluate(*, resolver, threats_path=None):
        inventory = resolver.manifest.inventory
        return {
            "evaluation": {
                "scenario_count": sum(
                    item.role is ArtifactRole.SCENARIO_YAML for item in inventory
                ),
                "feature_file_count": sum(
                    item.role is ArtifactRole.SCENARIO_FEATURE for item in inventory
                ),
            },
            "metrics": {},
        }

    stack.enter_context(
        patch("scenario_forge.eval.runner.run_evaluation", side_effect=evaluate)
    )

    def report(data, out_dir):
        path = Path(out_dir) / "report.html"
        path.write_text("<html></html>", encoding="utf-8")
        return path

    stack.enter_context(
        patch("scenario_forge.report.generator.generate_report", side_effect=report)
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True, violations=[]),
        )
    )
    args = {
        "use_case": "A chatbot with a direct user prompt entry point.",
        "risk_extraction_path": risk_path,
        "sssom_path": sssom_path,
        "output_dir": tmp_path / "runs",
    }
    return stack, patches, generate, args


def _successful_generation(projected_candidate):
    def generate(fseed, *args, **kwargs):
        assert kwargs["projected_candidate"] is projected_candidate
        envelope = _make_envelope(
            entry_point_id=get_canonical_ingress_id(),
            access=ActorAccessProvenance(
                initial_entry_point_id=get_canonical_ingress_id(),
                ingress_mode="direct",
                access_class="public",
            ),
        )
        envelope.narrative.access_realization = NarrativeAccessRealization(
            initial_entry_point_id=get_canonical_ingress_id(),
            responsible_step_number=1,
        )
        envelope.candidate_id = projected_candidate.candidate_id
        envelope.scenario_id = compute_scenario_id(
            kwargs["run_id"], projected_candidate.candidate_id, 1
        )
        envelope.attack_tree.root.threat_id = "T1"
        return envelope, []

    return generate


def test_exact_projection_match_uses_authoritative_identity(tmp_path: Path) -> None:
    projected = get_projected_candidate().model_copy(
        update={"candidate_id": "cand:v2:" + "1" * 32}
    )
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    generate.side_effect = _successful_generation(projected)
    with stack:
        result = run_pipeline(**args)

    assert generate.call_count == 1
    assert generate.call_args.kwargs["projected_candidate"] is projected
    assert result.scenarios[0].candidate_id == projected.candidate_id
    manifest = load_manifest(result.run_dir)
    scenario_inventory = [item for item in manifest.inventory if item.scenario_id]
    assert scenario_inventory
    assert {item.candidate_id for item in scenario_inventory} == {
        projected.candidate_id
    }
    admitted_candidate_ids = {
        attempt.candidate_id
        for attempt in manifest.attempts
        if attempt.disposition is AttemptDisposition.ADMITTED
    }
    assert projected.candidate_id in admitted_candidate_ids
    assert manifest.funnel["projection_rejected"] == 0
    assert manifest.funnel["selected"] == 1
    assert manifest.funnel["main_attempted"] == 1
    assert manifest.funnel["main_admitted"] == 1
    assert manifest.funnel["main_attempted"] == (
        manifest.funnel["main_admitted"] + manifest.funnel["generation_failed"]
    )


def test_zero_exact_projection_match_completes_without_generation(
    tmp_path: Path,
) -> None:
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id="ep:v1:" + "0" * 32,
        projected_candidates=[get_projected_candidate()],
    )
    with stack:
        result = run_pipeline(**args)
    assert result.run_dir is not None
    generate.assert_not_called()
    manifest = load_manifest(result.run_dir)
    assert manifest.funnel["projection_rejected"] == 1
    assert manifest.funnel["selected"] == 0


def test_multiple_exact_projection_matches_are_fatal(tmp_path: Path) -> None:
    first = get_projected_candidate()
    second = first.model_copy(update={"candidate_id": "cand:v2:" + "2" * 32})
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[first, second],
    )
    with (
        stack,
        pytest.raises(
            ScenarioForgeIntegrityError, match="Ambiguous projected candidates"
        ),
    ):
        run_pipeline(**args)


def test_remediation_rejects_candidate_already_attempted_by_main(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate().model_copy(
        update={"candidate_id": "cand:v2:" + "3" * 32}
    )
    stack, patches, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    generate.side_effect = _successful_generation(projected)
    patches["analyze_coverage_gaps"].return_value = CoverageGaps(
        uncovered_entry_points=[
            EntryPointGap(entry_point_id=get_canonical_ingress_id(), name="chat")
        ]
    )
    with stack, pytest.raises(ScenarioForgeIntegrityError, match="already attempted"):
        run_pipeline(**args)
    assert generate.call_count == 1


def test_runner_uses_unmodified_derived_projected_candidate(tmp_path: Path) -> None:
    """The runner must use the unmodified ProjectedCandidate returned by
    projection — not a copied or manually altered object."""
    projected = get_projected_candidate()  # unmodified
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    generate.side_effect = _successful_generation(projected)
    with stack:
        run_pipeline(**args)
    # generate_scenario must have been called with the exact projected candidate
    assert generate.call_count == 1
    call_kwargs = generate.call_args.kwargs
    assert call_kwargs["projected_candidate"] is projected
    # Check via the mock's return value
    call_result = generate.call_args
    assert call_result.kwargs["projected_candidate"] is projected
