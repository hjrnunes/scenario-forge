"""Regression tests for the third cmps.6 correction pass."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.llm.client import LLMResult
from scenario_forge.models.capability_profile import (
    BoundaryConfidence,
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    TrustBoundary,
    compute_trust_boundary_id,
    deduplicate_trust_boundaries,
)
from scenario_forge.models.projection_envelope import ProjectionTraceabilityResult
from scenario_forge.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
    ScenarioEnvelope,
)
from scenario_forge.pipeline.candidates import FilteredSeed, StageRecord
from scenario_forge.pipeline.coverage import CoverageGaps, EntryPointGap
from scenario_forge.pipeline.generate import (
    compute_scenario_id,
    generate_scenario,
)
from scenario_forge.pipeline.generate.actor import build_call0_context
from scenario_forge.pipeline.generate.narrative import (
    validate_narrative_access_realization,
)
from scenario_forge.pipeline.runner import run_pipeline
from scenario_forge.pipeline.seeds import RiskCardRef, ScenarioSeed
from scenario_forge.pipeline.threats import ThreatSurface
from tests.helpers.projection_factory import get_projected_candidate, get_test_snapshot
from tests.helpers.realization_helper import make_realizations
from tests.test_actor_entry_point_validation import (
    _make_envelope,
    _make_indirect_profile,
    _make_profile,
)

RUN_ID = "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _seed() -> ScenarioSeed:
    return ScenarioSeed(
        seed_id="AP-T1-01",
        threat_id="T1",
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="A test attack pattern.",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk",
            risk_description="Risk description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
    )


def _result(content: object = "mock") -> LLMResult:
    return LLMResult(
        content=content,
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )


def test_boundary_identity_collision_guard_and_call0_context() -> None:
    first = TrustBoundary(
        name="Vendor gateway",
        from_zone="memory",
        to_zone="input",
        confidence=BoundaryConfidence.explicit,
    )
    second = TrustBoundary(
        name="Document gateway",
        from_zone="memory",
        to_zone="input",
        confidence=BoundaryConfidence.explicit,
    )
    assert first.trust_boundary_id != second.trust_boundary_id
    assert first.trust_boundary_id == compute_trust_boundary_id(
        "memory", "input", "Vendor gateway"
    )
    assert deduplicate_trust_boundaries([first, second]) == [first, second]

    duplicate = first.model_copy()
    assert deduplicate_trust_boundaries([first, duplicate]) == [first]

    # Simulate a hash collision without weakening the production hash function.
    with patch.object(
        TrustBoundary,
        "trust_boundary_id",
        new_callable=MagicMock,
    ) as boundary_id:
        boundary_id.__get__ = MagicMock(return_value="tb:v1:" + "f" * 32)
        with pytest.raises(ValueError, match="Ambiguous trust boundary identity"):
            deduplicate_trust_boundaries([first, second])

    profile = _make_indirect_profile()
    target, upstream = profile.entry_points
    context = build_call0_context(
        _seed(),
        profile,
        "test use case",
        pinned_entry_point=target.name,
        pinned_entry_point_id=target.entry_point_id,
    )
    section = context["access_provenance_section"]
    assert upstream.entry_point_id in section
    assert profile.trust_boundaries[0].trust_boundary_id in section
    assert "Valid influence_source entry-point IDs" in section
    assert "Valid trust_boundary_id values" in section


def test_title_retry_cannot_bypass_realization_enforcement() -> None:
    profile = _make_profile()
    ep = profile.entry_points[0]
    access = ActorAccessProvenance(
        initial_entry_point_id=ep.entry_point_id,
        ingress_mode="direct",
        access_class="public",
    )
    actor = ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["The interface accepts input."],
        desires=["Compromise the system."],
        intentions=["Submit crafted input."],
        resources=["Standard tools."],
        access=access,
    )
    valid = NarrativeLayer(
        title="Already Used",
        summary="A valid first response.",
        entry_point=ep.name,
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Inject",
                effect="Parse",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            )
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id=ep.entry_point_id,
            responsible_step_number=1,
        ),
    )
    invalid_retry = valid.model_copy(
        update={"title": "Fresh Title", "access_realization": None}
    )
    template = _make_envelope(entry_point_id=ep.entry_point_id, access=access)
    template.actor_profile = actor
    candidate_id = "cand:v2:11111111111111111111111111111111"

    def assemble(*args, narrative, **kwargs) -> ScenarioEnvelope:
        envelope = template.model_copy(deep=True)
        envelope.narrative = narrative
        envelope.candidate_id = candidate_id
        envelope.scenario_id = compute_scenario_id(RUN_ID, candidate_id)
        return envelope

    with (
        patch(
            "scenario_forge.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ),
        patch(
            "scenario_forge.pipeline.generate._validate_actor_type",
            side_effect=lambda value: value,
        ),
        patch(
            "scenario_forge.pipeline.generate.validate_actor_access_provenance",
            return_value=[],
        ),
        patch(
            "scenario_forge.pipeline.generate._call_narrative",
            side_effect=[
                (valid, _result()),
                (invalid_retry, _result()),
                (invalid_retry, _result()),
            ],
        ) as narrative_call,
        patch(
            "scenario_forge.pipeline.generate._call_attack_tree",
            return_value=(template.attack_tree, _result()),
        ),
        patch("scenario_forge.pipeline.generate._strip_non_skeleton_techniques"),
        patch(
            "scenario_forge.pipeline.generate._validate_technique_zone_compatibility"
        ),
        patch(
            "scenario_forge.pipeline.generate.assembly._check_consistency",
            return_value=[],
        ),
        patch(
            "scenario_forge.pipeline.generate._call_behavior_spec",
            return_value=(None, _result()),
        ),
        patch(
            "scenario_forge.pipeline.generate._assemble_envelope", side_effect=assemble
        ),
        patch(
            "scenario_forge.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True, violations=[]),
        ),
    ):
        envelope, _ = generate_scenario(
            _seed(),
            profile,
            MagicMock(),
            "test",
            pinned_entry_point_id=ep.entry_point_id,
            pinned_entry_point=ep.name,
            prior_titles=["Already Used"],
            run_id=RUN_ID,
            candidate_id="",
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

    assert narrative_call.call_count >= 3
    violations = validate_narrative_access_realization(
        envelope.narrative, envelope.actor_profile
    )
    assert {violation.rule for violation in violations} == {
        "missing_access_realization"
    }


def test_early_access_gate_excludes_invalid_candidate_from_coverage_and_diversity(
    tmp_path: Path,
) -> None:
    first = EntryPoint(name="chat", direction="input", controllability="direct")
    second = EntryPoint(name="API", direction="input", controllability="direct")
    profile: CapabilityProfile = _make_profile(entry_points=[first, second])
    seed = _seed()

    def filtered(source_seed: ScenarioSeed, ep: EntryPoint, digit: str) -> FilteredSeed:
        return FilteredSeed(
            **source_seed.model_dump(),
            pinned_entry_point=ep.name,
            pinned_technique_ids=("AML.T0051.000",),
            pinned_technique_names=("Prompt Injection",),
            entry_point_id=ep.entry_point_id,
            candidate_id=f"cand:v2:{digit * 32}",
        )

    second_seed = seed.model_copy(update={"seed_id": "AP-T2-01"})
    valid_seed = filtered(seed, first, "1")
    invalid_seed = filtered(second_seed, second, "2")
    from scenario_forge.models.attack_pattern import EntryPointResourceReference

    projected_t1 = get_projected_candidate().model_copy(
        update={"candidate_id": valid_seed.candidate_id}
    )
    # projected_t2 must have a canonical ingress matching the "API"
    # entry point so the runner's exact-ingress selection finds it.
    projected_t2 = get_projected_candidate().model_copy(
        update={
            "pattern_id": "AP-T2-01",
            "candidate_id": invalid_seed.candidate_id,
            "canonical_ingress": EntryPointResourceReference(
                kind="entry_point",
                entry_point_id=second.entry_point_id,
            ),
        }
    )
    projection_batch = MagicMock(
        candidates=[projected_t1, projected_t2],
        infeasibilities=[],
        limitations=[],
    )

    def generate(fseed, *args, **kwargs):
        invalid = fseed is invalid_seed
        access = ActorAccessProvenance(
            initial_entry_point_id=fseed.entry_point_id,
            ingress_mode="direct",
            access_class="supply_chain" if invalid else "public",
        )
        envelope = _make_envelope(
            narrative_entry_point=fseed.pinned_entry_point,
            entry_point_id=fseed.entry_point_id,
            access=deepcopy(access),
        )
        envelope.narrative.access_realization = NarrativeAccessRealization(
            initial_entry_point_id=fseed.entry_point_id, responsible_step_number=1
        )
        envelope.initial_entry_point_id = fseed.entry_point_id
        envelope.candidate_id = fseed.candidate_id
        envelope.scenario_id = compute_scenario_id(kwargs["run_id"], fseed.candidate_id)
        return envelope, []

    coverage_inputs: list[list[str]] = []

    def coverage(_profile, _surface, scenarios):
        coverage_inputs.append([scenario.scenario_id for scenario in scenarios])
        if len(coverage_inputs) == 1:
            return CoverageGaps(
                uncovered_entry_points=[
                    EntryPointGap(second.entry_point_id, second.name)
                ]
            )
        return CoverageGaps()

    def expand(*args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="expansion", input_count=2, output_count=2, collapsed_count=0
            )
        )
        return [valid_seed, invalid_seed]

    def rules(candidates, *args, stage_records, **kwargs):
        stage_records.append(
            StageRecord(
                stage="rule_pruning", input_count=2, output_count=2, collapsed_count=0
            )
        )
        return candidates, [], []

    risk_path = tmp_path / "risk.json"
    risk_path.write_text("[]", encoding="utf-8")
    mapping = tmp_path / "mapping.tsv"
    mapping.write_text("", encoding="utf-8")
    client = MagicMock(
        model="test-model",
        base_url="mock://local",
        temperature=0.0,
        max_completion_tokens=1000,
    )
    tracker_update = MagicMock()

    with (
        patch("scenario_forge.pipeline.runner.LLMClient", return_value=client),
        patch(
            "scenario_forge.pipeline.runner.infer_capability_profile",
            return_value=(profile, _result()),
        ),
        patch("scenario_forge.pipeline.runner.load_risk_extraction", return_value=[]),
        patch(
            "scenario_forge.pipeline.runner.validate_risk_card_coherence",
            return_value=MagicMock(has_warnings=False),
        ),
        patch(
            "scenario_forge.pipeline.runner.determine_threat_surface",
            return_value=ThreatSurface(entries=[], governance_only=[]),
        ),
        patch("scenario_forge.pipeline.runner.expand_seeds", return_value=[seed]),
        patch("scenario_forge.pipeline.runner.expand_candidates", side_effect=expand),
        patch(
            "scenario_forge.pipeline.runner.apply_rule_based_filter", side_effect=rules
        ),
        patch(
            "scenario_forge.pipeline.runner.filter_candidates",
            return_value=([valid_seed, invalid_seed], []),
        ),
        patch("scenario_forge.pipeline.runner.generate_scenario", side_effect=generate),
        patch(
            "scenario_forge.pipeline.runner.project_authoritative_candidates",
            return_value=projection_batch,
        ),
        patch(
            "scenario_forge.pipeline.runner.capture_capability_snapshot",
            return_value=get_test_snapshot(),
        ),
        patch(
            "scenario_forge.pipeline.runner.analyze_coverage_gaps", side_effect=coverage
        ),
        patch("scenario_forge.pipeline.runner.DiversityTracker.update", tracker_update),
        patch(
            "scenario_forge.pipeline.runner.analyze_attacker_diversity",
            return_value=None,
        ),
        patch(
            "scenario_forge.eval.runner.run_evaluation", return_value={"metrics": {}}
        ),
        patch(
            "scenario_forge.report.generator.generate_report",
            side_effect=lambda data, out_dir: Path(out_dir) / "report.html",
        ),
        patch(
            "scenario_forge.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True, violations=[]),
        ),
    ):
        result = run_pipeline("test", risk_path, mapping, tmp_path / "runs")

    invalid_sid = compute_scenario_id(result.run_id, invalid_seed.candidate_id)
    assert invalid_sid not in coverage_inputs[0]
    updated_ids = [call.args[0].scenario_id for call in tracker_update.call_args_list]
    assert invalid_sid not in updated_ids
