"""Integration coverage for the runner's projection prejoin and identities."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.llm.client import LLMResult
from scenario_forge.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    RunStatus,
    load_manifest,
)
from scenario_forge.models.attack_pattern import AttackPattern
from scenario_forge.models.capability_profile import ConfidenceLevel, EntryPoint
from scenario_forge.models.projection_envelope import ProjectionTraceabilityResult
from scenario_forge.models.scenario import CallMetadata, CallName
from scenario_forge.pipeline.candidates import FilteredSeed, StageRecord
from scenario_forge.pipeline.coverage import CoverageGaps
from scenario_forge.pipeline.generate.stages import (
    ActorStageResult,
    BehaviorStageResult,
    NarrativeStageResult,
    StageCallEvidence,
    TreeStageResult,
)
from scenario_forge.pipeline.persistence import (
    read_coverage_plan,
    read_finalization_inventory,
)
from scenario_forge.pipeline.runner import resume_pipeline, run_pipeline
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.pipeline.threats import ThreatSurface
from tests.helpers.projection_factory import (
    _evidence,
    _pattern,
    _TaxonomyResolver,
    get_canonical_ingress_id,
    get_projected_candidate,
    get_test_profile,
    get_test_snapshot,
)
from tests.test_actor_entry_point_validation import (
    _make_envelope as _make_actor_envelope,
)
from tests.test_actor_entry_point_validation import (
    _make_profile,
)
from tests.test_finalization_gates import _phase3b_behavior
from tests.test_projection_traceability import _make_envelope as _make_valid_envelope


def _same_snapshot_fallbacks():
    """Return two binding variants that share one trusted capability snapshot."""
    from scenario_forge.models.capability_profile import CapabilityProfile
    from scenario_forge.pipeline.projection import (
        ProjectionBudget,
        capture_capability_snapshot,
        project_authoritative_candidates,
    )

    raw = _pattern()
    pattern = AttackPattern.model_validate(raw)
    resolver = _TaxonomyResolver(pattern.canonical_chain.taxonomy_context)
    for tool_name in ("reader", "sender", "executor", "alpha", "b", "zz"):
        profile_data = get_test_profile().model_dump(mode="json")
        profile_data["tool_inventory"].append(
            {"name": tool_name, "description": "reads state"}
        )
        profile_data["tool_types"].append(
            {
                "name": tool_name,
                "zone": "tool_execution",
                "can_modify_state": False,
                "data_sensitivity": "low",
                "code_execution": False,
            }
        )
        profile = CapabilityProfile.model_validate(profile_data)
        snapshot = capture_capability_snapshot(profile, (_evidence(),))
        batch = project_authoritative_candidates(
            [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
        )
        writer_id = profile.tool_inventory[0].tool_id
        writer = next(
            candidate
            for candidate in batch.candidates
            if writer_id in str(candidate.projection.bindings)
        )
        alternate = next(
            candidate for candidate in batch.candidates if candidate != writer
        )
        if alternate.candidate_id < writer.candidate_id:
            return profile, snapshot, [alternate, writer]
    raise AssertionError("fixture could not place the canonical writer as fallback")


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
        risk_card_ref=_make_actor_envelope().faceting.risk_card,
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
    pattern = _pattern()
    validated_pattern = AttackPattern.model_validate(pattern)
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
        "filter_candidates": MagicMock(return_value=([filtered], [], [])),
        "load_attack_patterns": MagicMock(return_value={"test": pattern}),
        "load_taxonomy_resolver": MagicMock(
            return_value=_TaxonomyResolver(
                validated_pattern.canonical_chain.taxonomy_context
            )
        ),
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
    from scenario_forge.pipeline.coverage_planning import (
        deserialize_qualified_candidate,
    )

    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.revalidate_qualified_candidate",
            side_effect=lambda raw, *_: deserialize_qualified_candidate(raw),
        )
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    envelope.behavior_spec = _phase3b_behavior(
        get_projected_candidate(), envelope.attack_tree
    )

    def evidence(call: CallName) -> StageCallEvidence:
        return StageCallEvidence(
            call,
            llm_result,
            CallMetadata(
                call=call, prompt_tokens=0, completion_tokens=0, duration_ms=0
            ),
        )

    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            return_value=ActorStageResult(
                envelope.actor_profile, evidence(CallName.actor_profile)
            ),
        )
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_narrative_stage",
            return_value=NarrativeStageResult(
                envelope.narrative, evidence(CallName.narrative)
            ),
        )
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_tree_stage",
            return_value=TreeStageResult(
                envelope.attack_tree, evidence(CallName.attack_tree)
            ),
        )
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.generate.stages.generate_behavior_stage",
            return_value=BehaviorStageResult(
                envelope.behavior_spec, evidence(CallName.behavior_spec)
            ),
        )
    )

    def evaluate(*, resolver, threats_path=None):
        inventory = resolver.manifest.inventory
        assert not any(
            item.role is ArtifactRole.QUARANTINE_BUNDLE for item in inventory
        )
        assert {item.role for item in inventory if item.scenario_id is not None} <= {
            ArtifactRole.SCENARIO_YAML,
            ArtifactRole.SCENARIO_FEATURE,
        }
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


def test_exact_projection_match_uses_authoritative_identity(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    with stack:
        result = run_pipeline(**args)

    generate.assert_not_called()
    assert result.scenarios[0].candidate_id == projected.candidate_id
    manifest = load_manifest(result.run_dir)
    scenario_inventory = [item for item in manifest.inventory if item.scenario_id]
    assert scenario_inventory
    assert {item.candidate_id for item in scenario_inventory} == {
        projected.candidate_id
    }
    assert manifest.manifest_version == "3"
    assert manifest.attempts == []
    assert manifest.funnel == {}


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
    assert manifest.funnel == {}
    assert read_finalization_inventory(result.run_dir).candidate_attempts == []
    assert all(
        target.target_state.value == "exhausted"
        for target in read_coverage_plan(result.run_dir).targets
    )


def test_multiple_exact_projection_matches_fan_out(tmp_path: Path) -> None:
    """cmps.4: Multiple projected candidates with distinct bindings for the
    same pattern+ingress are valid alternatives — fanned out, not fatal.

    Uses a real projection from a profile with two tools, producing two
    ProjectedCandidate records with the same pattern_id and same
    canonical_ingress entry_point_id but genuinely different concrete
    bindings (different tool bindings) and recomputed candidate_ids —
    not model_copy with a swapped ID.
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
    # Profile with 2 tools → 2 binding combinations for same ingress.
    profile = CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1", "KC5.1"],
        tool_inventory=[
            {"name": "writer", "description": "changes state"},
            {"name": "reader", "description": "reads state"},
        ],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            },
            {
                "name": "reader",
                "zone": "tool_execution",
                "can_modify_state": False,
                "data_sensitivity": "low",
                "code_execution": False,
            },
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
    batch = project_authoritative_candidates(
        [raw], resolver, snapshot, budget=ProjectionBudget(max_candidates=100)
    )
    assert len(batch.candidates) == 2
    first, second = batch.candidates
    assert first.candidate_id != second.candidate_id
    # Same pattern+ingress, different concrete bindings.
    assert (
        first.canonical_ingress.entry_point_id
        == second.canonical_ingress.entry_point_id
    )
    assert first.pattern_id == second.pattern_id

    # Arrange the runner with both projected candidates.  The filtered seed
    # matches the shared ingress; the runner fans out all matches.
    stack, _, _generate, args = _arrange(
        tmp_path,
        entry_point_id=first.canonical_ingress.entry_point_id,
        projected_candidates=[first, second],
    )
    with stack:
        result = run_pipeline(**args)
    assert result.run_dir is not None
    manifest = load_manifest(result.run_dir)
    assert manifest.funnel == {}
    plan = read_coverage_plan(result.run_dir)
    target = next(item for item in plan.targets if item.ordered_choices)
    assert [item.candidate_id for item in target.ordered_choices] == [
        first.candidate_id,
        second.candidate_id,
    ]


def test_runner_uses_unmodified_derived_projected_candidate(tmp_path: Path) -> None:
    """The runner must use the unmodified ProjectedCandidate returned by
    projection — not a copied or manually altered object."""
    projected = get_projected_candidate()  # unmodified
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    with stack:
        result = run_pipeline(**args)
    generate.assert_not_called()
    attempts = read_finalization_inventory(result.run_dir).candidate_attempts
    assert [item.candidate_id for item in attempts] == [projected.candidate_id]


def test_attempt_is_reserved_before_failed_actor_stage(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            side_effect=RuntimeError("generation failed"),
        )
    )
    with stack:
        result = run_pipeline(**args)

    generate.assert_not_called()
    inventory = read_finalization_inventory(result.run_dir)
    assert [item.candidate_id for item in inventory.candidate_attempts] == [
        projected.candidate_id
    ]
    assert inventory.admission_decisions[0].admitted is False
    assert inventory.quarantine_inventory


def test_production_primary_quarantine_then_fallback_admits(tmp_path: Path) -> None:
    profile, snapshot, projected = _same_snapshot_fallbacks()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected[0].canonical_ingress.entry_point_id,
        projected_candidates=projected,
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.infer_capability_profile",
            return_value=(
                profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
            ),
        )
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.capture_capability_snapshot",
            return_value=snapshot,
        )
    )
    from scenario_forge.pipeline.coverage_planning import SelectionResult

    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.select_with_coverage_priority",
            side_effect=lambda qualified, _queues, universe, **_kwargs: SelectionResult(
                selected=[
                    item
                    for item in qualified
                    if item.candidate_id == projected[0].candidate_id
                ],
                uncovered_target_ids=sorted(
                    universe.feasible_target_ids
                    - {projected[0].canonical_ingress.entry_point_id}
                ),
                primary_candidate_ids={
                    projected[0].canonical_ingress.entry_point_id: projected[
                        0
                    ].candidate_id
                },
                attempted_candidate_ids={projected[0].candidate_id},
                per_pattern_counts={projected[0].pattern_id: 1},
            ),
        )
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    actor_result = ActorStageResult(
        envelope.actor_profile,
        StageCallEvidence(
            CallName.actor_profile,
            LLMResult(
                content="mock",
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
                system_prompt="mock",
                user_prompt="mock",
            ),
            CallMetadata(
                call=CallName.actor_profile,
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
        ),
    )
    actor = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            side_effect=[
                RuntimeError("primary failed 0"),
                RuntimeError("primary failed 1"),
                RuntimeError("primary failed 2"),
                actor_result,
            ],
        )
    )
    for legacy_name in (
        "write_scenario_outputs",
        "replace_scenario_outputs",
        "validate_phantom_capabilities",
        "enforce_parsimony",
    ):
        stack.enter_context(
            patch(
                f"scenario_forge.pipeline.runner.{legacy_name}",
                side_effect=AssertionError(f"legacy path reached: {legacy_name}"),
            )
        )
    with stack:
        result = run_pipeline(**args)

    generate.assert_not_called()
    assert actor.call_count == 4
    inventory = read_finalization_inventory(result.run_dir)
    assert [item.admitted for item in inventory.admission_decisions] == [False, True]
    assert load_manifest(result.run_dir).status is RunStatus.COMPLETED_WITH_ERRORS


def test_public_resume_terminalizes_unknown_actor_without_reissue(
    tmp_path: Path,
) -> None:
    profile, snapshot, projected = _same_snapshot_fallbacks()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected[0].canonical_ingress.entry_point_id,
        projected_candidates=projected,
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.infer_capability_profile",
            return_value=(
                profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
            ),
        )
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.capture_capability_snapshot",
            return_value=snapshot,
        )
    )
    from scenario_forge.pipeline.coverage_planning import SelectionResult

    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.select_with_coverage_priority",
            side_effect=lambda qualified, _queues, universe, **_kwargs: SelectionResult(
                selected=[
                    item
                    for item in qualified
                    if item.candidate_id == projected[0].candidate_id
                ],
                uncovered_target_ids=sorted(
                    universe.feasible_target_ids
                    - {projected[0].canonical_ingress.entry_point_id}
                ),
                primary_candidate_ids={
                    projected[0].canonical_ingress.entry_point_id: projected[
                        0
                    ].candidate_id
                },
                attempted_candidate_ids={projected[0].candidate_id},
                per_pattern_counts={projected[0].pattern_id: 1},
            ),
        )
    )
    actor = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("simulated process exit"),
        )
    )
    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args)
        run_dir = next(args["output_dir"].iterdir())
        started = load_manifest(run_dir)
        assert started.status is RunStatus.STARTED
        assert {item.role for item in started.inventory} == {
            ArtifactRole.USE_CASE,
            ArtifactRole.CAPABILITY_PROFILE,
            ArtifactRole.THREAT_SURFACE,
            ArtifactRole.PLANNING_CHECKPOINT,
        }
        before = read_finalization_inventory(run_dir)
        assert len(before.transitions) >= 2
        assert before.stage_attempts == []

        envelope = _make_valid_envelope()
        envelope.attack_tree.root.threat_id = "T1"
        actor.side_effect = None
        actor.return_value = ActorStageResult(
            envelope.actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resumed = resume_pipeline(run_dir)

    generate.assert_not_called()
    assert resumed.run_dir == run_dir
    assert actor.call_count == 2  # crashed primary call plus fallback only
    inventory = read_finalization_inventory(run_dir)
    assert [item.admitted for item in inventory.admission_decisions] == [False, True]
    unknown = inventory.admission_decisions[0]
    assert [item.code for item in unknown.violations] == ["unknown_invocation_outcome"]
    assert unknown.terminal_receipts[0].role is ArtifactRole.QUARANTINE_BUNDLE
    assert load_manifest(run_dir).status is RunStatus.COMPLETED_WITH_ERRORS


def test_resume_preserves_persisted_no_eval_policy(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    actor = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt finalization"),
        )
    )
    evaluator = MagicMock(side_effect=AssertionError("evaluation must stay disabled"))
    stack.enter_context(patch("scenario_forge.eval.runner.run_evaluation", evaluator))

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, eval=False)
        run_dir = next(args["output_dir"].iterdir())
        actor.side_effect = None
        envelope = _make_valid_envelope()
        envelope.attack_tree.root.threat_id = "T1"
        actor.return_value = ActorStageResult(
            envelope.actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resumed = resume_pipeline(run_dir)

    generate.assert_not_called()
    evaluator.assert_not_called()
    assert resumed.run_dir == run_dir
    assert load_manifest(run_dir).status is RunStatus.COMPLETED_WITH_ERRORS


def test_resume_rejects_conflicting_eval_before_candidate_generation(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    actor = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt finalization"),
        )
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, eval=False)
        run_dir = next(args["output_dir"].iterdir())
        with pytest.raises(ManifestIntegrityError, match="eval override conflicts"):
            resume_pipeline(run_dir, eval=True)

    generate.assert_not_called()
    assert actor.call_count == 1


def test_resume_passes_persisted_custom_threats_path_to_evaluator(
    tmp_path: Path,
) -> None:
    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    custom_threats = tmp_path / "custom-threats.yaml"
    custom_threats.write_text("threats: []\n", encoding="utf-8")
    actor = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            side_effect=KeyboardInterrupt("interrupt finalization"),
        )
    )
    seen_paths: list[Path | None] = []

    def evaluate(*, resolver, threats_path=None):
        seen_paths.append(threats_path)
        return {"evaluation": {}, "metrics": {}}

    stack.enter_context(
        patch("scenario_forge.eval.runner.run_evaluation", side_effect=evaluate)
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args, threats_path=custom_threats)
        run_dir = next(args["output_dir"].iterdir())
        actor.side_effect = None
        actor.return_value = ActorStageResult(
            _make_valid_envelope().actor_profile,
            StageCallEvidence(
                CallName.actor_profile,
                LLMResult(
                    content="mock",
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                    system_prompt="mock",
                    user_prompt="mock",
                ),
                CallMetadata(
                    call=CallName.actor_profile,
                    prompt_tokens=0,
                    completion_tokens=0,
                    duration_ms=0,
                ),
            ),
        )
        resume_pipeline(run_dir)

    assert seen_paths == [custom_threats]


def test_resume_hydrates_production_planning_checkpoint_attribution(
    tmp_path: Path,
) -> None:
    """The resumed completion tail receives the exact production evidence."""
    from scenario_forge.pipeline.coverage_planning import (
        build_coverage_universe,
        emit_quality_gaps,
    )

    rejected_id = "cand:v2:" + "f" * 32
    arranged_profile = _make_profile()
    arranged_profile.confidence = ConfidenceLevel.high
    arranged_profile.entry_points.append(
        EntryPoint(name="chat", direction="input", controllability="direct")
    )
    feasible_ids = sorted(build_coverage_universe(arranged_profile).feasible_target_ids)
    rejected_target, limited_target = feasible_ids
    stack, patches, _, args = _arrange(
        tmp_path,
        entry_point_id=rejected_target,
        projected_candidates=[],
    )
    patches["project_authoritative_candidates"].return_value = SimpleNamespace(
        candidates=[],
        infeasibilities=[],
        limitations=[],
        unreserved_coverage_targets=[limited_target],
        infeasible_coverage_targets=[],
    )
    completion_inputs: list[dict] = []

    def interrupt_then_capture(**kwargs):
        completion_inputs.append(kwargs)
        if len(completion_inputs) == 1:
            raise KeyboardInterrupt("interrupt completion tail")
        return MagicMock(run_dir=kwargs["run_dir"], scenarios=[])

    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner._complete_v3_run",
            side_effect=interrupt_then_capture,
        )
    )

    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args)
        run_dir = next(args["output_dir"].iterdir())
        resume_pipeline(run_dir)

    fresh, resumed = completion_inputs
    fresh_events = [event.to_dict() for event in fresh["stage_ledger"].events]
    resumed_events = [event.to_dict() for event in resumed["stage_ledger"].events]
    assert resumed_events == fresh_events
    assert resumed["projection_limitation_target_ids"] == {limited_target}
    rejection = next(
        event for event in resumed_events if event["reason"] == "no_projection"
    )
    assert rejection["candidate_id"] == rejected_id

    fresh_gaps, fresh_summary = emit_quality_gaps(
        fresh["coverage_universe"],
        fresh["stage_ledger"],
        fresh["selection_result"],
        fresh["fallback_queues"],
        projection_limitation_target_ids=fresh["projection_limitation_target_ids"],
    )
    resumed_gaps, resumed_summary = emit_quality_gaps(
        resumed["coverage_universe"],
        resumed["stage_ledger"],
        resumed["selection_result"],
        resumed["fallback_queues"],
        projection_limitation_target_ids=resumed["projection_limitation_target_ids"],
    )
    assert resumed_summary.to_dict() == fresh_summary.to_dict()
    assert [gap.to_dict() for gap in resumed_gaps] == [
        gap.to_dict() for gap in fresh_gaps
    ]
    projection_gap = next(
        gap
        for gap in fresh_summary.structural_gaps
        if gap["reason"] == "projection_rejection"
    )
    assert projection_gap["candidate_ids"] == [rejected_id]
    assert fresh_summary.projection_limitations[0]["reason"] == "projection_limitation"


def test_failed_run_inventories_published_planning_checkpoint(tmp_path: Path) -> None:
    from scenario_forge.manifest import ManifestInventoryResolver

    projected = get_projected_candidate()
    stack, _, _, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.run_target_finalization",
            side_effect=RuntimeError("finalization failed after planning checkpoint"),
        )
    )

    with stack, pytest.raises(RuntimeError, match="finalization failed"):
        run_pipeline(**args)

    run_dir = next(args["output_dir"].iterdir())
    manifest = load_manifest(run_dir)
    assert manifest.status is RunStatus.FAILED
    assert any(
        item.role is ArtifactRole.PLANNING_CHECKPOINT for item in manifest.inventory
    )
    ManifestInventoryResolver(run_dir, manifest, check_orphans=True)


@pytest.mark.parametrize(
    ("retry_owner", "expected_calls"),
    [
        ("actor", (2, 2, 2, 2)),
        ("narrative", (1, 2, 2, 2)),
        ("tree", (1, 1, 2, 2)),
    ],
)
def test_public_resume_reuses_only_causal_frontier_after_owner_retry(
    tmp_path: Path,
    retry_owner: str,
    expected_calls: tuple[int, int, int, int],
) -> None:
    from scenario_forge.pipeline.finalization import (
        AdmissionDecision,
        GeneratedStage,
    )
    from scenario_forge.pipeline.finalization_admission import (
        PostbehaviorAdmissionReport,
    )
    from scenario_forge.pipeline.finalization_gates import (
        GateCode,
        GateResult,
        GateViolation,
    )
    from scenario_forge.pipeline.persistence import FinalizationPersistenceAdapter
    from scenario_forge.pipeline.runner_finalization import (
        make_postbehavior_admission as real_admission_factory,
    )

    owner = GeneratedStage(retry_owner)

    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=projected.canonical_ingress.entry_point_id,
        projected_candidates=[projected],
    )
    envelope = _make_valid_envelope()
    envelope.attack_tree.root.threat_id = "T1"
    envelope.behavior_spec = _phase3b_behavior(projected, envelope.attack_tree)
    llm_result = LLMResult(
        content="mock",
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )

    def evidence(call: CallName) -> StageCallEvidence:
        return StageCallEvidence(
            call,
            llm_result,
            CallMetadata(
                call=call, prompt_tokens=0, completion_tokens=0, duration_ms=0
            ),
        )

    actor = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_actor_stage",
            return_value=ActorStageResult(
                envelope.actor_profile, evidence(CallName.actor_profile)
            ),
        )
    )
    narrative = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_narrative_stage",
            return_value=NarrativeStageResult(
                envelope.narrative, evidence(CallName.narrative)
            ),
        )
    )
    tree = stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.generate_tree_stage",
            return_value=TreeStageResult(
                envelope.attack_tree, evidence(CallName.attack_tree)
            ),
        )
    )
    behavior = stack.enter_context(
        patch(
            "scenario_forge.pipeline.generate.stages.generate_behavior_stage",
            return_value=BehaviorStageResult(
                envelope.behavior_spec, evidence(CallName.behavior_spec)
            ),
        )
    )
    routed = False

    def admission_factory(*factory_args, **factory_kwargs):
        admitted = real_admission_factory(*factory_args, **factory_kwargs)

        def route_once(candidate, artifacts, snapshot):
            nonlocal routed
            if not routed:
                routed = True
                gate_violation = GateViolation(
                    GateCode.actor_access,
                    f"retry {owner.value} from durable admission evidence",
                    owner,
                )
                violation = gate_violation.lifecycle()
                return AdmissionDecision(
                    False,
                    (violation,),
                    value=PostbehaviorAdmissionReport(
                        envelope=None,
                        gate_results=(GateResult((gate_violation,)),),
                    ),
                )
            return admitted(candidate, artifacts, snapshot)

        return route_once

    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner_finalization.make_postbehavior_admission",
            side_effect=admission_factory,
        )
    )
    original_record = FinalizationPersistenceAdapter.record_stage_result
    crashed = False

    def crash_after_retry_commit(self, invocation, result):
        nonlocal crashed
        original_record(self, invocation, result)
        if (
            not crashed
            and invocation.stage is owner
            and invocation.invocation_index == 1
        ):
            crashed = True
            raise KeyboardInterrupt(f"crash after durable {owner.value} retry")

    stack.enter_context(
        patch.object(
            FinalizationPersistenceAdapter,
            "record_stage_result",
            new=crash_after_retry_commit,
        )
    )
    with stack:
        with pytest.raises(KeyboardInterrupt):
            run_pipeline(**args)
        run_dir = next(args["output_dir"].iterdir())
        resume_pipeline(run_dir)

    generate.assert_not_called()
    assert (
        actor.call_count,
        narrative.call_count,
        tree.call_count,
        behavior.call_count,
    ) == expected_calls
    inventory = read_finalization_inventory(run_dir)
    assert inventory.admission_decisions[-1].admitted is True
    owner_retry = [
        item
        for item in inventory.stage_attempts
        if item.stage is owner and item.invocation_index == 1
    ][0]
    downstream = tuple(GeneratedStage)[tuple(GeneratedStage).index(owner) + 1]
    resumed_downstream = [
        item
        for item in inventory.stage_attempts
        if item.stage is downstream and item.invocation_index == 1
    ][0]
    assert resumed_downstream.input.visible_artifacts[owner.value] == owner_retry.result


def _run_and_get_coverage_report(tmp_path: Path, *, confirmed: bool) -> dict:
    """Run the pipeline with a mocked profile and return coverage-gaps.json."""
    import json

    from scenario_forge.models.capability_profile import InventoryCompleteness

    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )

    # Patch the profile's entry_point_completeness after _arrange sets it up.
    if confirmed:
        # Need to find the profile in the patches and set confirmed.
        # _arrange patches infer_capability_profile; we re-patch it.
        from scenario_forge.models.capability_profile import (
            InventoryCompleteness,
        )
        from tests.helpers.projection_factory import get_test_profile

        profile = get_test_profile()
        profile.entry_point_completeness = (
            InventoryCompleteness.operator_confirmed_complete
        )
        profile.entry_point_evidence = ["operator-review:test-evidence"]

        infer_mock = stack.enter_context(
            __import__(
                "unittest.mock",
                fromlist=["patch"],
            ).patch("scenario_forge.pipeline.runner.infer_capability_profile")
        )
        from scenario_forge.llm.client import LLMResult

        llm_result = LLMResult(
            content="mock",
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
            system_prompt="mock",
            user_prompt="mock",
        )
        infer_mock.return_value = (profile, llm_result)

    with stack:
        result = run_pipeline(**args)

    report_path = result.run_dir / "coverage-gaps.json"
    return json.loads(report_path.read_text(encoding="utf-8"))


class TestRunnerProfileCompletenessDerivation:
    """cmps.4 blocker 4: runner must derive completeness from profile, not
    free-form input.  An inferred profile cannot claim confirmed by passing
    an enum."""

    def test_inferred_profile_reports_not_applicable(self, tmp_path: Path) -> None:
        report = _run_and_get_coverage_report(tmp_path, confirmed=False)
        universe = report.get("coverage_universe", {})
        assert universe["completeness"] == "not_applicable"
        plan = report.get("coverage_plan", {})
        assert plan["completeness"] == "not_applicable"

    def test_confirmed_profile_reports_confirmed_complete_with_refs(
        self, tmp_path: Path
    ) -> None:
        report = _run_and_get_coverage_report(tmp_path, confirmed=True)
        universe = report.get("coverage_universe", {})
        assert universe["completeness"] == "confirmed_complete"
        assert "operator-review:test-evidence" in universe.get("evidence_refs", [])
        plan = report.get("coverage_plan", {})
        assert plan["completeness"] == "confirmed_complete"
        assert "operator-review:test-evidence" in plan.get("evidence_refs", [])
