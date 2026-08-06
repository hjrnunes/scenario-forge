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
from scenario_forge.pipeline.coverage import CoverageGaps
from scenario_forge.pipeline.generate import (
    ScenarioForgeIntegrityError,
    compute_scenario_id,
)
from scenario_forge.pipeline.runner import run_pipeline
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
        "filter_candidates": MagicMock(return_value=([filtered], [], [])),
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
    # qualified counts both fanned-out projected candidates.
    assert manifest.funnel["qualified"] >= 2
    # Only the primary (first choice) is selected for generation.
    assert manifest.funnel["selected"] >= 1


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


def test_forged_candidate_identity_cannot_write(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    successful_generation = _successful_generation(projected)

    def forged_generation(*generation_args, **generation_kwargs):
        envelope, call_log = successful_generation(
            *generation_args, **generation_kwargs
        )
        envelope.candidate_id = "cand:v2:" + "9" * 32
        return envelope, call_log

    generate.side_effect = forged_generation
    with (
        stack,
        pytest.raises(
            ScenarioForgeIntegrityError, match="does not match attempted candidate_id"
        ),
    ):
        run_pipeline(**args)


def test_attempt_is_reserved_before_failed_generation(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    generate.side_effect = RuntimeError("generation failed")
    with stack:
        result = run_pipeline(**args)

    generate.assert_called_once()
    assert generate.call_args.kwargs["projected_candidate"] is projected
    manifest = load_manifest(result.run_dir)
    assert len(manifest.attempts) == 1
    assert manifest.attempts[0].candidate_id == projected.candidate_id
    assert manifest.attempts[0].disposition is AttemptDisposition.FAILED


def test_returned_scenario_identity_mismatch_is_fatal(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    successful_generation = _successful_generation(projected)

    def mismatched_generation(*generation_args, **generation_kwargs):
        envelope, call_log = successful_generation(
            *generation_args, **generation_kwargs
        )
        expected = compute_scenario_id(
            generation_kwargs["run_id"], projected.candidate_id, 1
        )
        envelope.scenario_id = f"{expected}-forged"
        return envelope, call_log

    generate.side_effect = mismatched_generation
    with (
        stack,
        pytest.raises(ScenarioForgeIntegrityError, match="does not match expected"),
    ):
        run_pipeline(**args)


def test_call_log_failure_after_artifact_write_is_fatal(tmp_path: Path) -> None:
    projected = get_projected_candidate()
    stack, _, generate, args = _arrange(
        tmp_path,
        entry_point_id=get_canonical_ingress_id(),
        projected_candidates=[projected],
    )
    generate.side_effect = _successful_generation(projected)
    stack.enter_context(
        patch(
            "scenario_forge.pipeline.runner.write_call_log",
            side_effect=OSError("call log unavailable"),
        )
    )

    with (
        stack,
        pytest.raises(
            ScenarioForgeIntegrityError,
            match="Call-log write failed after artifact creation",
        ),
    ):
        run_pipeline(**args)

    scenario_files = list(args["output_dir"].glob("*/scenarios/*"))
    assert any(path.suffix == ".yaml" for path in scenario_files)
    assert any(path.suffix == ".feature" for path in scenario_files)


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
    generate.side_effect = _successful_generation(projected)

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
