"""Focused failure-injection and invariant tests for PR #262 review corrections.

Covers:
  - Safe paired artifact operations (second-file failure cleanup, pre-existing
    fatal, missing-pair fatal, guarded replacement verifies feature bytes).
  - Fatal integrity errors escape recoverable generation handling.
  - Candidate ID reserved before LLM invocation.
  - Call-log failure after artifact creation aborts run.
  - End-to-end remediation funnel equations.
  - CandidateFunnel rejects negative / inconsistent equations.
  - rule_transformed counts transformed source identities pre-collapse.
  - Conflicting per-technique name/description metadata rejected.
  - Multiple techniques removed by different rules retain individual decisions.
  - Invalid run IDs / candidate IDs / attempt 0 rejected.
  - Remediation candidate ID matches the actual pinned canonical technique tuple.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    compute_entry_point_id,
)
from scenario_forge.models.scenario import (
    ArchitectureMatch,
    AttackComplexity,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    LikelihoodLevel,
    NarrativeLayer,
    NarrativeStep,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SeverityLevel,
    StructuralExposureSignal,
    TaxonomyChain,
    TechniqueMaturity,
)
from scenario_forge.pipeline.candidates import (
    CandidateFunnel,
    CandidateOrigin,
    CandidateTriple,
    apply_rule_based_filter,
    canonicalize_and_dedup,
    compute_candidate_id,
    _canonicalize_techniques,
)
from scenario_forge.pipeline.coverage import CoverageGaps, EntryPointGap
from scenario_forge.pipeline.generate import (
    GenerationError,
    ScenarioForgeIntegrityError,
    compute_scenario_id,
    replace_scenario_outputs,
    write_scenario_outputs,
)
from scenario_forge.pipeline.generate.assembly import (
    _validate_candidate_id,
    _validate_run_id,
)
from scenario_forge.pipeline.runner import _remediate_coverage_gaps
from scenario_forge.pipeline.seeds import ScenarioSeed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_RUN_ID = "a" * 32
_VALID_CANDIDATE_ID = "cand:v1:" + "1" * 32


def _make_ref(risk_id: str = "risk-1") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_seed(
    seed_id: str = "AP-T7-01",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    threat_id: str = "T7",
) -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=f"Threat {threat_id}",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        atlas_technique_ids=list(technique_ids),
    )


def _make_profile(
    entry_points: list[str] | None = None,
    zones_active: list[str] | None = None,
) -> CapabilityProfile:
    if entry_points is None:
        entry_points = ["user prompts (zone 1)", "admin console (zone 2)"]
    if zones_active is None:
        zones_active = ["input", "reasoning"]
    return CapabilityProfile(
        zones_active=zones_active,
        entry_points=entry_points,
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _make_envelope(
    scenario_id: str = "scenario:v2:abc123",
    behavior_spec: str | None = None,
    candidate_id: str = _VALID_CANDIDATE_ID,
) -> ScenarioEnvelope:
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate=GateType.OR,
        zone="input",
        children=[
            AttackTreeNode(
                id="n1.1",
                label="Path A",
                gate=GateType.LEAF,
                zone="input",
                technique_id="AML.T0051",
            ),
            AttackTreeNode(
                id="n1.2",
                label="Path B",
                gate=GateType.LEAF,
                zone="reasoning",
            ),
        ],
    )
    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="I craft a malicious prompt.",
                effect="The system processes the input.",
            ),
        ],
    )
    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )
    faceting = FacetingMetadata(
        risk_card=_make_ref("test-risk"),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts (zone 1)",
        ),
        maestro_layers=[1, 2],
    )
    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )
    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )
    return ScenarioEnvelope(
        scenario_id=scenario_id,
        candidate_id=candidate_id,
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec if behavior_spec is not None else {},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


def _make_candidate(
    seed_id: str = "AP-T7-01",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    direction: str = "input",
    origins: tuple[CandidateOrigin, ...] = (),
) -> CandidateTriple:
    ep_id = compute_entry_point_id(entry_point, direction, None)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return CandidateTriple(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        entry_point=entry_point,
        atlas_technique_ids=technique_ids,
        atlas_technique_names=tuple(f"Technique {t}" for t in technique_ids),
        atlas_technique_descriptions=tuple(f"Desc {t}" for t in technique_ids),
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        direction=direction,
        entry_point_id=ep_id,
        candidate_id=cand_id,
        origins=origins,
    )


# ---------------------------------------------------------------------------
# A. Safe paired artifact operations
# ---------------------------------------------------------------------------


class TestSafePairedArtifacts:
    """write_scenario_outputs and replace_scenario_outputs integrity."""

    def test_second_file_create_failure_cleans_up_yaml(self, tmp_path: Path):
        """If the feature write fails after YAML is created, the YAML
        created by this call must be cleaned up — no partial pair."""
        envelope = _make_envelope(
            scenario_id="scenario:v2:cleanup-test",
            behavior_spec="Feature: test\n  Scenario: test\n",
        )
        original_open = Path.open
        call_count = 0

        def failing_open(self_path, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise OSError("Injected failure on feature write")
            return original_open(self_path, *args, **kwargs)

        with patch.object(Path, "open", failing_open):
            with pytest.raises(OSError, match="Injected failure"):
                write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        assert not yaml_path.exists(), "YAML must be cleaned up on feature failure"
        assert not feature_path.exists(), "Feature must not exist"

    def test_preexisting_pair_is_fatal_and_untouched(self, tmp_path: Path):
        """Pre-existing YAML or feature files must cause a fatal
        integrity error, and the pre-existing files must not be modified."""
        envelope = _make_envelope(
            scenario_id="scenario:v2:preexist-test",
            behavior_spec="Feature: test\n",
        )
        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        original_yaml = "original: yaml\n"
        original_feature = "original: feature\n"
        yaml_path.write_text(original_yaml)
        feature_path.write_text(original_feature)

        with pytest.raises(ScenarioForgeIntegrityError):
            write_scenario_outputs(envelope, tmp_path)

        # Pre-existing files must be untouched.
        assert yaml_path.read_text() == original_yaml
        assert feature_path.read_text() == original_feature

    def test_preexisting_yaml_only_is_fatal(self, tmp_path: Path):
        """Pre-existing YAML without feature must be fatal."""
        envelope = _make_envelope(
            scenario_id="scenario:v2:yaml-only-test",
            behavior_spec=None,
        )
        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        yaml_path.write_text("original: data\n")

        with pytest.raises(ScenarioForgeIntegrityError):
            write_scenario_outputs(envelope, tmp_path)

    def test_missing_pair_during_guarded_replace_is_fatal(self, tmp_path: Path):
        """replace_scenario_outputs must raise fatal if YAML doesn't exist."""
        envelope = _make_envelope(scenario_id="scenario:v2:missing-pair")
        with pytest.raises(ScenarioForgeIntegrityError, match="non-existent"):
            replace_scenario_outputs(
                envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
            )

    def test_guarded_replace_verifies_feature_bytes_unchanged(self, tmp_path: Path):
        """Guarded replacement must verify feature bytes match and only
        update YAML atomically."""
        feature_text = "Feature: test\n  Scenario: test\n"
        envelope = _make_envelope(
            scenario_id="scenario:v2:replace-feature-test",
            behavior_spec=feature_text,
        )
        # Create initial artifacts.
        write_scenario_outputs(envelope, tmp_path)
        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        original_feature_bytes = feature_path.read_bytes()

        # Modify envelope (e.g. add validation metadata) but keep
        # behavior_spec identical — feature bytes must be verified.
        envelope.behavior_spec = feature_text  # same bytes
        # Add validation to force YAML change.
        from scenario_forge.models.scenario import ValidationBlock

        envelope.validation = ValidationBlock()

        yaml_path, feat_path = replace_scenario_outputs(
            envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
        )
        assert feat_path is not None
        assert feature_path.read_bytes() == original_feature_bytes
        # YAML was updated (contains validation now).
        assert yaml_path.exists()

    def test_guarded_replace_rejects_feature_byte_mismatch(self, tmp_path: Path):
        """If behavior_spec bytes differ from the existing feature file,
        guarded replacement must raise fatal."""
        feature_text = "Feature: original\n"
        envelope = _make_envelope(
            scenario_id="scenario:v2:feature-mismatch",
            behavior_spec=feature_text,
        )
        write_scenario_outputs(envelope, tmp_path)

        # Change behavior_spec to different bytes.
        envelope.behavior_spec = "Feature: different\n"
        with pytest.raises(ScenarioForgeIntegrityError, match="Feature byte mismatch"):
            replace_scenario_outputs(
                envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
            )

    def test_guarded_replace_rejects_id_mismatch(self, tmp_path: Path):
        """replace_scenario_outputs must reject if envelope scenario_id
        doesn't match the admitted_scenario_id."""
        envelope = _make_envelope(scenario_id="scenario:v2:id-a")
        with pytest.raises(ScenarioForgeIntegrityError, match="Scenario ID mismatch"):
            replace_scenario_outputs(
                envelope, tmp_path, admitted_scenario_id="scenario:v2:id-b"
            )


# ---------------------------------------------------------------------------
# B. Fatal integrity errors are not recoverable
# ---------------------------------------------------------------------------


class TestFatalIntegrityErrors:
    """ScenarioForgeIntegrityError must not be caught by GenerationError handlers."""

    def test_integrity_error_not_subclass_of_generation_error(self):
        assert not issubclass(ScenarioForgeIntegrityError, GenerationError)

    def test_integrity_error_is_exception(self):
        assert issubclass(ScenarioForgeIntegrityError, Exception)


# ---------------------------------------------------------------------------
# C. Candidate ID reserved before LLM invocation
# ---------------------------------------------------------------------------


class TestCandidateIdReservation:
    """The candidate_id must be in attempted_candidate_ids before
    generate_scenario is called."""

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_candidate_id_reserved_before_llm(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        captured_ids = []

        def capture_candidate_id(*args, **kwargs):
            # At this point, the candidate_id should already be reserved.
            captured_ids.append(kwargs.get("candidate_id"))
            env = _make_envelope(
                scenario_id="scenario:v2:reserve-test",
                candidate_id=kwargs.get("candidate_id", _VALID_CANDIDATE_ID),
            )
            return env, []

        mock_generate.side_effect = capture_candidate_id
        mock_write.return_value = (tmp_path / "test.yaml", None)

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep-1-id", name="user prompts (zone 1)"),
            ]
        )
        seeds = [_make_seed(seed_id="AP-T1-01", technique_ids=("AML.T0051",))]
        profile = _make_profile()
        attempted = set()

        _remediate_coverage_gaps(
            gaps,
            seeds,
            profile,
            MagicMock(),
            "test use case",
            tmp_path,
            run_id=_VALID_RUN_ID,
            attempted_candidate_ids=attempted,
            admitted_candidate_ids=set(),
            admitted_scenario_ids=set(),
            write_receipts=[],
        )

        # The candidate_id passed to generate_scenario must already be
        # in attempted_candidate_ids.
        assert len(captured_ids) == 1
        assert captured_ids[0] in attempted


# ---------------------------------------------------------------------------
# D. Call-log failure after artifact creation aborts run
# ---------------------------------------------------------------------------


class TestCallLogFailureAfterArtifact:
    """A call-log write failure after artifact creation must be fatal."""

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_call_log_failure_aborts(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        env = _make_envelope(
            scenario_id="scenario:v2:calllog-fail",
            candidate_id=_VALID_CANDIDATE_ID,
        )
        mock_generate.return_value = (env, [])
        mock_write.return_value = (tmp_path / "test.yaml", None)
        mock_write_log.side_effect = OSError("disk full")

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep-1-id", name="user prompts (zone 1)"),
            ]
        )
        seeds = [_make_seed(seed_id="AP-T1-01")]
        profile = _make_profile()

        with pytest.raises(ScenarioForgeIntegrityError, match="call-log"):
            _remediate_coverage_gaps(
                gaps,
                seeds,
                profile,
                MagicMock(),
                "test use case",
                tmp_path,
                run_id=_VALID_RUN_ID,
                attempted_candidate_ids=set(),
                admitted_candidate_ids=set(),
                admitted_scenario_ids=set(),
                write_receipts=[],
            )


# ---------------------------------------------------------------------------
# E. End-to-end remediation funnel equations
# ---------------------------------------------------------------------------


class TestRemediationFunnelEquations:
    """Remediation must produce exact attempted/admitted/failed counts."""

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_exact_attempted_admitted_failed(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        """2 uncovered EPs: one succeeds, one fails. Verify
        attempted=2, failed=1, admitted=1, write_receipts has 1."""
        ok_env = _make_envelope(
            scenario_id="scenario:v2:rem-ok",
            candidate_id=_VALID_CANDIDATE_ID,
        )
        mock_generate.side_effect = [
            (ok_env, []),
            RuntimeError("LLM timeout"),
        ]
        mock_write.return_value = (tmp_path / "test.yaml", None)

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id="ep-ok-id", name="user prompts (zone 1)"),
                EntryPointGap(
                    entry_point_id="ep-fail-id", name="admin console (zone 2)"
                ),
            ]
        )
        seeds = [_make_seed(seed_id="AP-T1-01"), _make_seed(seed_id="AP-T2-01")]
        profile = _make_profile()
        receipts: list[dict] = []

        scenarios, notes, attempted, failed = _remediate_coverage_gaps(
            gaps,
            seeds,
            profile,
            MagicMock(),
            "test use case",
            tmp_path,
            run_id=_VALID_RUN_ID,
            attempted_candidate_ids=set(),
            admitted_candidate_ids=set(),
            admitted_scenario_ids=set(),
            write_receipts=receipts,
        )

        assert attempted == 2
        assert failed == 1
        assert len(scenarios) == 1
        assert len(receipts) == 1
        # Reconciliation: attempted - failed == admitted
        assert attempted - failed == len(scenarios)


# ---------------------------------------------------------------------------
# F. CandidateFunnel validation
# ---------------------------------------------------------------------------


class TestCandidateFunnelValidation:
    """CandidateFunnel must reject negative and inconsistent counts."""

    def _valid_funnel_kwargs(self) -> dict:
        return dict(
            expanded_instances=10,
            unique_pre_rule_identities=8,
            rule_rejected=2,
            rule_transformed=1,
            post_rule_collapsed=1,
            filter_submitted=5,
            filter_accepted=3,
            selected=3,
            attempted=3,
            admitted=2,
            quarantined=1,
            persisted_artifacts=2,
        )

    def test_valid_funnel_accepted(self):
        f = CandidateFunnel(**self._valid_funnel_kwargs())
        assert f.admitted == 2

    def test_rejects_negative(self):
        kw = self._valid_funnel_kwargs()
        kw["admitted"] = -1
        with pytest.raises(ValueError, match="nonnegative"):
            CandidateFunnel(**kw)

    def test_rejects_admitted_gt_attempted(self):
        kw = self._valid_funnel_kwargs()
        kw["admitted"] = 5
        kw["persisted_artifacts"] = 5
        kw["attempted"] = 3
        with pytest.raises(ValueError, match="admitted.*attempted"):
            CandidateFunnel(**kw)

    def test_rejects_persisted_ne_admitted(self):
        kw = self._valid_funnel_kwargs()
        kw["persisted_artifacts"] = 99
        with pytest.raises(ValueError, match="persisted_artifacts.*admitted"):
            CandidateFunnel(**kw)

    def test_rejects_filter_submitted_mismatch(self):
        kw = self._valid_funnel_kwargs()
        kw["filter_submitted"] = 99
        with pytest.raises(ValueError, match="filter_submitted"):
            CandidateFunnel(**kw)

    def test_rejects_selected_gt_filter_accepted(self):
        kw = self._valid_funnel_kwargs()
        kw["selected"] = 10
        with pytest.raises(ValueError, match="selected.*filter_accepted"):
            CandidateFunnel(**kw)

    def test_rejects_quarantined_gt_admitted(self):
        kw = self._valid_funnel_kwargs()
        kw["quarantined"] = 99
        with pytest.raises(ValueError, match="quarantined.*admitted"):
            CandidateFunnel(**kw)


# ---------------------------------------------------------------------------
# G. rule_transformed counts source identities pre-collapse
# ---------------------------------------------------------------------------


class TestRuleTransformedCounting:
    """rule_transformed must count unique source candidate identities that
    had at least one technique pruned, not post-collapse outputs."""

    def test_counts_unique_source_identities(self):
        """Two different source candidates get pruned to the same
        post-collapse identity. rule_transformed should count 2, not 1."""
        ep = "user prompts (input)"

        # Source A: T1+T2 → T1 (T2 pruned)
        origin_a = CandidateOrigin(
            source_candidate_id="cand:src-a",
            original_technique_ids=("AML.T0051", "AML.T0052"),
            applied_rule="_rule_direct_vs_indirect",
            removed_technique_ids=("AML.T0052",),
            removal_reasons=("T2 is indirect",),
            transform_stage="rule_pruning",
        )
        # Source B: T1+T3 → T1 (T3 pruned)
        origin_b = CandidateOrigin(
            source_candidate_id="cand:src-b",
            original_technique_ids=("AML.T0051", "AML.T0053"),
            applied_rule="_rule_tool_execution_only",
            removed_technique_ids=("AML.T0053",),
            removal_reasons=("T3 requires tools",),
            transform_stage="rule_pruning",
        )

        c_a = _make_candidate(
            entry_point=ep,
            technique_ids=("AML.T0051",),
            origins=(origin_a,),
        )
        c_b = _make_candidate(
            entry_point=ep,
            technique_ids=("AML.T0051",),
            origins=(origin_b,),
        )

        result = canonicalize_and_dedup([c_a, c_b], "rule_pruning")
        assert len(result) == 1  # converged to one

        # Count unique source identities with rule_pruning origins.
        source_ids = {
            o.source_candidate_id
            for o in result[0].origins
            if o.transform_stage == "rule_pruning"
        }
        assert len(source_ids) == 2  # two distinct source identities


# ---------------------------------------------------------------------------
# H. Conflicting per-technique metadata rejected
# ---------------------------------------------------------------------------


class TestTechniqueMetadataConflicts:
    """_canonicalize_techniques must reject conflicting metadata for
    the same technique ID."""

    def test_conflicting_name_rejected(self):
        with pytest.raises(ValueError, match="Conflicting technique name"):
            _canonicalize_techniques(
                ("T1", "T1"),
                ("name-a", "name-b"),
                ("desc", "desc"),
            )

    def test_conflicting_description_rejected(self):
        with pytest.raises(ValueError, match="Conflicting technique description"):
            _canonicalize_techniques(
                ("T1", "T1"),
                ("name", "name"),
                ("desc-a", "desc-b"),
            )

    def test_duplicate_id_deduped(self):
        ids, names, descs = _canonicalize_techniques(
            ("T1", "T1"),
            ("name", "name"),
            ("desc", "desc"),
        )
        assert ids == ("T1",)
        assert names == ("name",)
        assert descs == ("desc",)

    def test_sorts_by_id(self):
        ids, names, descs = _canonicalize_techniques(
            ("B", "A"),
            ("name-b", "name-a"),
            ("desc-b", "desc-a"),
        )
        assert ids == ("A", "B")
        assert names == ("name-a", "name-b")
        assert descs == ("desc-a", "desc-b")


# ---------------------------------------------------------------------------
# I. Multiple techniques removed by different rules retain decisions
# ---------------------------------------------------------------------------


class TestRemovalDecisionProvenance:
    """Every removed technique must carry its own rule and reason in
    removal_decisions, not just removed_rules[0]."""

    def test_multiple_rules_retain_individual_decisions(self):
        """A candidate with T1+T2+T3 where T2 is removed by one rule and
        T3 by another must have two removal_decisions with distinct rules."""
        # Build a candidate with 3 techniques that will trigger 2
        # different rule rejections. We use apply_rule_based_filter
        # with a profile where T2 and T3 get rejected for different
        # reasons.

        profile = _make_profile()
        ep = "user prompts (input)"
        ep_id = compute_entry_point_id(ep, "input", None)

        candidate = CandidateTriple(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Threat T7",
            attack_pattern_name="Pattern",
            attack_pattern_description="Description",
            entry_point=ep,
            atlas_technique_ids=("AML.T0051", "AML.T0052", "AML.T0053"),
            atlas_technique_names=("T1 name", "T2 name", "T3 name"),
            atlas_technique_descriptions=("T1 desc", "T2 desc", "T3 desc"),
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            direction="input",
            entry_point_id=ep_id,
            candidate_id=compute_candidate_id(
                "AP-T7-01", ep_id, ("AML.T0051", "AML.T0052", "AML.T0053")
            ),
            origins=(),
        )

        # Mock _run_rules_on_technique to reject T2 and T3 with
        # different rules.
        def mock_rules(tid, entry_point, ep_type, prof):
            if tid == "AML.T0052":
                return True, "T2 is indirect for this EP", "_rule_direct_vs_indirect"
            if tid == "AML.T0053":
                return True, "T3 requires tool execution", "_rule_tool_execution_only"
            return False, "", ""

        with patch(
            "scenario_forge.pipeline.candidates._run_rules_on_technique",
            side_effect=mock_rules,
        ):
            rule_passed, rule_rejected, verdicts = apply_rule_based_filter(
                [candidate], profile
            )

        assert len(rule_passed) == 1
        merged = rule_passed[0]

        # Find the rule_pruning origin.
        pruning_origin = next(
            o for o in merged.origins if o.transform_stage == "rule_pruning"
        )
        assert len(pruning_origin.removal_decisions) == 2
        decisions_by_tid = {d.technique_id: d for d in pruning_origin.removal_decisions}

        assert "AML.T0052" in decisions_by_tid
        assert decisions_by_tid["AML.T0052"].rule == "_rule_direct_vs_indirect"
        assert "AML.T0053" in decisions_by_tid
        assert decisions_by_tid["AML.T0053"].rule == "_rule_tool_execution_only"
        # Verify reasons are distinct.
        assert (
            decisions_by_tid["AML.T0052"].reason != decisions_by_tid["AML.T0053"].reason
        )


# ---------------------------------------------------------------------------
# J. Invalid identity inputs rejected
# ---------------------------------------------------------------------------


class TestInvalidIdentityInputs:
    """compute_scenario_id must reject invalid run_id, candidate_id, attempt."""

    def test_invalid_run_id_too_short(self):
        with pytest.raises(ValueError, match="run_id"):
            compute_scenario_id("short", _VALID_CANDIDATE_ID, 1)

    def test_invalid_run_id_non_hex(self):
        with pytest.raises(ValueError, match="run_id"):
            compute_scenario_id("z" * 32, _VALID_CANDIDATE_ID, 1)

    def test_invalid_candidate_id_no_prefix(self):
        with pytest.raises(ValueError, match="candidate_id"):
            compute_scenario_id(_VALID_RUN_ID, "invalid", 1)

    def test_invalid_candidate_id_short_hex(self):
        with pytest.raises(ValueError, match="candidate_id"):
            compute_scenario_id(_VALID_RUN_ID, "cand:v1:short", 1)

    def test_attempt_zero_rejected(self):
        with pytest.raises(ValueError, match="attempt"):
            compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 0)

    def test_attempt_negative_rejected(self):
        with pytest.raises(ValueError, match="attempt"):
            compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, -1)

    def test_valid_inputs_produce_scenario_id(self):
        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        assert sid.startswith("scenario:v2:")
        # 256-bit hex = 64 chars after prefix.
        hex_part = sid.split(":")[-1]
        assert len(hex_part) == 64

    def test_validate_run_id_directly(self):
        _validate_run_id(_VALID_RUN_ID)  # no exception
        with pytest.raises(ValueError):
            _validate_run_id("")

    def test_validate_candidate_id_directly(self):
        _validate_candidate_id(_VALID_CANDIDATE_ID)  # no exception
        with pytest.raises(ValueError):
            _validate_candidate_id("")


# ---------------------------------------------------------------------------
# K. Remediation candidate ID matches pinned canonical technique tuple
# ---------------------------------------------------------------------------


class TestRemediationCandidateId:
    """The remediation candidate_id must be computed from the actual
    pinned canonical technique tuple, not an empty set."""

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_candidate_id_matches_pinned_techniques(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        captured_candidate_id = []

        def capture(*args, **kwargs):
            captured_candidate_id.append(kwargs.get("candidate_id"))
            env = _make_envelope(
                scenario_id="scenario:v2:rem-cand-id",
                candidate_id=kwargs.get("candidate_id", _VALID_CANDIDATE_ID),
            )
            return env, []

        mock_generate.side_effect = capture
        mock_write.return_value = (tmp_path / "test.yaml", None)

        ep_name = "user prompts (zone 1)"
        ep_id = "ep-1-id"
        seed = _make_seed(seed_id="AP-T1-01", technique_ids=("AML.T0051", "AML.T0052"))

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id=ep_id, name=ep_name),
            ]
        )
        profile = _make_profile()

        _remediate_coverage_gaps(
            gaps,
            [seed],
            profile,
            MagicMock(),
            "test use case",
            tmp_path,
            run_id=_VALID_RUN_ID,
            attempted_candidate_ids=set(),
            admitted_candidate_ids=set(),
            admitted_scenario_ids=set(),
            write_receipts=[],
        )

        expected = compute_candidate_id(seed.seed_id, ep_id, seed.atlas_technique_ids)
        assert captured_candidate_id[0] == expected


# ---------------------------------------------------------------------------
# L. Reversed equivalent inputs serialize identically
# ---------------------------------------------------------------------------


class TestReversedEquivalentInputs:
    """Reversed technique order in candidates must produce identical
    canonical output including aligned IDs/names/descriptions."""

    def test_reversed_techniques_same_canonical(self):
        ep = "user prompts (input)"
        c_forward = _make_candidate(
            entry_point=ep,
            technique_ids=("AML.T0051", "AML.T0052"),
        )
        c_reverse = _make_candidate(
            entry_point=ep,
            technique_ids=("AML.T0052", "AML.T0051"),
        )

        # Override names/descriptions to be reversed too.
        c_reverse = CandidateTriple.model_validate(
            c_reverse.model_dump(mode="python")
            | {
                "atlas_technique_names": ("Technique AML.T0052", "Technique AML.T0051"),
                "atlas_technique_descriptions": (
                    "Desc AML.T0052",
                    "Desc AML.T0051",
                ),
            }
        )

        result_f = canonicalize_and_dedup([c_forward], "expansion")
        result_r = canonicalize_and_dedup([c_reverse], "expansion")

        assert result_f[0].candidate_id == result_r[0].candidate_id
        assert result_f[0].atlas_technique_ids == result_r[0].atlas_technique_ids
        assert result_f[0].atlas_technique_names == result_r[0].atlas_technique_names
        assert (
            result_f[0].atlas_technique_descriptions
            == result_r[0].atlas_technique_descriptions
        )
        # Both sorted by ID.
        assert result_f[0].atlas_technique_ids == ("AML.T0051", "AML.T0052")
