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

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.manifest import AttemptRecord
from scenario_forge.models.attack_tree import (
    AiSystemAction,
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
    ActorAccessProvenance,
    ActorProfile,
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
    RemovalDecision,
    _canonicalize_techniques,
    apply_rule_based_filter,
    canonicalize_and_dedup,
    compute_candidate_id,
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

_VALID_RUN_ID = "20260101T000000_" + "a" * 32
_VALID_LEGACY_RUN_ID = "a" * 32
_VALID_CANDIDATE_ID = "cand:v1:" + "1" * 32

# Canonical entry_point_id for "user prompts (zone 1)" — the first entry
# point in ``_make_profile()``.  Remediation now resolves entry_point_id
# against the profile (cmps.9 correction 2), so tests must use the real
# computed ID rather than a synthetic placeholder.
_USER_PROMPT_EP_ID = compute_entry_point_id(
    "user prompts (zone 1)", "bidirectional", None
)
_ADMIN_CONSOLE_EP_ID = compute_entry_point_id(
    "admin console (zone 2)", "bidirectional", None
)


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
    scenario_id: str = "scenario:v2:8986bff34d530423761ccda45590e6f5c577814b6d647fd4a8001da76dd789b6",
    behavior_spec: str | None = None,
    candidate_id: str = _VALID_CANDIDATE_ID,
    entry_point_id: str = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
                action=AiSystemAction(),
            ),
            AttackTreeNode(
                id="n1.2",
                label="Path B",
                gate=GateType.LEAF,
                zone="reasoning",
                action=AiSystemAction(),
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
        initial_entry_point_id=entry_point_id,
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        actor_profile=ActorProfile(
            actor_type="adversarial-user",
            capability_level="intermediate",
            beliefs=["The system exposes a chat API"],
            desires=["Exfiltrate sensitive data"],
            intentions=["Exploit the chat interface"],
            resources=["open-source tools"],
            access=ActorAccessProvenance(
                initial_entry_point_id=entry_point_id,
                ingress_mode="direct",
                access_class="public",
            ),
        ),
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
            scenario_id="scenario:v2:1503279b4d55cb662f6bab433d9a79ff2da62bfae1e1f0bf4d87ec7d93ea2a54",
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

        with (
            patch.object(Path, "open", failing_open),
            pytest.raises(OSError, match="Injected failure"),
        ):
            write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        assert not yaml_path.exists(), "YAML must be cleaned up on feature failure"
        assert not feature_path.exists(), "Feature must not exist"

    def test_preexisting_pair_is_fatal_and_untouched(self, tmp_path: Path):
        """Pre-existing YAML or feature files must cause a fatal
        integrity error, and the pre-existing files must not be modified."""
        envelope = _make_envelope(
            scenario_id="scenario:v2:e52d5e8b4a98bf58090d37f04acbb0c9205c8e620edcbe166f1f963714598a54",
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
            scenario_id="scenario:v2:4a48656c5659c37d888a5d8d3ca6837bbbd714cf1aec963140e9e887f6ca94ca",
            behavior_spec=None,
        )
        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        yaml_path.write_text("original: data\n")

        with pytest.raises(ScenarioForgeIntegrityError):
            write_scenario_outputs(envelope, tmp_path)

    def test_missing_pair_during_guarded_replace_is_fatal(self, tmp_path: Path):
        """replace_scenario_outputs must raise fatal if YAML doesn't exist."""
        envelope = _make_envelope(
            scenario_id="scenario:v2:b8a8b7504ed8e2747f6d862b09f17e3f2d8dc6159a4fac68ef5144138faadd52"
        )
        with pytest.raises(ScenarioForgeIntegrityError, match="non-existent"):
            replace_scenario_outputs(
                envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
            )

    def test_guarded_replace_verifies_feature_bytes_unchanged(self, tmp_path: Path):
        """Guarded replacement must verify feature bytes match and only
        update YAML atomically."""
        feature_text = "Feature: test\n  Scenario: test\n"
        envelope = _make_envelope(
            scenario_id="scenario:v2:df5fe11e7673ab91f40604a8ced378a81198529cbe47faaec5585dba6388f1c7",
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
            scenario_id="scenario:v2:90b80a06586b377bafcaa855b16a683e07eff90975cd619e552f40e8aa7c20a0",
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
        envelope = _make_envelope(
            scenario_id="scenario:v2:4f90886b993007fa48cf5f3179dfbf46c7cce1607257e062a30dedf22f79bb82"
        )
        with pytest.raises(ScenarioForgeIntegrityError, match="Scenario ID mismatch"):
            replace_scenario_outputs(
                envelope,
                tmp_path,
                admitted_scenario_id="scenario:v2:6107c461fdc6d596b458079e622e8af9baf5b86f45bd9a67cff4b44470b5a7c6",
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
            cid = kwargs.get("candidate_id", _VALID_CANDIDATE_ID)
            sid = compute_scenario_id(kwargs.get("run_id", _VALID_RUN_ID), cid, 1)
            env = _make_envelope(
                scenario_id=sid,
                candidate_id=cid,
                entry_point_id=kwargs.get("pinned_entry_point_id", _USER_PROMPT_EP_ID),
            )
            return env, []

        mock_generate.side_effect = capture_candidate_id
        mock_write.return_value = (tmp_path / "test.yaml", None)

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(
                    entry_point_id=_USER_PROMPT_EP_ID, name="user prompts (zone 1)"
                ),
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
            attempts=[],
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
        # Compute the actual candidate_id that remediation will use.
        seed = _make_seed(seed_id="AP-T1-01")
        ep_id = _USER_PROMPT_EP_ID
        pinned_tids = seed.atlas_technique_ids or seed.laaf_technique_ids or []
        cand_id = compute_candidate_id(seed.seed_id, ep_id, pinned_tids)
        sid = compute_scenario_id(_VALID_RUN_ID, cand_id, 1)
        env = _make_envelope(
            scenario_id=sid,
            candidate_id=cand_id,
            entry_point_id=ep_id,
        )
        mock_generate.return_value = (env, [])
        mock_write.return_value = (tmp_path / "test.yaml", None)
        mock_write_log.side_effect = OSError("disk full")

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(
                    entry_point_id=_USER_PROMPT_EP_ID, name="user prompts (zone 1)"
                ),
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
                attempts=[],
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
        # Use a side_effect that derives IDs from the kwargs so the
        # pre-write identity verification passes.  Second call raises.
        call_count = [0]

        def gen(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                raise RuntimeError("LLM timeout")
            cid = kwargs["candidate_id"]
            sid = compute_scenario_id(_VALID_RUN_ID, cid, 1)
            return (
                _make_envelope(
                    scenario_id=sid,
                    candidate_id=cid,
                    entry_point_id=kwargs.get(
                        "pinned_entry_point_id", _USER_PROMPT_EP_ID
                    ),
                ),
                [],
            )

        mock_generate.side_effect = gen
        mock_write.return_value = (tmp_path / "test.yaml", None)

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(
                    entry_point_id=_USER_PROMPT_EP_ID, name="user prompts (zone 1)"
                ),
                EntryPointGap(
                    entry_point_id=_ADMIN_CONSOLE_EP_ID, name="admin console (zone 2)"
                ),
            ]
        )
        seeds = [_make_seed(seed_id="AP-T1-01"), _make_seed(seed_id="AP-T2-01")]
        profile = _make_profile()
        receipts: list[dict] = []
        attempts_list: list[AttemptRecord] = []

        scenarios, _notes, attempted, failed = _remediate_coverage_gaps(
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
            attempts=attempts_list,
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
        return {
            "expanded_instances": 10,
            "unique_pre_rule_identities": 8,
            "rule_rejected": 2,
            "rule_transformed": 1,
            "post_rule_collapsed": 1,
            "filter_submitted": 5,
            "filter_accepted": 3,
            "selected": 3,
            "main_attempted": 3,
            "main_admitted": 2,
            "generation_failed": 1,
            "remediation_attempted": 0,
            "remediation_admitted": 0,
            "remediation_failed": 0,
            "attempted": 3,
            "admitted": 2,
            "quarantined": 1,
            "persisted_artifacts": 2,
        }

    def test_valid_funnel_accepted(self):
        f = CandidateFunnel(**self._valid_funnel_kwargs())
        assert f.admitted == 2

    def test_rejects_negative(self):
        kw = self._valid_funnel_kwargs()
        kw["admitted"] = -1
        with pytest.raises(ValueError, match="nonnegative"):
            CandidateFunnel(**kw)

    def test_rejects_main_attempted_ne_selected(self):
        kw = self._valid_funnel_kwargs()
        kw["main_attempted"] = 99
        kw["attempted"] = 99
        with pytest.raises(ValueError, match="main_attempted.*selected"):
            CandidateFunnel(**kw)

    def test_rejects_main_attempted_ne_admitted_plus_failed(self):
        kw = self._valid_funnel_kwargs()
        kw["generation_failed"] = 99
        with pytest.raises(
            ValueError, match="main_attempted.*main_admitted.*generation_failed"
        ):
            CandidateFunnel(**kw)

    def test_rejects_aggregate_attempted_mismatch(self):
        kw = self._valid_funnel_kwargs()
        kw["attempted"] = 99
        with pytest.raises(
            ValueError, match="attempted.*main_attempted.*remediation_attempted"
        ):
            CandidateFunnel(**kw)

    def test_rejects_aggregate_admitted_mismatch(self):
        kw = self._valid_funnel_kwargs()
        kw["admitted"] = 99
        kw["persisted_artifacts"] = 99
        with pytest.raises(
            ValueError, match="admitted.*main_admitted.*remediation_admitted"
        ):
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

    def test_rejects_filter_accepted_gt_submitted(self):
        kw = self._valid_funnel_kwargs()
        kw["filter_accepted"] = 99
        with pytest.raises(ValueError, match="filter_accepted.*filter_submitted"):
            CandidateFunnel(**kw)

    def test_rejects_selected_gt_filter_accepted(self):
        kw = self._valid_funnel_kwargs()
        kw["selected"] = 10
        kw["main_attempted"] = 10
        kw["attempted"] = 10
        with pytest.raises(ValueError, match="selected.*filter_accepted"):
            CandidateFunnel(**kw)

    def test_rejects_quarantined_gt_admitted(self):
        kw = self._valid_funnel_kwargs()
        kw["quarantined"] = 99
        with pytest.raises(ValueError, match="quarantined.*admitted"):
            CandidateFunnel(**kw)

    def test_rejects_remediation_attempted_ne_admitted_plus_failed(self):
        kw = self._valid_funnel_kwargs()
        kw["remediation_attempted"] = 5
        kw["attempted"] = 8
        with pytest.raises(
            ValueError,
            match="remediation_attempted.*remediation_admitted.*remediation_failed",
        ):
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
            rule_passed, _rule_rejected, _verdicts = apply_rule_based_filter(
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
            cid = kwargs.get("candidate_id", _VALID_CANDIDATE_ID)
            sid = compute_scenario_id(_VALID_RUN_ID, cid, 1)
            env = _make_envelope(
                scenario_id=sid,
                candidate_id=cid,
                entry_point_id=kwargs.get("pinned_entry_point_id", _USER_PROMPT_EP_ID),
            )
            return env, []

        mock_generate.side_effect = capture
        mock_write.return_value = (tmp_path / "test.yaml", None)

        ep_name = "user prompts (zone 1)"
        ep_id = _USER_PROMPT_EP_ID
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
            attempts=[],
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


# ---------------------------------------------------------------------------#
# M. Second-review: paired-write failure injection after file creation
# ---------------------------------------------------------------------------#


class TestWriteFailureAfterCreation:
    """write() must fail after file creation, not only open before creation."""

    def test_yaml_write_fails_after_open_cleans_up(self, tmp_path: Path):
        """If yaml.write() fails after exclusive open, the YAML file
        created by this call must be cleaned up."""
        envelope = _make_envelope(
            behavior_spec=None,
        )
        original_write = Path.write_text

        def failing_write(self_path, *args, **kwargs):
            if self_path.suffix == ".yaml":
                raise OSError("Injected write failure on YAML")
            return original_write(self_path, *args, **kwargs)

        with patch.object(Path, "write_text", failing_write):
            # write_text is not used directly; the code uses fh.write().
            # So we patch the file handle's write method instead.
            pass

        # Actually, write_scenario_outputs uses fh.write(), not
        # Path.write_text().  We need to patch at the file-handle level.
        original_open = Path.open

        def open_with_failing_yaml_write(self_path, *args, **kwargs):
            fh = original_open(self_path, *args, **kwargs)
            if self_path.suffix == ".yaml" and args[0] == "x":

                def failing_fh_write(data):
                    raise OSError("Injected write failure on YAML handle")

                fh.write = failing_fh_write
            return fh

        with (
            patch.object(Path, "open", open_with_failing_yaml_write),
            pytest.raises(OSError, match="Injected write failure"),
        ):
            write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        assert not yaml_path.exists(), "YAML must be cleaned up on write failure"

    def test_feature_write_fails_after_both_open_cleans_up_both(self, tmp_path: Path):
        """If feature write() fails after both files are opened, both
        current-call files must be cleaned up."""
        envelope = _make_envelope(
            behavior_spec="Feature: test\n  Scenario: test\n",
        )
        original_open = Path.open
        call_count = [0]

        def open_with_failing_feature_write(self_path, *args, **kwargs):
            call_count[0] += 1
            fh = original_open(self_path, *args, **kwargs)
            if self_path.suffix == ".feature" and args[0] == "x":

                def failing_fh_write(data):
                    raise OSError("Injected write failure on feature handle")

                fh.write = failing_fh_write
            return fh

        with (
            patch.object(Path, "open", open_with_failing_feature_write),
            pytest.raises(OSError, match="Injected write failure"),
        ):
            write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        assert not yaml_path.exists(), "YAML must be cleaned up"
        assert not feature_path.exists(), "Feature must not exist"


# ---------------------------------------------------------------------------#
# N. Second-review: race-time FileExistsError conversion
# ---------------------------------------------------------------------------#


class TestRaceTimeFileExistsConversion:
    """Race-time FileExistsError from open('x') must become
    ScenarioForgeIntegrityError, not a recoverable error."""

    def test_yaml_race_file_exists_is_fatal(self, tmp_path: Path):
        envelope = _make_envelope()
        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        yaml_path.write_text("pre-existing\n")

        with pytest.raises(ScenarioForgeIntegrityError, match="already exists"):
            write_scenario_outputs(envelope, tmp_path)

    def test_feature_race_file_exists_is_fatal(self, tmp_path: Path):
        envelope = _make_envelope(behavior_spec="Feature: test\n")
        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        # Pre-create only the feature file to trigger FileExistsError
        # on the second open('x') call.
        feature_path.write_text("pre-existing feature\n")

        with pytest.raises(ScenarioForgeIntegrityError, match="already exists"):
            write_scenario_outputs(envelope, tmp_path)


# ---------------------------------------------------------------------------#
# O. Second-review: cleanup unlink failure is fatal
# ---------------------------------------------------------------------------#


class TestCleanupFailureFatal:
    """If cleanup of a current-call file fails, raise fatal integrity."""

    def test_cleanup_unlink_failure_is_fatal(self, tmp_path: Path):
        envelope = _make_envelope(behavior_spec="Feature: test\n")
        original_open = Path.open

        call_count = [0]

        def open_with_failing_feature_write(self_path, *args, **kwargs):
            call_count[0] += 1
            fh = original_open(self_path, *args, **kwargs)
            if self_path.suffix == ".feature" and args[0] == "x":

                def failing_fh_write(data):
                    raise OSError("Injected write failure on feature handle")

                fh.write = failing_fh_write
            return fh

        # Patch unlink to fail for the YAML file (cleanup will try
        # to remove the YAML that was successfully created).
        original_unlink = Path.unlink

        def failing_unlink(self_path, *args, **kwargs):
            if self_path.suffix == ".yaml":
                raise OSError("Injected unlink failure")
            return original_unlink(self_path, *args, **kwargs)

        with (
            patch.object(Path, "open", open_with_failing_feature_write),
            patch.object(Path, "unlink", failing_unlink),
            pytest.raises(ScenarioForgeIntegrityError, match="Failed to clean up"),
        ):
            write_scenario_outputs(envelope, tmp_path)


# ---------------------------------------------------------------------------#
# P. Second-review: scenario_id Pydantic and JSON-schema validation
# ---------------------------------------------------------------------------#


class TestScenarioIdValidation:
    """scenario_id must be validated at Pydantic and JSON-schema boundaries."""

    def test_invalid_scenario_id_pydantic_no_prefix(self):
        with pytest.raises(ValueError, match="scenario_id must follow"):
            ScenarioEnvelope.model_validate(
                {
                    **_make_envelope().model_dump(mode="json"),
                    "scenario_id": "invalid-id",
                }
            )

    def test_invalid_scenario_id_pydantic_short_hex(self):
        with pytest.raises(ValueError, match="64 chars"):
            ScenarioEnvelope.model_validate(
                {
                    **_make_envelope().model_dump(mode="json"),
                    "scenario_id": "scenario:v2:abc123",
                }
            )

    def test_invalid_scenario_id_pydantic_non_hex(self):
        with pytest.raises(ValueError, match="valid hex"):
            ScenarioEnvelope.model_validate(
                {
                    **_make_envelope().model_dump(mode="json"),
                    "scenario_id": "scenario:v2:" + "g" * 64,
                }
            )

    def test_valid_scenario_id_accepted(self):
        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        env = _make_envelope(scenario_id=sid)
        assert env.scenario_id == sid

    def test_invalid_scenario_id_json_schema(self):
        import json

        import jsonschema

        schema_path = (
            Path(__file__).parent.parent
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text())

        env = _make_envelope()
        env_dict = env.model_dump(mode="json")
        env_dict["scenario_id"] = "scenario:v2:short"

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(env_dict, schema)

    def test_valid_scenario_id_json_schema(self):
        import json

        import jsonschema

        schema_path = (
            Path(__file__).parent.parent
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text())

        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        env = _make_envelope(scenario_id=sid)
        env_dict = env.model_dump(mode="json")

        # Should not raise.
        jsonschema.validate(env_dict, schema)


# ---------------------------------------------------------------------------#
# Q. Second-review: remediation LAAF fallback pins LAAF tuple
# ---------------------------------------------------------------------------#


class TestRemediationLaafFallback:
    """Remediation must use ATLAS techniques, otherwise LAAF techniques,
    and pin exactly that tuple in the candidate_id."""

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_laaf_fallback_when_no_atlas(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        """When seed has no ATLAS techniques but has LAAF techniques,
        the candidate_id must be computed from LAAF techniques."""
        captured_candidate_id = []

        def capture(*args, **kwargs):
            captured_candidate_id.append(kwargs.get("candidate_id"))
            cid = kwargs.get("candidate_id", _VALID_CANDIDATE_ID)
            sid = compute_scenario_id(_VALID_RUN_ID, cid, 1)
            env = _make_envelope(
                scenario_id=sid,
                candidate_id=cid,
                entry_point_id=kwargs.get("pinned_entry_point_id", _USER_PROMPT_EP_ID),
            )
            return env, []

        mock_generate.side_effect = capture
        mock_write.return_value = (tmp_path / "test.yaml", None)

        # Seed with no ATLAS but LAAF techniques.
        seed = _make_seed(seed_id="AP-T3-01", technique_ids=())
        seed.laaf_technique_ids = ["LAAF.T001", "LAAF.T002"]
        seed.atlas_technique_ids = []

        ep_name = "user prompts (zone 1)"
        ep_id = _USER_PROMPT_EP_ID
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
            attempts=[],
        )

        expected = compute_candidate_id(seed.seed_id, ep_id, seed.laaf_technique_ids)
        assert captured_candidate_id[0] == expected


# ---------------------------------------------------------------------------#
# R. Second-review: forged returned identity fatal before write
# ---------------------------------------------------------------------------#


class TestForgedReturnIdentity:
    """Returned envelope with wrong candidate_id or scenario_id must
    abort the run before writing."""

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_remediation_forged_candidate_id_fatal(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        """Remediation returned envelope with wrong candidate_id must
        raise ScenarioForgeIntegrityError, not write."""
        seed = _make_seed(seed_id="AP-T1-01", technique_ids=("AML.T0051",))
        ep_id = _USER_PROMPT_EP_ID
        pinned_tids = seed.atlas_technique_ids or seed.laaf_technique_ids or []
        correct_cid = compute_candidate_id(seed.seed_id, ep_id, pinned_tids)
        wrong_cid = "cand:v1:22222222222222222222222222222222"
        correct_sid = compute_scenario_id(_VALID_RUN_ID, correct_cid, 1)

        mock_generate.return_value = (
            _make_envelope(scenario_id=correct_sid, candidate_id=wrong_cid),
            [],
        )
        mock_write.return_value = (tmp_path / "test.yaml", None)

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id=ep_id, name="user prompts (zone 1)"),
            ]
        )
        with pytest.raises(
            ScenarioForgeIntegrityError, match="candidate_id.*does not match"
        ):
            _remediate_coverage_gaps(
                gaps,
                [seed],
                _make_profile(),
                MagicMock(),
                "test use case",
                tmp_path,
                run_id=_VALID_RUN_ID,
                attempted_candidate_ids=set(),
                admitted_candidate_ids=set(),
                admitted_scenario_ids=set(),
                write_receipts=[],
                attempts=[],
            )
        mock_write.assert_not_called()

    @patch("scenario_forge.pipeline.runner.write_call_log")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    @patch("scenario_forge.pipeline.runner.generate_scenario")
    def test_remediation_forged_scenario_id_fatal(
        self, mock_generate, mock_write, mock_write_log, tmp_path: Path
    ):
        """Remediation returned envelope with wrong scenario_id must
        raise ScenarioForgeIntegrityError, not write."""
        seed = _make_seed(seed_id="AP-T1-01", technique_ids=("AML.T0051",))
        ep_id = _USER_PROMPT_EP_ID
        pinned_tids = seed.atlas_technique_ids or seed.laaf_technique_ids or []
        correct_cid = compute_candidate_id(seed.seed_id, ep_id, pinned_tids)
        wrong_sid = "scenario:v2:" + "f" * 64

        mock_generate.return_value = (
            _make_envelope(scenario_id=wrong_sid, candidate_id=correct_cid),
            [],
        )
        mock_write.return_value = (tmp_path / "test.yaml", None)

        gaps = CoverageGaps(
            uncovered_entry_points=[
                EntryPointGap(entry_point_id=ep_id, name="user prompts (zone 1)"),
            ]
        )
        with pytest.raises(
            ScenarioForgeIntegrityError, match="scenario_id.*does not match"
        ):
            _remediate_coverage_gaps(
                gaps,
                [seed],
                _make_profile(),
                MagicMock(),
                "test use case",
                tmp_path,
                run_id=_VALID_RUN_ID,
                attempted_candidate_ids=set(),
                admitted_candidate_ids=set(),
                admitted_scenario_ids=set(),
                write_receipts=[],
                attempts=[],
            )
        mock_write.assert_not_called()


# ---------------------------------------------------------------------------#
# S. Second-review: reversed origins serialize byte-identically
# ---------------------------------------------------------------------------#


class TestReversedOriginsByteIdentical:
    """Reversed equivalent inputs must produce byte/equality-identical
    serialized origins, not just matching sort keys."""

    def test_reversed_origins_serialize_identically(self):
        """Two candidates with reversed technique order that converge
        must produce identical serialized origin objects."""
        import json

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

        # Serialized origins must be identical.
        origins_f = json.dumps(
            [o.model_dump(mode="json") for o in result_f[0].origins],
            sort_keys=True,
        )
        origins_r = json.dumps(
            [o.model_dump(mode="json") for o in result_r[0].origins],
            sort_keys=True,
        )
        assert origins_f == origins_r, (
            "Serialized origins must be byte-identical regardless of input order"
        )


# ---------------------------------------------------------------------------#
# T. Second-review: cross-candidate technique metadata conflict
# ---------------------------------------------------------------------------#


class TestCrossCandidateMetadataConflict:
    """Converged candidates with same technique IDs but different
    names/descriptions must be rejected."""

    def test_conflicting_name_across_converged_candidates(self):
        """Two candidates with same technique IDs but different names
        must raise ValueError before template selection."""
        ep = "user prompts (input)"
        ep_id = compute_entry_point_id(ep, "input", None)
        common_kwargs = {
            "seed_id": "AP-T7-01",
            "threat_id": "T7",
            "threat_name": "Threat T7",
            "attack_pattern_name": "Pattern",
            "attack_pattern_description": "Description",
            "entry_point": ep,
            "atlas_technique_ids": ("AML.T0051", "AML.T0052"),
            "risk_card_ref": _make_ref(),
            "owasp_llm_ids": ["LLM01"],
            "direction": "input",
            "entry_point_id": ep_id,
            "origins": (),
        }
        c1 = CandidateTriple(
            atlas_technique_names=("Name A", "Name B"),
            atlas_technique_descriptions=("Desc A", "Desc B"),
            candidate_id=compute_candidate_id(
                "AP-T7-01", ep_id, ("AML.T0051", "AML.T0052")
            ),
            **common_kwargs,
        )
        c2 = CandidateTriple(
            atlas_technique_names=("Name A DIFFERENT", "Name B"),
            atlas_technique_descriptions=("Desc A", "Desc B"),
            candidate_id=compute_candidate_id(
                "AP-T7-01", ep_id, ("AML.T0051", "AML.T0052")
            ),
            **common_kwargs,
        )

        with pytest.raises(ValueError, match="Conflicting.*metadata"):
            canonicalize_and_dedup([c1, c2], "expansion")

    def test_conflicting_description_across_converged_candidates(self):
        """Two candidates with same technique IDs but different
        descriptions must raise ValueError."""
        ep = "user prompts (input)"
        ep_id = compute_entry_point_id(ep, "input", None)
        common_kwargs = {
            "seed_id": "AP-T7-01",
            "threat_id": "T7",
            "threat_name": "Threat T7",
            "attack_pattern_name": "Pattern",
            "attack_pattern_description": "Description",
            "entry_point": ep,
            "atlas_technique_ids": ("AML.T0051", "AML.T0052"),
            "risk_card_ref": _make_ref(),
            "owasp_llm_ids": ["LLM01"],
            "direction": "input",
            "entry_point_id": ep_id,
            "origins": (),
        }
        c1 = CandidateTriple(
            atlas_technique_names=("Name A", "Name B"),
            atlas_technique_descriptions=("Desc A", "Desc B"),
            candidate_id=compute_candidate_id(
                "AP-T7-01", ep_id, ("AML.T0051", "AML.T0052")
            ),
            **common_kwargs,
        )
        c2 = CandidateTriple(
            atlas_technique_names=("Name A", "Name B"),
            atlas_technique_descriptions=("Desc A DIFFERENT", "Desc B"),
            candidate_id=compute_candidate_id(
                "AP-T7-01", ep_id, ("AML.T0051", "AML.T0052")
            ),
            **common_kwargs,
        )

        with pytest.raises(ValueError, match="Conflicting.*metadata"):
            canonicalize_and_dedup([c1, c2], "expansion")


# ---------------------------------------------------------------------------#
# U. Second-review: fully rejected combos persist all decisions
# ---------------------------------------------------------------------------#


class TestFullyRejectedAllDecisions:
    """Fully rejected technique combinations must persist all
    per-technique rule/reason decisions in rule_verdicts."""

    def test_fully_rejected_multiple_rules_all_decisions_in_verdicts(self):
        """A candidate with T1+T2+T3 where all are rejected by different
        rules must have a RejectionRecord with 3 removal_decisions."""
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

        def mock_rules(tid, entry_point, ep_type, prof):
            if tid == "AML.T0051":
                return True, "T1 wrong zone", "_rule_zone_mismatch"
            if tid == "AML.T0052":
                return True, "T2 indirect", "_rule_direct_vs_indirect"
            if tid == "AML.T0053":
                return True, "T3 tool only", "_rule_tool_execution_only"
            return False, "", ""

        with patch(
            "scenario_forge.pipeline.candidates._run_rules_on_technique",
            side_effect=mock_rules,
        ):
            rule_passed, rule_rejected, verdicts = apply_rule_based_filter(
                [candidate], profile
            )

        assert len(rule_passed) == 0
        assert len(rule_rejected) == 1
        assert len(verdicts) == 1

        verdict = verdicts[0]
        assert len(verdict.removal_decisions) == 3
        decisions_by_tid = {d.technique_id: d for d in verdict.removal_decisions}
        assert decisions_by_tid["AML.T0051"].rule == "_rule_zone_mismatch"
        assert decisions_by_tid["AML.T0052"].rule == "_rule_direct_vs_indirect"
        assert decisions_by_tid["AML.T0053"].rule == "_rule_tool_execution_only"
        assert decisions_by_tid["AML.T0051"].reason == "T1 wrong zone"
        assert decisions_by_tid["AML.T0052"].reason == "T2 indirect"
        assert decisions_by_tid["AML.T0053"].reason == "T3 tool only"

        # Serialized verdict must contain all decisions.
        dumped = verdict.model_dump(mode="json")
        assert len(dumped["removal_decisions"]) == 3


# ---------------------------------------------------------------------------#
# V. Third-review: receipt/admission exactness and canonical paths
# ---------------------------------------------------------------------------#


class TestReceiptAdmissionExactness:
    """Receipts must exactly match admitted scenarios and canonical paths."""

    def test_forged_swapped_candidate_receipt_is_fatal(self, tmp_path: Path):
        """A receipt with a swapped candidate_id for an admitted scenario
        must be rejected — the (scenario_id, candidate_id) pair must
        belong to admitted_keys."""
        from scenario_forge.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError as SIE,
        )
        from scenario_forge.pipeline.runner import _reconcile_artifacts

        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        env = _make_envelope(scenario_id=sid, candidate_id=_VALID_CANDIDATE_ID)
        wrong_cid = "cand:v1:22222222222222222222222222222222"
        receipts = [
            {
                "scenario_id": sid,
                "candidate_id": wrong_cid,
                "yaml_path": str(tmp_path / f"{sid}.yaml"),
                "feature_path": None,
            }
        ]
        with pytest.raises(SIE, match="does not match any admitted"):
            _reconcile_artifacts(
                scenarios=[env],
                write_receipts=receipts,
                scenarios_dir=tmp_path,
            )

    def test_missing_admitted_receipt_is_fatal(self, tmp_path: Path):
        """An admitted scenario with no corresponding receipt must be
        rejected — seen_receipt_keys must equal admitted_keys."""
        from scenario_forge.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError as SIE,
        )
        from scenario_forge.pipeline.runner import _reconcile_artifacts

        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        env = _make_envelope(scenario_id=sid, candidate_id=_VALID_CANDIDATE_ID)
        # Empty receipts — no receipt for the admitted scenario.
        with pytest.raises(SIE, match="Receipt/admission mismatch.*missing"):
            _reconcile_artifacts(
                scenarios=[env],
                write_receipts=[],
                scenarios_dir=tmp_path,
            )

    def test_noncanonical_same_stem_path_is_fatal(self, tmp_path: Path):
        """A receipt whose yaml_path is in the wrong directory (even if
        the stem matches the scenario_id) must be rejected."""
        from scenario_forge.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError as SIE,
        )
        from scenario_forge.pipeline.runner import _reconcile_artifacts

        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        env = _make_envelope(scenario_id=sid, candidate_id=_VALID_CANDIDATE_ID)
        wrong_dir = tmp_path / "wrong_dir"
        wrong_dir.mkdir()
        yaml_path = wrong_dir / f"{sid}.yaml"
        yaml_path.write_text("dummy", encoding="utf-8")
        receipts = [
            {
                "scenario_id": sid,
                "candidate_id": _VALID_CANDIDATE_ID,
                "yaml_path": str(yaml_path),
                "feature_path": None,
            }
        ]
        with pytest.raises(SIE, match="does not match canonical path"):
            _reconcile_artifacts(
                scenarios=[env],
                write_receipts=receipts,
                scenarios_dir=tmp_path / "scenarios",
            )

    def test_noncanonical_suffix_is_fatal(self, tmp_path: Path):
        """A receipt whose yaml_path has a wrong suffix must be rejected."""
        from scenario_forge.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError as SIE,
        )
        from scenario_forge.pipeline.runner import _reconcile_artifacts

        sid = compute_scenario_id(_VALID_RUN_ID, _VALID_CANDIDATE_ID, 1)
        env = _make_envelope(scenario_id=sid, candidate_id=_VALID_CANDIDATE_ID)
        scenarios_dir = tmp_path / "scenarios"
        scenarios_dir.mkdir()
        wrong_path = scenarios_dir / f"{sid}.txt"
        wrong_path.write_text("dummy", encoding="utf-8")
        receipts = [
            {
                "scenario_id": sid,
                "candidate_id": _VALID_CANDIDATE_ID,
                "yaml_path": str(wrong_path),
                "feature_path": None,
            }
        ]
        with pytest.raises(SIE, match="does not match canonical path"):
            _reconcile_artifacts(
                scenarios=[env],
                write_receipts=receipts,
                scenarios_dir=scenarios_dir,
            )


# ---------------------------------------------------------------------------#
# W. Third-review: lowercase identity consistency
# ---------------------------------------------------------------------------#


class TestLowercaseIdentityConsistency:
    """run_id, candidate_id, and scenario_id must be lowercase hex.
    Pydantic and assembly validators must reject uppercase, matching
    the JSON Schema [0-9a-f] pattern."""

    # --- Assembly/generation validators ---

    def test_uppercase_run_id_rejected_by_assembly(self):
        from scenario_forge.pipeline.generate.assembly import _validate_run_id

        with pytest.raises(ValueError):
            _validate_run_id("A" * 32)

    def test_uppercase_candidate_id_rejected_by_assembly(self):
        from scenario_forge.pipeline.generate.assembly import _validate_candidate_id

        upper = "cand:v1:" + "A" * 32
        with pytest.raises(ValueError, match="lowercase"):
            _validate_candidate_id(upper)

    def test_uppercase_scenario_id_rejected_by_compute(self):
        with pytest.raises(ValueError, match="lowercase"):
            compute_scenario_id(
                _VALID_RUN_ID,
                "cand:v1:" + "A" * 32,
                1,
            )

    def test_lowercase_run_id_accepted_by_assembly(self):
        from scenario_forge.pipeline.generate.assembly import _validate_run_id

        _validate_run_id(_VALID_RUN_ID)  # no exception

    # --- Pydantic validators ---

    def test_uppercase_candidate_id_rejected_by_pydantic(self):
        with pytest.raises(ValueError, match="lowercase"):
            ScenarioEnvelope.model_validate(
                {
                    **_make_envelope().model_dump(mode="json"),
                    "candidate_id": "cand:v1:" + "A" * 32,
                }
            )

    def test_uppercase_scenario_id_rejected_by_pydantic(self):
        sid_upper = "scenario:v2:" + "A" * 64
        with pytest.raises(ValueError, match="lowercase"):
            ScenarioEnvelope.model_validate(
                {
                    **_make_envelope().model_dump(mode="json"),
                    "scenario_id": sid_upper,
                }
            )

    # --- JSON Schema boundary ---

    def test_uppercase_scenario_id_rejected_by_json_schema(self):
        import json

        import jsonschema

        schema_path = (
            Path(__file__).parent.parent
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text())

        env = _make_envelope()
        env_dict = env.model_dump(mode="json")
        env_dict["scenario_id"] = "scenario:v2:" + "A" * 64

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(env_dict, schema)

    def test_uppercase_candidate_id_rejected_by_json_schema(self):
        import json

        import jsonschema

        schema_path = (
            Path(__file__).parent.parent
            / "src"
            / "scenario_forge"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text())

        env = _make_envelope()
        env_dict = env.model_dump(mode="json")
        env_dict["candidate_id"] = "cand:v1:" + "A" * 32

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(env_dict, schema)


# ---------------------------------------------------------------------------#
# X. Third-review: canonicalize singleton origins
# ---------------------------------------------------------------------------#


class TestCanonicalizeSingletonOrigins:
    """Singleton candidates must also have canonicalized origins, and
    removal decisions must sort by full (technique_id, rule, reason)."""

    def test_singleton_reversed_origins_identical_serialized(self):
        """A singleton candidate with reversed original/removed technique
        IDs, aligned reasons, and reversed decisions must produce
        identical serialized origins after canonicalization."""
        # Build two identical candidates with origins in reversed order.
        origin_forward = CandidateOrigin(
            source_candidate_id="cand:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            original_technique_ids=("AML.T0051", "AML.T0052", "AML.T0053"),
            applied_rule="_rule_a",
            removed_technique_ids=("AML.T0052", "AML.T0053"),
            removal_reasons=("T2 reason", "T3 reason"),
            removal_decisions=(
                RemovalDecision(
                    technique_id="AML.T0052",
                    rule="_rule_a",
                    reason="T2 reason",
                ),
                RemovalDecision(
                    technique_id="AML.T0053",
                    rule="_rule_b",
                    reason="T3 reason",
                ),
            ),
            transform_stage="rule_pruning",
        )
        origin_reverse = CandidateOrigin(
            source_candidate_id="cand:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            original_technique_ids=("AML.T0053", "AML.T0052", "AML.T0051"),
            applied_rule="_rule_a",
            removed_technique_ids=("AML.T0053", "AML.T0052"),
            removal_reasons=("T3 reason", "T2 reason"),
            removal_decisions=(
                RemovalDecision(
                    technique_id="AML.T0053",
                    rule="_rule_b",
                    reason="T3 reason",
                ),
                RemovalDecision(
                    technique_id="AML.T0052",
                    rule="_rule_a",
                    reason="T2 reason",
                ),
            ),
            transform_stage="rule_pruning",
        )

        c_forward = _make_candidate(
            technique_ids=("AML.T0051",),
            origins=(origin_forward,),
        )
        c_reverse = _make_candidate(
            technique_ids=("AML.T0051",),
            origins=(origin_reverse,),
        )

        result_f = canonicalize_and_dedup([c_forward], "rule_pruning")
        result_r = canonicalize_and_dedup([c_reverse], "rule_pruning")

        # Serialized origins must be identical.
        import json

        origins_f = json.dumps(
            [o.model_dump(mode="json") for o in result_f[0].origins],
            sort_keys=True,
        )
        origins_r = json.dumps(
            [o.model_dump(mode="json") for o in result_r[0].origins],
            sort_keys=True,
        )
        assert origins_f == origins_r, (
            "Singleton origins must serialize identically regardless of "
            "input ordering after canonicalization"
        )

    def test_removal_decisions_sort_by_full_key(self):
        """Two decisions with the same technique_id but different rules
        must sort by (technique_id, rule, reason), not technique_id alone."""
        origin_a = CandidateOrigin(
            source_candidate_id="cand:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            original_technique_ids=("AML.T0051", "AML.T0052"),
            applied_rule="_rule_a",
            removed_technique_ids=("AML.T0051",),
            removal_reasons=("reason a",),
            removal_decisions=(
                RemovalDecision(
                    technique_id="AML.T0051",
                    rule="_rule_b",
                    reason="reason b",
                ),
                RemovalDecision(
                    technique_id="AML.T0051",
                    rule="_rule_a",
                    reason="reason a",
                ),
            ),
            transform_stage="rule_pruning",
        )
        origin_b = CandidateOrigin(
            source_candidate_id="cand:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            original_technique_ids=("AML.T0051", "AML.T0052"),
            applied_rule="_rule_a",
            removed_technique_ids=("AML.T0051",),
            removal_reasons=("reason a",),
            removal_decisions=(
                RemovalDecision(
                    technique_id="AML.T0051",
                    rule="_rule_a",
                    reason="reason a",
                ),
                RemovalDecision(
                    technique_id="AML.T0051",
                    rule="_rule_b",
                    reason="reason b",
                ),
            ),
            transform_stage="rule_pruning",
        )

        c_a = _make_candidate(
            technique_ids=("AML.T0052",),
            origins=(origin_a,),
        )
        c_b = _make_candidate(
            technique_ids=("AML.T0052",),
            origins=(origin_b,),
        )

        result_a = canonicalize_and_dedup([c_a], "rule_pruning")
        result_b = canonicalize_and_dedup([c_b], "rule_pruning")

        import json

        origins_a = json.dumps(
            [o.model_dump(mode="json") for o in result_a[0].origins],
            sort_keys=True,
        )
        origins_b = json.dumps(
            [o.model_dump(mode="json") for o in result_b[0].origins],
            sort_keys=True,
        )
        assert origins_a == origins_b, (
            "Removal decisions with same technique_id but different rules "
            "must sort by full (technique_id, rule, reason) key"
        )
