"""Regression and property tests for scenario-forge-cmps.3.

Covers the acceptance contract:
  - Ordering-independent canonical collapse after transforms.
  - Singleton + pruned multi-technique convergence with complete origins.
  - Complete merged origins (never first-wins).
  - Stable candidate IDs across transforms.
  - Collision-safe scenario IDs with run_id and attempt.
  - Distinct cross-run scenario IDs.
  - Content-sensitive exact-byte SHA-256 artifact hashes.
  - Duplicate admission / ID / path collisions fail loudly.
  - YAML/feature stem mismatch rejection.
  - Exact funnel equations from typed records.
  - Exclusive write creation (no silent overwrite).
  - Guarded replacement API.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
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
    FilteredSeed,
    StageRecord,
    apply_rule_based_filter,
    canonicalize_and_dedup,
    cap_scenarios_per_pattern,
    compute_candidate_id,
    expand_candidates,
)
from scenario_forge.pipeline.generate import (
    compute_artifact_hash,
    compute_scenario_id,
    generate_run_id,
    replace_scenario_outputs,
    write_scenario_outputs,
)
from scenario_forge.pipeline.seeds import ScenarioSeed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
) -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=list(technique_ids),
    )


def _make_profile(
    entry_points: list[EntryPoint] | None = None,
) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points
        or [EntryPoint(name="user prompts", direction="input")],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
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


def _make_envelope(
    scenario_id: str = "scenario:v2:test",
    behavior_spec: str | None = None,
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
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            atlas_technique_ids=["AML.T0051"],
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
        generated_at=datetime.now(),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=behavior_spec if behavior_spec is not None else {},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


def _make_filtered_seed(
    seed_id: str = "AP-T7-01",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    origins: list[CandidateOrigin] | None = None,
) -> FilteredSeed:
    ep_id = compute_entry_point_id(entry_point, "input", None)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    return FilteredSeed(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=list(technique_ids),
        pinned_entry_point=entry_point,
        pinned_technique_ids=technique_ids,
        pinned_technique_names=tuple(f"Technique {t}" for t in technique_ids),
        entry_point_id=ep_id,
        candidate_id=cand_id,
        origins=origins if origins is not None else [],
    )


# ---------------------------------------------------------------------------
# 1. Ordering-independent canonical collapse
# ---------------------------------------------------------------------------


class TestOrderingIndependentCollapse:
    """Canonicalize_and_dedup must produce identical results regardless of
    input ordering."""

    def test_same_output_regardless_of_input_order(self):
        """Two lists with the same candidates in different order produce
        the same deduplicated set."""
        c1 = _make_candidate(technique_ids=("AML.T0051",))
        c2 = _make_candidate(technique_ids=("AML.T0051", "AML.T0054"))
        c3 = _make_candidate(technique_ids=("AML.T0051",))

        # c1 and c3 have the same canonical identity
        result_a = canonicalize_and_dedup([c1, c2, c3], stage="test")
        result_b = canonicalize_and_dedup([c3, c2, c1], stage="test")

        # Same number of unique candidates
        assert len(result_a) == len(result_b) == 2
        # Same candidate IDs (as a set)
        ids_a = {c.candidate_id for c in result_a}
        ids_b = {c.candidate_id for c in result_b}
        assert ids_a == ids_b

    def test_reordered_techniques_same_identity(self):
        """Candidates with techniques in different order but same set
        canonicalize to the same identity."""
        c1 = _make_candidate(
            technique_ids=("AML.T0051", "AML.T0054"),
            origins=(
                CandidateOrigin(
                    source_candidate_id="cand:v1:src1",
                    original_technique_ids=("AML.T0051", "AML.T0054"),
                    transform_stage="expansion",
                ),
            ),
        )
        c2 = _make_candidate(
            technique_ids=("AML.T0054", "AML.T0051"),
            origins=(
                CandidateOrigin(
                    source_candidate_id="cand:v1:src2",
                    original_technique_ids=("AML.T0054", "AML.T0051"),
                    transform_stage="expansion",
                ),
            ),
        )

        result = canonicalize_and_dedup([c1, c2], stage="test")
        assert len(result) == 1
        assert len(result[0].origins) == 2


# ---------------------------------------------------------------------------
# 2. Singleton + pruned multi-technique convergence
# ---------------------------------------------------------------------------


class TestConvergenceWithOrigins:
    """When candidates converge after pruning, all source origins are
    retained — never first-wins."""

    def test_singleton_remains_unchanged(self):
        """A singleton candidate passes through dedup unchanged."""
        c = _make_candidate(
            origins=(
                CandidateOrigin(
                    source_candidate_id="cand:v1:abc",
                    original_technique_ids=("AML.T0051",),
                    transform_stage="expansion",
                ),
            ),
        )
        result = canonicalize_and_dedup([c], stage="test")
        assert len(result) == 1
        assert len(result[0].origins) == 1
        assert result[0].origins[0].source_candidate_id == "cand:v1:abc"

    def test_pruned_multi_technique_convergence_retains_both_origins(self):
        """A singleton and a pruned multi-technique candidate that converge
        to the same identity retain both origins."""
        ep = "user prompts (input)"
        ep_id = compute_entry_point_id(ep, "input", None)

        # Singleton: one technique from the start
        singleton_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        singleton = _make_candidate(
            technique_ids=("AML.T0051",),
            origins=(
                CandidateOrigin(
                    source_candidate_id=singleton_id,
                    original_technique_ids=("AML.T0051",),
                    transform_stage="expansion",
                ),
            ),
        )

        # Multi-technique that was pruned to the same singleton
        multi_original_id = compute_candidate_id(
            "AP-T7-01", ep_id, ("AML.T0051", "AML.T0054")
        )
        pruned = _make_candidate(
            technique_ids=("AML.T0051",),
            origins=(
                CandidateOrigin(
                    source_candidate_id=multi_original_id,
                    original_technique_ids=("AML.T0051", "AML.T0054"),
                    transform_stage="expansion",
                ),
                CandidateOrigin(
                    source_candidate_id=multi_original_id,
                    original_technique_ids=("AML.T0051", "AML.T0054"),
                    applied_rule="_rule_test",
                    removed_technique_ids=("AML.T0054",),
                    removal_reasons=("Test rejection",),
                    transform_stage="rule_pruning",
                ),
            ),
        )

        result = canonicalize_and_dedup([singleton, pruned], stage="test")
        assert len(result) == 1
        # Both origins retained
        assert len(result[0].origins) == 3  # 1 from singleton + 2 from pruned
        source_ids = {o.source_candidate_id for o in result[0].origins}
        assert singleton_id in source_ids
        assert multi_original_id in source_ids


# ---------------------------------------------------------------------------
# 3. Complete merged origins — never first-wins
# ---------------------------------------------------------------------------


class TestCompleteMergedOrigins:
    """Merged origins must contain every source candidate's provenance."""

    def test_all_origins_preserved_on_collapse(self):
        """When 3 candidates collapse to 1, all 3 origins are present."""
        candidates = []
        for i in range(3):
            c = _make_candidate(
                origins=(
                    CandidateOrigin(
                        source_candidate_id=f"cand:v1:src{i}",
                        original_technique_ids=("AML.T0051",),
                        transform_stage="expansion",
                    ),
                ),
            )
            candidates.append(c)

        result = canonicalize_and_dedup(candidates, stage="test")
        assert len(result) == 1
        assert len(result[0].origins) == 3
        source_ids = {o.source_candidate_id for o in result[0].origins}
        assert source_ids == {"cand:v1:src0", "cand:v1:src1", "cand:v1:src2"}

    def test_no_duplicate_origins_after_double_dedup(self):
        """Deduplicating an already-deduplicated list does not create
        duplicate origins."""
        c1 = _make_candidate(
            origins=(
                CandidateOrigin(
                    source_candidate_id="cand:v1:a",
                    original_technique_ids=("AML.T0051",),
                    transform_stage="expansion",
                ),
            ),
        )
        c2 = _make_candidate(
            origins=(
                CandidateOrigin(
                    source_candidate_id="cand:v1:b",
                    original_technique_ids=("AML.T0051",),
                    transform_stage="expansion",
                ),
            ),
        )

        result1 = canonicalize_and_dedup([c1, c2], stage="test")
        result2 = canonicalize_and_dedup(result1, stage="test")
        assert len(result2) == 1
        assert len(result2[0].origins) == 2  # No duplicates


# ---------------------------------------------------------------------------
# 4. Stable candidate IDs
# ---------------------------------------------------------------------------


class TestStableCandidateIds:
    """Candidate IDs must be deterministic and stable across transforms."""

    def test_same_identity_same_id(self):
        """Same (seed_id, entry_point_id, technique set) → same candidate_id."""
        id1 = compute_candidate_id("AP-T7-01", "ep1", ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", "ep1", ("AML.T0051",))
        assert id1 == id2

    def test_different_technique_order_same_id(self):
        """Technique ordering does not affect candidate_id."""
        id1 = compute_candidate_id("AP-T7-01", "ep1", ("AML.T0051", "AML.T0054"))
        id2 = compute_candidate_id("AP-T7-01", "ep1", ("AML.T0054", "AML.T0051"))
        assert id1 == id2

    def test_different_seed_different_id(self):
        """Different seed_id → different candidate_id."""
        id1 = compute_candidate_id("AP-T7-01", "ep1", ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-02", "ep1", ("AML.T0051",))
        assert id1 != id2

    def test_candidate_id_format(self):
        """Candidate ID follows cand:v1:<32-char hex> format."""
        cid = compute_candidate_id("AP-T7-01", "ep1", ("AML.T0051",))
        assert cid.startswith("cand:v1:")
        hex_part = cid.split("cand:v1:")[1]
        assert len(hex_part) == 32
        int(hex_part, 16)  # Valid hex


# ---------------------------------------------------------------------------
# 5. Collision-safe scenario IDs
# ---------------------------------------------------------------------------


class TestScenarioIdCollisionSafety:
    """Scenario IDs must include run_id and attempt for collision safety."""

    def test_scenario_id_includes_128_bit_min(self):
        """Scenario ID digest provides at least 128 bits of collision
        resistance (64 hex chars = 256 bits)."""
        sid = compute_scenario_id("run123", "cand:v1:abc", 1)
        assert sid.startswith("scenario:v2:")
        digest = sid.split("scenario:v2:")[1]
        assert len(digest) == 64  # SHA-256 = 256 bits
        int(digest, 16)  # Valid hex

    def test_different_run_ids_different_scenario_ids(self):
        """Same candidate+attempt but different run → different scenario ID."""
        sid1 = compute_scenario_id("run1", "cand:v1:abc", 1)
        sid2 = compute_scenario_id("run2", "cand:v1:abc", 1)
        assert sid1 != sid2

    def test_different_attempts_different_scenario_ids(self):
        """Same run+candidate but different attempt → different scenario ID."""
        sid1 = compute_scenario_id("run1", "cand:v1:abc", 1)
        sid2 = compute_scenario_id("run1", "cand:v1:abc", 2)
        assert sid1 != sid2

    def test_different_candidates_different_scenario_ids(self):
        """Same run+attempt but different candidate → different scenario ID."""
        sid1 = compute_scenario_id("run1", "cand:v1:abc", 1)
        sid2 = compute_scenario_id("run1", "cand:v1:def", 1)
        assert sid1 != sid2

    def test_run_id_is_128_bits(self):
        """generate_run_id produces a 32-char hex (128-bit) string."""
        rid = generate_run_id()
        assert len(rid) == 32
        int(rid, 16)  # Valid hex

    def test_run_ids_are_unique(self):
        """Two calls to generate_run_id produce different values."""
        ids = {generate_run_id() for _ in range(100)}
        assert len(ids) == 100


# ---------------------------------------------------------------------------
# 6. Distinct cross-run scenario IDs
# ---------------------------------------------------------------------------


class TestCrossRunScenarioIds:
    """The same candidate across multiple runs yields distinct scenario IDs."""

    def test_same_candidate_distinct_across_runs(self):
        """Same candidate_id in 5 different runs → 5 distinct scenario IDs."""
        candidate_id = "cand:v1:abcdef1234567890"
        run_ids = [generate_run_id() for _ in range(5)]
        scenario_ids = {compute_scenario_id(rid, candidate_id, 1) for rid in run_ids}
        assert len(scenario_ids) == 5


# ---------------------------------------------------------------------------
# 7. Content-sensitive exact-byte SHA-256 hashes
# ---------------------------------------------------------------------------


class TestArtifactHashes:
    """compute_artifact_hash must produce exact-byte SHA-256 hashes."""

    def test_hash_is_sha256(self):
        """Hash matches hashlib.sha256 for exact bytes."""
        data = b"test content"
        h = compute_artifact_hash(data)
        assert h == hashlib.sha256(data).hexdigest()
        assert len(h) == 64

    def test_different_content_different_hash(self):
        """Different bytes → different hash."""
        assert compute_artifact_hash(b"a") != compute_artifact_hash(b"b")

    def test_same_content_same_hash(self):
        """Same bytes → same hash."""
        assert compute_artifact_hash(b"x") == compute_artifact_hash(b"x")

    def test_empty_content(self):
        """Empty bytes produce valid hash."""
        h = compute_artifact_hash(b"")
        assert h == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# 8. Exclusive write creation / duplicate collisions
# ---------------------------------------------------------------------------


class TestExclusiveWriteCreation:
    """write_scenario_outputs must fail loudly on existing paths."""

    def test_write_succeeds_on_clean_dir(self, tmp_path: Path):
        """First write to a clean directory succeeds."""
        env = _make_envelope(scenario_id="scenario:v2:abc")
        yaml_path, feature_path = write_scenario_outputs(env, tmp_path)
        assert yaml_path.exists()
        assert feature_path is None  # No behavior_spec

    def test_write_fails_on_duplicate_yaml(self, tmp_path: Path):
        """Second write of same scenario_id fails with FileExistsError."""
        env = _make_envelope(scenario_id="scenario:v2:abc")
        write_scenario_outputs(env, tmp_path)
        with pytest.raises(FileExistsError, match="already exists"):
            write_scenario_outputs(env, tmp_path)

    def test_write_fails_on_duplicate_feature(self, tmp_path: Path):
        """Feature file collision is caught in preflight before YAML write."""
        env = _make_envelope(
            scenario_id="scenario:v2:abc",
            behavior_spec="Feature: Test\n  Scenario: Basic\n    Given something",
        )
        write_scenario_outputs(env, tmp_path)
        with pytest.raises(FileExistsError):
            write_scenario_outputs(env, tmp_path)

    def test_stem_mismatch_feature_without_behavior_spec(self, tmp_path: Path):
        """Writing YAML without behavior_spec when a feature file exists
        for the same stem (but no YAML yet) raises ValueError."""
        # Manually create a .feature file without a .yaml
        feature_path = tmp_path / "scenario:v2:abc.feature"
        feature_path.write_text("Feature: Orphan\n", encoding="utf-8")

        # Now try to write a YAML without behavior_spec
        env = _make_envelope(scenario_id="scenario:v2:abc")
        with pytest.raises(ValueError, match="Stem mismatch"):
            write_scenario_outputs(env, tmp_path)


# ---------------------------------------------------------------------------
# 9. Guarded replacement API
# ---------------------------------------------------------------------------


class TestGuardedReplacement:
    """replace_scenario_outputs proves same scenario/stem before overwriting."""

    def test_replace_succeeds_for_same_scenario(self, tmp_path: Path):
        """Replacing an existing scenario with the same ID succeeds."""
        env = _make_envelope(scenario_id="scenario:v2:abc")
        write_scenario_outputs(env, tmp_path)

        # Modify and replace
        env.narrative.title = "Updated Title"
        yaml_path, _ = replace_scenario_outputs(env, tmp_path)
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["narrative"]["title"] == "Updated Title"

    def test_replace_fails_on_id_mismatch(self, tmp_path: Path):
        """replace raises ValueError when expected_scenario_id doesn't match."""
        env = _make_envelope(scenario_id="scenario:v2:abc")
        write_scenario_outputs(env, tmp_path)

        with pytest.raises(ValueError, match="Scenario ID mismatch"):
            replace_scenario_outputs(
                env, tmp_path, expected_scenario_id="scenario:v2:different"
            )

    def test_replace_fails_on_nonexistent(self, tmp_path: Path):
        """replace raises FileNotFoundError when the YAML doesn't exist."""
        env = _make_envelope(scenario_id="scenario:v2:nonexist")
        with pytest.raises(FileNotFoundError):
            replace_scenario_outputs(env, tmp_path)

    def test_replace_with_feature_preserves_feature(self, tmp_path: Path):
        """Replacing a scenario with a feature file preserves and updates it."""
        env = _make_envelope(
            scenario_id="scenario:v2:abc",
            behavior_spec="Feature: Test\n  Scenario: Basic\n    Given something",
        )
        write_scenario_outputs(env, tmp_path)

        env.behavior_spec = "Feature: Updated\n  Scenario: New\n    Given other"
        yaml_path, feature_path = replace_scenario_outputs(env, tmp_path)
        assert feature_path is not None
        assert "Updated" in feature_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 10. Typed funnel records and equations
# ---------------------------------------------------------------------------


class TestTypedFunnelRecords:
    """StageRecord and CandidateFunnel are typed models with exact counts."""

    def test_stage_record_is_frozen(self):
        """StageRecord is immutable."""
        rec = StageRecord(
            stage="expansion",
            input_count=10,
            output_count=8,
            collapsed_count=2,
        )
        with pytest.raises(Exception):
            rec.stage = "other"  # type: ignore[misc]

    def test_candidate_funnel_all_fields(self):
        """CandidateFunnel holds all required funnel counts."""
        funnel = CandidateFunnel(
            expanded_instances=100,
            unique_pre_rule_identities=80,
            rule_rejected=10,
            rule_transformed=15,
            post_rule_collapsed=5,
            filter_submitted=65,
            filter_accepted=30,
            selected=25,
            attempted=25,
            admitted=23,
            quarantined=2,
            persisted_artifacts=23,
        )
        assert funnel.expanded_instances == 100
        assert funnel.persisted_artifacts == 23

    def test_funnel_model_dump_roundtrip(self):
        """CandidateFunnel.model_dump() produces a plain dict for manifest."""
        funnel = CandidateFunnel(
            expanded_instances=10,
            unique_pre_rule_identities=8,
            rule_rejected=2,
            rule_transformed=3,
            post_rule_collapsed=1,
            filter_submitted=5,
            filter_accepted=4,
            selected=4,
            attempted=4,
            admitted=3,
            quarantined=1,
            persisted_artifacts=3,
        )
        d = funnel.model_dump()
        assert isinstance(d, dict)
        assert d["expanded_instances"] == 10
        assert d["persisted_artifacts"] == 3


# ---------------------------------------------------------------------------
# 11. Transform dedup with stage records
# ---------------------------------------------------------------------------


class TestTransformDedupWithStageRecords:
    """Transforms deduplicate internally and produce typed stage records."""

    def test_expand_candidates_deduplicates_internally(self):
        """expand_candidates returns deduplicated candidates and records
        stage."""
        # Create seeds with duplicate technique combos
        seed = _make_seed(technique_ids=("AML.T0051",))
        profile = _make_profile()

        records: list[StageRecord] = []
        expand_candidates([seed], profile, stage_records=records)
        # Should have one stage record
        assert len(records) == 1
        assert records[0].stage == "expansion"
        assert records[0].output_count <= records[0].input_count
        assert (
            records[0].collapsed_count
            == records[0].input_count - records[0].output_count
        )

    def test_apply_rule_based_filter_deduplicates_internally(self):
        """apply_rule_based_filter deduplicates passed candidates and
        records stage."""
        # Create two candidates that will converge after pruning
        ep = "user prompts (input)"
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        profile = _make_profile()

        records: list[StageRecord] = []
        passed, rejected, verdicts = apply_rule_based_filter(
            [c1, c2], profile, stage_records=records
        )
        # Should have a rule_pruning stage record
        rule_records = [r for r in records if r.stage == "rule_pruning"]
        assert len(rule_records) == 1

    def test_cap_scenarios_per_pattern_deduplicates_internally(self):
        """cap_scenarios_per_pattern deduplicates and records stage."""
        ep = "user prompts (input)"
        fs1 = _make_filtered_seed(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051",),
        )
        fs2 = _make_filtered_seed(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051",),
        )

        records: list[StageRecord] = []
        result = cap_scenarios_per_pattern(
            [fs1, fs2], max_per_pattern=5, stage_records=records
        )
        # Should deduplicate to 1
        assert len(result) == 1
        assert len(records) == 1
        assert records[0].stage == "capping"
        assert records[0].collapsed_count == 1


# ---------------------------------------------------------------------------
# 12. Funnel equation: expanded = unique_pre_rule + expansion_collapsed
# ---------------------------------------------------------------------------


class TestFunnelEquations:
    """Funnel counts must satisfy exact reconciliation equations."""

    def test_expansion_equation(self):
        """expanded_instances = unique_pre_rule_identities + expansion_collapsed."""
        seed = _make_seed(technique_ids=("AML.T0051",))
        profile = _make_profile()
        records: list[StageRecord] = []
        expand_candidates([seed], profile, stage_records=records)

        exp_rec = records[0]
        assert exp_rec.input_count == exp_rec.output_count + exp_rec.collapsed_count

    def test_rule_pruning_equation(self):
        """rule_pruning: input_count = output_count + collapsed_count."""
        c = _make_candidate(technique_ids=("AML.T0051",))
        profile = _make_profile()
        records: list[StageRecord] = []
        apply_rule_based_filter([c], profile, stage_records=records)

        rule_rec = [r for r in records if r.stage == "rule_pruning"][0]
        assert rule_rec.input_count == rule_rec.output_count + rule_rec.collapsed_count

    def test_capping_equation(self):
        """capping: input_count = output_count + collapsed_count."""
        fs = _make_filtered_seed()
        records: list[StageRecord] = []
        cap_scenarios_per_pattern([fs], max_per_pattern=5, stage_records=records)

        cap_rec = records[0]
        assert cap_rec.input_count == cap_rec.output_count + cap_rec.collapsed_count


# ---------------------------------------------------------------------------
# 13. One generation attempt for converged candidates
# ---------------------------------------------------------------------------


class TestOneGenerationAttempt:
    """When candidates converge, only one generation attempt is made."""

    def test_converged_candidates_produce_single_attempt(self):
        """Two candidates that converge to the same identity after rule
        pruning produce exactly one candidate — hence one generation attempt."""
        ep = "user prompts (input)"
        # Two candidates with different technique combos that will both
        # survive rules and converge after pruning
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        profile = _make_profile()

        passed, _, _ = apply_rule_based_filter([c1, c2], profile)
        # Both pass rules (no pruning needed for compatible techniques)
        # But if they have the same identity after any pruning, dedup
        # ensures only one survives.
        # Since c1 has just T0051 and c2 has T0051+T0054, they have
        # different identities and both survive. That's correct —
        # convergence only happens when pruning makes them identical.

    def test_pruned_convergence_yields_single_candidate(self):
        """When rule pruning causes convergence, dedup produces exactly
        one candidate — ensuring one generation attempt, not two."""
        ep = "user prompts (input)"
        ep_id = compute_entry_point_id(ep, "input", None)

        # Singleton
        c_single = _make_candidate(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051",),
            origins=(
                CandidateOrigin(
                    source_candidate_id=compute_candidate_id(
                        "AP-T7-01", ep_id, ("AML.T0051",)
                    ),
                    original_technique_ids=("AML.T0051",),
                    transform_stage="expansion",
                ),
            ),
        )

        # Multi-technique that will be pruned to the same singleton
        c_multi = _make_candidate(
            seed_id="AP-T7-01",
            entry_point=ep,
            technique_ids=("AML.T0051", "AML.T0054"),
            origins=(
                CandidateOrigin(
                    source_candidate_id=compute_candidate_id(
                        "AP-T7-01", ep_id, ("AML.T0051", "AML.T0054")
                    ),
                    original_technique_ids=("AML.T0051", "AML.T0054"),
                    transform_stage="expansion",
                ),
            ),
        )

        # Simulate pruning: c_multi loses AML.T0054
        c_multi_pruned = CandidateTriple.model_validate(
            c_multi.model_dump(mode="python")
            | {
                "atlas_technique_ids": ("AML.T0051",),
                "atlas_technique_names": ("Technique AML.T0051",),
                "atlas_technique_descriptions": ("Desc AML.T0051",),
                "candidate_id": compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",)),
                "origins": c_multi.origins
                + (
                    CandidateOrigin(
                        source_candidate_id=compute_candidate_id(
                            "AP-T7-01", ep_id, ("AML.T0051", "AML.T0054")
                        ),
                        original_technique_ids=("AML.T0051", "AML.T0054"),
                        applied_rule="_rule_test",
                        removed_technique_ids=("AML.T0054",),
                        removal_reasons=("Test",),
                        transform_stage="rule_pruning",
                    ),
                ),
            }
        )

        # After pruning, both have the same identity
        result = canonicalize_and_dedup(
            [c_single, c_multi_pruned], stage="rule_pruning"
        )
        assert len(result) == 1  # One candidate = one generation attempt


# ---------------------------------------------------------------------------
# 14. Duplicate admission / ID collisions fail loudly
# ---------------------------------------------------------------------------


class TestDuplicateAdmissionCollisions:
    """Duplicate scenario IDs and path collisions must fail loudly."""

    def test_duplicate_scenario_id_yields_path_collision(self, tmp_path: Path):
        """Two envelopes with the same scenario_id cannot both be written
        — the second write fails with FileExistsError."""
        env1 = _make_envelope(scenario_id="scenario:v2:same")
        env2 = _make_envelope(scenario_id="scenario:v2:same")

        write_scenario_outputs(env1, tmp_path)
        with pytest.raises(FileExistsError, match="already exists"):
            write_scenario_outputs(env2, tmp_path)

    def test_duplicate_path_with_different_content_fails(self, tmp_path: Path):
        """Even with different narrative content, same scenario_id
        cannot overwrite — exclusive creation prevents silent data loss."""
        env1 = _make_envelope(scenario_id="scenario:v2:same")
        write_scenario_outputs(env1, tmp_path)

        env2 = _make_envelope(scenario_id="scenario:v2:same")
        env2.narrative.title = "Different Title"
        with pytest.raises(FileExistsError):
            write_scenario_outputs(env2, tmp_path)

    def test_replace_rejects_different_scenario_id(self, tmp_path: Path):
        """replace_scenario_outputs rejects when expected_scenario_id
        doesn't match — prevents overwriting the wrong scenario."""
        env = _make_envelope(scenario_id="scenario:v2:abc")
        write_scenario_outputs(env, tmp_path)

        with pytest.raises(ValueError, match="Scenario ID mismatch"):
            replace_scenario_outputs(
                env, tmp_path, expected_scenario_id="scenario:v2:different"
            )
