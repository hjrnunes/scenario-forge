"""Focused tests for canonical candidate identity and strict filter protocol.

Covers the scenario-forge-cmps.2 bead contract:
  - Stable/changing entry-point IDs.
  - Semantic duplicate dedup and ambiguous/colliding identity rejection.
  - Stable candidate ID with sorted unique technique IDs; changes on any
    identity component.
  - Reordered response accepted; wrong seed, unknown ID, duplicate ID,
    omitted ID, repeated accept/reject, empty response.
  - Metadata immutability / application authority.
  - Retry succeeds on second attempt; second failure raises with no output
    and two evidence entries.
  - Bounded set-based coverage.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from scenario_forge.eval.diversity import entry_point_entropy
from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    compute_entry_point_id,
    deduplicate_entry_points,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import (
    BatchFilterResponse,
    CandidateTriple,
    FilterProtocolError,
    FilteredSeed,
    FilterVerdict,
    _reconcile_filter_response,
    apply_rule_based_filter,
    compute_candidate_id,
    filter_candidates,
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


def _make_seed(seed_id: str = "AP-T7-01") -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        atlas_technique_ids=["AML.T0051"],
    )


def _make_candidate(
    seed_id: str = "AP-T7-01",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    direction: str = "input",
    controllability: str | None = None,
    technique_names: tuple[str, ...] | None = None,
    technique_descs: tuple[str, ...] | None = None,
) -> CandidateTriple:
    ep_id = compute_entry_point_id(entry_point, direction, controllability)
    cand_id = compute_candidate_id(seed_id, ep_id, technique_ids)
    if technique_names is None:
        technique_names = tuple(f"Technique {t}" for t in technique_ids)
    if technique_descs is None:
        technique_descs = tuple(f"Desc {t}" for t in technique_ids)
    return CandidateTriple(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        entry_point=entry_point,
        atlas_technique_ids=technique_ids,
        atlas_technique_names=technique_names,
        atlas_technique_descriptions=technique_descs,
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        entry_point_id=ep_id,
        candidate_id=cand_id,
    )


def _make_profile(entry_points: list[EntryPoint] | None = None) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points
        or [EntryPoint(name="user prompts", direction="input")],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _make_llm_result(content, attempt_label: str = "test") -> MagicMock:
    """Build a mock LLMResult with the given parsed content."""
    result = MagicMock()
    result.content = content
    result.system_prompt = "sys"
    result.user_prompt = "user"
    result.prompt_tokens = 100
    result.completion_tokens = 50
    result.duration_ms = 500
    return result


# ---------------------------------------------------------------------------
# 1. Stable / changing entry-point IDs
# ---------------------------------------------------------------------------


class TestEntryPointIdStability:
    """Entry-point IDs are deterministic and change only when identity changes."""

    def test_same_name_direction_controllability_same_id(self):
        """Same canonical inputs produce the same entry_point_id."""
        id1 = compute_entry_point_id("User Prompts", "input", None)
        id2 = compute_entry_point_id("user prompts", "input", None)
        assert id1 == id2

    def test_different_direction_different_id(self):
        """Changing direction changes the ID."""
        id_input = compute_entry_point_id("user prompts", "input", None)
        id_output = compute_entry_point_id("user prompts", "output", None)
        assert id_input != id_output

    def test_different_controllability_different_id(self):
        """Changing explicit controllability changes the ID."""
        id_direct = compute_entry_point_id("user prompts", "input", "direct")
        id_indirect = compute_entry_point_id("user prompts", "input", "indirect")
        assert id_direct != id_indirect

    def test_different_name_different_id(self):
        """Different names produce different IDs (barring hash collision)."""
        id1 = compute_entry_point_id("user prompts", "input", None)
        id2 = compute_entry_point_id("RAG knowledge", "input", None)
        assert id1 != id2

    def test_case_and_whitespace_invariant(self):
        """Case and whitespace variations produce the same ID."""
        id1 = compute_entry_point_id("User   Prompts", "input", None)
        id2 = compute_entry_point_id("user prompts", "input", None)
        assert id1 == id2

    def test_trailing_punctuation_invariant(self):
        """Trailing punctuation is stripped for canonical comparison."""
        id1 = compute_entry_point_id("user prompts.", "input", None)
        id2 = compute_entry_point_id("user prompts", "input", None)
        assert id1 == id2

    def test_id_format(self):
        """ID follows the ep:v1:<12 hex> format."""
        eid = compute_entry_point_id("user prompts", "input", None)
        assert eid.startswith("ep:v1:")
        hex_part = eid.split(":")[2]
        assert len(hex_part) == 12
        int(hex_part, 16)  # valid hex

    def test_entry_point_model_has_entry_point_id(self):
        """EntryPoint model exposes entry_point_id as a computed field."""
        ep = EntryPoint(name="user prompts", direction="input")
        assert ep.entry_point_id.startswith("ep:v1:")

    def test_entry_point_id_in_model_dump(self):
        """entry_point_id appears in model_dump()."""
        ep = EntryPoint(name="user prompts", direction="input")
        d = ep.model_dump()
        assert "entry_point_id" in d
        assert d["entry_point_id"].startswith("ep:v1:")


# ---------------------------------------------------------------------------
# 2. Semantic duplicate dedup and ambiguous/colliding identity rejection
# ---------------------------------------------------------------------------


class TestEntryPointDedup:
    """deduplicate_entry_points dedupes semantic duplicates and rejects collisions."""

    def test_semantic_duplicates_deduped(self):
        """Entry points with same canonical name/direction/controllability are deduped."""
        eps = [
            EntryPoint(name="User Prompts", direction="input"),
            EntryPoint(name="user prompts", direction="input"),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 1

    def test_different_directions_not_deduped(self):
        """Entry points with different directions are NOT deduped."""
        eps = [
            EntryPoint(name="user prompts", direction="input"),
            EntryPoint(name="user prompts", direction="output"),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 2

    def test_different_controllability_not_deduped(self):
        """Entry points with different controllability are NOT deduped."""
        eps = [
            EntryPoint(
                name="some channel", direction="input", controllability="direct"
            ),
            EntryPoint(
                name="some channel", direction="input", controllability="indirect"
            ),
        ]
        result = deduplicate_entry_points(eps)
        assert len(result) == 2

    def test_first_encounter_order_preserved(self):
        """Dedup keeps the first-encountered entry point."""
        eps = [
            EntryPoint(name="User Prompts", direction="input"),
            EntryPoint(name="user prompts", direction="input"),
        ]
        result = deduplicate_entry_points(eps)
        assert result[0].name == "User Prompts"

    def test_collision_rejected(self):
        """Two entry points with same ID but different canonical names raise ValueError."""
        # This is hard to trigger naturally (requires a hash collision),
        # so we monkeypatch compute_entry_point_id to force a collision.
        with patch(
            "scenario_forge.models.capability_profile.compute_entry_point_id",
            return_value="ep:v1:collision00",
        ):
            eps = [
                EntryPoint(name="entry A", direction="input"),
                EntryPoint(name="entry B", direction="input"),
            ]
            with pytest.raises(ValueError, match="Ambiguous entry point identity"):
                deduplicate_entry_points(eps)

    def test_profile_post_init_deduplicates(self):
        """CapabilityProfile model_validator deduplicates entry points."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="User Prompts", direction="input"),
                EntryPoint(name="user prompts", direction="input"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        assert len(profile.entry_points) == 1


# ---------------------------------------------------------------------------
# 3. Stable candidate ID with sorted unique technique IDs
# ---------------------------------------------------------------------------


class TestCandidateIdStability:
    """Candidate IDs are deterministic from (seed_id, entry_point_id, sorted unique technique IDs)."""

    def test_same_identity_same_id(self):
        """Same (seed_id, entry_point_id, technique_ids) produces same candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        assert id1 == id2

    def test_technique_order_invariant(self):
        """Technique order does not change the candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051", "AML.T0054"))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0054", "AML.T0051"))
        assert id1 == id2

    def test_duplicate_techniques_collapsed(self):
        """Duplicate technique IDs are collapsed to unique set."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051", "AML.T0051"))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        assert id1 == id2

    def test_different_seed_different_id(self):
        """Different seed_id produces different candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-02", ep_id, ("AML.T0051",))
        assert id1 != id2

    def test_different_entry_point_different_id(self):
        """Different entry_point_id produces different candidate_id."""
        id1 = compute_candidate_id("AP-T7-01", "ep:v1:aaa111", ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", "ep:v1:bbb222", ("AML.T0051",))
        assert id1 != id2

    def test_different_techniques_different_id(self):
        """Different technique set produces different candidate_id."""
        ep_id = "ep:v1:abc123"
        id1 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        id2 = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0054",))
        assert id1 != id2

    def test_id_format(self):
        """ID follows the cand:v1:<12 hex> format."""
        cid = compute_candidate_id("AP-T7-01", "ep:v1:abc123", ("AML.T0051",))
        assert cid.startswith("cand:v1:")
        hex_part = cid.split(":")[2]
        assert len(hex_part) == 12
        int(hex_part, 16)  # valid hex


# ---------------------------------------------------------------------------
# 4. Reconciliation: reordered, wrong seed, unknown ID, duplicate ID,
#    omitted ID, repeated accept/reject, empty response
# ---------------------------------------------------------------------------


class TestReconciliation:
    """_reconcile_filter_response validates against the exact submitted ID set."""

    def _make_submitted_ids(self) -> set[str]:
        return {"cand:v1:aaa111", "cand:v1:bbb222", "cand:v1:ccc333"}

    def test_valid_response_accepted(self):
        """A correct response with all IDs passes reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is True
        assert err is None

    def test_reordered_response_accepted(self):
        """Response with verdicts in different order passes reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:ccc333", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is True
        assert err is None

    def test_wrong_seed_rejected(self):
        """Response with wrong seed_id fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-99",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "seed_id" in err

    def test_unknown_id_rejected(self):
        """Response with an unknown candidate_id fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:ccc333", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:zzz999", verdict="accept", rationale="unknown"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Unknown" in err

    def test_duplicate_id_rejected(self):
        """Response with duplicate candidate_ids fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="reject", rationale="dup"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Duplicate" in err

    def test_omitted_id_rejected(self):
        """Response missing a submitted candidate_id fails reconciliation."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Missing" in err

    def test_repeated_accept_reject_is_duplicate(self):
        """Two verdicts for the same ID (one accept, one reject) is a duplicate."""
        resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="accept", rationale="ok"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:aaa111", verdict="reject", rationale="dup"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:bbb222", verdict="reject", rationale="no"
                ),
                FilterVerdict(
                    candidate_id="cand:v1:ccc333", verdict="accept", rationale="ok"
                ),
            ],
        )
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Duplicate" in err

    def test_empty_verdicts_rejected(self):
        """Empty verdicts list fails reconciliation (all IDs omitted)."""
        resp = BatchFilterResponse(seed_id="AP-T7-01", verdicts=[])
        ok, err = _reconcile_filter_response(
            resp, "AP-T7-01", self._make_submitted_ids()
        )
        assert ok is False
        assert "Missing" in err


# ---------------------------------------------------------------------------
# 5. Metadata immutability / application authority
# ---------------------------------------------------------------------------


class TestMetadataImmutability:
    """The LLM is never authoritative for metadata — IDs are application-computed."""

    def test_candidate_triple_ids_are_application_computed(self):
        """CandidateTriple IDs are deterministic from application inputs, not LLM."""
        c = _make_candidate(entry_point="user prompts", technique_ids=("AML.T0051",))
        expected_ep_id = compute_entry_point_id("user prompts", "input", None)
        expected_cand_id = compute_candidate_id(
            "AP-T7-01", expected_ep_id, ("AML.T0051",)
        )
        assert c.entry_point_id == expected_ep_id
        assert c.candidate_id == expected_cand_id

    def test_filter_verdict_has_no_metadata_fields(self):
        """FilterVerdict (wire protocol) only has candidate_id, verdict, rationale."""
        fields = set(FilterVerdict.model_fields.keys())
        assert fields == {"candidate_id", "verdict", "rationale"}

    def test_filter_verdict_rejects_entry_point_field(self):
        """FilterVerdict with extra='forbid' rejects legacy entry_point field."""
        with pytest.raises(ValidationError):
            FilterVerdict(
                candidate_id="cand:v1:abc",
                verdict="accept",
                rationale="ok",
                entry_point="user prompts",
            )

    def test_filtered_seed_carries_canonical_ids(self):
        """FilteredSeed carries entry_point_id and candidate_id from the candidate."""
        ep_id = compute_entry_point_id("user prompts", "input", None)
        cand_id = compute_candidate_id("AP-T7-01", ep_id, ("AML.T0051",))
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="T7",
            attack_pattern_name="P",
            attack_pattern_description="D",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("T1",),
            entry_point_id=ep_id,
            candidate_id=cand_id,
        )
        assert fs.entry_point_id == ep_id
        assert fs.candidate_id == cand_id

    def test_rule_pruning_recomputes_candidate_id(self):
        """When rule-based filter prunes techniques, candidate_id is recomputed."""
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[
                EntryPoint(name="RAG knowledge-grounding", direction="input"),
            ],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        # AML.T0070 is compatible with indirect EP, AML.T0054 is not.
        candidate = _make_candidate(
            entry_point="RAG knowledge-grounding",
            technique_ids=("AML.T0070", "AML.T0054"),
            technique_names=("RAG Poisoning", "LLM Jailbreak"),
            technique_descs=("RAG poisoning desc", "Jailbreak desc"),
        )
        original_cand_id = candidate.candidate_id
        passed, _, _ = apply_rule_based_filter([candidate], profile)
        assert len(passed) == 1
        # Candidate ID should change because technique set changed.
        assert passed[0].candidate_id != original_cand_id
        # New candidate_id should match the recomputed value.
        expected_new_id = compute_candidate_id(
            candidate.seed_id,
            candidate.entry_point_id,
            ("AML.T0070",),
        )
        assert passed[0].candidate_id == expected_new_id


# ---------------------------------------------------------------------------
# 6. Retry / exhaustion behaviour
# ---------------------------------------------------------------------------


class TestFilterRetryExhaustion:
    """filter_candidates retries malformed batches exactly once, then fails."""

    def _make_two_candidates(self) -> list[CandidateTriple]:
        return [
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="user prompts",
                technique_ids=("AML.T0051",),
            ),
            _make_candidate(
                seed_id="AP-T7-01",
                entry_point="RAG knowledge",
                technique_ids=("AML.T0051.001",),
            ),
        ]

    def _make_valid_response(
        self, seed_id: str, candidates: list[CandidateTriple]
    ) -> BatchFilterResponse:
        return BatchFilterResponse(
            seed_id=seed_id,
            verdicts=[
                FilterVerdict(
                    candidate_id=c.candidate_id,
                    verdict="accept" if i == 0 else "reject",
                    rationale=f"verdict {i}",
                )
                for i, c in enumerate(candidates)
            ],
        )

    def test_retry_succeeds_on_second_attempt(self):
        """First attempt malformed, second attempt valid — filter succeeds."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        malformed_resp = BatchFilterResponse(
            seed_id="AP-T7-01",
            verdicts=[],  # empty -> omitted IDs
        )

        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(malformed_resp),
            _make_llm_result(valid_resp),
        ]

        results, logs = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        assert results[0].candidate_id == candidates[0].candidate_id
        assert len(logs) == 2  # two attempts logged

    def test_second_failure_raises_with_no_output(self):
        """Two malformed attempts raise FilterProtocolError with no partial output."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        malformed_resp = BatchFilterResponse(
            seed_id="WRONG",
            verdicts=[],
        )

        client = MagicMock()
        client.complete.side_effect = [
            _make_llm_result(malformed_resp),
            _make_llm_result(malformed_resp),
        ]

        with pytest.raises(FilterProtocolError) as exc_info:
            filter_candidates(candidates, seeds, client, "test", profile)

        # Two call log entries (one per attempt).
        assert len(exc_info.value.call_log_entries) == 2

    def test_duplicate_input_candidate_ids_raise(self):
        """Duplicate candidate IDs in submitted input raise FilterProtocolError."""
        # Create two candidates with the same candidate_id by using same inputs.
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        # Force same candidate_id (they should already be identical).
        assert c1.candidate_id == c2.candidate_id

        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()
        client = MagicMock()

        with pytest.raises(FilterProtocolError, match="Duplicate candidate IDs"):
            filter_candidates([c1, c2], seeds, client, "test", profile)

    def test_metadata_from_application_not_llm(self):
        """Accepted FilteredSeed metadata comes from CandidateTriple, not LLM response."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.return_value = _make_llm_result(valid_resp)

        results, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        # The accepted candidate's entry_point and technique_ids come from
        # the CandidateTriple, not from the LLM response.
        assert results[0].pinned_entry_point == candidates[0].entry_point
        assert results[0].pinned_technique_ids == candidates[0].atlas_technique_ids
        assert results[0].entry_point_id == candidates[0].entry_point_id
        assert results[0].candidate_id == candidates[0].candidate_id

    def test_rejection_records_carry_application_metadata(self):
        """RejectionRecord metadata is resolved from candidate lookup, not LLM."""
        candidates = self._make_two_candidates()
        seeds = [_make_seed("AP-T7-01")]
        profile = _make_profile()

        valid_resp = self._make_valid_response("AP-T7-01", candidates)
        client = MagicMock()
        client.complete.return_value = _make_llm_result(valid_resp)

        results, _ = filter_candidates(candidates, seeds, client, "test", profile)
        assert len(results) == 1
        # The rejected candidate's metadata should be in rejection_rationales.
        assert len(results[0].rejection_rationales) == 1
        rr = results[0].rejection_rationales[0]
        assert rr.candidate_id == candidates[1].candidate_id
        assert rr.entry_point == candidates[1].entry_point
        assert rr.atlas_technique_ids == candidates[1].atlas_technique_ids

    def test_no_partial_output_on_protocol_failure(self):
        """When one seed fails protocol, no results are returned for any seed."""
        c1 = _make_candidate(
            seed_id="AP-T7-01",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        c2 = _make_candidate(
            seed_id="AP-T7-02",
            entry_point="user prompts",
            technique_ids=("AML.T0051",),
        )
        seeds = [_make_seed("AP-T7-01"), _make_seed("AP-T7-02")]
        profile = _make_profile()

        valid_resp_1 = self._make_valid_response("AP-T7-01", [c1])
        malformed_resp = BatchFilterResponse(seed_id="WRONG", verdicts=[])

        client = MagicMock()
        # Seed 1 succeeds, seed 2 fails twice.
        client.complete.side_effect = [
            _make_llm_result(valid_resp_1),  # seed 1 attempt 1 (success)
            _make_llm_result(malformed_resp),  # seed 2 attempt 1 (fail)
            _make_llm_result(malformed_resp),  # seed 2 attempt 2 (fail)
        ]

        with pytest.raises(FilterProtocolError):
            filter_candidates([c1, c2], seeds, client, "test", profile)


# ---------------------------------------------------------------------------
# 7. Bounded set-based coverage
# ---------------------------------------------------------------------------


class TestBoundedCoverage:
    """Coverage is set-based and bounded in [0, 1]."""

    def test_coverage_bounded_at_1(self):
        """Coverage is clamped to 1.0 when actual exceeds expected."""
        scenarios = [
            {
                "narrative": {"entry_point": "ep1"},
                "candidate_filter": {"entry_point_id": "ep:v1:a"},
            },
            {
                "narrative": {"entry_point": "ep2"},
                "candidate_filter": {"entry_point_id": "ep:v1:b"},
            },
            {
                "narrative": {"entry_point": "ep3"},
                "candidate_filter": {"entry_point_id": "ep:v1:c"},
            },
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=2)
        assert result["entry_point_coverage"] == 1.0
        assert 0.0 <= result["entry_point_coverage"] <= 1.0

    def test_coverage_zero_when_no_entry_points(self):
        """Coverage is 0.0 when no scenarios have entry points."""
        scenarios = [{"narrative": {}, "candidate_filter": {}}]
        result = entry_point_entropy(scenarios, expected_entry_points=5)
        assert result["entry_point_coverage"] == 0.0

    def test_coverage_fractional(self):
        """Coverage is a proper fraction in [0, 1]."""
        scenarios = [
            {"narrative": {}, "candidate_filter": {"entry_point_id": "ep:v1:a"}},
            {"narrative": {}, "candidate_filter": {"entry_point_id": "ep:v1:b"}},
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=4)
        assert result["entry_point_coverage"] == 0.5

    def test_coverage_uses_canonical_ids(self):
        """Coverage counts unique canonical entry_point_ids, not display text."""
        scenarios = [
            {
                "narrative": {"entry_point": "User Prompts"},
                "candidate_filter": {"entry_point_id": "ep:v1:same"},
            },
            {
                "narrative": {"entry_point": "user prompts"},
                "candidate_filter": {"entry_point_id": "ep:v1:same"},
            },
        ]
        result = entry_point_entropy(scenarios, expected_entry_points=5)
        # Only 1 unique entry_point_id despite 2 scenarios.
        assert result["entry_point_coverage"] == round(1 / 5, 4)
