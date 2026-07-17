"""Tests for the candidate filtering pipeline stage.

Covers:
  - Data model validation for CandidateTriple, FilterVerdict,
    BatchFilterResponse, and FilteredSeed.
  - expand_candidates() cross-product logic (skipped if not yet available).
  - Multi-technique combo expansion (max_techniques parameter).
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from scenario_forge.models.capability_profile import CapabilityProfile, ConfidenceLevel
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import (
    BatchFilterResponse,
    CandidateTriple,
    FilteredSeed,
    FilterVerdict,
    cap_scenarios_per_pattern,
)
from scenario_forge.pipeline.seeds import ScenarioSeed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ref(risk_id: str = "risk-1", confidence: float = 0.9) -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description for {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=confidence,
        grounding_confidence=ConfidenceLevel.high,
    )


def _make_seed(
    seed_id: str = "AP-T7-01",
    threat_id: str = "T7",
    atlas_technique_ids: list[str] | None = None,
    laaf_technique_ids: list[str] | None = None,
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
        atlas_technique_ids=atlas_technique_ids or [],
        laaf_technique_ids=laaf_technique_ids or [],
    )


def _make_filtered_seed(
    seed_id: str = "AP-T7-01",
    entry_point: str = "user prompts (input)",
    technique_ids: tuple[str, ...] = ("AML.T0051",),
    technique_names: tuple[str, ...] | None = None,
) -> FilteredSeed:
    """Build a FilteredSeed with minimal boilerplate for capping tests."""
    if technique_names is None:
        technique_names = tuple(f"Technique {t}" for t in technique_ids)
    return FilteredSeed(
        seed_id=seed_id,
        threat_id="T7",
        threat_name="Threat T7",
        attack_pattern_name=f"Pattern {seed_id}",
        attack_pattern_description=f"Description for {seed_id}",
        risk_card_ref=_make_ref(),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T7"],
        pinned_entry_point=entry_point,
        pinned_technique_ids=technique_ids,
        pinned_technique_names=technique_names,
    )


def _make_profile(entry_points: list[str] | None = None) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=entry_points or ["user prompts (input)"],
        confidence=ConfidenceLevel.high,
    )


# ---------------------------------------------------------------------------
# Model validation tests
# ---------------------------------------------------------------------------


class TestCandidateTriple:
    """CandidateTriple model validation."""

    def test_candidate_triple_creation(self):
        """CandidateTriple accepts all required fields with tuple technique fields."""
        ct = CandidateTriple(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051",),
            atlas_technique_names=("LLM Prompt Injection",),
            atlas_technique_descriptions=("Crafting inputs to manipulate LLM behavior",),
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01", "LLM06"],
        )
        assert ct.seed_id == "AP-T7-01"
        assert ct.threat_id == "T7"
        assert ct.threat_name == "Misaligned Behaviors"
        assert ct.attack_pattern_name == "Constraint bypass"
        assert ct.attack_pattern_description == "Agent bypasses constraints"
        assert ct.entry_point == "user prompts (input)"
        assert ct.atlas_technique_ids == ("AML.T0051",)
        assert ct.atlas_technique_names == ("LLM Prompt Injection",)
        assert ct.atlas_technique_descriptions == ("Crafting inputs to manipulate LLM behavior",)
        assert ct.risk_card_ref.risk_id == "risk-1"
        assert ct.owasp_llm_ids == ["LLM01", "LLM06"]

    def test_candidate_triple_multi_technique(self):
        """CandidateTriple with multiple techniques in a combo."""
        ct = CandidateTriple(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051", "AML.T0054"),
            atlas_technique_names=("LLM Prompt Injection", "LLM Jailbreak"),
            atlas_technique_descriptions=("Crafting inputs", "Bypassing guardrails"),
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
        )
        assert len(ct.atlas_technique_ids) == 2
        assert ct.atlas_technique_ids == ("AML.T0051", "AML.T0054")


class TestFilterVerdict:
    """FilterVerdict model validation."""

    def test_filter_verdict_accept(self):
        """FilterVerdict with verdict='accept' and a rationale."""
        v = FilterVerdict(
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051",),
            verdict="accept",
            rationale="Entry point directly exposes the LLM to user-crafted input.",
        )
        assert v.verdict == "accept"
        assert v.rationale == "Entry point directly exposes the LLM to user-crafted input."

    def test_filter_verdict_reject(self):
        """FilterVerdict with verdict='reject' and a rationale."""
        v = FilterVerdict(
            entry_point="internal API (tool_execution)",
            atlas_technique_ids=("AML.T0054",),
            verdict="reject",
            rationale="No plausible path from this entry point to the technique.",
        )
        assert v.verdict == "reject"
        assert v.entry_point == "internal API (tool_execution)"
        assert v.atlas_technique_ids == ("AML.T0054",)

    def test_filter_verdict_invalid_verdict(self):
        """verdict must be 'accept' or 'reject', not 'maybe'."""
        with pytest.raises(ValidationError) as exc_info:
            FilterVerdict(
                entry_point="user prompts (input)",
                atlas_technique_ids=("AML.T0051",),
                verdict="maybe",
                rationale="Uncertain.",
            )
        # Pydantic should report the literal constraint violation
        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert any("verdict" in str(e.get("loc", "")) for e in errors)

    def test_filter_verdict_multi_technique(self):
        """FilterVerdict with a multi-technique combo."""
        v = FilterVerdict(
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051", "AML.T0054"),
            verdict="accept",
            rationale="Both techniques are plausible in combination.",
        )
        assert len(v.atlas_technique_ids) == 2


class TestBatchFilterResponse:
    """BatchFilterResponse model validation."""

    def test_batch_filter_response(self):
        """BatchFilterResponse with seed_id and list of verdicts."""
        v1 = FilterVerdict(
            entry_point="user prompts (input)",
            atlas_technique_ids=("AML.T0051",),
            verdict="accept",
            rationale="Direct exposure.",
        )
        v2 = FilterVerdict(
            entry_point="internal API (tool_execution)",
            atlas_technique_ids=("AML.T0054",),
            verdict="reject",
            rationale="No path.",
        )
        resp = BatchFilterResponse(seed_id="AP-T7-01", verdicts=[v1, v2])
        assert resp.seed_id == "AP-T7-01"
        assert len(resp.verdicts) == 2
        assert resp.verdicts[0].verdict == "accept"
        assert resp.verdicts[1].verdict == "reject"


class TestFilteredSeed:
    """FilteredSeed model validation."""

    def test_filtered_seed_inherits_scenario_seed(self):
        """FilteredSeed has all ScenarioSeed fields plus pinned fields."""
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts (input)",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("LLM Prompt Injection",),
        )
        # ScenarioSeed fields present
        assert fs.seed_id == "AP-T7-01"
        assert fs.threat_id == "T7"
        assert fs.threat_name == "Misaligned Behaviors"
        assert fs.attack_pattern_name == "Constraint bypass"
        assert fs.attack_pattern_description == "Agent bypasses constraints"
        assert fs.risk_card_ref.risk_id == "risk-1"
        assert fs.owasp_llm_ids == ["LLM01"]
        assert fs.agentic_threat_ids == ["T7"]
        # Pinned fields
        assert fs.pinned_entry_point == "user prompts (input)"
        assert fs.pinned_technique_ids == ("AML.T0051",)
        assert fs.pinned_technique_names == ("LLM Prompt Injection",)
        # Inherits from ScenarioSeed
        assert isinstance(fs, ScenarioSeed)

    def test_filtered_seed_default_rejection_rationales(self):
        """Default rejection_rationales is an empty list."""
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts (input)",
            pinned_technique_ids=("AML.T0051",),
            pinned_technique_names=("LLM Prompt Injection",),
        )
        assert fs.rejection_rationales == []
        assert isinstance(fs.rejection_rationales, list)

    def test_filtered_seed_multi_technique(self):
        """FilteredSeed with multiple pinned techniques."""
        fs = FilteredSeed(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T7"],
            pinned_entry_point="user prompts (input)",
            pinned_technique_ids=("AML.T0051", "AML.T0054"),
            pinned_technique_names=("LLM Prompt Injection", "LLM Jailbreak"),
        )
        assert len(fs.pinned_technique_ids) == 2
        assert len(fs.pinned_technique_names) == 2


# ---------------------------------------------------------------------------
# Expansion tests (skip if expand_candidates not yet available)
# ---------------------------------------------------------------------------

_expand_candidates = pytest.importorskip(
    "scenario_forge.pipeline.candidates",
    reason="expand_candidates not yet available",
).expand_candidates if hasattr(
    __import__("scenario_forge.pipeline.candidates", fromlist=["expand_candidates"]),
    "expand_candidates",
) else None

_skip_expand = pytest.mark.skipif(
    _expand_candidates is None,
    reason="expand_candidates not yet available in scenario_forge.pipeline.candidates",
)


@_skip_expand
class TestExpandCandidates:
    """expand_candidates() cross-product logic."""

    def test_expand_candidates_cross_product(self):
        """2 seeds x 2 entry points x 2 techniques = 8 candidates."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051", "AML.T0054"]),
            _make_seed("AP-T2-01", "T2", atlas_technique_ids=["AML.T0051", "AML.T0054"]),
        ]
        profile = _make_profile(
            entry_points=["user prompts (input)", "API calls (tool_execution)"],
        )
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 8

    def test_expand_candidates_carries_full_context(self):
        """Each CandidateTriple has attack_pattern_name, description,
        technique name(s), technique description(s), and entry point text."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051"]),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) >= 1
        c = candidates[0]
        # Full context carried (not empty / not just IDs)
        assert c.attack_pattern_name != ""
        assert c.attack_pattern_description != ""
        assert len(c.atlas_technique_names) >= 1
        assert c.atlas_technique_names[0] != ""
        assert len(c.atlas_technique_descriptions) >= 1
        assert c.entry_point != ""

    def test_expand_candidates_empty_techniques(self):
        """Seed with no technique IDs (ATLAS or LAAF) produces no candidates."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=[], laaf_technique_ids=[]),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 0

    def test_expand_candidates_laaf_only_fallback(self):
        """Seed with LAAF IDs but no ATLAS IDs uses LAAF for cross-product."""
        seeds = [
            _make_seed(
                "AP-T7-01", "T7",
                atlas_technique_ids=[],
                laaf_technique_ids=["S1", "M3"],
            ),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        # 1 seed x 1 entry_point x 2 LAAF techniques = 2 candidates
        assert len(candidates) == 2
        technique_ids = {c.atlas_technique_ids[0] for c in candidates}
        assert technique_ids == {"S1", "M3"}

    def test_expand_candidates_atlas_preferred_over_laaf(self):
        """When seed has both ATLAS and LAAF IDs, ATLAS is used."""
        seeds = [
            _make_seed(
                "AP-T2-01", "T2",
                atlas_technique_ids=["AML.T0051"],
                laaf_technique_ids=["S1", "M3"],
            ),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        # Should use ATLAS (1 technique), not LAAF (2 techniques)
        assert len(candidates) == 1
        assert candidates[0].atlas_technique_ids == ("AML.T0051",)

    def test_expand_candidates_empty_entry_points(self):
        """Profile with no entry points returns empty list."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051"]),
        ]
        # CapabilityProfile requires min 1 entry point, so we test with
        # an empty-entry-points object if the function handles it,
        # otherwise we verify the cross-product produces nothing when
        # there are no entry points to iterate over.
        # Since CapabilityProfile validates min_length=1, we construct
        # a mock profile with empty entry_points.
        from unittest.mock import MagicMock

        profile = MagicMock(spec=CapabilityProfile)
        profile.entry_points = []
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 0

    def test_expand_candidates_max_techniques_1_default(self):
        """Default max_techniques=1 produces only single-technique candidates."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051", "AML.T0054", "AML.T0053"]),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        # 1 seed x 1 entry_point x C(3,1)=3 single combos = 3
        assert len(candidates) == 3
        # Each candidate should have exactly 1 technique
        for c in candidates:
            assert len(c.atlas_technique_ids) == 1

    def test_expand_candidates_max_techniques_2(self):
        """max_techniques=2 produces C(N,1)+C(N,2) candidates per seed x entry_point."""
        n_techniques = 4
        technique_ids = [f"AML.T00{i}" for i in range(n_techniques)]
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=technique_ids),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile, max_techniques=2)
        # Expected: C(4,1) + C(4,2) = 4 + 6 = 10
        expected = math.comb(n_techniques, 1) + math.comb(n_techniques, 2)
        assert len(candidates) == expected

        # Verify we have both single and pair combos
        singles = [c for c in candidates if len(c.atlas_technique_ids) == 1]
        pairs = [c for c in candidates if len(c.atlas_technique_ids) == 2]
        assert len(singles) == math.comb(n_techniques, 1)
        assert len(pairs) == math.comb(n_techniques, 2)

    def test_expand_candidates_max_techniques_3(self):  # noqa: E301
        """max_techniques=3 with 3 techniques produces C(3,1)+C(3,2)+C(3,3)=7."""
        n_techniques = 3
        technique_ids = ["AML.T0051", "AML.T0054", "AML.T0053"]
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=technique_ids),
        ]
        profile = _make_profile(entry_points=["ep1"])
        candidates = _expand_candidates(seeds, profile, max_techniques=3)
        # C(3,1) + C(3,2) + C(3,3) = 3 + 3 + 1 = 7
        expected = sum(math.comb(n_techniques, k) for k in range(1, 4))
        assert len(candidates) == expected

    def test_expand_candidates_max_techniques_2_multiple_seeds_and_entry_points(self):
        """Combinatorial count with 2 seeds x 2 entry points x max_techniques=2."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=["AML.T0051", "AML.T0054"]),
            _make_seed("AP-T2-01", "T2", atlas_technique_ids=["AML.T0051", "AML.T0054"]),
        ]
        profile = _make_profile(
            entry_points=["user prompts (input)", "API calls (tool_execution)"],
        )
        candidates = _expand_candidates(seeds, profile, max_techniques=2)
        # 2 seeds x 2 entry_points x (C(2,1) + C(2,2)) = 2 x 2 x 3 = 12
        combos_per_seed_ep = math.comb(2, 1) + math.comb(2, 2)  # 3
        assert len(candidates) == 2 * 2 * combos_per_seed_ep


# ---------------------------------------------------------------------------
# cap_scenarios_per_pattern greedy marginal coverage tests
# ---------------------------------------------------------------------------


class TestCapScenariosPerPattern:
    """Greedy marginal coverage capping logic."""

    # -- Core algorithm properties --

    def test_dual_technique_preferred_over_single(self):
        """A dual-technique candidate covers more new techniques and is selected first."""
        dual = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        single = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051",),
        )
        # Only 1 slot: the dual-technique candidate should win.
        result = cap_scenarios_per_pattern([single, dual], max_per_pattern=1)
        assert len(result) == 1
        assert result[0].pinned_technique_ids == ("AML.T0051", "AML.T0054")

    def test_entry_point_diversity_adds_score(self):
        """A new entry point contributes +1, so candidates with unseen entry points are preferred."""
        # Both cover the same technique, but ep2 is a new entry point.
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        c = _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0051",))

        result = cap_scenarios_per_pattern([a, b, c], max_per_pattern=2)
        assert len(result) == 2
        entry_points = {fs.pinned_entry_point for fs in result}
        assert entry_points == {"ep1", "ep2"}

    def test_technique_coverage_then_entry_point_diversity(self):
        """After all techniques are covered, entry-point diversity drives selection."""
        # T0051 + T0054 covered by first pick (dual). Second pick should favor new EP.
        dual_ep1 = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        single_ep1 = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0051",),
        )
        single_ep2 = _make_filtered_seed(
            entry_point="ep2",
            technique_ids=("AML.T0051",),
        )
        result = cap_scenarios_per_pattern(
            [dual_ep1, single_ep1, single_ep2], max_per_pattern=2,
        )
        assert len(result) == 2
        # First pick: dual on ep1 (marginal=3: 2 new techs + 1 new ep).
        assert result[0] is dual_ep1
        # Second pick: single_ep2 wins (marginal=1 for new ep) over single_ep1 (marginal=0).
        assert result[1] is single_ep2

    def test_cap_respected(self):
        """Never more than max_per_pattern returned per seed_id."""
        seeds = [
            _make_filtered_seed(entry_point=f"ep{i}", technique_ids=(f"AML.T{i:04d}",))
            for i in range(10)
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=3)
        assert len(result) == 3

    def test_no_capping_when_under_limit(self):
        """Groups at or below the limit pass through unchanged."""
        seeds = [
            _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",)),
            _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0054",)),
        ]
        result = cap_scenarios_per_pattern(seeds, max_per_pattern=5)
        assert len(result) == 2
        assert result == seeds

    # -- Edge cases --

    def test_empty_input(self):
        """Empty input produces empty output."""
        result = cap_scenarios_per_pattern([], max_per_pattern=3)
        assert result == []

    def test_single_candidate(self):
        """A single candidate passes through regardless of cap."""
        seed = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        result = cap_scenarios_per_pattern([seed], max_per_pattern=1)
        assert len(result) == 1
        assert result[0] is seed

    def test_all_same_entry_point(self):
        """When all candidates share the same entry point, technique diversity drives selection."""
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0054",))
        c = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))

        result = cap_scenarios_per_pattern([a, b, c], max_per_pattern=2)
        assert len(result) == 2
        # First pick: a (1 new tech + 1 new ep = 2). Second pick: b (1 new tech = 1).
        techs = {t for fs in result for t in fs.pinned_technique_ids}
        assert techs == {"AML.T0051", "AML.T0054"}

    def test_max_per_pattern_one(self):
        """max_per_pattern=1 selects the single best candidate."""
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(
            entry_point="ep2",
            technique_ids=("AML.T0051", "AML.T0054"),
        )
        result = cap_scenarios_per_pattern([a, b], max_per_pattern=1)
        assert len(result) == 1
        # b has marginal 3 (2 new techs + 1 new ep) vs a's marginal 2 (1 tech + 1 ep).
        assert result[0].pinned_technique_ids == ("AML.T0051", "AML.T0054")

    def test_invalid_max_per_pattern(self):
        """max_per_pattern < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_per_pattern must be >= 1"):
            cap_scenarios_per_pattern([], max_per_pattern=0)

    # -- Multi-group behaviour --

    def test_multiple_seed_ids_capped_independently(self):
        """Each seed_id group is capped independently."""
        group_a = [
            _make_filtered_seed(seed_id="AP-01", entry_point=f"ep{i}", technique_ids=("AML.T0051",))
            for i in range(5)
        ]
        group_b = [
            _make_filtered_seed(seed_id="AP-02", entry_point=f"ep{i}", technique_ids=("AML.T0054",))
            for i in range(5)
        ]
        result = cap_scenarios_per_pattern(group_a + group_b, max_per_pattern=2)
        ids = [fs.seed_id for fs in result]
        assert ids.count("AP-01") == 2
        assert ids.count("AP-02") == 2

    # -- Tie-breaking --

    def test_tiebreak_prefers_larger_combo(self):
        """When marginal coverage is equal, prefer the larger technique combo."""
        # First pick: 'first' wins with marginal=4 (3 new techs + 1 new ep).
        # After: covered={T1, T2, T3}, seen={ep1}.
        # Second pick:
        #   ta: ep2, (T4,)        -> 1 new tech + 1 new ep = 2, combo_size=1
        #   tb: ep3, (T1, T5)     -> 1 new tech (T5) + 1 new ep = 2, combo_size=2
        # Equal marginal=2 -> tiebreak by combo_size: tb wins.
        first = _make_filtered_seed(
            entry_point="ep1",
            technique_ids=("AML.T0001", "AML.T0002", "AML.T0003"),
        )
        ta = _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0004",))
        tb = _make_filtered_seed(
            entry_point="ep3", technique_ids=("AML.T0001", "AML.T0005"),
        )
        result = cap_scenarios_per_pattern([first, ta, tb], max_per_pattern=2)
        assert len(result) == 2
        assert result[0] is first
        assert result[1] is tb

    def test_tiebreak_encounter_order(self):
        """When marginal and combo size are equal, earlier encounter order wins."""
        a = _make_filtered_seed(entry_point="ep1", technique_ids=("AML.T0051",))
        b = _make_filtered_seed(entry_point="ep2", technique_ids=("AML.T0054",))
        c = _make_filtered_seed(entry_point="ep3", technique_ids=("AML.T0053",))
        # All have the same marginal on first pick (1 tech + 1 ep = 2) and combo_size=1.
        # Tiebreak by encounter order: a first.
        result = cap_scenarios_per_pattern([a, b, c], max_per_pattern=1)
        assert len(result) == 1
        assert result[0] is a

    # -- Greedy selection ordering --

    def test_greedy_technique_coverage_ordering(self):
        """The greedy algorithm picks candidates that maximise new technique coverage."""
        # 4 candidates, 3 techniques, cap=2.
        # dual covers T1+T2, single_t3 covers T3. Together they cover all 3.
        dual = _make_filtered_seed(
            entry_point="ep1", technique_ids=("AML.T0001", "AML.T0002"),
        )
        single_t1 = _make_filtered_seed(
            entry_point="ep2", technique_ids=("AML.T0001",),
        )
        single_t2 = _make_filtered_seed(
            entry_point="ep3", technique_ids=("AML.T0002",),
        )
        single_t3 = _make_filtered_seed(
            entry_point="ep4", technique_ids=("AML.T0003",),
        )
        result = cap_scenarios_per_pattern(
            [single_t1, dual, single_t2, single_t3], max_per_pattern=2,
        )
        assert len(result) == 2
        # dual is picked first (covers 2 new techniques + 1 ep = 3).
        assert result[0] is dual
        # single_t3 is picked second (covers 1 new technique + 1 new ep = 2)
        # vs single_t1 (0 new tech + 1 new ep = 1) and single_t2 (0 + 1 = 1).
        assert result[1] is single_t3
