"""Tests for the candidate filtering pipeline stage.

Covers:
  - Data model validation for CandidateTriple, FilterVerdict,
    BatchFilterResponse, and FilteredSeed.
  - expand_candidates() cross-product logic (skipped if not yet available).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from scenario_forge.models.capability_profile import CapabilityProfile, ConfidenceLevel
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import (
    BatchFilterResponse,
    CandidateTriple,
    FilteredSeed,
    FilterVerdict,
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
        """CandidateTriple accepts all required fields."""
        ct = CandidateTriple(
            seed_id="AP-T7-01",
            threat_id="T7",
            threat_name="Misaligned Behaviors",
            attack_pattern_name="Constraint bypass",
            attack_pattern_description="Agent bypasses constraints",
            entry_point="user prompts (input)",
            atlas_technique_id="AML.T0051",
            atlas_technique_name="LLM Prompt Injection",
            atlas_technique_description="Crafting inputs to manipulate LLM behavior",
            risk_card_ref=_make_ref(),
            owasp_llm_ids=["LLM01", "LLM06"],
        )
        assert ct.seed_id == "AP-T7-01"
        assert ct.threat_id == "T7"
        assert ct.threat_name == "Misaligned Behaviors"
        assert ct.attack_pattern_name == "Constraint bypass"
        assert ct.attack_pattern_description == "Agent bypasses constraints"
        assert ct.entry_point == "user prompts (input)"
        assert ct.atlas_technique_id == "AML.T0051"
        assert ct.atlas_technique_name == "LLM Prompt Injection"
        assert ct.atlas_technique_description == "Crafting inputs to manipulate LLM behavior"
        assert ct.risk_card_ref.risk_id == "risk-1"
        assert ct.owasp_llm_ids == ["LLM01", "LLM06"]


class TestFilterVerdict:
    """FilterVerdict model validation."""

    def test_filter_verdict_accept(self):
        """FilterVerdict with verdict='accept' and a rationale."""
        v = FilterVerdict(
            entry_point="user prompts (input)",
            atlas_technique_id="AML.T0051",
            verdict="accept",
            rationale="Entry point directly exposes the LLM to user-crafted input.",
        )
        assert v.verdict == "accept"
        assert v.rationale == "Entry point directly exposes the LLM to user-crafted input."

    def test_filter_verdict_reject(self):
        """FilterVerdict with verdict='reject' and a rationale."""
        v = FilterVerdict(
            entry_point="internal API (tool_execution)",
            atlas_technique_id="AML.T0054",
            verdict="reject",
            rationale="No plausible path from this entry point to the technique.",
        )
        assert v.verdict == "reject"
        assert v.entry_point == "internal API (tool_execution)"
        assert v.atlas_technique_id == "AML.T0054"

    def test_filter_verdict_invalid_verdict(self):
        """verdict must be 'accept' or 'reject', not 'maybe'."""
        with pytest.raises(ValidationError) as exc_info:
            FilterVerdict(
                entry_point="user prompts (input)",
                atlas_technique_id="AML.T0051",
                verdict="maybe",
                rationale="Uncertain.",
            )
        # Pydantic should report the literal constraint violation
        errors = exc_info.value.errors()
        assert len(errors) >= 1
        assert any("verdict" in str(e.get("loc", "")) for e in errors)


class TestBatchFilterResponse:
    """BatchFilterResponse model validation."""

    def test_batch_filter_response(self):
        """BatchFilterResponse with seed_id and list of verdicts."""
        v1 = FilterVerdict(
            entry_point="user prompts (input)",
            atlas_technique_id="AML.T0051",
            verdict="accept",
            rationale="Direct exposure.",
        )
        v2 = FilterVerdict(
            entry_point="internal API (tool_execution)",
            atlas_technique_id="AML.T0054",
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
            pinned_technique_id="AML.T0051",
            pinned_technique_name="LLM Prompt Injection",
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
        assert fs.pinned_technique_id == "AML.T0051"
        assert fs.pinned_technique_name == "LLM Prompt Injection"
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
            pinned_technique_id="AML.T0051",
            pinned_technique_name="LLM Prompt Injection",
        )
        assert fs.rejection_rationales == []
        assert isinstance(fs.rejection_rationales, list)


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
        technique name, technique description, and entry point text."""
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
        assert c.atlas_technique_name != ""
        assert c.atlas_technique_description != ""
        assert c.entry_point != ""

    def test_expand_candidates_empty_techniques(self):
        """Seed with no atlas_technique_ids produces no candidates for that seed."""
        seeds = [
            _make_seed("AP-T7-01", "T7", atlas_technique_ids=[]),
        ]
        profile = _make_profile(entry_points=["user prompts (input)"])
        candidates = _expand_candidates(seeds, profile)
        assert len(candidates) == 0

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
