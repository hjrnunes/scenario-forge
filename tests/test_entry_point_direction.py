"""Tests for entry point directional constraints.

Covers:
- EntryPoint model validation (name, direction, default direction)
- Backward compatibility: plain string -> EntryPoint conversion
- expand_candidates skips output-only entry points
- expand_candidates includes input and bidirectional entry points
- Entry point affinity/assignment functions work with string names
- Serialization round-trip (EntryPoint to dict/JSON and back)
"""

from __future__ import annotations

from collections import Counter

import pytest

from scenario_forge.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    Stage1Profile,
    _coerce_entry_points,
)
from scenario_forge.models.scenario import RiskCardRef
from scenario_forge.pipeline.candidates import expand_candidates
from scenario_forge.pipeline.generate import (
    assign_entry_point,
    compute_entry_point_affinity,
    get_overused_entry_points,
)
from scenario_forge.pipeline.seeds import ScenarioSeed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_seed(seed_id: str = "AP-T1-01") -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id="T1",
        threat_name="Test Threat",
        attack_pattern_name="Test Attack Pattern",
        attack_pattern_description="A test description",
        risk_card_ref=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="Test description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
        atlas_technique_ids=["AML.T0051"],
    )


def _make_profile(
    entry_points: list | None = None,
) -> CapabilityProfile:
    if entry_points is None:
        entry_points = [
            EntryPoint(name="user prompts (input)", direction="input"),
        ]
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=entry_points,
        confidence="high",
    )


# ---------------------------------------------------------------------------
# EntryPoint model validation
# ---------------------------------------------------------------------------


class TestEntryPointModel:
    """Tests for the EntryPoint model itself."""

    def test_basic_construction(self):
        ep = EntryPoint(name="user prompts via chat", direction="input")
        assert ep.name == "user prompts via chat"
        assert ep.direction == "input"

    def test_default_direction_is_bidirectional(self):
        ep = EntryPoint(name="some endpoint")
        assert ep.direction == "bidirectional"

    def test_output_direction(self):
        ep = EntryPoint(name="backend API calls", direction="output")
        assert ep.direction == "output"

    def test_bidirectional_direction(self):
        ep = EntryPoint(name="webhook endpoint", direction="bidirectional")
        assert ep.direction == "bidirectional"

    def test_invalid_direction_rejected(self):
        with pytest.raises(Exception):
            EntryPoint(name="test", direction="inbound")

    def test_str_returns_name(self):
        ep = EntryPoint(name="user chat widget", direction="input")
        assert str(ep) == "user chat widget"


# ---------------------------------------------------------------------------
# Backward compatibility: plain string -> EntryPoint conversion
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Backward-compat: plain strings are coerced to EntryPoint objects."""

    def test_coerce_plain_string(self):
        result = _coerce_entry_points(["user prompts (input)"])
        assert len(result) == 1
        assert isinstance(result[0], EntryPoint)
        assert result[0].name == "user prompts (input)"
        assert result[0].direction == "bidirectional"

    def test_coerce_dict_with_name_only(self):
        result = _coerce_entry_points([{"name": "chat widget"}])
        assert len(result) == 1
        assert result[0].name == "chat widget"
        assert result[0].direction == "bidirectional"

    def test_coerce_dict_with_direction(self):
        result = _coerce_entry_points(
            [{"name": "backend API", "direction": "output"}]
        )
        assert len(result) == 1
        assert result[0].name == "backend API"
        assert result[0].direction == "output"

    def test_coerce_entry_point_passthrough(self):
        ep = EntryPoint(name="test", direction="input")
        result = _coerce_entry_points([ep])
        assert result[0] is ep

    def test_coerce_mixed_types(self):
        result = _coerce_entry_points([
            "plain string entry",
            {"name": "dict entry", "direction": "output"},
            EntryPoint(name="object entry", direction="input"),
        ])
        assert len(result) == 3
        assert result[0].name == "plain string entry"
        assert result[0].direction == "bidirectional"
        assert result[1].name == "dict entry"
        assert result[1].direction == "output"
        assert result[2].name == "object entry"
        assert result[2].direction == "input"

    def test_capability_profile_accepts_plain_strings(self):
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (input)", "API endpoint (input)"],
            confidence="high",
        )
        assert len(profile.entry_points) == 2
        assert all(isinstance(ep, EntryPoint) for ep in profile.entry_points)
        assert profile.entry_points[0].name == "user prompts (input)"
        assert profile.entry_points[0].direction == "bidirectional"

    def test_stage1_profile_accepts_plain_strings(self):
        profile = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=["user prompts (input)"],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        assert len(profile.entry_points) == 1
        assert isinstance(profile.entry_points[0], EntryPoint)
        assert profile.entry_points[0].name == "user prompts (input)"

    def test_stage1_profile_accepts_dicts(self):
        profile = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=[
                {"name": "user prompts", "direction": "input"},
                {"name": "backend calls", "direction": "output"},
            ],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        assert profile.entry_points[0].direction == "input"
        assert profile.entry_points[1].direction == "output"


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSerialization:
    """EntryPoint serialization round-trip tests."""

    def test_entry_point_to_dict(self):
        ep = EntryPoint(name="user chat", direction="input")
        d = ep.model_dump()
        assert d == {"name": "user chat", "direction": "input"}

    def test_entry_point_from_dict(self):
        d = {"name": "backend API", "direction": "output"}
        ep = EntryPoint(**d)
        assert ep.name == "backend API"
        assert ep.direction == "output"

    def test_entry_point_json_round_trip(self):
        ep = EntryPoint(name="webhook endpoint", direction="bidirectional")
        json_str = ep.model_dump_json()
        restored = EntryPoint.model_validate_json(json_str)
        assert restored.name == ep.name
        assert restored.direction == ep.direction

    def test_profile_model_dump_includes_direction(self):
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="chat input", direction="input"),
                EntryPoint(name="api calls", direction="output"),
            ]
        )
        data = profile.model_dump(mode="json")
        ep_data = data["entry_points"]
        assert ep_data[0] == {"name": "chat input", "direction": "input"}
        assert ep_data[1] == {"name": "api calls", "direction": "output"}

    def test_profile_model_dump_reload(self):
        """Round-trip: profile -> dict -> profile preserves entry points."""
        original = _make_profile(
            entry_points=[
                EntryPoint(name="input ep", direction="input"),
                EntryPoint(name="output ep", direction="output"),
                EntryPoint(name="bidi ep", direction="bidirectional"),
            ]
        )
        data = original.model_dump(mode="json")
        restored = CapabilityProfile(**data)
        assert len(restored.entry_points) == 3
        assert restored.entry_points[0].name == "input ep"
        assert restored.entry_points[0].direction == "input"
        assert restored.entry_points[1].direction == "output"
        assert restored.entry_points[2].direction == "bidirectional"


# ---------------------------------------------------------------------------
# expand_candidates: direction filtering
# ---------------------------------------------------------------------------


class TestExpandCandidatesDirectionFilter:
    """Tests that expand_candidates respects entry point direction."""

    def test_output_only_entry_points_excluded(self):
        """Output-only entry points should NOT appear in candidates."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="user prompts (input)", direction="input"),
                EntryPoint(name="backend API calls", direction="output"),
            ]
        )
        candidates = expand_candidates(seeds, profile)
        entry_points_in_candidates = {c.entry_point for c in candidates}
        assert "user prompts (input)" in entry_points_in_candidates
        assert "backend API calls" not in entry_points_in_candidates

    def test_input_entry_points_included(self):
        """Input entry points should appear in candidates."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="user chat (input)", direction="input"),
            ]
        )
        candidates = expand_candidates(seeds, profile)
        assert len(candidates) == 1
        assert candidates[0].entry_point == "user chat (input)"

    def test_bidirectional_entry_points_included(self):
        """Bidirectional entry points should appear in candidates."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="webhook endpoint", direction="bidirectional"),
            ]
        )
        candidates = expand_candidates(seeds, profile)
        assert len(candidates) == 1
        assert candidates[0].entry_point == "webhook endpoint"

    def test_all_output_returns_empty(self):
        """When all entry points are output-only, no candidates are generated."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="backend API", direction="output"),
                EntryPoint(name="escalation trigger", direction="output"),
            ]
        )
        candidates = expand_candidates(seeds, profile)
        assert candidates == []

    def test_mixed_directions_filters_correctly(self):
        """Only input and bidirectional entry points produce candidates."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="user prompts", direction="input"),
                EntryPoint(name="backend API calls", direction="output"),
                EntryPoint(name="webhook", direction="bidirectional"),
                EntryPoint(name="escalation", direction="output"),
            ]
        )
        candidates = expand_candidates(seeds, profile)
        entry_points_used = {c.entry_point for c in candidates}
        assert entry_points_used == {"user prompts", "webhook"}
        # 1 seed x 2 ingress entry points x 1 technique = 2 candidates
        assert len(candidates) == 2

    def test_backward_compat_strings_are_bidirectional(self):
        """Plain string entry points default to bidirectional and are included."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                "legacy plain string entry point",
            ]
        )
        candidates = expand_candidates(seeds, profile)
        assert len(candidates) == 1
        assert candidates[0].entry_point == "legacy plain string entry point"

    def test_candidate_entry_point_is_name_string(self):
        """CandidateTriple.entry_point should be a plain string (the name), not an EntryPoint object."""
        seeds = [_make_seed()]
        profile = _make_profile(
            entry_points=[
                EntryPoint(name="user prompts (input)", direction="input"),
            ]
        )
        candidates = expand_candidates(seeds, profile)
        assert isinstance(candidates[0].entry_point, str)
        assert candidates[0].entry_point == "user prompts (input)"


# ---------------------------------------------------------------------------
# Entry point affinity/assignment with string names
# ---------------------------------------------------------------------------


class TestAffinityWithEntryPointNames:
    """The affinity/assignment/overuse functions operate on string names.

    This confirms they work correctly when called with entry point name
    strings extracted from EntryPoint objects (as the pipeline does).
    """

    def test_affinity_with_entry_point_names(self):
        """compute_entry_point_affinity works with plain string names."""
        names = ["user input form (zone 1)", "admin console (zone 2)"]
        scores = compute_entry_point_affinity(names, ["input", "reasoning"])
        assert len(scores) == 2
        for score in scores.values():
            assert 0.0 <= score <= 1.0

    def test_assign_with_entry_point_names(self):
        """assign_entry_point works with plain string names."""
        names = ["chat input (zone 1)", "API endpoint (zone 1)"]
        result = assign_entry_point(names, ["input"], Counter(), 10)
        assert result in names

    def test_overused_with_entry_point_names(self):
        """get_overused_entry_points works with plain string names."""
        names = ["a", "b"]
        usage = Counter({"a": 6})
        result = get_overused_entry_points(names, usage, 10)
        assert result == ["a"]


# ---------------------------------------------------------------------------
# Stage1Profile.to_capability_profile preserves direction
# ---------------------------------------------------------------------------


class TestStage1ToCapabilityProfile:
    """Verify that to_capability_profile preserves entry point direction."""

    def test_direction_preserved_through_promotion(self):
        stage1 = Stage1Profile(
            has_persistent_memory=False,
            multi_agent=False,
            hitl=False,
            entry_points=[
                {"name": "user prompts", "direction": "input"},
                {"name": "backend calls", "direction": "output"},
                {"name": "webhook", "direction": "bidirectional"},
            ],
            confidence="high",
            kc_subcodes=["KC1.1"],
        )
        profile = stage1.to_capability_profile()
        assert len(profile.entry_points) == 3
        assert profile.entry_points[0].direction == "input"
        assert profile.entry_points[1].direction == "output"
        assert profile.entry_points[2].direction == "bidirectional"
