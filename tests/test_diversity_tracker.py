"""Tests for the DiversityTracker extracted from runner.py."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone

import pytest

from scenario_forge.models.attack_tree import AttackTree, AttackTreeNode, GateType
from scenario_forge.models.scenario import (
    ACTOR_TYPES,
    ActorProfile,
    CallMetadata,
    CallName,
    CapabilityProfileRef,
    FacetingMetadata,
    GenerationMetadata,
    NarrativeLayer,
    NarrativeStep,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    TaxonomyChain,
)
from scenario_forge.pipeline.diversity import (
    DiversityHints,
    DiversityTracker,
    _CAP_LEVELS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_envelope(
    title: str = "Test Scenario",
    entry_point: str = "user prompts (input)",
    actor_type: str = "cybercriminal",
    capability_level: str = "intermediate",
    goal_category: str | None = None,
    steps: list[NarrativeStep] | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing tracker.update()."""
    if steps is None:
        steps = [
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Inject malicious content into the prompt",
                effect="Agent processes the injected content",
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Exfiltrate sensitive data via side channel",
                effect="Data leaks to external server",
            ),
        ]
    zone_sequence = ["input", "reasoning"]

    narrative = NarrativeLayer(
        title=title,
        summary="A test scenario summary.",
        entry_point=entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
    )

    actor = ActorProfile(
        actor_type=actor_type,
        capability_level=capability_level,
        beliefs=["The system is vulnerable"],
        desires=["Steal data"],
        intentions=["Inject then exfiltrate"],
        resources=["Open-source tools"],
        goal_category=goal_category,
    )

    attack_tree = AttackTree(
        id="tree-AP-T2-01",
        seed_id="AP-T2-01",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1", label="Inject", gate=GateType.LEAF, zone="input"
                ),
                AttackTreeNode(
                    id="n1.2", label="Exfiltrate", gate=GateType.LEAF, zone="reasoning"
                ),
            ],
        ),
    )

    faceting = FacetingMetadata(
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T2"],
            scenario_seed="AP-T2-01",
        ),
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=zone_sequence,
            architecture_match="explicit",
            entry_point=entry_point,
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity="feasible",
            risk_impact="high",
            risk_likelihood="medium",
            attack_complexity="medium",
            architecture_match="explicit",
            structural_exposure="none",
        ),
    )

    return ScenarioEnvelope(
        scenario_id="test-001",
        version=1,
        generated_at=datetime.now(timezone.utc),
        generator_version="0.0.0-test",
        narrative=narrative,
        actor_profile=actor,
        attack_tree=attack_tree,
        behavior_spec="Feature: test\n  Scenario: basic\n    Given context\n    When action\n    Then result",
        faceting=faceting,
        priority=priority,
        generation=GenerationMetadata(
            model="test-model",
            call_metadata=[
                CallMetadata(
                    call=CallName.narrative,
                    prompt_tokens=100,
                    completion_tokens=50,
                    duration_ms=1000,
                ),
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------


class TestDiversityTrackerInit:
    """Test DiversityTracker initialization."""

    def test_empty_counters(self):
        tracker = DiversityTracker()
        assert tracker.entry_point_usage == Counter()
        assert tracker.pattern_usage == Counter()
        assert tracker.structural_usage == Counter()
        assert tracker.actor_type_usage == Counter()
        assert tracker.capability_level_usage == Counter()
        assert tracker.goal_usage == Counter()

    def test_empty_prior_titles(self):
        tracker = DiversityTracker()
        assert tracker.prior_titles == []

    def test_counters_are_independent(self):
        tracker = DiversityTracker()
        tracker.actor_type_usage["cybercriminal"] += 1
        assert tracker.capability_level_usage["cybercriminal"] == 0


# ---------------------------------------------------------------------------
# Diversity hint computation with empty counters
# ---------------------------------------------------------------------------


class TestDiversityHintsEmpty:
    """Test diversity hint computation with empty/fresh counters."""

    def test_excluded_patterns_empty(self):
        tracker = DiversityTracker()
        assert tracker.get_excluded_patterns() is None

    def test_excluded_structural_patterns_empty(self):
        tracker = DiversityTracker()
        assert tracker.get_excluded_structural_patterns() is None

    def test_preferred_actor_empty(self):
        tracker = DiversityTracker()
        # With all zero counts, min picks the first in ACTOR_TYPES order.
        result = tracker.get_preferred_actor(total_seeds=10)
        assert result == ACTOR_TYPES[0]

    def test_excluded_actors_empty(self):
        tracker = DiversityTracker()
        # With no usage, no actor exceeds fair share.
        assert tracker.get_excluded_actors(total_seeds=10) is None

    def test_preferred_capability_level_empty(self):
        tracker = DiversityTracker()
        result = tracker.get_preferred_capability_level()
        assert result == _CAP_LEVELS[0]

    def test_select_goal_no_goals(self):
        tracker = DiversityTracker()
        result = tracker.select_goal(
            seed_threat_id="T2",
            available_goals=[],
            zones_active=["input", "reasoning"],
            kc_subcodes=None,
            total_seeds=10,
        )
        assert result is None

    def test_get_diversity_hints_returns_hints_object(self):
        tracker = DiversityTracker()
        hints = tracker.get_diversity_hints(
            seed_threat_id="T2",
            total_seeds=10,
            available_goals=[],
            zones_active=["input", "reasoning"],
            kc_subcodes=None,
        )
        assert isinstance(hints, DiversityHints)
        assert hints.excluded_patterns is None
        assert hints.excluded_structural_patterns is None
        assert hints.preferred_actor_type == ACTOR_TYPES[0]
        assert hints.excluded_actor_types is None
        assert hints.preferred_capability_level == _CAP_LEVELS[0]
        assert hints.selected_goal is None


# ---------------------------------------------------------------------------
# Diversity hint computation with populated counters
# ---------------------------------------------------------------------------


class TestDiversityHintsPopulated:
    """Test diversity hint computation with populated counters."""

    def test_excluded_patterns_when_overused(self):
        tracker = DiversityTracker()
        # Pump a keyword past the threshold (default 2)
        tracker.pattern_usage["injection"] = 5
        tracker.pattern_usage["poison"] = 3
        tracker.pattern_usage["probe"] = 1
        result = tracker.get_excluded_patterns()
        assert result is not None
        assert "injection" in result
        assert "poison" in result
        assert "probe" not in result

    def test_excluded_structural_when_overused(self):
        tracker = DiversityTracker()
        tracker.structural_usage["inject->exfiltrate"] = 4
        tracker.structural_usage["probe->inject"] = 1
        result = tracker.get_excluded_structural_patterns()
        assert result is not None
        assert "inject->exfiltrate" in result
        assert "probe->inject" not in result

    def test_preferred_actor_picks_least_used(self):
        tracker = DiversityTracker()
        tracker.actor_type_usage["cybercriminal"] = 5
        tracker.actor_type_usage["nation-state"] = 3
        # "hacktivist" has 0 usage, so it (or another 0-count type) wins
        result = tracker.get_preferred_actor(total_seeds=20)
        assert tracker.actor_type_usage.get(result, 0) == 0

    def test_preferred_capability_picks_least_used(self):
        tracker = DiversityTracker()
        tracker.capability_level_usage["novice"] = 3
        tracker.capability_level_usage["intermediate"] = 2
        tracker.capability_level_usage["advanced"] = 1
        # "expert" has 0 usage
        result = tracker.get_preferred_capability_level()
        assert result == "expert"


# ---------------------------------------------------------------------------
# Fair-share actor exclusion logic
# ---------------------------------------------------------------------------


class TestFairShareActorExclusion:
    """Test the fair-share actor exclusion logic."""

    def test_no_exclusions_when_under_fair_share(self):
        tracker = DiversityTracker()
        total_seeds = 18  # 9 actor types -> fair share = ceil(18/9) = 2
        tracker.actor_type_usage["cybercriminal"] = 2
        result = tracker.get_excluded_actors(total_seeds=total_seeds)
        # 2 is not > 2, so no exclusion
        assert result is None

    def test_exclusion_when_over_fair_share(self):
        tracker = DiversityTracker()
        total_seeds = 18  # fair share = ceil(18/9) = 2
        tracker.actor_type_usage["cybercriminal"] = 3  # > 2
        tracker.actor_type_usage["nation-state"] = 1
        result = tracker.get_excluded_actors(total_seeds=total_seeds)
        assert result is not None
        assert "cybercriminal" in result
        assert "nation-state" not in result

    def test_fair_share_with_zero_seeds(self):
        tracker = DiversityTracker()
        result = tracker.get_excluded_actors(total_seeds=0)
        # fair share = 1 when total_seeds=0
        assert result is None

    def test_fair_share_ceiling_math(self):
        """Verify the fair-share ceiling matches the expected formula."""
        tracker = DiversityTracker()
        num_actor_types = len(ACTOR_TYPES)
        total_seeds = 15
        expected_fair_share = math.ceil(total_seeds / num_actor_types)

        # Set one actor type just above the ceiling
        tracker.actor_type_usage["cybercriminal"] = expected_fair_share + 1
        result = tracker.get_excluded_actors(total_seeds=total_seeds)
        assert result is not None
        assert "cybercriminal" in result


# ---------------------------------------------------------------------------
# Update tests
# ---------------------------------------------------------------------------


class TestDiversityTrackerUpdate:
    """Test the update method after scenario generation."""

    def test_update_tracks_title(self):
        tracker = DiversityTracker()
        envelope = _make_envelope(title="Data Poisoning Attack")
        tracker.update(envelope, attack_pattern_name="Data Poisoning")
        assert "Data Poisoning Attack" in tracker.prior_titles

    def test_update_tracks_entry_point(self):
        tracker = DiversityTracker()
        envelope = _make_envelope(entry_point="user prompts (input)")
        tracker.update(envelope, attack_pattern_name="Prompt Injection")
        assert tracker.entry_point_usage["user prompts (input)"] == 1

    def test_update_tracks_actor_type(self):
        tracker = DiversityTracker()
        envelope = _make_envelope(actor_type="nation-state")
        tracker.update(envelope, attack_pattern_name="APT Attack")
        assert tracker.actor_type_usage["nation-state"] == 1

    def test_update_tracks_capability_level(self):
        tracker = DiversityTracker()
        envelope = _make_envelope(capability_level="expert")
        tracker.update(envelope, attack_pattern_name="Sophisticated Attack")
        assert tracker.capability_level_usage["expert"] == 1

    def test_update_tracks_goal_category(self):
        tracker = DiversityTracker()
        envelope = _make_envelope(goal_category="PR-1")
        tracker.update(envelope, attack_pattern_name="Privacy Attack")
        assert tracker.goal_usage["PR-1"] == 1

    def test_update_skips_goal_when_none(self):
        tracker = DiversityTracker()
        envelope = _make_envelope(goal_category=None)
        tracker.update(envelope, attack_pattern_name="Generic Attack")
        assert sum(tracker.goal_usage.values()) == 0

    def test_update_tracks_pattern_keywords(self):
        tracker = DiversityTracker()
        envelope = _make_envelope()
        tracker.update(envelope, attack_pattern_name="Data Poisoning via Supply Chain")
        # Should have extracted keywords from the attack pattern name
        assert sum(tracker.pattern_usage.values()) > 0

    def test_update_tracks_structural_pattern(self):
        tracker = DiversityTracker()
        envelope = _make_envelope()
        tracker.update(envelope, attack_pattern_name="Injection Attack")
        # Should have at least one structural pattern recorded
        assert sum(tracker.structural_usage.values()) == 1

    def test_multiple_updates_accumulate(self):
        tracker = DiversityTracker()
        for i in range(3):
            envelope = _make_envelope(
                title=f"Scenario {i}",
                actor_type="cybercriminal",
            )
            tracker.update(envelope, attack_pattern_name=f"Pattern {i}")

        assert len(tracker.prior_titles) == 3
        assert tracker.actor_type_usage["cybercriminal"] == 3

    def test_update_without_actor_profile(self):
        """Envelope with no actor_profile should not crash."""
        tracker = DiversityTracker()
        envelope = _make_envelope()
        # Force actor_profile to None
        envelope.actor_profile = None
        tracker.update(envelope, attack_pattern_name="Test Pattern")
        # Should still track title, entry point, patterns
        assert len(tracker.prior_titles) == 1
        assert sum(tracker.actor_type_usage.values()) == 0
        assert sum(tracker.capability_level_usage.values()) == 0


# ---------------------------------------------------------------------------
# Goal selection integration
# ---------------------------------------------------------------------------


class TestGoalSelectionIntegration:
    """Test goal selection through the DiversityTracker."""

    def test_select_goal_with_available_goals(self):
        tracker = DiversityTracker()
        goals = [
            {
                "id": "PR-1",
                "name": "Data Theft",
                "description": "Steal data",
                "category_id": "PR",
                "category_name": "Privacy",
                "category_description": "Privacy violations",
            },
            {
                "id": "IN-1",
                "name": "Data Corruption",
                "description": "Corrupt data",
                "category_id": "IN",
                "category_name": "Integrity",
                "category_description": "Integrity violations",
            },
        ]
        result = tracker.select_goal(
            seed_threat_id="T2",
            available_goals=goals,
            zones_active=["input", "reasoning", "output"],
            kc_subcodes=None,
            total_seeds=10,
        )
        assert result is not None
        assert result["id"] in ("PR-1", "IN-1")

    def test_select_goal_updates_usage_via_tracker_update(self):
        """Goal usage counter is updated via tracker.update(), not select_goal."""
        tracker = DiversityTracker()
        envelope = _make_envelope(goal_category="PR-1")
        tracker.update(envelope, attack_pattern_name="Data Theft Attack")
        assert tracker.goal_usage["PR-1"] == 1

    def test_hints_include_selected_goal(self):
        tracker = DiversityTracker()
        goals = [
            {
                "id": "AB-1",
                "name": "Jailbreak",
                "description": "Break safety",
                "category_id": "AB",
                "category_name": "Abuse",
                "category_description": "Abuse violations",
            },
        ]
        hints = tracker.get_diversity_hints(
            seed_threat_id="T7",
            total_seeds=5,
            available_goals=goals,
            zones_active=["input", "reasoning", "output"],
            kc_subcodes=None,
        )
        assert hints.selected_goal is not None
        assert hints.selected_goal["id"] == "AB-1"
