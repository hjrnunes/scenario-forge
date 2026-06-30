"""Tests for post-generation coverage analysis.

Covers:
- Coverage gap analysis (scenario-forge-n63):
  - All entry points covered (no gaps)
  - Some entry points missing
  - All entry points missing
  - Zone coverage gaps
  - Threat coverage gaps
  - Empty scenarios list
- Actor profile diversity:
  - Diverse actor types (no flag)
  - Monotone actor types (flagged)
  - Single scenario edge case
  - Missing actor profile (unknown)
  - Empty scenarios list
- Coverage report output
- Coverage remediation (scenario-forge-5gs):
  - _pick_best_seed_for_entry_point selection
  - _remediate_coverage_gaps full flow
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scenario_forge.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
)
from scenario_forge.models.capability_profile import CapabilityProfile
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
from scenario_forge.models.scenario import ActorProfile
from scenario_forge.pipeline.coverage import (
    AttackerDiversityResult,
    CoverageGaps,
    _normalize_entry_point,
    analyze_attacker_diversity,
    analyze_coverage_gaps,
    write_coverage_report,
)
from scenario_forge.pipeline.runner import (
    _pick_best_seed_for_entry_point,
    _remediate_coverage_gaps,
)
from scenario_forge.pipeline.seeds import ScenarioSeed
from scenario_forge.pipeline.threats import ThreatSurface, ThreatSurfaceEntry


# ---------------------------------------------------------------------------
# Fixtures: helpers to build minimal valid objects
# ---------------------------------------------------------------------------


def _make_risk_card_ref(risk_id: str = "test-risk") -> RiskCardRef:
    return RiskCardRef(
        risk_id=risk_id,
        risk_name="Test Risk",
        risk_description="A test risk.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _make_envelope(
    entry_point: str = "user prompts (zone 1)",
    zone_sequence: list[int] | None = None,
    agentic_threat_ids: list[str] | None = None,
    summary: str = "The attacker exploits user prompts to inject malicious instructions.",
    step_actions: list[str] | None = None,
    actor_type: str | None = "adversarial-user",
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope for testing."""
    if zone_sequence is None:
        zone_sequence = [1, 2]
    if agentic_threat_ids is None:
        agentic_threat_ids = ["T1"]
    if step_actions is None:
        step_actions = ["I craft a malicious prompt to inject commands."]

    steps = [
        NarrativeStep(
            step_number=i + 1,
            zone=zone_sequence[min(i, len(zone_sequence) - 1)],
            action=action,
            effect="The system processes the input.",
        )
        for i, action in enumerate(step_actions)
    ]

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary=summary,
        entry_point=entry_point,
        zone_sequence=zone_sequence,
        steps=steps,
    )

    attack_tree = AttackTree(
        id="tree-T1-S1",
        seed_id="T1-S1",
        goal="Compromise the system",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.OR,
            zone=1,
            children=[
                AttackTreeNode(id="n1.1", label="Path A", gate=GateType.LEAF, zone=1),
                AttackTreeNode(id="n1.2", label="Path B", gate=GateType.LEAF, zone=2),
            ],
        ),
    )

    faceting = FacetingMetadata(
        risk_card=_make_risk_card_ref(),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=agentic_threat_ids,
            scenario_seed="T1-S1",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=zone_sequence,
            architecture_match=ArchitectureMatch.explicit,
            entry_point=entry_point,
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

    actor_profile = None
    if actor_type is not None:
        actor_profile = ActorProfile(
            actor_type=actor_type,  # type: ignore[arg-type]
            motivation="Motivated to compromise the system.",
            objective="Exfiltrate sensitive data.",
            capability_level="intermediate",
            resources=["open-source tools"],
            campaign_context="Opportunistic attack.",
        )

    return ScenarioEnvelope(
        scenario_id="T1-S1-abc123",
        generated_at=datetime.now(),
        generator_version="0.1.0",
        actor_profile=actor_profile,
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec={},
        faceting=faceting,
        priority=priority,
        generation=generation,
    )


def _make_profile(
    entry_points: list[str] | None = None,
    zones_active: list[int] | None = None,
) -> CapabilityProfile:
    if entry_points is None:
        entry_points = [
            "user prompts (zone 1)",
            "document uploads (zone 1)",
            "admin console (zone 2)",
        ]
    if zones_active is None:
        zones_active = [1, 2, 3]
    return CapabilityProfile(
        zones_active=zones_active,
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=entry_points,
        confidence="high",
    )


def _make_threat_surface(
    threat_ids: list[list[str]] | None = None,
) -> ThreatSurface:
    """Build a ThreatSurface with the given threat IDs per entry."""
    if threat_ids is None:
        threat_ids = [["T1", "T2"]]
    entries = []
    for i, ids in enumerate(threat_ids):
        entries.append(
            ThreatSurfaceEntry(
                risk_card=_make_risk_card_ref(f"risk-{i}"),
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=ids,
                sub_scenarios=[f"{t}-S1" for t in ids],
            )
        )
    return ThreatSurface(entries=entries, governance_only=[])


# ---------------------------------------------------------------------------
# Coverage gap analysis tests (scenario-forge-n63)
# ---------------------------------------------------------------------------


class TestCoverageGaps:
    """Tests for analyze_coverage_gaps."""

    def test_all_entry_points_covered(self):
        """When every entry point has at least one scenario, no gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(entry_point="ep-a (zone 1)", agentic_threat_ids=["T1"]),
            _make_envelope(entry_point="ep-b (zone 2)", agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []
        assert not gaps.has_gaps

    def test_some_entry_points_missing(self):
        """When some entry points have no scenarios, they appear as gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)", "ep-c (zone 3)"],
            zones_active=[1, 2, 3],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="ep-a (zone 1)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_entry_points) == {"ep-b (zone 2)", "ep-c (zone 3)"}
        assert gaps.has_gaps

    def test_all_entry_points_missing(self):
        """No scenarios at all means every entry point is uncovered."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)"],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_entry_points) == {"ep-a (zone 1)", "ep-b (zone 2)"}

    def test_all_zones_covered(self):
        """When all active zones are traversed, no zone gaps."""
        profile = _make_profile(zones_active=[1, 2, 3])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=[1, 2, 3], agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == []

    def test_some_zones_uncovered(self):
        """Zones not traversed by any scenario appear as gaps."""
        profile = _make_profile(zones_active=[1, 2, 3])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=[1, 2], agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == [3]

    def test_all_threats_covered(self):
        """When every in-scope threat has at least one scenario, no gaps."""
        threat_surface = _make_threat_surface([["T1", "T2"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1", "T2"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == []

    def test_some_threats_uncovered(self):
        """Threats with no scenarios appear as gaps."""
        threat_surface = _make_threat_surface([["T1", "T2", "T3"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_threats) == {"T2", "T3"}

    def test_empty_scenarios_flags_everything(self):
        """With no scenarios, all entry points, zones, and threats are gaps."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])

        gaps = analyze_coverage_gaps(profile, threat_surface, [])
        assert gaps.uncovered_entry_points == ["ep-a (zone 1)"]
        assert gaps.uncovered_zones == [1, 2]
        assert gaps.uncovered_threats == ["T1"]
        assert gaps.has_gaps

    def test_zones_across_multiple_scenarios(self):
        """Zone coverage is the union across all scenarios."""
        profile = _make_profile(zones_active=[1, 2, 3])
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(zone_sequence=[1], agentic_threat_ids=["T1"]),
            _make_envelope(zone_sequence=[2, 3], agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_zones == []

    def test_threats_across_multiple_entries(self):
        """Threats from multiple threat surface entries are all checked."""
        threat_surface = _make_threat_surface([["T1"], ["T2"]])
        profile = _make_profile()
        scenarios = [
            _make_envelope(agentic_threat_ids=["T1"]),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_threats == ["T2"]

    def test_to_dict(self):
        """CoverageGaps.to_dict returns a serializable dict."""
        gaps = CoverageGaps(
            uncovered_entry_points=["ep-a"],
            uncovered_zones=[3],
            uncovered_threats=["T5"],
        )
        d = gaps.to_dict()
        assert d["uncovered_entry_points"] == ["ep-a"]
        assert d["uncovered_zones"] == [3]
        assert d["uncovered_threats"] == ["T5"]

    def test_has_gaps_false_when_empty(self):
        """No gaps means has_gaps is False."""
        gaps = CoverageGaps()
        assert not gaps.has_gaps

    def test_has_gaps_true_for_entry_points(self):
        gaps = CoverageGaps(uncovered_entry_points=["ep-a"])
        assert gaps.has_gaps

    def test_has_gaps_true_for_zones(self):
        gaps = CoverageGaps(uncovered_zones=[3])
        assert gaps.has_gaps

    def test_has_gaps_true_for_threats(self):
        gaps = CoverageGaps(uncovered_threats=["T5"])
        assert gaps.has_gaps


# ---------------------------------------------------------------------------
# Entry point normalization tests (scenario-forge-8dd)
# ---------------------------------------------------------------------------


class TestNormalizeEntryPoint:
    """Tests for _normalize_entry_point helper."""

    def test_lowercases(self):
        assert _normalize_entry_point("User Prompts (Zone 1)") == "user prompts (zone 1)"

    def test_strips_whitespace(self):
        assert _normalize_entry_point("  user prompts (zone 1)  ") == "user prompts (zone 1)"

    def test_collapses_internal_whitespace(self):
        assert _normalize_entry_point("user  prompts   (zone 1)") == "user prompts (zone 1)"

    def test_removes_trailing_period(self):
        assert _normalize_entry_point("user prompts (zone 1).") == "user prompts (zone 1)"

    def test_removes_trailing_comma(self):
        assert _normalize_entry_point("user prompts (zone 1),") == "user prompts (zone 1)"

    def test_removes_trailing_semicolon(self):
        assert _normalize_entry_point("user prompts (zone 1);") == "user prompts (zone 1)"

    def test_identity_for_already_normalized(self):
        assert _normalize_entry_point("user prompts (zone 1)") == "user prompts (zone 1)"


class TestCoverageGapsEntryPointMatching:
    """Tests for entry point coverage with normalized matching (scenario-forge-8dd)."""

    def test_partial_entry_points_used(self):
        """Scenarios using only 3 of 5 profile entry points → 2 uncovered."""
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "document uploads (zone 1)",
                "admin console (zone 2)",
                "API gateway (zone 3)",
                "message queue (zone 3)",
            ],
            zones_active=[1, 2, 3],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user prompts (zone 1)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="admin console (zone 2)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="API gateway (zone 3)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_entry_points) == {
            "document uploads (zone 1)",
            "message queue (zone 3)",
        }
        assert len(gaps.uncovered_entry_points) == 2
        assert gaps.has_gaps

    def test_all_entry_points_used_no_gaps(self):
        """All entry points used → 0 uncovered."""
        profile = _make_profile(
            entry_points=["ep-a (zone 1)", "ep-b (zone 2)", "ep-c (zone 3)"],
            zones_active=[1, 2, 3],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="ep-a (zone 1)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="ep-b (zone 2)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="ep-c (zone 3)",
                zone_sequence=[1, 2, 3],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []
        assert not gaps.has_gaps

    def test_empty_scenarios_all_uncovered(self):
        """Empty scenarios list → all entry points uncovered."""
        profile = _make_profile(
            entry_points=[
                "user prompts (zone 1)",
                "document uploads (zone 1)",
                "admin console (zone 2)",
            ],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert set(gaps.uncovered_entry_points) == {
            "user prompts (zone 1)",
            "document uploads (zone 1)",
            "admin console (zone 2)",
        }
        assert len(gaps.uncovered_entry_points) == 3

    def test_case_insensitive_matching(self):
        """LLM-generated entry points with different casing should match."""
        profile = _make_profile(
            entry_points=["User Prompts (Zone 1)", "Admin Console (Zone 2)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user prompts (zone 1)",
                zone_sequence=[1, 2],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="ADMIN CONSOLE (ZONE 2)",
                zone_sequence=[1, 2],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []

    def test_whitespace_normalized_matching(self):
        """Extra whitespace in LLM output should not cause false gaps."""
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "admin console (zone 2)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user  prompts  (zone  1)",
                zone_sequence=[1, 2],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="  admin console (zone 2)  ",
                zone_sequence=[1, 2],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []

    def test_trailing_punctuation_normalized(self):
        """Trailing punctuation from LLM output should not cause false gaps."""
        profile = _make_profile(
            entry_points=["user prompts (zone 1)", "admin console (zone 2)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios = [
            _make_envelope(
                entry_point="user prompts (zone 1).",
                zone_sequence=[1, 2],
                agentic_threat_ids=["T1"],
            ),
            _make_envelope(
                entry_point="admin console (zone 2)",
                zone_sequence=[1, 2],
                agentic_threat_ids=["T1"],
            ),
        ]

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        assert gaps.uncovered_entry_points == []

    def test_uncovered_preserves_original_profile_names(self):
        """Uncovered entry points should use the original profile names, not normalized."""
        profile = _make_profile(
            entry_points=["User Prompts (Zone 1)", "Admin Console (Zone 2)"],
            zones_active=[1, 2],
        )
        threat_surface = _make_threat_surface([["T1"]])
        scenarios: list[ScenarioEnvelope] = []

        gaps = analyze_coverage_gaps(profile, threat_surface, scenarios)
        # Should preserve original casing from the profile
        assert "User Prompts (Zone 1)" in gaps.uncovered_entry_points
        assert "Admin Console (Zone 2)" in gaps.uncovered_entry_points


# ---------------------------------------------------------------------------
# Actor profile diversity tests
# ---------------------------------------------------------------------------


class TestAnalyzeAttackerDiversity:
    """Tests for analyze_attacker_diversity (actor_profile based)."""

    def test_empty_scenarios(self):
        result = analyze_attacker_diversity([])
        assert result.model_counts == {}
        assert result.dominant_model is None
        assert result.is_flagged is False

    def test_diverse_actor_types_no_flag(self):
        """When scenarios have varied actor types, no flag."""
        scenarios = [
            _make_envelope(actor_type="malicious-insider"),
            _make_envelope(actor_type="supply-chain-actor"),
            _make_envelope(actor_type="hacktivist"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="nation-state"),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert not result.is_flagged
        assert len(result.model_counts) == 5

    def test_monotone_actor_type_flagged(self):
        """When >80% of scenarios use the same actor type, flag is raised."""
        scenarios = [
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
            _make_envelope(actor_type="adversarial-user"),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.is_flagged
        assert result.dominant_model == "adversarial-user"
        assert result.dominant_fraction > 0.8

    def test_exactly_at_threshold_not_flagged(self):
        """Exactly 80% (4/5) should NOT be flagged (> threshold, not >=)."""
        scenarios = [
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="malicious-insider"),
        ]

        result = analyze_attacker_diversity(scenarios)
        # 4 cybercriminal + 1 malicious-insider = 4/5 = 0.8
        assert result.dominant_fraction == pytest.approx(0.8)
        assert not result.is_flagged

    def test_single_scenario_flagged(self):
        """One scenario = 100% one type, which is > 80%, so it IS flagged."""
        scenarios = [
            _make_envelope(actor_type="nation-state"),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.dominant_fraction == 1.0
        assert result.is_flagged

    def test_no_actor_profile_classified_as_unknown(self):
        """Envelopes without actor_profile are classified as 'unknown'."""
        scenarios = [
            _make_envelope(actor_type=None),
            _make_envelope(actor_type=None),
            _make_envelope(actor_type=None),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.dominant_model == "unknown"
        assert result.is_flagged

    def test_mixed_with_and_without_actor_profile(self):
        """Mix of envelopes with and without actor_profile."""
        scenarios = [
            _make_envelope(actor_type="cybercriminal"),
            _make_envelope(actor_type="nation-state"),
            _make_envelope(actor_type=None),
        ]

        result = analyze_attacker_diversity(scenarios)
        assert result.model_counts == {
            "cybercriminal": 1,
            "nation-state": 1,
            "unknown": 1,
        }
        assert not result.is_flagged

    def test_to_dict(self):
        result = AttackerDiversityResult(
            model_counts={"cybercriminal": 3, "malicious-insider": 1},
            dominant_model="cybercriminal",
            dominant_fraction=0.75,
            is_flagged=False,
        )
        d = result.to_dict()
        assert d["model_counts"] == {"cybercriminal": 3, "malicious-insider": 1}
        assert d["dominant_model"] == "cybercriminal"
        assert d["dominant_fraction"] == 0.75
        assert d["is_flagged"] is False


# ---------------------------------------------------------------------------
# Coverage report output tests
# ---------------------------------------------------------------------------


class TestWriteCoverageReport:
    """Tests for write_coverage_report."""

    def test_writes_json_file(self, tmp_path: Path):
        gaps = CoverageGaps(
            uncovered_entry_points=["ep-a"],
            uncovered_zones=[3],
            uncovered_threats=["T5"],
        )
        diversity = AttackerDiversityResult(
            model_counts={"external_attacker": 5},
            dominant_model="external_attacker",
            dominant_fraction=1.0,
            is_flagged=True,
        )

        path = write_coverage_report(gaps, tmp_path, diversity)
        assert path.exists()
        assert path.name == "coverage-gaps.json"

        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == ["ep-a"]
        assert data["coverage_gaps"]["uncovered_zones"] == [3]
        assert data["coverage_gaps"]["uncovered_threats"] == ["T5"]
        assert data["attacker_diversity"]["is_flagged"] is True
        assert data["attacker_diversity"]["dominant_model"] == "external_attacker"

    def test_writes_empty_gaps(self, tmp_path: Path):
        gaps = CoverageGaps()

        path = write_coverage_report(gaps, tmp_path)
        data = json.loads(path.read_text())
        assert data["coverage_gaps"]["uncovered_entry_points"] == []
        assert data["coverage_gaps"]["uncovered_zones"] == []
        assert data["coverage_gaps"]["uncovered_threats"] == []
        assert "attacker_diversity" not in data

    def test_writes_with_attacker_diversity(self, tmp_path: Path):
        gaps = CoverageGaps()
        diversity = AttackerDiversityResult(
            model_counts={"insider": 2, "external_attacker": 3},
            dominant_model="external_attacker",
            dominant_fraction=0.6,
            is_flagged=False,
        )

        path = write_coverage_report(gaps, tmp_path, diversity)
        data = json.loads(path.read_text())
        assert data["attacker_diversity"]["dominant_model"] == "external_attacker"
        assert data["attacker_diversity"]["is_flagged"] is False


# ---------------------------------------------------------------------------
# Coverage remediation tests (scenario-forge-5gs)
# ---------------------------------------------------------------------------


def _make_seed(
    seed_id: str = "T1-S1",
    threat_id: str = "T1",
    threat_name: str = "Prompt Injection",
    agentic_threat_ids: list[str] | None = None,
) -> ScenarioSeed:
    """Build a minimal valid ScenarioSeed for testing."""
    if agentic_threat_ids is None:
        agentic_threat_ids = [threat_id]
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name=threat_name,
        sub_scenario_name=f"Sub-scenario for {threat_name}",
        sub_scenario_description=f"Description of {threat_name} sub-scenario.",
        risk_card_ref=_make_risk_card_ref(),
        contributing_risk_cards=[_make_risk_card_ref()],
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=agentic_threat_ids,
    )


class TestPickBestSeedForEntryPoint:
    """Tests for _pick_best_seed_for_entry_point."""

    def test_returns_none_for_empty_seeds(self):
        profile = _make_profile()
        result = _pick_best_seed_for_entry_point("chat input (zone 1)", [], profile)
        assert result is None

    def test_returns_only_seed_when_one_available(self):
        profile = _make_profile()
        seed = _make_seed()
        result = _pick_best_seed_for_entry_point("chat input (zone 1)", [seed], profile)
        assert result is seed

    def test_returns_a_seed_from_multiple(self):
        """With multiple seeds, should return one of them (not None)."""
        profile = _make_profile(zones_active=[1, 2, 3])
        seeds = [
            _make_seed(seed_id="T1-S1", threat_id="T1"),
            _make_seed(seed_id="T2-S1", threat_id="T2"),
            _make_seed(seed_id="T3-S1", threat_id="T3"),
        ]
        result = _pick_best_seed_for_entry_point(
            "admin console (zone 2)", seeds, profile
        )
        assert result is not None
        assert result in seeds


class TestRemediateCoverageGaps:
    """Tests for _remediate_coverage_gaps."""

    def test_no_uncovered_entry_points_returns_empty(self, tmp_path: Path):
        """When there are no uncovered entry points, nothing happens."""
        gaps = CoverageGaps(uncovered_entry_points=[])
        profile = _make_profile()
        client = MagicMock()

        scenarios, notes = _remediate_coverage_gaps(
            gaps, [_make_seed()], profile, client, "test use case", tmp_path
        )
        assert scenarios == []
        assert notes == []

    def test_no_seeds_records_skip_note(self, tmp_path: Path):
        """When seeds are empty, each uncovered EP gets a skip note."""
        gaps = CoverageGaps(uncovered_entry_points=["chat input (zone 1)"])
        profile = _make_profile()
        client = MagicMock()

        scenarios, notes = _remediate_coverage_gaps(
            gaps, [], profile, client, "test use case", tmp_path
        )
        assert scenarios == []
        assert len(notes) == 1
        assert "no seeds available" in notes[0]

    @patch("scenario_forge.pipeline.runner.generate_scenario")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    def test_generates_scenario_for_each_uncovered_ep(
        self, mock_write, mock_generate, tmp_path: Path
    ):
        """Each uncovered entry point should trigger one generate_scenario call."""
        uncovered = ["chat input (zone 1)", "admin dashboard (zone 2)"]
        gaps = CoverageGaps(uncovered_entry_points=uncovered)
        profile = _make_profile(
            entry_points=["existing ep", "chat input (zone 1)", "admin dashboard (zone 2)"],
            zones_active=[1, 2],
        )
        seeds = [_make_seed(seed_id="T1-S1"), _make_seed(seed_id="T2-S1")]
        client = MagicMock()

        # Create mock envelopes for each uncovered EP.
        mock_envelopes = []
        for ep in uncovered:
            env = _make_envelope(entry_point=ep)
            mock_envelopes.append(env)

        mock_generate.side_effect = mock_envelopes
        mock_write.return_value = (tmp_path / "test.yaml", None)

        scenarios, notes = _remediate_coverage_gaps(
            gaps, seeds, profile, client, "test use case", tmp_path
        )

        assert len(scenarios) == 2
        assert mock_generate.call_count == 2

        # Verify each call used the correct preferred_entry_point.
        for i, ep in enumerate(uncovered):
            call_kwargs = mock_generate.call_args_list[i]
            assert call_kwargs.kwargs.get("preferred_entry_point") == ep

    @patch("scenario_forge.pipeline.runner.generate_scenario")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    def test_handles_generation_failure_gracefully(
        self, mock_write, mock_generate, tmp_path: Path
    ):
        """When generate_scenario raises, we record a note and continue."""
        gaps = CoverageGaps(
            uncovered_entry_points=["ep-fail (zone 1)", "ep-ok (zone 2)"]
        )
        profile = _make_profile(zones_active=[1, 2])
        seeds = [_make_seed()]
        client = MagicMock()

        # First call fails, second succeeds.
        ok_envelope = _make_envelope(entry_point="ep-ok (zone 2)")
        mock_generate.side_effect = [
            RuntimeError("LLM timeout"),
            ok_envelope,
        ]
        mock_write.return_value = (tmp_path / "test.yaml", None)

        scenarios, notes = _remediate_coverage_gaps(
            gaps, seeds, profile, client, "test use case", tmp_path
        )

        assert len(scenarios) == 1
        assert scenarios[0] is ok_envelope
        assert len(notes) == 1
        assert "Remediation generation failed" in notes[0]
        assert "ep-fail (zone 1)" in notes[0]

    @patch("scenario_forge.pipeline.runner.generate_scenario")
    @patch("scenario_forge.pipeline.runner.write_scenario_outputs")
    def test_passes_seed_and_profile_to_generate(
        self, mock_write, mock_generate, tmp_path: Path
    ):
        """Verify generate_scenario receives the correct seed, profile, and use_case."""
        gaps = CoverageGaps(uncovered_entry_points=["api gateway (zone 3)"])
        profile = _make_profile(zones_active=[1, 2, 3])
        seed = _make_seed(seed_id="T5-S1")
        client = MagicMock()

        mock_envelope = _make_envelope(entry_point="api gateway (zone 3)")
        mock_generate.return_value = mock_envelope
        mock_write.return_value = (tmp_path / "test.yaml", None)

        _remediate_coverage_gaps(
            gaps, [seed], profile, client, "my use case", tmp_path
        )

        call_args = mock_generate.call_args
        assert call_args.args[0] is seed  # seed
        assert call_args.args[1] is profile  # profile
        assert call_args.args[2] is client  # client
        assert call_args.args[3] == "my use case"  # use_case
        assert call_args.kwargs["preferred_entry_point"] == "api gateway (zone 3)"
